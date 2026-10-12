//! Webhook delivery: retry with backoff, every attempt logged in `webhook_deliveries`.
use crate::{now, St};
use rusqlite::{params, Connection};
use serde_json::json;
use std::{sync::Arc, time::Duration};

// Delay before retry n (1-based); None once the attempts are used up.
pub fn backoff(retry: usize) -> Option<Duration> {
    [10, 60, 300]
        .get(retry.checked_sub(1)?)
        .map(|s| Duration::from_secs(*s))
}

/// Sends once, or with retries (4 attempts total) on network error / non-2xx; logs each attempt.
pub async fn deliver(
    st: &St,
    mid: i64,
    invoice: Option<&str>,
    typ: &str,
    (url, secret): (&str, &str),
    body: String,
    retry: bool,
) -> anyhow::Result<u16> {
    let mut attempt = 1;
    loop {
        let r = crate::account::send_webhook(&st.http, url, secret, body.clone()).await;
        let _ = st.db.lock().unwrap().execute(
            "INSERT INTO webhook_deliveries(merchant_id,invoice_id,type,url,status_code,error,attempt,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![mid, invoice, typ, url, r.as_ref().ok(), r.as_ref().err().map(|e| e.to_string()), attempt, now()],
        );
        let wait = backoff(attempt);
        if matches!(r, Ok(s) if (200..300).contains(&s)) || !retry || wait.is_none() {
            return r;
        }
        tokio::time::sleep(wait.unwrap()).await;
        attempt += 1;
    }
}

/// Fire-and-forget delivery of the invoice event `typ` to the merchant's webhook, if one is set.
// ponytail: in-process task, pending retries are lost on restart; a persisted queue would fix that
pub fn notify(st: &Arc<St>, db: &Connection, id: &str, typ: &str) -> anyhow::Result<()> {
    let (mid, url, secret, status, amount, txid, received): (
        i64,
        Option<String>,
        String,
        String,
        i64,
        Option<String>,
        i64,
    ) = db.query_row(
        "SELECT i.merchant_id, m.webhook_url, m.webhook_secret, i.status, i.amount_zat, i.txid,
            (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=i.id)
         FROM invoices i JOIN merchants m ON m.id=i.merchant_id WHERE i.id=?1",
        [id],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        },
    )?;
    let Some(url) = url else { return Ok(()) };
    let body = json!({"type": typ, "invoice_id": id, "status": status, "amount_zat": amount, "received_zat": received,
        "overpaid_zat": (received - amount).max(0), "txid": txid, "swap": crate::swap::webhook_json(db, id)}).to_string();
    let (st, id, typ) = (st.clone(), id.to_string(), typ.to_string());
    tokio::spawn(async move {
        if let Err(e) = deliver(&st, mid, Some(&id), &typ, (&url, &secret), body, true).await {
            tracing::warn!("webhook {typ} {id}: {e}");
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule() {
        let s: Vec<_> = (0..6).map(|n| backoff(n).map(|d| d.as_secs())).collect();
        assert_eq!(s, [None, Some(10), Some(60), Some(300), None, None]);
    }
}
