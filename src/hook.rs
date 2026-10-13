//! Webhook delivery: persisted events, a background loop sends them, every attempt logged in `webhook_deliveries`.
use crate::{now, St};
use rusqlite::{params, Connection};
use serde_json::json;
use std::{sync::Arc, time::Duration};

/// Delay in seconds before retry n; the first send is immediate, so attempts in total = len + 1.
const RETRY_DELAYS: [i64; 2] = [10, 60];
pub const MAX_ATTEMPTS: i64 = RETRY_DELAYS.len() as i64 + 1;
/// A claimed event is not picked again for this long (crash safety).
const LEASE: i64 = 30;
const DAY: i64 = 86400;

/// Outcome of an attempt: (status, delay before the next attempt).
fn decide(attempts: i64, ok: bool, retry: bool) -> (&'static str, Option<i64>) {
    let delay = RETRY_DELAYS.get(attempts as usize - 1).copied();
    match (ok, retry, delay) {
        (true, ..) => ("delivered", None),
        (false, true, Some(d)) => ("pending", Some(d)),
        _ => ("failed", None),
    }
}

/// Persists an event for the merchant's webhook (skipped when no URL is set) and wakes the sender.
pub fn enqueue(
    st: &Arc<St>,
    db: &Connection,
    mid: i64,
    invoice: Option<&str>,
    typ: &str,
    body: String,
) -> anyhow::Result<()> {
    let has_url: bool = db.query_row(
        "SELECT webhook_url IS NOT NULL FROM merchants WHERE id=?1",
        [mid],
        |r| r.get(0),
    )?;
    if has_url {
        insert(db, mid, invoice, typ, &body, Some(now()))?;
        tokio::spawn(tick(st.clone()));
    }
    Ok(())
}

fn insert(
    db: &Connection,
    mid: i64,
    invoice: Option<&str>,
    typ: &str,
    body: &str,
    next: Option<i64>,
) -> rusqlite::Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO webhook_events(id,merchant_id,invoice_id,type,body,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,'pending',0,?6,?7,?7)",
        params![id, mid, invoice, typ, body, next, now()],
    )?;
    Ok(id)
}

/// One attempt for event `id`; records the delivery and the new event state. Returns the HTTP status.
async fn send(st: &St, id: &str, retry: bool) -> anyhow::Result<u16> {
    let (mid, invoice, typ, body, attempts, url, secret): (i64, Option<String>, String, String, i64, Option<String>, String) =
        st.db.lock().unwrap().query_row(
            "SELECT e.merchant_id, e.invoice_id, e.type, e.body, e.attempts, m.webhook_url, m.webhook_secret
             FROM webhook_events e JOIN merchants m ON m.id=e.merchant_id WHERE e.id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
        )?;
    let attempt = attempts + 1;
    let Some(url) = url else {
        let e = "no webhook URL configured";
        st.db.lock().unwrap().execute(
            "UPDATE webhook_events SET status='failed', attempts=?1, next_attempt_at=NULL, last_status_code=NULL, last_error=?2, updated_at=?3 WHERE id=?4",
            params![attempt, e, now(), id],
        )?;
        anyhow::bail!(e);
    };
    let r = crate::account::send_webhook(&st.http, &url, &secret, body).await;
    let ok = matches!(r, Ok(s) if (200..300).contains(&s));
    let err = r
        .as_ref()
        .err()
        .map(|e| e.to_string())
        .or_else(|| (!ok).then(|| format!("HTTP {}", r.as_ref().unwrap())));
    let (status, delay) = decide(attempt, ok, retry);
    let t = now();
    let db = st.db.lock().unwrap();
    db.execute(
        "INSERT INTO webhook_deliveries(merchant_id,invoice_id,type,url,status_code,error,attempt,created_at,event_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![mid, invoice, typ, url, r.as_ref().ok(), r.as_ref().err().map(|e| e.to_string()), attempt, t, id],
    )?;
    db.execute(
        "UPDATE webhook_events SET status=?1, attempts=?2, next_attempt_at=?3, last_status_code=?4, last_error=?5, updated_at=?6 WHERE id=?7",
        params![status, attempt, delay.map(|d| t + d), r.as_ref().ok(), err, t, id],
    )?;
    r
}

/// Sends one `test` event synchronously (no retries); the event keeps its final status.
pub async fn send_test(st: &St, mid: i64, body: String) -> anyhow::Result<u16> {
    let id = insert(&st.db.lock().unwrap(), mid, None, "test", &body, None)?;
    send(st, &id, false).await
}

/// Claims due pending events (lease) and sends each one.
pub async fn tick(st: Arc<St>) {
    let ids: Vec<String> = (|| -> rusqlite::Result<_> {
        let db = st.db.lock().unwrap();
        let t = now();
        let mut q = db.prepare(
            "UPDATE webhook_events SET next_attempt_at=?1 WHERE id IN
             (SELECT id FROM webhook_events WHERE status='pending' AND next_attempt_at<=?2 ORDER BY next_attempt_at LIMIT 50) RETURNING id",
        )?;
        let v = q.query_map(params![t + LEASE, t], |r| r.get(0))?.collect();
        v
    })()
    .unwrap_or_default();
    for id in ids {
        if let Err(e) = send(&st, &id, true).await {
            tracing::warn!("webhook event {id}: {e}");
        }
    }
}

/// Background sender: survives restarts because all state is in the database.
pub async fn run(st: Arc<St>) {
    loop {
        tick(st.clone()).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Drops delivered events after 30 days and failed ones after 90 (with their attempt logs).
pub fn purge(db: &Connection) {
    let t = now();
    let _ = db.execute(
        "DELETE FROM webhook_deliveries WHERE event_id IN (SELECT id FROM webhook_events WHERE (status='delivered' AND updated_at<?1) OR (status='failed' AND updated_at<?2))",
        params![t - 30 * DAY, t - 90 * DAY],
    );
    let _ = db.execute(
        "DELETE FROM webhook_events WHERE (status='delivered' AND updated_at<?1) OR (status='failed' AND updated_at<?2)",
        params![t - 30 * DAY, t - 90 * DAY],
    );
}

/// Queues the invoice event `typ` for the merchant's webhook.
pub fn notify(st: &Arc<St>, db: &Connection, id: &str, typ: &str) -> anyhow::Result<()> {
    let (mid, status, amount, txid, received): (i64, String, i64, Option<String>, i64) = db
        .query_row(
            "SELECT i.merchant_id, i.status, i.amount_zat, i.txid,
            (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=i.id)
         FROM invoices i WHERE i.id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
    let body = json!({"type": typ, "invoice_id": id, "status": status, "amount_zat": amount, "received_zat": received,
        "overpaid_zat": (received - amount).max(0), "txid": txid, "swap": crate::swap::webhook_json(db, id)}).to_string();
    enqueue(st, db, mid, Some(id), typ, body)
}

/// Requeues one failed event of the merchant; false if it is not failed (or not theirs).
pub fn retry(db: &Connection, mid: i64, id: &str) -> rusqlite::Result<bool> {
    Ok(db.execute(
        "UPDATE webhook_events SET status='pending', attempts=0, next_attempt_at=?1, updated_at=?1 WHERE id=?2 AND merchant_id=?3 AND status='failed'",
        params![now(), id, mid],
    )? > 0)
}

/// Requeues the merchant's failed events from the last 7 days (max 100).
pub fn retry_failed(db: &Connection, mid: i64) -> rusqlite::Result<usize> {
    db.execute(
        "UPDATE webhook_events SET status='pending', attempts=0, next_attempt_at=?1, updated_at=?1 WHERE id IN
         (SELECT id FROM webhook_events WHERE merchant_id=?2 AND status='failed' AND created_at>=?3 ORDER BY created_at DESC LIMIT 100)",
        params![now(), mid, now() - 7 * DAY],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule() {
        assert_eq!(MAX_ATTEMPTS, 3);
        // three failures end failed, delays 10 s then 60 s
        assert_eq!(decide(1, false, true), ("pending", Some(10)));
        assert_eq!(decide(2, false, true), ("pending", Some(60)));
        assert_eq!(decide(3, false, true), ("failed", None));
        // success on attempt 2
        assert_eq!(decide(2, true, true), ("delivered", None));
        // test events never retry
        assert_eq!(decide(1, false, false), ("failed", None));
    }

    #[test]
    fn retry_resets() {
        let st = crate::tests::test_st();
        let db = st.db.lock().unwrap();
        db.execute("INSERT INTO merchants(id,email,password_hash,name,webhook_secret) VALUES(1,'a','','','s')", []).unwrap();
        let id = insert(&db, 1, None, "test", "{}", None).unwrap();
        assert!(!retry(&db, 1, &id).unwrap()); // pending: not retryable
        db.execute("UPDATE webhook_events SET status='failed', attempts=3", [])
            .unwrap();
        assert!(!retry(&db, 2, &id).unwrap()); // other merchant
        assert_eq!(retry_failed(&db, 1).unwrap(), 1);
        let (s, a, n): (String, i64, Option<i64>) = db
            .query_row(
                "SELECT status, attempts, next_attempt_at FROM webhook_events",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((s.as_str(), a), ("pending", 0));
        assert!(n.is_some());
    }
}
