//! Accountant CSV export, built from the rows the viewing-key scanner decrypted.
use crate::account::{auth, S};
use crate::api::{bad, AppErr};
use crate::swap::iso;
use crate::watcher::IRONWOOD_IDX;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rusqlite::params;
use serde::Deserialize;

const MAX_ROWS: i64 = 50_000;

/// Exact decimal from zatoshi, no float rounding.
fn zec(z: i64) -> String {
    format!("{}.{:08}", z / 100_000_000, z % 100_000_000)
}

fn field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn line(cols: &[String]) -> String {
    cols.iter().map(|c| field(c)).collect::<Vec<_>>().join(",") + "\r\n"
}

#[derive(Deserialize)]
pub struct Q {
    from: Option<i64>,
    to: Option<i64>,
    kind: Option<String>,
}

pub async fn export_csv(
    State(st): S,
    h: HeaderMap,
    Query(q): Query<Q>,
) -> Result<Response, AppErr> {
    let mid = auth(&st, &h)?;
    let kind = q.kind.as_deref().unwrap_or("invoices");
    let (from, to) = (q.from.unwrap_or(0), q.to.unwrap_or(i64::MAX));
    let db = st.db.lock().unwrap();
    let mut out = String::new();
    match kind {
        "invoices" => {
            out += &line(
                &"invoice_id,created_at,paid_at,status,amount_zec,received_zec,overpaid_zec,usd_rate,received_usd,txid,paid_with,origin_chain,origin_amount,swap_status"
                    .split(',').map(String::from).collect::<Vec<_>>(),
            );
            let mut stmt = db.prepare(
                "SELECT i.id, i.created_at, i.paid_at, i.status, i.amount_zat,
                    (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=i.id), i.paid_usd_rate, i.txid,
                    w.symbol, w.blockchain, w.amount_in_formatted, w.status
                 FROM invoices i LEFT JOIN swaps w ON w.invoice_id=i.id
                 WHERE i.merchant_id=?1 AND i.created_at>=?2 AND i.created_at<=?3
                 ORDER BY i.created_at, i.div_index LIMIT ?4",
            )?;
            let mut rows = stmt.query(params![mid, from, to, MAX_ROWS])?;
            while let Some(r) = rows.next()? {
                let (amount, recv): (i64, i64) = (r.get(4)?, r.get(5)?);
                let status: String = r.get(3)?;
                let rate: Option<f64> = r.get(6)?;
                let (sym, chain, amt, sw): (
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                ) = (r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?);
                let paid_with = if !matches!(status.as_str(), "paid" | "underpaid") {
                    String::new()
                } else if sw.as_deref() == Some("SUCCESS") {
                    sym.clone().unwrap_or_default()
                } else {
                    "ZEC".into()
                };
                out += &line(&[
                    r.get(0)?,
                    iso(r.get(1)?),
                    r.get::<_, Option<i64>>(2)?.map(iso).unwrap_or_default(),
                    status,
                    zec(amount),
                    zec(recv),
                    zec((recv - amount).max(0)),
                    rate.map(|p| p.to_string()).unwrap_or_default(),
                    rate.map(|p| format!("{:.2}", recv as f64 / 1e8 * p))
                        .unwrap_or_default(),
                    r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                    paid_with,
                    chain.unwrap_or_default(),
                    amt.unwrap_or_default(),
                    sw.unwrap_or_default(),
                ]);
            }
        }
        "payments" => {
            out += &line(
                &"txid,action_index,pool,invoice_id,value_zec,block_height,invoice_status"
                    .split(',')
                    .map(String::from)
                    .collect::<Vec<_>>(),
            );
            let mut stmt = db.prepare(
                "SELECT p.txid, p.action_idx, p.invoice_id, p.value_zat, p.height, i.status
                 FROM payments p JOIN invoices i ON i.id=p.invoice_id
                 WHERE i.merchant_id=?1 AND i.created_at>=?2 AND i.created_at<=?3
                 ORDER BY i.created_at, p.txid, p.action_idx LIMIT ?4",
            )?;
            let mut rows = stmt.query(params![mid, from, to, MAX_ROWS])?;
            while let Some(r) = rows.next()? {
                let idx: i64 = r.get(1)?;
                let ironwood = idx >= IRONWOOD_IDX as i64;
                out += &line(&[
                    r.get(0)?,
                    (if ironwood {
                        idx - IRONWOOD_IDX as i64
                    } else {
                        idx
                    })
                    .to_string(),
                    (if ironwood { "ironwood" } else { "orchard" }).into(),
                    r.get(2)?,
                    zec(r.get(3)?),
                    r.get::<_, Option<i64>>(4)?
                        .map(|h| h.to_string())
                        .unwrap_or_default(),
                    r.get(5)?,
                ]);
            }
        }
        _ => {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "kind must be invoices or payments",
            ))
        }
    }
    let r = |v: Option<i64>| v.map_or("all".into(), |v| v.to_string());
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"lunaz-{kind}-{}-{}.csv\"",
                    r(q.from),
                    r(q.to)
                ),
            ),
        ],
        out,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zat_decimals() {
        assert_eq!(zec(0), "0.00000000");
        assert_eq!(zec(1), "0.00000001");
        assert_eq!(zec(123_456_789), "1.23456789");
        assert_eq!(zec(2_100_000_000_000_000), "21000000.00000000");
    }

    #[test]
    fn csv_escaping() {
        assert_eq!(field("plain"), "plain");
        assert_eq!(field("a,b"), "\"a,b\"");
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(field("l1\nl2"), "\"l1\nl2\"");
        assert_eq!(line(&["a".into(), "b,c".into()]), "a,\"b,c\"\r\n");
    }
}
