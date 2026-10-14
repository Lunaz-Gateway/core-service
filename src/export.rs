//! Accountant CSV export, built from the rows the viewing-key scanner decrypted.
use crate::account::{auth, S};
use crate::api::{bad, AppErr};
use crate::now;
use crate::swap::iso;
use crate::watcher::IRONWOOD_IDX;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rusqlite::{params, Connection, OpenFlags};
use serde::Deserialize;
use std::time::Duration;

const MAX_ROWS: i64 = 50_000;

/// Exact decimal from zatoshi, no float rounding.
fn zec(z: i64) -> String {
    format!("{}.{:08}", z / 100_000_000, z % 100_000_000)
}

/// RFC 4180 quoting; a text cell a spreadsheet would run as a formula gets a leading ' (numbers stay as they are).
fn field(s: &str) -> String {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) && s.parse::<f64>().is_err() {
        format!("\"'{}\"", s.replace('"', "\"\""))
    } else if s.contains([',', '"', '\n', '\r']) {
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
    let kind = q.kind.clone().unwrap_or("invoices".into());
    if kind != "invoices" && kind != "payments" {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "kind must be invoices or payments",
        ));
    }
    if !st.limits.hit(&format!("export:{mid}"), 5, 60, now()) {
        return Err(bad(
            StatusCode::TOO_MANY_REQUESTS,
            "too many exports, try again in a minute",
        ));
    }
    let (from, to) = (q.from.unwrap_or(0), q.to.unwrap_or(i64::MAX));
    let (path, k) = (st.db_path.clone(), kind.clone());
    // Own read-only connection off the async runtime: WAL readers never hold the shared db lock.
    let out = tokio::task::spawn_blocking(move || build(&path, &k, mid, from, to))
        .await
        .map_err(anyhow::Error::from)??;
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

fn build(path: &str, kind: &str, mid: i64, from: i64, to: i64) -> rusqlite::Result<String> {
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.busy_timeout(Duration::from_secs(5))?;
    let mut out = String::new();
    match kind {
        "invoices" => {
            out += &line(
                &"invoice_id,created_at,paid_at,status,amount_zec,fee_zec,received_zec,overpaid_zec,usd_rate,received_usd,txid,paid_with,origin_chain,origin_amount,swap_status"
                    .split(',').map(String::from).collect::<Vec<_>>(),
            );
            let mut stmt = db.prepare(
                "SELECT i.id, i.created_at, i.paid_at, i.status, i.amount_zat,
                    (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=i.id AND height IS NOT NULL), i.paid_usd_rate, i.txid,
                    w.symbol, w.blockchain, w.amount_in_formatted, w.status, i.fee_zat
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
                    zec(r.get(12)?),
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
        _ => {}
    }
    Ok(out)
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
        // formula injection
        assert_eq!(field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        for s in ["+1+cmd", "-2+3", "@SUM(A1)", "\tx", "\rx"] {
            assert_eq!(field(s), format!("\"'{s}\""));
        }
        assert_eq!(field("a=b"), "a=b");
        // numeric cells are untouched
        for s in ["-1", "0.00000000", "+5", "-0.5"] {
            assert_eq!(field(s), s);
        }
    }
}
