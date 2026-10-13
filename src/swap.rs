//! Cross-chain payments via NEAR Intents 1Click: the buyer pays on their chain, 1Click delivers ZEC to the invoice address.
use crate::api::{bad, AppErr, R};
use crate::{now, Lk, St};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

const API: &str = "https://1click.chaindefuser.com/v0";
const ZEC: &str = "nep141:zec.omft.near";
const FINAL: &str = "('SUCCESS','REFUNDED','FAILED')";
const REPLACEABLE: &str = "('PENDING_DEPOSIT','REFUNDED','FAILED')";
// (symbol, chain) pairs offered to buyers
const WANT: &[(&str, &str)] = &[
    ("USDC", "sol"),
    ("USDC", "eth"),
    ("USDC", "base"),
    ("USDC", "arb"),
    ("USDT", "sol"),
    ("USDT", "eth"),
    ("USDT", "base"),
    ("USDT", "arb"),
    ("SOL", "sol"),
    ("ETH", "eth"),
    ("ETH", "base"),
    ("ETH", "arb"),
    ("BTC", "btc"),
    ("wNEAR", "near"),
];

pub fn curate(tokens: &Value) -> Vec<Value> {
    let s = |t: &Value, k: &str| t[k].as_str().unwrap_or_default().to_string();
    let mut out: Vec<Value> = tokens
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| s(t, "assetId").starts_with("nep141:") && WANT.contains(&(s(t, "symbol").as_str(), s(t, "blockchain").as_str())))
        .map(|t| json!({"asset_id": t["assetId"], "symbol": t["symbol"], "blockchain": t["blockchain"], "decimals": t["decimals"], "price_usd": t["price"]}))
        .collect();
    out.sort_by_key(|t| {
        WANT.iter()
            .position(|w| w.0 == t["symbol"] && w.1 == t["blockchain"])
    });
    out
}

fn call(st: &St, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match &st.jwt {
        Some(j) => rb.bearer_auth(j),
        None => rb,
    }
}

async fn assets(st: &St) -> anyhow::Result<Vec<Value>> {
    if let Some((t, v)) = &*st.assets.lk() {
        if *t > now() - 300 {
            return Ok(v.clone());
        }
    }
    let toks: Value = call(st, st.http.get(format!("{API}/tokens")))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let v = curate(&toks);
    *st.zec_price.lk() = toks
        .as_array()
        .into_iter()
        .flatten()
        .find(|t| t["assetId"] == ZEC)
        .and_then(|t| t["price"].as_f64());
    *st.assets.lk() = Some((now(), v.clone()));
    Ok(v)
}

/// ZEC price in USD from the cached 1Click token list; None when unavailable.
pub async fn zec_price(st: &St) -> Option<f64> {
    assets(st).await.ok()?;
    st.zec_price.lk().filter(|p| *p > 0.0)
}

pub async fn list_assets(State(st): State<Arc<St>>) -> R {
    let v = assets(&st).await.map_err(|e| {
        tracing::warn!("tokens: {e:#}");
        bad(StatusCode::BAD_GATEWAY, "swap provider unavailable")
    })?;
    Ok(Json(v.into()))
}

pub fn iso(t: i64) -> String {
    let (d, s) = (t.div_euclid(86400), t.rem_euclid(86400));
    let z = d + 719468;
    let (era, doe) = (z.div_euclid(146097), z.rem_euclid(146097));
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

const SWAP_SECS: i64 = 1800;

/// (invoice expiry, swap deadline). An invoice too close to expiry is extended once, never past its original expiry + 30 min; billing invoices never.
fn window(expires: i64, extended: bool, billing: bool, t: i64) -> Result<(i64, i64), &'static str> {
    if expires >= t + 600 {
        return Ok((expires, expires.min(t + SWAP_SECS)));
    }
    if billing {
        return Err("billing invoice expires too soon for a swap; start a new checkout");
    }
    if extended {
        return Err("invoice expires too soon for a swap; pay in ZEC");
    }
    let e = (t + SWAP_SECS).min(expires + SWAP_SECS);
    Ok((e, e))
}

/// Status of a swap that must not be replaced: a deposit may already be on its way.
fn active(db: &Connection, id: &str) -> rusqlite::Result<Option<String>> {
    db.query_row(
        &format!("SELECT status FROM swaps WHERE invoice_id=?1 AND status NOT IN {REPLACEABLE}"),
        [id],
        |r| r.get(0),
    )
    .optional()
}

/// Re-checks invoice and swaps under the db lock (the quote round-trip happened without it), then replaces the swap. Some(reason) = conflict, nothing written.
fn commit(
    db: &Connection,
    id: &str,
    t: i64,
    new_exp: i64,
    insert: impl FnOnce(&Connection) -> rusqlite::Result<usize>,
) -> rusqlite::Result<Option<String>> {
    let tx = db.unchecked_transaction()?;
    let (status, expires): (String, i64) = tx.query_row(
        "SELECT status, expires_at FROM invoices WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if status != "pending" || expires < t {
        return Ok(Some("invoice is not pending".into()));
    }
    if let Some(s) = active(&tx, id)? {
        return Ok(Some(format!("a swap is already in progress ({s})")));
    }
    tx.execute(
        &format!("DELETE FROM swaps WHERE invoice_id=?1 AND status IN {REPLACEABLE}"),
        [id],
    )?;
    insert(&tx)?;
    if new_exp > expires {
        tx.execute(
            "UPDATE invoices SET expires_at=?1, extended_at=?3 WHERE id=?2 AND extended_at IS NULL",
            params![new_exp, id, t],
        )?;
    }
    tx.commit()?;
    Ok(None)
}

#[derive(Deserialize)]
pub struct NewSwap {
    asset_id: String,
    refund_to: String,
}

pub async fn create_swap(
    State(st): State<Arc<St>>,
    Path(id): Path<String>,
    Json(b): Json<NewSwap>,
) -> Result<(StatusCode, Json<Value>), AppErr> {
    type Inv = (String, i64, String, i64, bool, bool);
    let (status, amount, address, expires, extended, billing): Inv = st
        .db
        .lk()
        .query_row(
            "SELECT status, amount_zat, address, expires_at, extended_at IS NOT NULL,
             EXISTS(SELECT 1 FROM subscriptions WHERE invoice_id=invoices.id) FROM invoices WHERE id=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()?
        .ok_or_else(|| bad(StatusCode::NOT_FOUND, "no such invoice"))?;
    let t = now();
    // each call can create a 1Click quote, so cap them per invoice
    if !st.limits.hit(&format!("swap:{id}"), 5, 600, t) {
        return Err(bad(
            StatusCode::TOO_MANY_REQUESTS,
            "too many swap requests, try again later",
        ));
    }
    if status != "pending" || expires < t {
        return Err(bad(StatusCode::CONFLICT, "invoice is not pending"));
    }
    let (new_exp, deadline) =
        window(expires, extended, billing, t).map_err(|m| bad(StatusCode::CONFLICT, m))?;
    if let Some(s) = active(&st.db.lk(), &id)? {
        return Err(bad(
            StatusCode::CONFLICT,
            &format!("a swap is already in progress ({s})"),
        ));
    }
    let refund = b.refund_to.trim();
    if refund.is_empty() || refund.len() > 128 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "refund_to must be 1-128 characters",
        ));
    }
    let list = assets(&st).await.map_err(|e| {
        tracing::warn!("tokens: {e:#}");
        bad(StatusCode::BAD_GATEWAY, "swap provider unavailable")
    })?;
    let a = list
        .iter()
        .find(|a| a["asset_id"] == b.asset_id)
        .ok_or_else(|| bad(StatusCode::BAD_REQUEST, "unsupported asset_id"))?;
    // Invoice amount is the exact 1Click output: withdrawFee is added to amountIn, not deducted from amountOut.
    let body = json!({"dry": false, "swapType": "EXACT_OUTPUT", "slippageTolerance": 100, "originAsset": b.asset_id, "depositType": "ORIGIN_CHAIN",
        "destinationAsset": ZEC, "amount": amount.to_string(), "recipient": address, "recipientType": "DESTINATION_CHAIN",
        "refundTo": refund, "refundType": "ORIGIN_CHAIN", "deadline": iso(deadline)});
    let r = call(&st, st.http.post(format!("{API}/quote")))
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            tracing::warn!("quote: {e}");
            bad(StatusCode::BAD_GATEWAY, "swap provider unavailable")
        })?;
    let code = r.status();
    let v: Value = r.json().await.unwrap_or_default();
    if code.is_client_error() {
        let m = v["message"].as_str().unwrap_or("quote rejected");
        return Err(AppErr::new(StatusCode::BAD_REQUEST, m.into()));
    }
    let q = &v["quote"];
    let Some(dep) = q["depositAddress"].as_str().filter(|_| code.is_success()) else {
        tracing::warn!("quote: {code} {v}");
        return Err(bad(StatusCode::BAD_GATEWAY, "swap provider error"));
    };
    let s = |k: &str| q[k].as_str().map(String::from);
    let sid = uuid::Uuid::new_v4().to_string();
    let conflict = commit(&st.db.lk(), &id, t, new_exp, |db| {
        db.execute(
            "INSERT INTO swaps(id,invoice_id,origin_asset,symbol,blockchain,deposit_address,deposit_memo,amount_in,amount_in_formatted,amount_in_usd,refund_to,deadline,created_at,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13)",
            params![sid, id, b.asset_id, a["symbol"].as_str(), a["blockchain"].as_str(), dep, s("depositMemo"), s("amountIn"), s("amountInFormatted"), s("amountInUsd"), refund, iso(deadline), t],
        )
    })?;
    if let Some(m) = conflict {
        // the unused quote simply expires at its deadline
        tracing::info!("swap quote for invoice {id} abandoned: {m}");
        return Err(bad(StatusCode::CONFLICT, &m));
    }
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"swap_id": sid, "deposit_address": dep, "deposit_memo": s("depositMemo"), "amount_in": s("amountIn"), "amount_in_formatted": s("amountInFormatted"),
            "amount_in_usd": s("amountInUsd"), "symbol": a["symbol"], "blockchain": a["blockchain"], "deadline": iso(deadline), "time_estimate": q["timeEstimate"]}),
        ),
    ))
}

pub fn swap_json(db: &Connection, invoice: &str) -> Option<Value> {
    db.query_row(
        "SELECT status, symbol, blockchain, deposit_address, amount_in_formatted, deadline FROM swaps WHERE invoice_id=?1",
        [invoice],
        |r| Ok(json!({"status": r.get::<_, String>(0)?, "symbol": r.get::<_, String>(1)?, "blockchain": r.get::<_, String>(2)?,
            "deposit_address": r.get::<_, String>(3)?, "amount_in_formatted": r.get::<_, String>(4)?, "deadline": r.get::<_, String>(5)?})),
    )
    .optional()
    .ok()
    .flatten()
}

pub fn webhook_json(db: &Connection, invoice: &str) -> Value {
    db.query_row("SELECT symbol, blockchain, amount_in_formatted, status FROM swaps WHERE invoice_id=?1", [invoice], |r| {
        Ok(json!({"asset": r.get::<_, String>(0)?, "blockchain": r.get::<_, String>(1)?, "amount_in_formatted": r.get::<_, String>(2)?, "status": r.get::<_, String>(3)?}))
    })
    .unwrap_or(Value::Null)
}

pub async fn poller(st: Arc<St>) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        if let Err(e) = poll_once(&st).await {
            tracing::warn!("swap poll: {e:#}");
        }
    }
}

async fn poll_once(st: &Arc<St>) -> anyhow::Result<()> {
    type Row = (String, String, String, Option<String>, String);
    let rows: Vec<Row> = {
        let db = st.db.lk();
        let mut q = db.prepare(&format!("SELECT id, invoice_id, deposit_address, deposit_memo, status FROM swaps WHERE status NOT IN {FINAL} AND created_at>?1"))?;
        let v = q
            .query_map([now() - 7200], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        v
    };
    for (sid, inv, dep, memo, old) in rows {
        let mut rb =
            call(st, st.http.get(format!("{API}/status"))).query(&[("depositAddress", &dep)]);
        if let Some(m) = &memo {
            rb = rb.query(&[("depositMemo", m)]);
        }
        let v: Value = match rb.send().await.and_then(|r| r.error_for_status()) {
            Ok(r) => r.json().await?,
            Err(e) => {
                tracing::debug!("swap status {sid}: {e}");
                continue;
            }
        };
        let Some(new) = v["status"].as_str().filter(|s| *s != old) else {
            continue;
        };
        let inv_status = {
            let db = st.db.lk();
            db.execute(
                "UPDATE swaps SET status=?1, updated_at=?2 WHERE id=?3",
                params![new, now(), sid],
            )?;
            db.query_row("SELECT status FROM invoices WHERE id=?1", [&inv], |r| {
                r.get::<_, String>(0)
            })?
        };
        tracing::info!("swap {sid} {old} -> {new}");
        // REFUNDED/FAILED are final, so they fire once; the invoice stays pending for a retry
        let typ = match new {
            "REFUNDED" => Some("swap.refunded"),
            "FAILED" => Some("swap.failed"),
            "INCOMPLETE_DEPOSIT" => Some("swap.incomplete_deposit"),
            _ => None,
        };
        if let Some(t) = typ {
            crate::hook::notify(st, &st.db.lk(), &inv, t)?;
        }
        let _ = st.events.send((inv, inv_status));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_filter() {
        let t = |id: &str, sym: &str, ch: &str| json!({"assetId": id, "symbol": sym, "blockchain": ch, "decimals": 6, "price": 1.0});
        let toks = json!([
            t("nep141:zec.omft.near", "ZEC", "zec"),
            t("nep141:eth.omft.near", "ETH", "eth"),
            t("nep141:abs.omdep.near", "ETH", "abs"),
            t("1cs_v1:sol:spl:x", "SOL", "sol"),
            t("nep141:sol-5ce3.omft.near", "USDC", "sol"),
            t("nep141:usdt.tether-token.near", "USDT", "near"),
            t("nep141:wrap.near", "wNEAR", "near"),
        ]);
        let ids: Vec<_> = curate(&toks)
            .iter()
            .map(|a| a["asset_id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            ids,
            [
                "nep141:sol-5ce3.omft.near",
                "nep141:eth.omft.near",
                "nep141:wrap.near"
            ]
        );
        assert_eq!(iso(1_760_000_000), "2025-10-09T08:53:20Z");
    }

    fn swap(db: &Connection, sid: &str, status: &str) -> rusqlite::Result<usize> {
        db.execute("INSERT INTO swaps(id,invoice_id,origin_asset,symbol,blockchain,deposit_address,amount_in,amount_in_formatted,refund_to,deadline,status,created_at,updated_at)
            VALUES(?1,'inv','a','USDC','sol','dep','1','1','r','d',?2,0,0)", params![sid, status])
    }

    fn swaps(db: &Connection) -> Vec<(String, String)> {
        db.prepare("SELECT id, status FROM swaps ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    #[test]
    fn commit_keeps_progressed_swap() {
        let st = crate::tests::test_st();
        let db = st.db.lk();
        let t = now();
        db.execute("INSERT INTO invoices(id,merchant_id,div_index,address,amount_zat,status,created_at,expires_at) VALUES('inv',1,0,'addr',1,'pending',?1,?2)", params![t, t + 300]).unwrap();
        swap(&db, "old", "PENDING_DEPOSIT").unwrap();
        // the old swap got a deposit while the new quote was being fetched
        db.execute("UPDATE swaps SET status='PROCESSING'", [])
            .unwrap();
        let r = commit(&db, "inv", t, t + 1800, |db| {
            swap(db, "new", "PENDING_DEPOSIT")
        });
        assert_eq!(
            r.unwrap().unwrap(),
            "a swap is already in progress (PROCESSING)"
        );
        assert_eq!(swaps(&db), [("old".into(), "PROCESSING".into())]);
        let e: (i64, Option<i64>) = db
            .query_row("SELECT expires_at, extended_at FROM invoices", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(e, (t + 300, None)); // nothing written
                                        // a replaceable one is swapped out and the invoice extended once
        db.execute("UPDATE swaps SET status='REFUNDED'", [])
            .unwrap();
        assert_eq!(
            commit(&db, "inv", t, t + 1800, |db| swap(
                db,
                "new",
                "PENDING_DEPOSIT"
            ))
            .unwrap(),
            None
        );
        assert_eq!(swaps(&db), [("new".into(), "PENDING_DEPOSIT".into())]);
        let e: (i64, Option<i64>) = db
            .query_row("SELECT expires_at, extended_at FROM invoices", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(e, (t + 1800, Some(t)));
        // invoice paid meanwhile
        db.execute("UPDATE invoices SET status='paid'", []).unwrap();
        assert!(commit(&db, "inv", t, t + 1800, |db| swap(
            db,
            "x",
            "PENDING_DEPOSIT"
        ))
        .unwrap()
        .is_some());
        assert_eq!(swaps(&db).len(), 1);
    }

    #[test]
    fn extension_once() {
        let t = 10_000;
        assert_eq!(window(t + 900, false, false, t), Ok((t + 900, t + 900)));
        assert_eq!(window(t + 5000, false, true, t), Ok((t + 5000, t + 1800)));
        assert_eq!(window(t + 100, false, false, t), Ok((t + 1800, t + 1800)));
        assert!(window(t + 100, true, false, t).is_err()); // already extended
        assert!(window(t + 100, false, true, t).is_err()); // billing
                                                           // the extended expiry is far enough out that the next call does not extend again
        let (e, _) = window(t + 100, false, false, t).unwrap();
        assert_eq!(window(e, true, false, t + 60), Ok((e, e)));
    }
}
