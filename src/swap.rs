//! Cross-chain payments via NEAR Intents 1Click: the buyer pays on their chain, 1Click delivers ZEC to the invoice address.
use crate::api::{bad, AppErr, R};
use crate::{now, St};
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
    if let Some((t, v)) = &*st.assets.lock().unwrap() {
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
    *st.assets.lock().unwrap() = Some((now(), v.clone()));
    Ok(v)
}

pub async fn list_assets(State(st): State<Arc<St>>) -> R {
    let v = assets(&st).await.map_err(|e| {
        tracing::warn!("tokens: {e:#}");
        bad(StatusCode::BAD_GATEWAY, "swap provider unavailable")
    })?;
    Ok(Json(v.into()))
}

fn iso(t: i64) -> String {
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
    let (status, amount, address, expires): (String, i64, String, i64) = st
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT status, amount_zat, address, expires_at FROM invoices WHERE id=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?
        .ok_or_else(|| bad(StatusCode::NOT_FOUND, "no such invoice"))?;
    let t = now();
    if status != "pending" || expires < t {
        return Err(bad(StatusCode::CONFLICT, "invoice is not pending"));
    }
    let refund = b.refund_to.trim();
    if refund.is_empty() {
        return Err(bad(StatusCode::BAD_REQUEST, "refund_to required"));
    }
    let list = assets(&st).await.map_err(|e| {
        tracing::warn!("tokens: {e:#}");
        bad(StatusCode::BAD_GATEWAY, "swap provider unavailable")
    })?;
    let a = list
        .iter()
        .find(|a| a["asset_id"] == b.asset_id)
        .ok_or_else(|| bad(StatusCode::BAD_REQUEST, "unsupported asset_id"))?;
    // Too close to expiry for a swap to finish: extend the invoice. Otherwise the deadline never outlives the invoice.
    let (new_exp, deadline) = if expires < t + 600 {
        (t + 1800, t + 1800)
    } else {
        (expires, expires.min(t + 1800))
    };
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
    let db = st.db.lock().unwrap();
    db.execute("DELETE FROM swaps WHERE invoice_id=?1", [&id])?; // one active swap per invoice
    db.execute(
        "INSERT INTO swaps(id,invoice_id,origin_asset,symbol,blockchain,deposit_address,deposit_memo,amount_in,amount_in_formatted,amount_in_usd,refund_to,deadline,created_at,updated_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13)",
        params![sid, id, b.asset_id, a["symbol"].as_str(), a["blockchain"].as_str(), dep, s("depositMemo"), s("amountIn"), s("amountInFormatted"), s("amountInUsd"), refund, iso(deadline), t],
    )?;
    if new_exp > expires {
        db.execute(
            "UPDATE invoices SET expires_at=?1 WHERE id=?2",
            params![new_exp, id],
        )?;
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
    db.query_row("SELECT symbol, blockchain, amount_in_formatted FROM swaps WHERE invoice_id=?1", [invoice], |r| {
        Ok(json!({"asset": r.get::<_, String>(0)?, "blockchain": r.get::<_, String>(1)?, "amount_in_formatted": r.get::<_, String>(2)?}))
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

async fn poll_once(st: &St) -> anyhow::Result<()> {
    type Row = (String, String, String, Option<String>, String);
    let rows: Vec<Row> = {
        let db = st.db.lock().unwrap();
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
            let db = st.db.lock().unwrap();
            db.execute(
                "UPDATE swaps SET status=?1, updated_at=?2 WHERE id=?3",
                params![new, now(), sid],
            )?;
            db.query_row("SELECT status FROM invoices WHERE id=?1", [&inv], |r| {
                r.get::<_, String>(0)
            })?
        };
        tracing::info!("swap {sid} {old} -> {new}");
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
}
