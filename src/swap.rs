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
        .map(|t| json!({"asset_id": t["assetId"], "symbol": t["symbol"], "blockchain": t["blockchain"], "decimals": t["decimals"], "price_usd": t["price"], "contract_address": t["contractAddress"]}))
        .collect();
    out.sort_by_key(|t| {
        WANT.iter()
            .position(|w| w.0 == t["symbol"] && w.1 == t["blockchain"])
    });
    out
}

/// Exact decimal string for `amount` base units, e.g. ("1500000", 6) -> "1.5".
fn decimal(amount: &str, decimals: usize) -> Option<String> {
    if amount.is_empty() || !amount.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let p = format!("{amount:0>width$}", width = decimals + 1);
    let (int, frac) = p.split_at(p.len() - decimals);
    let int = int.trim_start_matches('0');
    let int = if int.is_empty() { "0" } else { int };
    let frac = frac.trim_end_matches('0');
    Some(if frac.is_empty() {
        int.into()
    } else {
        format!("{int}.{frac}")
    })
}

/// Wallet payment URI (EIP-681, Solana Pay, BIP-21) for a swap deposit; None when the chain has no standard or a memo is needed.
pub fn deposit_uri(
    chain: &str,
    symbol: &str,
    contract: Option<&str>,
    deposit: &str,
    amount: &str,
    decimals: usize,
    memo: Option<&str>,
) -> Option<String> {
    if memo.is_some_and(|m| !m.is_empty())
        || !amount.bytes().all(|b| b.is_ascii_digit())
        || amount.is_empty()
    {
        return None;
    }
    let contract = contract.filter(|c| !c.is_empty());
    let native = matches!(
        (symbol, chain),
        ("ETH", "eth" | "base" | "arb") | ("SOL", "sol") | ("BTC", "btc")
    );
    if !native && contract.is_none() {
        return None;
    }
    match chain {
        "eth" | "base" | "arb" => {
            let id = match chain {
                "eth" => 1,
                "base" => 8453,
                _ => 42161,
            };
            Some(match contract.filter(|_| !native) {
                None => format!("ethereum:{deposit}@{id}?value={amount}"),
                Some(c) => format!("ethereum:{c}@{id}/transfer?address={deposit}&uint256={amount}"),
            })
        }
        "sol" => {
            let a = decimal(amount, decimals)?;
            Some(match contract.filter(|_| !native) {
                None => format!("solana:{deposit}?amount={a}"),
                Some(m) => format!("solana:{deposit}?amount={a}&spl-token={m}"),
            })
        }
        "btc" if native => Some(format!(
            "bitcoin:{deposit}?amount={}",
            decimal(amount, decimals)?
        )),
        _ => None,
    }
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

/// Parses LUNAZ_APP_FEE_RECIPIENT and LUNAZ_APP_FEE_BPS; both unset or empty disables the fee.
pub fn app_fee(
    recipient: Option<String>,
    bps: Option<String>,
) -> anyhow::Result<Option<(String, u32)>> {
    let recipient = recipient
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty());
    let bps = bps.map(|b| b.trim().to_string()).filter(|b| !b.is_empty());
    match (recipient, bps) {
        (None, None) => Ok(None),
        (Some(r), Some(b)) => match b.parse::<u32>() {
            Ok(0) => Ok(None),
            Ok(f) if f <= 1000 => Ok(Some((r, f))),
            _ => anyhow::bail!("LUNAZ_APP_FEE_BPS must be 0-1000 basis points, got {b}"),
        },
        _ => anyhow::bail!("set both LUNAZ_APP_FEE_RECIPIENT and LUNAZ_APP_FEE_BPS, or neither"),
    }
}

const SWAP_SECS: i64 = 1800;

/// (invoice expiry, swap deadline). An invoice too close to expiry is extended once, never past its original expiry + 30 min; fee settlement invoices never.
fn window(expires: i64, extended: bool, billing: bool, t: i64) -> Result<(i64, i64), &'static str> {
    if expires >= t + 600 {
        return Ok((expires, expires.min(t + SWAP_SECS)));
    }
    if billing {
        return Err("settlement invoice expires too soon for a swap; start a new settlement");
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

/// Fixed buyer-facing text for a 1Click rejection; the raw message only goes to the log.
fn quote_error(m: &str) -> &'static str {
    let m = m.to_lowercase();
    if m.contains("refund") || m.contains("address") {
        "refund address is not valid for this asset"
    } else if ["amount", "too low", "small", "minimum"]
        .iter()
        .any(|k| m.contains(k))
    {
        "amount is too small to swap with this asset"
    } else {
        "swap quote rejected, try another asset or pay in ZEC"
    }
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
    type Inv = (String, i64, String, i64, bool, bool, i64, i64);
    let (status, amount, address, expires, extended, billing, fee_zat, mid): Inv = st
        .db
        .lk()
        .query_row(
            "SELECT status, amount_zat, address, expires_at, extended_at IS NOT NULL,
             EXISTS(SELECT 1 FROM fee_settlements WHERE invoice_id=invoices.id), fee_zat, merchant_id FROM invoices WHERE id=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
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
    let price = zec_price(&st)
        .await
        .ok_or_else(|| bad(StatusCode::SERVICE_UNAVAILABLE, "zec price unavailable"))?;
    crate::caps::check_swap(&st, &st.db.lk(), mid, &id, amount, price, t)?;
    let list = assets(&st).await.map_err(|e| {
        tracing::warn!("tokens: {e:#}");
        bad(StatusCode::BAD_GATEWAY, "swap provider unavailable")
    })?;
    let a = list
        .iter()
        .find(|a| a["asset_id"] == b.asset_id)
        .ok_or_else(|| bad(StatusCode::BAD_REQUEST, "unsupported asset_id"))?;
    // Invoice amount is the exact 1Click output: withdrawFee is added to amountIn, not deducted from amountOut.
    let mut body = json!({"dry": false, "swapType": "EXACT_OUTPUT", "slippageTolerance": 100, "originAsset": b.asset_id, "depositType": "ORIGIN_CHAIN",
        "destinationAsset": ZEC, "amount": amount.to_string(), "recipient": address, "recipientType": "DESTINATION_CHAIN",
        "refundTo": refund, "refundType": "ORIGIN_CHAIN", "deadline": iso(deadline)});
    // The swap delivers only the merchant amount, so the Lunaz fee rides on the app fee instead of a second output.
    let mut lunaz_bps = 0;
    if let Some((recipient, fee)) = &st.app_fee {
        if fee_zat > 0 {
            lunaz_bps = st.fee.bps;
        }
        // EXACT_OUTPUT: the fee is added to amountIn, so the buyer pays it and the invoice still gets its amount.
        body["appFees"] = json!([{"recipient": recipient, "fee": fee + lunaz_bps}]);
    }
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
        let m = v["message"].as_str().unwrap_or_default();
        tracing::info!(
            "quote for invoice {id} rejected: {code} {}",
            m.replace(refund, "<refund_to>")
        );
        return Err(bad(StatusCode::BAD_REQUEST, quote_error(m)));
    }
    let q = &v["quote"];
    let Some(dep) = q["depositAddress"].as_str().filter(|_| code.is_success()) else {
        tracing::warn!("quote for invoice {id}: unexpected response {code}");
        return Err(bad(StatusCode::BAD_GATEWAY, "swap provider error"));
    };
    let s = |k: &str| q[k].as_str().map(String::from);
    let sid = uuid::Uuid::new_v4().to_string();
    let uri = s("amountIn").and_then(|amt| {
        deposit_uri(
            a["blockchain"].as_str()?,
            a["symbol"].as_str()?,
            a["contract_address"].as_str(),
            dep,
            &amt,
            a["decimals"].as_u64()? as usize,
            s("depositMemo").as_deref(),
        )
    });
    let conflict = commit(&st.db.lk(), &id, t, new_exp, |db| {
        db.execute(
            "INSERT INTO swaps(id,invoice_id,origin_asset,symbol,blockchain,deposit_address,deposit_memo,amount_in,amount_in_formatted,amount_in_usd,refund_to,deadline,created_at,updated_at,lunaz_fee_bps,deposit_uri)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13,?14,?15)",
            params![sid, id, b.asset_id, a["symbol"].as_str(), a["blockchain"].as_str(), dep, s("depositMemo"), s("amountIn"), s("amountInFormatted"), s("amountInUsd"), refund, iso(deadline), t, lunaz_bps, uri],
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
            json!({"swap_id": sid, "deposit_address": dep, "deposit_memo": s("depositMemo"), "deposit_uri": uri, "amount_in": s("amountIn"), "amount_in_formatted": s("amountInFormatted"),
            "amount_in_usd": s("amountInUsd"), "symbol": a["symbol"], "blockchain": a["blockchain"], "deadline": iso(deadline), "time_estimate": q["timeEstimate"]}),
        ),
    ))
}

pub fn swap_json(db: &Connection, invoice: &str) -> Option<Value> {
    db.query_row(
        "SELECT status, symbol, blockchain, deposit_address, amount_in_formatted, deadline, deposit_memo, deposit_uri FROM swaps WHERE invoice_id=?1",
        [invoice],
        |r| Ok(json!({"status": r.get::<_, String>(0)?, "symbol": r.get::<_, String>(1)?, "blockchain": r.get::<_, String>(2)?,
            "deposit_address": r.get::<_, String>(3)?, "amount_in_formatted": r.get::<_, String>(4)?, "deadline": r.get::<_, String>(5)?,
            "deposit_memo": r.get::<_, Option<String>>(6)?, "deposit_uri": r.get::<_, Option<String>>(7)?})),
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
    fn app_fee_env() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(app_fee(None, None).unwrap(), None);
        assert_eq!(app_fee(s(""), s(" ")).unwrap(), None);
        assert_eq!(app_fee(s("lunaz.near"), s("0")).unwrap(), None);
        assert_eq!(
            app_fee(s(" lunaz.near "), s("50")).unwrap(),
            Some(("lunaz.near".into(), 50))
        );
        assert!(app_fee(s("lunaz.near"), s("1001")).is_err());
        assert!(app_fee(s("lunaz.near"), s("0.5")).is_err());
        assert!(app_fee(s("lunaz.near"), None).is_err());
        assert!(app_fee(None, s("50")).is_err());
    }

    #[test]
    fn deposit_uris() {
        assert_eq!(decimal("1", 9).unwrap(), "0.000000001");
        assert_eq!(decimal("1500000", 6).unwrap(), "1.5");
        assert_eq!(decimal("100000000", 8).unwrap(), "1");
        assert_eq!(decimal("0", 6).unwrap(), "0");
        assert_eq!(decimal("1234", 0).unwrap(), "1234");
        assert_eq!(decimal("1e5", 6), None);
        let u = |ch, sym, c, amt, d, m| deposit_uri(ch, sym, c, "DEP", amt, d, m);
        assert_eq!(
            u("eth", "ETH", None, "1000000000000000", 18, None).unwrap(),
            "ethereum:DEP@1?value=1000000000000000"
        );
        assert_eq!(
            u("arb", "ETH", None, "5", 18, None).unwrap(),
            "ethereum:DEP@42161?value=5"
        );
        assert_eq!(
            u("base", "USDC", Some("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"), "1500000", 6, None).unwrap(),
            "ethereum:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913@8453/transfer?address=DEP&uint256=1500000"
        );
        assert_eq!(
            u("sol", "SOL", None, "1", 9, None).unwrap(),
            "solana:DEP?amount=0.000000001"
        );
        assert_eq!(
            u("sol", "USDT", Some("Es9v"), "2500000", 6, None).unwrap(),
            "solana:DEP?amount=2.5&spl-token=Es9v"
        );
        assert_eq!(
            u("btc", "BTC", None, "100000000", 8, None).unwrap(),
            "bitcoin:DEP?amount=1"
        );
        assert_eq!(u("near", "wNEAR", Some("wrap.near"), "1", 24, None), None);
        assert_eq!(u("eth", "USDC", None, "1", 6, None), None);
        assert_eq!(u("sol", "USDC", Some(""), "1", 6, None), None);
        assert_eq!(u("eth", "ETH", None, "1", 18, Some("memo")), None);
        assert_eq!(
            u("eth", "ETH", None, "1", 18, Some("")).unwrap(),
            "ethereum:DEP@1?value=1"
        );
        assert_eq!(u("doge", "DOGE", None, "1", 8, None), None);
        assert_eq!(u("eth", "ETH", None, "", 18, None), None);
    }

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
    fn quote_errors_fixed() {
        assert_eq!(
            quote_error("refundTo is not valid: 0xdead"),
            "refund address is not valid for this asset"
        );
        assert_eq!(
            quote_error("Amount is too low for bridge, try at least 1.5"),
            "amount is too small to swap with this asset"
        );
        assert_eq!(
            quote_error("<script>"),
            "swap quote rejected, try another asset or pay in ZEC"
        );
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
