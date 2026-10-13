//! Mocked off-ramp (withdraw to bank). The merchant is the provider's customer: they send ZEC from
//! their own wallet to the provider's deposit address, the provider pays fiat. Lunaz stores the
//! order and its status only, never bank account numbers or KYC data.
use crate::account::{auth, S};
use crate::api::{bad, AppErr, R};
use crate::{now, Lk, St};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub const MIN_ZAT: u64 = 100_000;
const MAX_ZAT: u64 = 21_000_000 * 100_000_000;
const NETWORK_FEE_ZAT: u64 = 10_000; // 0.0001 ZEC
const QUOTE_SECS: i64 = 600;
const DEPOSIT_SECS: i64 = 1800;
// Deliberately invalid base58 ('O' is not in the alphabet): can never be a real address.
const MOCK_ADDR: &str = "t1SANDBOXxDoNotSendFundsxxxxxxxxx";

#[derive(Clone, Copy, PartialEq)]
pub enum Provider {
    Mock,
    TransFi,
}

pub struct Cfg {
    pub provider: Provider,
    pub fx: BTreeMap<String, f64>, // USD -> fiat, indicative
    pub zec_usd: Option<f64>,      // mock-only price override
}

impl Cfg {
    pub fn from_env(env: impl Fn(&str) -> Option<String>) -> anyhow::Result<Cfg> {
        let provider = match env("LUNAZ_OFFRAMP").as_deref().unwrap_or("mock") {
            "mock" => Provider::Mock,
            "transfi" => Provider::TransFi,
            v => anyhow::bail!("LUNAZ_OFFRAMP must be mock or transfi, got {v}"),
        };
        let fx = env("LUNAZ_MOCK_FX").unwrap_or(r#"{"IDR":16400,"USD":1}"#.into());
        Ok(Cfg {
            provider,
            fx: serde_json::from_str(&fx)
                .map_err(|e| anyhow::anyhow!("LUNAZ_MOCK_FX invalid: {e}"))?,
            zec_usd: env("LUNAZ_MOCK_ZEC_USD")
                .and_then(|v| v.parse().ok())
                .filter(|_| provider == Provider::Mock),
        })
    }
}
impl Default for Cfg {
    fn default() -> Cfg {
        Cfg::from_env(|_| None).unwrap()
    }
}

impl Provider {
    fn name(self) -> &'static str {
        match self {
            Provider::Mock => "mock",
            Provider::TransFi => "transfi",
        }
    }
}

fn not_configured() -> AppErr {
    bad(
        StatusCode::NOT_IMPLEMENTED,
        "off-ramp provider not configured",
    )
}

/// Status machine; `quote` is the unsaved pre-state.
pub fn can(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("quote", "awaiting_kyc")
            | ("awaiting_kyc", "awaiting_deposit")
            | ("awaiting_deposit", "deposit_received")
            | ("deposit_received", "converting")
            | ("converting", "payout_processing")
            | ("payout_processing", "completed")
            | ("awaiting_kyc" | "awaiting_deposit", "expired" | "cancelled")
            | (
                "awaiting_kyc"
                    | "awaiting_deposit"
                    | "deposit_received"
                    | "converting"
                    | "payout_processing",
                "failed"
            )
    )
}

/// Decimal string of `n / 10^scale`.
fn dec(n: u128, scale: u32) -> String {
    let p = 10u128.pow(scale);
    format!("{}.{:0w$}", n / p, n % p, w = scale as usize)
}

#[derive(Serialize)]
pub struct Quote {
    amount_zat: u64,
    currency: String,
    rate: String,
    fee_fiat: String,
    network_fee_zat: u64,
    fiat_amount: String,
    expires_at: i64,
}

/// Fiat for `zat` at `rate_micro` (fiat per ZEC x 1e6), in minor units (2 dp), rounded down.
fn minor(zat: u64, rate_micro: u128) -> u128 {
    zat as u128 * rate_micro / 10u128.pow(12)
}

pub fn calc(amount: u64, cur: &str, zec_usd: f64, fx: f64, t: i64) -> Quote {
    let rate = (zec_usd * fx * 1e6).round() as u128;
    let fee_zat = amount * 15 / 1000; // 1.5%
    let net = amount - fee_zat - NETWORK_FEE_ZAT;
    Quote {
        amount_zat: amount,
        currency: cur.into(),
        rate: dec(rate, 6),
        fee_fiat: dec(minor(fee_zat, rate), 2),
        network_fee_zat: NETWORK_FEE_ZAT,
        fiat_amount: dec(minor(net, rate), 2),
        expires_at: t + QUOTE_SECS,
    }
}

async fn zec_usd(st: &St) -> Option<f64> {
    match st.off.zec_usd {
        Some(p) => Some(p),
        None => crate::swap::zec_price(st).await,
    }
}

// Provider seam 1: create a quote.
async fn quote(st: &St, amount: u64, cur: &str) -> Result<Quote, AppErr> {
    if st.off.provider != Provider::Mock {
        return Err(not_configured());
    }
    let cur = cur.to_uppercase();
    let fx = *st
        .off
        .fx
        .get(&cur)
        .ok_or_else(|| bad(StatusCode::BAD_REQUEST, "unsupported currency"))?;
    if !(MIN_ZAT..=MAX_ZAT).contains(&amount) {
        return Err(bad(StatusCode::BAD_REQUEST, "invalid amount_zat"));
    }
    let p = zec_usd(st)
        .await
        .ok_or_else(|| bad(StatusCode::SERVICE_UNAVAILABLE, "zec price unavailable"))?;
    Ok(calc(amount, &cur, p, fx, now()))
}

// Provider seam 2: create the order; returns (deposit_address, deposit_uri, provider_ref).
fn create_order(st: &St, q: &Quote) -> Result<(String, String, Option<String>), AppErr> {
    match st.off.provider {
        Provider::Mock => Ok((
            MOCK_ADDR.into(),
            format!("zcash:{MOCK_ADDR}?amount={}", dec(q.amount_zat as u128, 8)),
            None,
        )),
        Provider::TransFi => Err(not_configured()),
    }
}

// Provider seam 3: apply a (webhook-shaped) status update, log it and notify the merchant.
// Returns false when the transition is not allowed from the current status.
pub fn apply(
    st: &Arc<St>,
    id: &str,
    to: &str,
    note: &str,
    expires_at: Option<i64>,
    bank: Option<&str>,
) -> anyhow::Result<bool> {
    let db = st.db.lk();
    #[allow(clippy::type_complexity)]
    let Some((cur, mid, amount, cc, fiat)): Option<(String, i64, i64, String, String)> = db
        .query_row(
            "SELECT status, merchant_id, amount_zat, fiat_currency, fiat_amount FROM withdrawals WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?
    else {
        return Ok(false);
    };
    let t = now();
    if !can(&cur, to)
        || db.execute(
            "UPDATE withdrawals SET status=?1, updated_at=?2, expires_at=COALESCE(?3,expires_at), bank_label=COALESCE(?4,bank_label) WHERE id=?5 AND status=?6",
            params![to, t, expires_at, bank, id, cur],
        )? == 0
    {
        return Ok(false);
    }
    db.execute(
        "INSERT INTO withdrawal_events(withdrawal_id,status,note,created_at) VALUES(?1,?2,?3,?4)",
        params![id, to, note, t],
    )?;
    let body =
        json!({"type": "withdrawal.updated", "invoice_id": null, "withdrawal_id": id, "status": to,
        "amount_zat": amount, "fiat_currency": cc, "fiat_amount": fiat})
        .to_string();
    crate::hook::enqueue(st, &db, mid, None, "withdrawal.updated", body)?;
    Ok(true)
}

/// Expires withdrawals whose quote or deposit window has passed.
pub fn expire(st: &Arc<St>) {
    let ids: Vec<String> = (|| -> rusqlite::Result<_> {
        let db = st.db.lk();
        let mut q = db.prepare("SELECT id FROM withdrawals WHERE status IN ('awaiting_kyc','awaiting_deposit') AND expires_at<?1")?;
        let v = q.query_map([now()], |r| r.get(0))?.collect();
        v
    })()
    .unwrap_or_default();
    for id in ids {
        let _ = apply(st, &id, "expired", "window passed", None, None);
    }
}

fn wjson(db: &Connection, mid: i64, id: &str) -> rusqlite::Result<Option<Value>> {
    let w = db
        .query_row(
            "SELECT id,provider,status,amount_zat,fiat_currency,fiat_amount,rate_zec_fiat,fee_fiat,network_fee_zat,deposit_address,deposit_uri,bank_label,provider_ref,created_at,updated_at,expires_at
             FROM withdrawals WHERE id=?1 AND merchant_id=?2",
            params![id, mid],
            |r| {
                Ok(json!({"id": r.get::<_, String>(0)?, "provider": r.get::<_, String>(1)?, "status": r.get::<_, String>(2)?,
                    "amount_zat": r.get::<_, i64>(3)?, "fiat_currency": r.get::<_, String>(4)?, "fiat_amount": r.get::<_, String>(5)?,
                    "rate": r.get::<_, String>(6)?, "fee_fiat": r.get::<_, String>(7)?, "network_fee_zat": r.get::<_, i64>(8)?,
                    "deposit_address": r.get::<_, String>(9)?, "deposit_uri": r.get::<_, String>(10)?, "sandbox": r.get::<_, String>(1)? == "mock",
                    "bank_label": r.get::<_, Option<String>>(11)?, "provider_ref": r.get::<_, Option<String>>(12)?,
                    "created_at": r.get::<_, i64>(13)?, "updated_at": r.get::<_, i64>(14)?, "expires_at": r.get::<_, i64>(15)?}))
            },
        )
        .optional()?;
    let Some(mut w) = w else { return Ok(None) };
    let mut q = db.prepare(
        "SELECT status, note, created_at FROM withdrawal_events WHERE withdrawal_id=?1 ORDER BY id",
    )?;
    w["events"] = q
        .query_map([id], |r| {
            Ok(json!({"status": r.get::<_, String>(0)?, "note": r.get::<_, String>(1)?, "created_at": r.get::<_, i64>(2)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into();
    Ok(Some(w))
}

fn get_owned(st: &St, mid: i64, id: &str) -> Result<Value, AppErr> {
    wjson(&st.db.lk(), mid, id)?.ok_or_else(|| bad(StatusCode::NOT_FOUND, "no such withdrawal"))
}

fn mock_only(st: &St) -> Result<(), AppErr> {
    match st.off.provider {
        Provider::Mock => Ok(()),
        _ => Err(bad(StatusCode::NOT_FOUND, "not found")),
    }
}

pub async fn info(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let received: i64 = st.db.lk().query_row(
        "SELECT COALESCE(SUM(p.value_zat),0) FROM payments p JOIN invoices i ON i.id=p.invoice_id WHERE i.merchant_id=?1 AND p.height IS NOT NULL",
        [mid],
        |r| r.get(0),
    )?;
    let cur: Vec<_> = st.off.fx.keys().collect();
    Ok(Json(
        json!({"provider": st.off.provider.name(), "sandbox": st.off.provider == Provider::Mock, "currencies": cur,
        "min_zat": MIN_ZAT, "received_zat": received, "zec_usd": zec_usd(&st).await}),
    ))
}

#[derive(Deserialize)]
pub struct Req {
    amount_zat: u64,
    currency: String,
}

pub async fn quote_h(State(st): S, h: HeaderMap, Json(b): Json<Req>) -> R {
    auth(&st, &h)?;
    Ok(Json(json!(quote(&st, b.amount_zat, &b.currency).await?)))
}

pub async fn create(
    State(st): S,
    h: HeaderMap,
    Json(b): Json<Req>,
) -> Result<(StatusCode, Json<Value>), AppErr> {
    let mid = auth(&st, &h)?;
    let q = quote(&st, b.amount_zat, &b.currency).await?;
    let (addr, uri, pref) = create_order(&st, &q)?;
    let (id, t) = (uuid::Uuid::new_v4().to_string(), now());
    {
        let db = st.db.lk();
        db.execute(
            "INSERT INTO withdrawals(id,merchant_id,provider,status,amount_zat,fiat_currency,fiat_amount,rate_zec_fiat,fee_fiat,network_fee_zat,deposit_address,deposit_uri,provider_ref,created_at,updated_at,expires_at)
             VALUES(?1,?2,?3,'awaiting_kyc',?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13,?14)",
            params![id, mid, st.off.provider.name(), q.amount_zat, q.currency, q.fiat_amount, q.rate, q.fee_fiat, q.network_fee_zat, addr, uri, pref, t, q.expires_at],
        )?;
        db.execute(
            "INSERT INTO withdrawal_events(withdrawal_id,status,note,created_at) VALUES(?1,'awaiting_kyc','order created',?2)",
            params![id, t],
        )?;
    }
    Ok((StatusCode::CREATED, Json(get_owned(&st, mid, &id)?)))
}

#[derive(Deserialize)]
pub struct Kyc {
    bank_name: String,
    account_last4: String,
}

/// Mock of the provider-hosted KYC + bank step. Only a display label is kept.
pub async fn kyc(State(st): S, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Kyc>) -> R {
    let mid = auth(&st, &h)?;
    mock_only(&st)?;
    get_owned(&st, mid, &id)?;
    let bank = b.bank_name.trim();
    if bank.is_empty() || bank.chars().count() > 40 {
        return Err(bad(StatusCode::BAD_REQUEST, "invalid bank_name"));
    }
    if b.account_last4.len() != 4 || !b.account_last4.bytes().all(|c| c.is_ascii_digit()) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "account_last4 must be exactly 4 digits",
        ));
    }
    let label = format!("{bank} \u{2022}\u{2022}\u{2022}\u{2022}{}", b.account_last4);
    transition(
        &st,
        &id,
        "awaiting_deposit",
        "kyc and bank linked",
        Some(now() + DEPOSIT_SECS),
        Some(&label),
    )?;
    Ok(Json(get_owned(&st, mid, &id)?))
}

fn transition(
    st: &Arc<St>,
    id: &str,
    to: &str,
    note: &str,
    exp: Option<i64>,
    bank: Option<&str>,
) -> Result<(), AppErr> {
    if apply(st, id, to, note, exp, bank)? {
        Ok(())
    } else {
        Err(bad(StatusCode::CONFLICT, "invalid status for this action"))
    }
}

pub async fn simulate_deposit(State(st): S, h: HeaderMap, Path(id): Path<String>) -> R {
    let mid = auth(&st, &h)?;
    mock_only(&st)?;
    get_owned(&st, mid, &id)?;
    transition(
        &st,
        &id,
        "deposit_received",
        "sandbox deposit simulated",
        None,
        None,
    )?;
    let (s, i) = (st.clone(), id.clone());
    tokio::spawn(async move {
        for (to, note) in [
            ("converting", "converting ZEC to fiat"),
            ("payout_processing", "fiat payout sent to bank"),
            ("completed", "payout completed"),
        ] {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if !matches!(apply(&s, &i, to, note, None, None), Ok(true)) {
                return;
            }
        }
    });
    Ok(Json(get_owned(&st, mid, &id)?))
}

pub async fn cancel(State(st): S, h: HeaderMap, Path(id): Path<String>) -> R {
    let mid = auth(&st, &h)?;
    get_owned(&st, mid, &id)?;
    transition(&st, &id, "cancelled", "cancelled by merchant", None, None)?;
    Ok(Json(get_owned(&st, mid, &id)?))
}

#[derive(Deserialize)]
pub struct Lim {
    limit: Option<i64>,
}

pub async fn list(State(st): S, h: HeaderMap, Query(q): Query<Lim>) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lk();
    let ids: Vec<String> = db
        .prepare("SELECT id FROM withdrawals WHERE merchant_id=?1 ORDER BY created_at DESC, rowid DESC LIMIT ?2")?
        .query_map(params![mid, q.limit.unwrap_or(50).clamp(1, 200)], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let v: Vec<Value> = ids
        .iter()
        .filter_map(|i| wjson(&db, mid, i).transpose())
        .collect::<rusqlite::Result<_>>()?;
    Ok(Json(v.into()))
}

pub async fn get_one(State(st): S, h: HeaderMap, Path(id): Path<String>) -> R {
    let mid = auth(&st, &h)?;
    Ok(Json(get_owned(&st, mid, &id)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_st;
    use zcash_address::ZcashAddress;

    #[test]
    fn fake_address_rejected() {
        assert!(ZcashAddress::try_from_encoded(MOCK_ADDR).is_err());
    }

    #[test]
    fn quote_math() {
        // 1 ZEC at $50 x 16400 IDR: fee 1.5% = 0.015 ZEC, net = 0.9849 ZEC
        let q = calc(100_000_000, "IDR", 50.0, 16400.0, 1000);
        assert_eq!(q.rate, "820000.000000");
        assert_eq!(q.fee_fiat, "12300.00");
        assert_eq!(q.fiat_amount, "807618.00");
        assert_eq!((q.network_fee_zat, q.expires_at), (10_000, 1600));
        let q = calc(MIN_ZAT, "USD", 33.33, 1.0, 0);
        assert_eq!(
            (q.fee_fiat.as_str(), q.fiat_amount.as_str()),
            ("0.00", "0.02")
        );
    }

    #[test]
    fn status_machine() {
        let path = [
            "quote",
            "awaiting_kyc",
            "awaiting_deposit",
            "deposit_received",
            "converting",
            "payout_processing",
            "completed",
        ];
        assert!(path.windows(2).all(|w| can(w[0], w[1])));
        assert!(can("awaiting_deposit", "cancelled") && can("converting", "failed"));
        assert!(!can("deposit_received", "cancelled") && !can("deposit_received", "expired"));
        assert!(!can("completed", "failed") && !can("cancelled", "awaiting_deposit"));
        assert!(!can("awaiting_kyc", "deposit_received"));
    }

    #[test]
    fn apply_logs_and_guards() {
        let st = test_st();
        {
            let db = st.db.lk();
            db.execute("INSERT INTO merchants(email,password_hash,name,webhook_secret) VALUES('a@b.c','x','n','s')", []).unwrap();
            db.execute("INSERT INTO withdrawals VALUES('w',1,'mock','awaiting_kyc',1,'USD','1.00','1','0','0',?1,'u',NULL,NULL,0,0,1)", [MOCK_ADDR]).unwrap();
        }
        assert!(!apply(&st, "w", "completed", "", None, None).unwrap());
        assert!(apply(
            &st,
            "w",
            "awaiting_deposit",
            "k",
            Some(99_999_999_999),
            Some("BCA")
        )
        .unwrap());
        expire(&st);
        assert!(apply(&st, "w", "deposit_received", "d", None, None).unwrap());
        assert!(!apply(&st, "w", "deposit_received", "d", None, None).unwrap());
        let n: i64 = st
            .db
            .lk()
            .query_row("SELECT COUNT(*) FROM withdrawal_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }
}
