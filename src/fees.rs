//! Lunaz per-payment fee: a second ZIP-321 payment to a treasury address, and settlement of fees not paid in the invoice tx.
use crate::account::{auth, S};
use crate::api::{bad, new_invoice, AppErr, R};
use crate::{now, Lk, St};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;
use zcash_protocol::value::Zatoshis;

const SETTLE_TTL: i64 = 3600;

pub struct Cfg {
    pub bps: u32,
    pub min_zat: u64,
    pub merchant: Option<i64>, // treasury
    pub sandbox: bool,
}

impl Cfg {
    pub fn from_env(env: impl Fn(&str) -> Option<String>) -> anyhow::Result<Cfg> {
        let num = |k: &str, d: u64| -> anyhow::Result<u64> {
            match env(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
            {
                None => Ok(d),
                Some(v) => v
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{k} must be a whole number, got {v}")),
            }
        };
        let bps = num("LUNAZ_FEE_BPS", 50)?;
        anyhow::ensure!(
            bps <= 1000,
            "LUNAZ_FEE_BPS must be 0-1000 basis points, got {bps}"
        );
        let min_zat = num("LUNAZ_FEE_MIN_ZAT", 1000)?;
        anyhow::ensure!(
            Zatoshis::from_u64(min_zat).is_ok(),
            "LUNAZ_FEE_MIN_ZAT is larger than the ZEC supply"
        );
        Ok(Cfg {
            bps: bps as u32,
            min_zat,
            merchant: env("LUNAZ_BILLING_MERCHANT_ID").and_then(|v| v.parse().ok()),
            sandbox: crate::truthy(env("LUNAZ_BILLING_SANDBOX")),
        })
    }

    pub fn fee_zat(&self, amount: u64) -> u64 {
        ((amount as u128 * self.bps as u128 / 10_000) as u64).max(self.min_zat)
    }
}
impl Default for Cfg {
    fn default() -> Cfg {
        Cfg::from_env(|_| None).unwrap()
    }
}

/// Treasury merchant id when it is configured and has a viewing key.
fn treasury(st: &St, db: &Connection) -> rusqlite::Result<Option<i64>> {
    let Some(t) = st.fee.merchant else {
        return Ok(None);
    };
    let ok: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM merchants WHERE id=?1 AND ufvk IS NOT NULL",
        [t],
        |r| r.get(0),
    )?;
    Ok(ok.then_some(t))
}

/// Fee in basis points as currently charged on new invoices (0 when inactive).
fn live_bps(st: &St, db: &Connection) -> rusqlite::Result<u32> {
    Ok(match treasury(st, db)? {
        Some(_) => st.fee.bps,
        None => 0,
    })
}

/// (charged, paid in tx, settled, outstanding); in-tx payments are capped per invoice at its fee.
pub fn owed(db: &Connection, mid: i64) -> rusqlite::Result<(i64, i64, i64, i64)> {
    let (charged, in_tx): (i64, i64) = db.query_row(
        "SELECT COALESCE(SUM(fee_zat),0), COALESCE(SUM(MIN(fee_zat,
           (SELECT COALESCE(SUM(value_zat),0) FROM fee_payments WHERE invoice_id=invoices.id AND height IS NOT NULL))),0)
         FROM invoices WHERE merchant_id=?1 AND fee_zat>0 AND status IN ('paid','underpaid')
           AND NOT EXISTS(SELECT 1 FROM swaps WHERE invoice_id=invoices.id AND status='SUCCESS' AND lunaz_fee_bps>0)",
        [mid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let settled: i64 = db.query_row(
        "SELECT COALESCE(SUM(amount_zat),0) FROM fee_settlements WHERE merchant_id=?1 AND status='paid'",
        [mid],
        |r| r.get(0),
    )?;
    Ok((charged, in_tx, settled, (charged - in_tx - settled).max(0)))
}

pub async fn pricing(State(st): S) -> R {
    let bps = live_bps(&st, &st.db.lk())?;
    Ok(Json(
        json!({"fee_bps": bps, "fee_min_zat": st.fee.min_zat, "swap_fee_bps": st.app_fee.as_ref().map_or(0, |f| f.1)}),
    ))
}

pub async fn summary(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lk();
    let (charged, in_tx, settled, out) = owed(&db, mid)?;
    let list = db
        .prepare("SELECT id, invoice_id, amount_zat, status, created_at, paid_at FROM fee_settlements WHERE merchant_id=?1 ORDER BY created_at DESC, rowid DESC LIMIT 50")?
        .query_map([mid], |r| {
            Ok(json!({"id": r.get::<_, String>(0)?, "invoice_id": r.get::<_, String>(1)?, "amount_zat": r.get::<_, i64>(2)?,
                "status": r.get::<_, String>(3)?, "created_at": r.get::<_, i64>(4)?, "paid_at": r.get::<_, Option<i64>>(5)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(
        json!({"fee_bps": live_bps(&st, &db)?, "fee_min_zat": st.fee.min_zat, "charged_zat": charged, "paid_in_tx_zat": in_tx,
        "settled_zat": settled, "outstanding_zat": out, "settlements": list}),
    ))
}

pub async fn settle(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lk();
    let t = treasury(&st, &db)?.ok_or_else(|| {
        bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "fee settlement not configured",
        )
    })?;
    if mid == t {
        return Err(bad(
            StatusCode::CONFLICT,
            "the treasury account has no fees to settle",
        ));
    }
    if !st.limits.hit(&format!("settle:{mid}"), 10, 900, now()) {
        return Err(bad(StatusCode::TOO_MANY_REQUESTS, "too many settlements"));
    }
    let out = owed(&db, mid)?.3;
    if out == 0 {
        return Err(bad(StatusCode::CONFLICT, "nothing to settle"));
    }
    let open = db
        .query_row(
            "SELECT s.id, s.invoice_id, s.amount_zat, s.created_at FROM fee_settlements s JOIN invoices i ON i.id=s.invoice_id
             WHERE s.merchant_id=?1 AND s.status='pending' AND i.status!='expired' ORDER BY s.created_at DESC LIMIT 1",
            [mid],
            |r| Ok(json!({"id": r.get::<_, String>(0)?, "invoice_id": r.get::<_, String>(1)?, "amount_zat": r.get::<_, i64>(2)?,
                "status": "pending", "created_at": r.get::<_, i64>(3)?, "paid_at": null})),
        )
        .optional()?;
    if let Some(s) = open {
        return Err(AppErr::with(
            StatusCode::CONFLICT,
            "a settlement is already pending".into(),
            json!({"settlement": s}),
        ));
    }
    let sid = uuid::Uuid::new_v4().to_string();
    let inv = new_invoice(
        &st,
        &db,
        t,
        out as u64,
        SETTLE_TTL,
        Some(&format!("lunaz-settle:{sid}")),
    )?;
    db.execute(
        "INSERT INTO fee_settlements(id,merchant_id,invoice_id,amount_zat,status,created_at) VALUES(?1,?2,?3,?4,'pending',?5)",
        params![sid, mid, inv["id"].as_str(), out, now()],
    )?;
    Ok(Json(
        json!({"id": sid, "amount_zat": out, "invoice": {"id": inv["id"], "address": inv["address"], "amount_zat": inv["amount_zat"],
        "zip321_uri": inv["zip321_uri"], "expires_at": inv["expires_at"]}}),
    ))
}

pub async fn simulate_paid(State(st): S, h: HeaderMap, Path(sid): Path<String>) -> R {
    if !st.fee.sandbox {
        return Err(bad(StatusCode::NOT_FOUND, "not found"));
    }
    let mid = auth(&st, &h)?;
    let db = st.db.lk();
    let owned: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM fee_settlements WHERE id=?1 AND merchant_id=?2",
        params![sid, mid],
        |r| r.get(0),
    )?;
    if !owned {
        return Err(bad(StatusCode::NOT_FOUND, "no such settlement"));
    }
    let n = db.execute(
        "UPDATE fee_settlements SET status='paid', paid_at=?1 WHERE id=?2 AND status IN ('pending','expired')",
        params![now(), sid],
    )?;
    if n == 0 {
        return Err(bad(StatusCode::CONFLICT, "settlement is not payable"));
    }
    Ok(Json(json!({"status": "paid"})))
}

/// Settlement reaction to a treasury invoice status change; no-op for other invoices.
/// Paid or underpaid credits what was mined, capped at the invoice amount (a later top-up raises it).
pub fn on_invoice(db: &Connection, invoice: &str, status: &str) -> rusqlite::Result<()> {
    match status {
        "paid" | "underpaid" => db.execute(
            "UPDATE fee_settlements SET status='paid', paid_at=COALESCE(paid_at,?2),
             amount_zat=MIN((SELECT amount_zat FROM invoices WHERE id=?1),
               (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=?1 AND height IS NOT NULL))
             WHERE invoice_id=?1",
            params![invoice, now()],
        )?,
        "expired" => db.execute(
            "UPDATE fee_settlements SET status='expired' WHERE invoice_id=?1 AND status='pending'",
            [invoice],
        )?,
        _ => 0,
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_math() {
        let c = Cfg::default();
        assert_eq!((c.bps, c.min_zat), (50, 1000));
        assert_eq!(c.fee_zat(1), 1000); // minimum
        assert_eq!(c.fee_zat(100_000_000), 500_000); // 0.5%
        assert_eq!(c.fee_zat(100_000_199), 500_000); // rounds down
        assert_eq!(
            Cfg { bps: 1000, ..c }.fee_zat(2_100_000_000_000_000),
            210_000_000_000_000
        );
        let e = |k: &'static str, v: &'static str| {
            Cfg::from_env(move |q| (q == k).then(|| v.to_string())).is_err()
        };
        assert!(
            e("LUNAZ_FEE_BPS", "1001") && e("LUNAZ_FEE_BPS", "-1") && e("LUNAZ_FEE_MIN_ZAT", "x")
        );
        assert!(!e("LUNAZ_FEE_BPS", "0") && !e("LUNAZ_FEE_BPS", "1000"));
    }
}
