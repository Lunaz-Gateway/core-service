//! Plans, usage limits and ZEC billing. Subscriptions are paid through an ordinary invoice on the treasury merchant.
use crate::account::{auth, S};
use crate::api::{bad, new_invoice, AppErr, R};
use crate::{now, St};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

const MONTH_SECS: i64 = 30 * 86400;
const CHECKOUT_TTL: i64 = 1800;

#[derive(Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub price_usd: Option<f64>,
    pub invoices_per_month: Option<i64>,
    pub api_keys: Option<i64>,
}

fn plan(id: &str, name: &str, p: Option<f64>, i: Option<i64>, k: Option<i64>) -> Plan {
    Plan {
        id: id.into(),
        name: name.into(),
        price_usd: p,
        invoices_per_month: i,
        api_keys: k,
    }
}

/// The single plan table; LUNAZ_PLANS replaces it.
fn default_plans() -> Vec<Plan> {
    vec![
        plan("free", "Free", Some(0.0), Some(100), Some(2)),
        plan("pro", "Pro", Some(29.0), Some(5000), Some(10)),
        plan("platform", "Platform", Some(199.0), None, Some(50)),
        plan("enterprise", "Enterprise", None, None, None),
    ]
}

pub struct Cfg {
    pub plans: Vec<Plan>,
    pub merchant: Option<i64>, // treasury
    pub sandbox: bool,
}

impl Cfg {
    pub fn from_env(env: impl Fn(&str) -> Option<String>) -> anyhow::Result<Cfg> {
        let plans = match env("LUNAZ_PLANS") {
            Some(s) => {
                serde_json::from_str(&s).map_err(|e| anyhow::anyhow!("LUNAZ_PLANS invalid: {e}"))?
            }
            None => default_plans(),
        };
        anyhow::ensure!(
            plans.iter().any(|p: &Plan| p.id == "free"),
            "LUNAZ_PLANS needs a free plan"
        );
        Ok(Cfg {
            plans,
            merchant: env("LUNAZ_BILLING_MERCHANT_ID").and_then(|v| v.parse().ok()),
            sandbox: env("LUNAZ_BILLING_SANDBOX").as_deref() == Some("1"),
        })
    }
}
impl Default for Cfg {
    fn default() -> Cfg {
        Cfg::from_env(|_| None).unwrap()
    }
}

/// Stored plan, or free once it has expired.
pub fn effective(plan: &str, expires: Option<i64>, t: i64) -> &str {
    match expires {
        Some(e) if e <= t => "free",
        _ => plan,
    }
}

/// (start, end) of a purchased period; same active plan extends from its expiry.
pub fn period(t: i64, cur: &str, cur_exp: Option<i64>, plan: &str, months: i64) -> (i64, i64) {
    let start = match cur_exp {
        Some(e) if cur == plan && e > t => e,
        _ => t,
    };
    (start, start + months * MONTH_SECS)
}

/// Smallest zat amount covering `price_usd * months` at `zec_usd`.
pub fn amount_zat(price_usd: f64, months: i64, zec_usd: f64) -> u64 {
    (price_usd * months as f64 * 1e8 / zec_usd).ceil() as u64
}

/// Unix time of 00:00 UTC on the first of the month containing `t`.
pub fn month_start(t: i64) -> i64 {
    let days = t.div_euclid(86400);
    let z = days + 719468;
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    (days - (d - 1)) * 86400
}

pub fn plan_of<'a>(st: &'a St, db: &Connection, mid: i64) -> rusqlite::Result<&'a Plan> {
    let (p, e): (String, Option<i64>) = db.query_row(
        "SELECT plan, plan_expires_at FROM merchants WHERE id=?1",
        [mid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let id = effective(&p, e, now());
    let ps = &st.bill.plans;
    Ok(ps
        .iter()
        .find(|x| x.id == id)
        .unwrap_or_else(|| ps.iter().find(|x| x.id == "free").unwrap()))
}

fn usage(db: &Connection, mid: i64) -> rusqlite::Result<(i64, i64)> {
    Ok((
        db.query_row(
            "SELECT COUNT(*) FROM invoices WHERE merchant_id=?1 AND created_at>=?2 AND id NOT IN (SELECT invoice_id FROM subscriptions)",
            params![mid, month_start(now())],
            |r| r.get(0),
        )?,
        db.query_row(
            "SELECT COUNT(*) FROM api_keys WHERE merchant_id=?1 AND revoked_at IS NULL",
            [mid],
            |r| r.get(0),
        )?,
    ))
}

fn over(p: &Plan, what: &str, limit: Option<i64>, used: i64) -> Result<(), AppErr> {
    match limit {
        Some(l) if used >= l => Err(AppErr::with(
            StatusCode::PAYMENT_REQUIRED,
            format!("{what} limit reached for the {} plan", p.name),
            json!({"limit": l, "used": used, "plan": p.id}),
        )),
        _ => Ok(()),
    }
}

pub fn check_invoices(st: &St, db: &Connection, mid: i64) -> Result<(), AppErr> {
    let p = plan_of(st, db, mid)?;
    over(
        p,
        "monthly invoice",
        p.invoices_per_month,
        usage(db, mid)?.0,
    )
}

pub fn check_keys(st: &St, db: &Connection, mid: i64) -> Result<(), AppErr> {
    let p = plan_of(st, db, mid)?;
    over(p, "api key", p.api_keys, usage(db, mid)?.1)
}

pub async fn plans(State(st): S) -> R {
    Ok(Json(json!(st.bill.plans)))
}

pub async fn my_plan(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lock().unwrap();
    let p = plan_of(&st, &db, mid)?;
    let (inv, keys) = usage(&db, mid)?;
    let exp: Option<i64> = db.query_row(
        "SELECT plan_expires_at FROM merchants WHERE id=?1",
        [mid],
        |r| r.get(0),
    )?;
    Ok(Json(
        json!({"plan": p.id, "plan_name": p.name, "expires_at": exp.filter(|_| p.id != "free"),
        "limits": {"invoices_per_month": p.invoices_per_month, "api_keys": p.api_keys},
        "usage": {"invoices_this_month": inv, "api_keys_active": keys},
        "period_start_of_month": month_start(now()), "sandbox_billing": st.bill.sandbox,
        "billing_configured": st.bill.merchant.is_some()}),
    ))
}

pub async fn list(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lock().unwrap();
    let mut q = db.prepare(
        "SELECT s.id, s.plan, s.months, s.price_usd, s.amount_zat, s.zec_usd, s.invoice_id, s.status, i.status, s.created_at, s.paid_at, s.period_start, s.period_end
         FROM subscriptions s LEFT JOIN invoices i ON i.id=s.invoice_id WHERE s.merchant_id=?1 ORDER BY s.created_at DESC, s.rowid DESC",
    )?;
    let v = q
        .query_map([mid], |r| {
            Ok(json!({"id": r.get::<_, String>(0)?, "plan": r.get::<_, String>(1)?, "months": r.get::<_, i64>(2)?, "price_usd": r.get::<_, f64>(3)?,
                "amount_zat": r.get::<_, i64>(4)?, "zec_usd": r.get::<_, f64>(5)?, "invoice_id": r.get::<_, String>(6)?, "status": r.get::<_, String>(7)?,
                "invoice_status": r.get::<_, Option<String>>(8)?, "created_at": r.get::<_, i64>(9)?, "paid_at": r.get::<_, Option<i64>>(10)?,
                "period_start": r.get::<_, Option<i64>>(11)?, "period_end": r.get::<_, Option<i64>>(12)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(v.into()))
}

#[derive(Deserialize)]
pub struct Checkout {
    plan: String,
    months: i64,
}

pub async fn checkout(State(st): S, h: HeaderMap, Json(b): Json<Checkout>) -> R {
    let mid = auth(&st, &h)?;
    let treasury = st
        .bill
        .merchant
        .ok_or_else(|| bad(StatusCode::SERVICE_UNAVAILABLE, "billing not configured"))?;
    let p = st
        .bill
        .plans
        .iter()
        .find(|p| p.id == b.plan && p.price_usd.is_some_and(|x| x > 0.0))
        .ok_or_else(|| bad(StatusCode::BAD_REQUEST, "plan is not purchasable"))?;
    if !matches!(b.months, 1 | 3 | 12) {
        return Err(bad(StatusCode::BAD_REQUEST, "months must be 1, 3 or 12"));
    }
    if mid == treasury {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "the billing account cannot subscribe",
        ));
    }
    if !st.limits.hit(&format!("checkout:{mid}"), 10, 900, now()) {
        return Err(bad(StatusCode::TOO_MANY_REQUESTS, "too many checkouts"));
    }
    let zec_usd = match crate::swap::zec_price(&st).await {
        Some(x) => x,
        None => st
            .off
            .zec_usd
            .ok_or_else(|| bad(StatusCode::SERVICE_UNAVAILABLE, "zec price unavailable"))?,
    };
    let price = p.price_usd.unwrap() * b.months as f64;
    let amount = amount_zat(p.price_usd.unwrap(), b.months, zec_usd);
    let sid = uuid::Uuid::new_v4().to_string();
    let db = st.db.lock().unwrap();
    let ready: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM merchants WHERE id=?1 AND ufvk IS NOT NULL",
        [treasury],
        |r| r.get(0),
    )?;
    if !ready {
        return Err(bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "billing not configured",
        ));
    }
    let inv = new_invoice(
        &st,
        &db,
        treasury,
        amount,
        CHECKOUT_TTL,
        Some(&format!("lunaz:billing:{sid}")),
    )?;
    db.execute(
        "INSERT INTO subscriptions(id,merchant_id,plan,months,price_usd,amount_zat,zec_usd,invoice_id,status,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'pending',?9)",
        params![sid, mid, p.id, b.months, price, amount, zec_usd, inv["id"].as_str(), now()],
    )?;
    Ok(Json(
        json!({"subscription_id": sid, "plan": p.id, "months": b.months, "price_usd": price, "amount_zat": amount, "zec_usd": zec_usd,
        "invoice": {"id": inv["id"], "address": inv["address"], "zip321_uri": inv["zip321_uri"], "expires_at": inv["expires_at"], "status": inv["status"]}}),
    ))
}

pub async fn simulate_paid(State(st): S, h: HeaderMap, Path(sid): Path<String>) -> R {
    if !st.bill.sandbox {
        return Err(bad(StatusCode::NOT_FOUND, "not found"));
    }
    let mid = auth(&st, &h)?;
    let db = st.db.lock().unwrap();
    let owned: bool = db.query_row(
        "SELECT COUNT(*) > 0 FROM subscriptions WHERE id=?1 AND merchant_id=?2",
        params![sid, mid],
        |r| r.get(0),
    )?;
    if !owned {
        return Err(bad(StatusCode::NOT_FOUND, "no such subscription"));
    }
    if !apply_paid(&st, &db, "id", &sid)? {
        return Err(bad(StatusCode::CONFLICT, "subscription is not payable"));
    }
    Ok(Json(json!({"status": "paid"})))
}

/// Marks the subscription (looked up by `col`) paid and upgrades the merchant; false if nothing was payable.
fn apply_paid(st: &Arc<St>, db: &Connection, col: &str, key: &str) -> anyhow::Result<bool> {
    let row: Option<(String, i64, String, i64)> = db
        .query_row(
            &format!("SELECT id, merchant_id, plan, months FROM subscriptions WHERE {col}=?1 AND status IN ('pending','expired')"),
            [key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((sid, mid, plan, months)) = row else {
        return Ok(false);
    };
    let (cur, exp): (String, Option<i64>) = db.query_row(
        "SELECT plan, plan_expires_at FROM merchants WHERE id=?1",
        [mid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let t = now();
    let (start, end) = period(t, &cur, exp, &plan, months);
    db.execute(
        "UPDATE subscriptions SET status='paid', paid_at=?1, period_start=?2, period_end=?3 WHERE id=?4",
        params![t, start, end, sid],
    )?;
    db.execute(
        "UPDATE merchants SET plan=?1, plan_expires_at=?2 WHERE id=?3",
        params![plan, end, mid],
    )?;
    tracing::info!("merchant {mid} -> plan {plan} until {end}");
    plan_updated(st, db, mid)?;
    Ok(true)
}

/// Billing reaction to an invoice status change; no-op for ordinary invoices.
pub fn on_invoice(
    st: &Arc<St>,
    db: &Connection,
    invoice: &str,
    status: &str,
) -> anyhow::Result<()> {
    match status {
        "paid" => {
            apply_paid(st, db, "invoice_id", invoice)?;
        }
        "underpaid" | "expired" => {
            db.execute(
                "UPDATE subscriptions SET status='expired' WHERE invoice_id=?1 AND status='pending'",
                [invoice],
            )?;
        }
        _ => {}
    }
    Ok(())
}

/// Drops expired paid plans back to free.
pub fn sweep(st: &Arc<St>) {
    let db = st.db.lock().unwrap();
    let ids: Vec<i64> = db
        .prepare("UPDATE merchants SET plan='free', plan_expires_at=NULL WHERE plan!='free' AND plan_expires_at IS NOT NULL AND plan_expires_at<=?1 RETURNING id")
        .and_then(|mut q| q.query_map([now()], |r| r.get(0))?.collect())
        .unwrap_or_default();
    for mid in ids {
        let _ = plan_updated(st, &db, mid);
    }
}

fn plan_updated(st: &Arc<St>, db: &Connection, mid: i64) -> anyhow::Result<()> {
    let (plan, exp): (String, Option<i64>) = db.query_row(
        "SELECT plan, plan_expires_at FROM merchants WHERE id=?1",
        [mid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let body = json!({"type": "plan.updated", "invoice_id": null, "plan": plan, "expires_at": exp})
        .to_string();
    crate::hook::enqueue(st, db, mid, None, "plan.updated", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_expiry() {
        assert_eq!(effective("pro", None, 100), "pro");
        assert_eq!(effective("pro", Some(101), 100), "pro");
        assert_eq!(effective("pro", Some(100), 100), "free");
    }

    #[test]
    fn limits() {
        let p = &default_plans()[0];
        assert!(over(p, "x", p.invoices_per_month, 99).is_ok());
        assert!(over(p, "x", p.invoices_per_month, 100).is_err());
        assert!(over(p, "x", None, 1_000_000).is_ok());
    }

    #[test]
    fn amount_rounds_up() {
        assert_eq!(amount_zat(29.0, 1, 100.0), 29_000_000);
        assert_eq!(amount_zat(29.0, 3, 100.0), 87_000_000);
        assert_eq!(amount_zat(10.0, 1, 3.0), 333_333_334);
    }

    #[test]
    fn extension() {
        let m = MONTH_SECS;
        assert_eq!(period(100, "free", None, "pro", 1), (100, 100 + m));
        assert_eq!(period(100, "pro", Some(500), "pro", 3), (500, 500 + 3 * m));
        assert_eq!(period(100, "pro", Some(50), "pro", 1), (100, 100 + m)); // lapsed
        assert_eq!(period(100, "pro", Some(500), "platform", 1), (100, 100 + m));
        // upgrade
    }

    #[test]
    fn month_boundaries() {
        assert_eq!(month_start(1710504000), 1709251200); // 2024-03-15 -> 03-01
        assert_eq!(month_start(1709251199), 1706745600); // 2024-02-29 23:59:59 -> 02-01
        assert_eq!(month_start(1709251200), 1709251200);
    }
}
