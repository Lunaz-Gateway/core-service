//! Account limits: USD volume caps by tier, strict on cross-chain, loose on shielded.
use crate::account::{auth, S};
use crate::api::{AppErr, R};
use crate::{now, Lk, St};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::{params, Connection};
use serde_json::json;

const DAY: i64 = 86400;

pub struct Cfg {
    pub new_xc_invoice: u64,
    pub new_xc_day: u64,
    pub new_xc_first: u64,
    pub new_zec_day: u64,
    pub est_xc_invoice: u64,
    pub est_xc_day: u64,
    pub est_xc_month: u64,
    pub invoices_day: u64,
    pub est_min_age_days: u64,
    pub est_min_paid: u64,
}

impl Cfg {
    /// `0` disables a cap.
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
        Ok(Cfg {
            new_xc_invoice: num("LUNAZ_LIMIT_NEW_XC_INVOICE_USD", 200)?,
            new_xc_day: num("LUNAZ_LIMIT_NEW_XC_DAY_USD", 300)?,
            new_xc_first: num("LUNAZ_LIMIT_NEW_XC_FIRST_USD", 1000)?,
            new_zec_day: num("LUNAZ_LIMIT_NEW_ZEC_DAY_USD", 1000)?,
            est_xc_invoice: num("LUNAZ_LIMIT_EST_XC_INVOICE_USD", 1000)?,
            est_xc_day: num("LUNAZ_LIMIT_EST_XC_DAY_USD", 3000)?,
            est_xc_month: num("LUNAZ_LIMIT_EST_XC_MONTH_USD", 20000)?,
            invoices_day: num("LUNAZ_LIMIT_INVOICES_DAY", 500)?,
            est_min_age_days: num("LUNAZ_LIMIT_EST_MIN_AGE_DAYS", 14)?,
            est_min_paid: num("LUNAZ_LIMIT_EST_MIN_PAID", 10)?,
        })
    }
    fn age_secs(&self) -> i64 {
        self.est_min_age_days as i64 * DAY
    }
}
impl Default for Cfg {
    fn default() -> Cfg {
        Cfg::from_env(|_| None).unwrap()
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Tier {
    New,
    Established,
    Verified,
}

pub struct Standing {
    pub tier: Tier,
    created_at: i64,
    paid: i64,
    fee_due: bool,
}

fn tier_of(c: &Cfg, verified: bool, age: i64, paid: i64, fee_due: bool) -> Tier {
    if verified {
        Tier::Verified
    } else if age >= c.age_secs() && paid >= c.est_min_paid as i64 && !fee_due {
        Tier::Established
    } else {
        Tier::New
    }
}

pub fn standing(st: &St, db: &Connection, mid: i64, t: i64) -> rusqlite::Result<Standing> {
    let (created_at, verified, paid): (i64, bool, i64) = db.query_row(
        "SELECT created_at, verified, (SELECT COUNT(*) FROM invoices WHERE merchant_id=?1 AND status='paid') FROM merchants WHERE id=?1",
        [mid],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    // the fee treasury is exempt
    let verified = verified || st.fee.merchant == Some(mid);
    let fee_due = !verified && crate::fees::owed(db, mid)?.3 > 0;
    Ok(Standing {
        tier: tier_of(&st.caps, verified, t - created_at, paid, fee_due),
        created_at,
        paid,
        fee_due,
    })
}

#[derive(Clone, Copy, PartialEq)]
enum Rail {
    Xc,
    Zec,
    Count,
}

struct Lim {
    id: &'static str,
    rail: Rail,
    cap: u64,
    since: Option<i64>, // None: per invoice
    until: Option<i64>,
}

/// Active caps of an account at `t`; a 0 cap is left out.
fn limits(c: &Cfg, s: &Standing, t: i64) -> Vec<Lim> {
    let l = |id, rail, cap, since: Option<i64>| Lim {
        id,
        rail,
        cap,
        since,
        until: None,
    };
    let mut v = vec![l(
        "invoices_day",
        Rail::Count,
        c.invoices_day,
        Some(t - DAY),
    )];
    match s.tier {
        Tier::New => {
            v.push(l("xc_invoice", Rail::Xc, c.new_xc_invoice, None));
            v.push(l("xc_day", Rail::Xc, c.new_xc_day, Some(t - DAY)));
            let end = s.created_at + c.age_secs();
            if t < end {
                v.push(Lim {
                    until: Some(end),
                    ..l("xc_first", Rail::Xc, c.new_xc_first, Some(s.created_at))
                });
            }
            v.push(l("zec_day", Rail::Zec, c.new_zec_day, Some(t - DAY)));
        }
        Tier::Established => {
            v.push(l("xc_invoice", Rail::Xc, c.est_xc_invoice, None));
            v.push(l("xc_day", Rail::Xc, c.est_xc_day, Some(t - DAY)));
            v.push(l("xc_month", Rail::Xc, c.est_xc_month, Some(t - 30 * DAY)));
        }
        Tier::Verified => {}
    }
    v.retain(|l| l.cap > 0);
    v
}

fn usd(zat: i64, price: f64) -> f64 {
    zat as f64 * price / 1e8
}

/// Usage of a windowed cap; None for per-invoice caps or a USD cap without a price.
fn used(
    db: &Connection,
    mid: i64,
    l: &Lim,
    price: Option<f64>,
    skip_invoice: &str,
    t: i64,
) -> rusqlite::Result<Option<f64>> {
    let Some(since) = l.since else {
        return Ok(None);
    };
    let n: f64 = match (l.rail, price) {
        (Rail::Count, _) => db.query_row(
            "SELECT COUNT(*) FROM invoices WHERE merchant_id=?1 AND created_at>?2",
            params![mid, since],
            |r| r.get::<_, i64>(0),
        )? as f64,
        // Settled or still open swaps; a quote nobody paid stops counting at its deadline.
        // An invoice lives at most a day plus one extension, so i.created_at bounds the scan.
        (Rail::Xc, Some(p)) => db.query_row(
            "SELECT COALESCE(SUM(COALESCE(CAST(NULLIF(s.amount_in_usd,'') AS REAL), i.amount_zat*?2/1e8)),0)
             FROM invoices i JOIN swaps s ON s.invoice_id=i.id
             WHERE i.merchant_id=?1 AND i.created_at>?3-90000 AND s.created_at>?3 AND i.id!=?4
               AND s.status NOT IN ('REFUNDED','FAILED') AND (s.status!='PENDING_DEPOSIT' OR s.deadline>?5)",
            params![mid, p, since, skip_invoice, crate::swap::iso(t)],
            |r| r.get(0),
        )?,
        // Invoices that may still be paid or were paid, minus those settled by a swap.
        (Rail::Zec, Some(p)) => usd(
            db.query_row(
                "SELECT COALESCE(SUM(amount_zat),0) FROM invoices i WHERE merchant_id=?1 AND created_at>?2
                   AND (status IN ('detected','paid','underpaid') OR (status='pending' AND expires_at>=?3))
                   AND NOT EXISTS(SELECT 1 FROM swaps WHERE invoice_id=i.id AND status='SUCCESS')",
                params![mid, since, t],
                |r| r.get(0),
            )?,
            p,
        ),
        _ => return Ok(None),
    };
    Ok(Some(n))
}

fn dollars(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    format!("${out}")
}

fn refuse(c: &Cfg, tier: Tier, l: &Lim) -> AppErr {
    let who = if tier == Tier::New {
        "new accounts"
    } else {
        "this account"
    };
    let cap = dollars(l.cap);
    let what = match l.id {
        "invoices_day" => format!(
            "accounts can create up to {} invoices per rolling 24 hours, try again later",
            l.cap
        ),
        "xc_invoice" => format!("{who} can receive up to {cap} per cross-chain payment"),
        "xc_day" => {
            format!("{who} can receive up to {cap} in cross-chain payments per rolling 24 hours")
        }
        "xc_month" => {
            format!("{who} can receive up to {cap} in cross-chain payments per rolling 30 days")
        }
        "xc_first" => format!(
            "new accounts can receive up to {cap} in cross-chain payments in their first {} days",
            c.est_min_age_days
        ),
        _ => format!("{who} can receive up to {cap} in ZEC payments per rolling 24 hours"),
    };
    let how = match (l.rail, tier) {
        (Rail::Count, _) => "",
        (_, Tier::New) => {
            "; limits rise automatically as the account builds a history (see the dashboard)"
        }
        _ => "; contact Lunaz support to raise it",
    };
    AppErr::with(
        StatusCode::FORBIDDEN,
        format!("limit reached: {what}{how}"),
        json!({"code": "limit_exceeded", "limit": l.id}),
    )
}

/// Refuses an invoice or payment of `add_zat` that would go over a cap on one of `rails`.
#[allow(clippy::too_many_arguments)]
fn check(
    st: &St,
    db: &Connection,
    mid: i64,
    rails: &[Rail],
    add_zat: i64,
    price: Option<f64>,
    skip_invoice: &str,
    t: i64,
) -> Result<(), AppErr> {
    let s = standing(st, db, mid, t)?;
    for l in limits(&st.caps, &s, t)
        .iter()
        .filter(|l| rails.contains(&l.rail))
    {
        let add = match (l.rail, price) {
            (Rail::Count, _) => 1.0,
            (_, Some(p)) => usd(add_zat, p),
            (_, None) => continue,
        };
        let u = used(db, mid, l, price, skip_invoice, t)?.unwrap_or(0.0);
        if u + add > l.cap as f64 {
            return Err(refuse(&st.caps, s.tier, l));
        }
    }
    Ok(())
}

/// Cross-chain caps for a swap paying `invoice`; the invoice's own replaceable swap is not counted.
pub fn check_swap(
    st: &St,
    db: &Connection,
    mid: i64,
    invoice: &str,
    amount_zat: i64,
    price: f64,
    t: i64,
) -> Result<(), AppErr> {
    check(
        st,
        db,
        mid,
        &[Rail::Xc],
        amount_zat,
        Some(price),
        invoice,
        t,
    )
}

/// Invoice count cap, plus the shielded USD cap when a price is known.
pub fn check_invoice(
    st: &St,
    db: &Connection,
    mid: i64,
    amount_zat: i64,
    price: Option<f64>,
    t: i64,
) -> Result<(), AppErr> {
    check(
        st,
        db,
        mid,
        &[Rail::Count, Rail::Zec],
        amount_zat,
        price,
        "",
        t,
    )
}

/// Whether invoice creation needs the ZEC price (a shielded USD cap applies).
pub fn wants_price(st: &St, db: &Connection, mid: i64, t: i64) -> rusqlite::Result<bool> {
    Ok(standing(st, db, mid, t)?.tier == Tier::New && st.caps.new_zec_day > 0)
}

pub async fn get(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let price = crate::swap::zec_price(&st).await;
    let t = now();
    let db = st.db.lk();
    let (c, s) = (&st.caps, standing(&st, &db, mid, t)?);
    let mut out = vec![];
    for l in limits(c, &s, t) {
        let window = match (l.since, l.until) {
            (None, _) => "invoice",
            (_, Some(_)) => "first_days",
            (Some(f), _) if f == t - DAY => "24h",
            _ => "30d",
        };
        let rail = match l.rail {
            Rail::Xc => "cross_chain",
            Rail::Zec => "zec",
            Rail::Count => "invoices",
        };
        out.push(
            json!({"id": l.id, "rail": rail, "window": window, "cap": l.cap,
            "used": used(&db, mid, &l, price, "", t)?, "ends_at": l.until}),
        );
    }
    let tier = |t| match t {
        Tier::New => "new",
        Tier::Established => "established",
        Tier::Verified => "verified",
    };
    let next = (s.tier == Tier::New).then(|| {
        json!({"tier": "established",
            "age_days_left": (s.created_at + c.age_secs() - t + DAY - 1).max(0) / DAY,
            "paid_invoices_left": (c.est_min_paid as i64 - s.paid).max(0),
            "fee_outstanding": s.fee_due})
    });
    Ok(Json(
        json!({"tier": tier(s.tier), "limits": out, "next": next, "first_days": c.est_min_age_days}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const ZEC: i64 = 100_000_000;

    fn setup(created: i64, edit: impl FnOnce(&mut St)) -> Arc<St> {
        let mut st = crate::tests::test_st();
        edit(Arc::get_mut(&mut st).unwrap());
        st.db.lk().execute("INSERT INTO merchants(id,email,password_hash,name,webhook_secret,created_at) VALUES(1,'a','','','s',?1)", [created]).unwrap();
        st
    }

    fn inv(db: &Connection, id: &str, zat: i64, status: &str, created: i64) {
        db.execute("INSERT INTO invoices(id,merchant_id,div_index,address,amount_zat,status,created_at,expires_at) VALUES(?1,1,(SELECT COUNT(*) FROM invoices),'a',?2,?3,?4,?4+900)",
            params![id, zat, status, created]).unwrap();
    }

    fn swap(
        db: &Connection,
        inv: &str,
        usd: Option<&str>,
        status: &str,
        created: i64,
        deadline: i64,
    ) {
        db.execute("INSERT INTO swaps(id,invoice_id,origin_asset,symbol,blockchain,deposit_address,amount_in,amount_in_formatted,amount_in_usd,refund_to,deadline,status,created_at,updated_at)
            VALUES(?1,?1,'a','USDC','sol','d','1','1',?2,'r',?3,?4,?5,?5)", params![inv, usd, crate::swap::iso(deadline), status, created]).unwrap();
    }

    fn limit_of(r: Result<(), AppErr>) -> Option<String> {
        use axum::response::IntoResponse;
        let r = r.err()?.into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let b = futures_body(r);
        assert_eq!(b["code"], "limit_exceeded");
        Some(b["limit"].as_str().unwrap().to_string())
    }

    fn futures_body(r: axum::response::Response) -> serde_json::Value {
        let b = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(axum::body::to_bytes(r.into_body(), 1 << 16))
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    #[test]
    fn tiers() {
        let c = Cfg::default();
        let (age, paid) = (c.age_secs(), c.est_min_paid as i64);
        assert_eq!(tier_of(&c, false, age, paid, false), Tier::Established);
        assert_eq!(tier_of(&c, false, age - 1, paid, false), Tier::New);
        assert_eq!(tier_of(&c, false, age, paid - 1, false), Tier::New);
        assert_eq!(tier_of(&c, false, age, paid, true), Tier::New); // outstanding fee
        assert_eq!(tier_of(&c, true, 0, 0, true), Tier::Verified);
        let t = now();
        let st = setup(t, |_| {});
        assert_eq!(standing(&st, &st.db.lk(), 1, t).unwrap().tier, Tier::New);
        st.db
            .lk()
            .execute("UPDATE merchants SET verified=1", [])
            .unwrap();
        assert_eq!(
            standing(&st, &st.db.lk(), 1, t).unwrap().tier,
            Tier::Verified
        );
        let st = setup(t, |s| s.fee.merchant = Some(1));
        assert_eq!(
            standing(&st, &st.db.lk(), 1, t).unwrap().tier,
            Tier::Verified
        );
        // old account with enough paid invoices, then a fee left unpaid
        let st = setup(0, |_| {});
        let db = st.db.lk();
        for i in 0..paid {
            inv(&db, &format!("p{i}"), ZEC, "paid", t - 100);
        }
        assert_eq!(standing(&st, &db, 1, t).unwrap().tier, Tier::Established);
        db.execute("UPDATE invoices SET fee_zat=1000 WHERE id='p0'", [])
            .unwrap();
        assert_eq!(standing(&st, &db, 1, t).unwrap().tier, Tier::New);
        let e = |k: &'static str, v: &'static str| {
            Cfg::from_env(move |q| (q == k).then(|| v.into())).is_err()
        };
        assert!(e("LUNAZ_LIMIT_NEW_XC_DAY_USD", "x") && e("LUNAZ_LIMIT_INVOICES_DAY", "-1"));
        assert!(!e("LUNAZ_LIMIT_NEW_XC_DAY_USD", "0"));
        assert_eq!(dollars(20000), "$20,000");
        assert_eq!(dollars(300), "$300");
    }

    #[test]
    fn cross_chain_caps() {
        let (t, p) = (now(), 100.0); // $100 per ZEC
        let st = setup(t - 2 * DAY, |_| {});
        let db = st.db.lk();
        let ck = |zat| limit_of(check_swap(&st, &db, 1, "new", zat, p, t));
        assert_eq!(ck(2 * ZEC), None); // exactly $200
        assert_eq!(ck(2 * ZEC + 1).as_deref(), Some("xc_invoice"));
        inv(&db, "a", ZEC, "paid", t - DAY);
        swap(&db, "a", Some("150"), "SUCCESS", t - DAY + 60, t);
        inv(&db, "b", ZEC, "pending", t - 100);
        swap(&db, "b", None, "REFUNDED", t - 100, t + 900);
        inv(&db, "c", ZEC, "pending", t - 100);
        swap(&db, "c", None, "PENDING_DEPOSIT", t - 100, t - 1); // quote expired unpaid
        assert_eq!(ck(ZEC + ZEC / 2), None); // 150 + 150 = 300
        assert_eq!(ck(ZEC + ZEC / 2 + 1).as_deref(), Some("xc_day"));
        // an open quote counts at the invoice amount, except on the invoice being re-quoted
        db.execute(
            "UPDATE swaps SET deadline=?1 WHERE invoice_id='c'",
            [crate::swap::iso(t + 900)],
        )
        .unwrap();
        assert_eq!(ck(ZEC / 2), None);
        assert_eq!(ck(ZEC / 2 + 1).as_deref(), Some("xc_day"));
        assert_eq!(
            limit_of(check_swap(&st, &db, 1, "c", ZEC + ZEC / 2, p, t)),
            None
        );
        // the first-days total counts swaps older than a day
        db.execute(
            "UPDATE swaps SET amount_in_usd='900', created_at=?1 WHERE invoice_id='a'",
            [t - DAY - 60],
        )
        .unwrap();
        assert_eq!(ck(ZEC / 2 + 1).as_deref(), Some("xc_first")); // 900 + 100 + 50.x
        drop(db);
        // 0 disables a cap
        let st = setup(t, |s| {
            s.caps = Cfg {
                new_xc_invoice: 0,
                new_xc_day: 0,
                new_xc_first: 0,
                ..Cfg::default()
            }
        });
        assert_eq!(
            limit_of(check_swap(&st, &st.db.lk(), 1, "x", 1000 * ZEC, p, t)),
            None
        );
    }

    #[test]
    fn invoice_caps() {
        let (t, p) = (now(), Some(100.0));
        let st = setup(t, |s| s.caps.invoices_day = 4);
        let db = st.db.lk();
        let ck = |zat, p| limit_of(check_invoice(&st, &db, 1, zat, p, t));
        inv(&db, "a", 4 * ZEC, "paid", t - 100);
        inv(&db, "b", 5 * ZEC, "pending", t - 100);
        inv(&db, "x", 50 * ZEC, "expired", t - 100);
        assert_eq!(ck(ZEC, p), None); // $1,000 exactly
        assert_eq!(ck(ZEC + 1, p).as_deref(), Some("zec_day"));
        assert_eq!(ck(100 * ZEC, None), None); // no price: allowed
        inv(&db, "c", 1, "pending", t - 100);
        assert_eq!(ck(1, None).as_deref(), Some("invoices_day"));
        drop(db);
        let st = setup(t, |s| {
            s.caps = Cfg {
                invoices_day: 0,
                new_zec_day: 0,
                ..Cfg::default()
            }
        });
        let db = st.db.lk();
        for i in 0..5 {
            inv(&db, &format!("i{i}"), 1000 * ZEC, "paid", t - 100);
        }
        assert_eq!(limit_of(check_invoice(&st, &db, 1, ZEC, p, t)), None);
    }

    #[tokio::test]
    async fn handlers_refuse_over_cap() {
        use axum::{extract::Path, response::IntoResponse};
        let t = now();
        let st = setup(t, |s| s.caps.invoices_day = 1);
        *st.zec_price.lk() = Some(100.0);
        {
            let db = st.db.lk();
            inv(&db, "a", 3 * ZEC, "pending", t);
            db.execute("INSERT INTO api_keys(merchant_id,name,prefix,key_hash,created_at) VALUES(1,'k','k',?1,0)", [crate::api::sha_hex("key")]).unwrap();
        }
        let b = serde_json::from_value(json!({"asset_id": "x", "refund_to": "r"})).unwrap();
        let r = crate::swap::create_swap(State(st.clone()), Path("a".into()), Json(b)).await;
        assert_eq!(
            r.err().unwrap().into_response().status(),
            StatusCode::FORBIDDEN
        );
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer key".parse().unwrap());
        let b = serde_json::from_value(json!({"amount_zat": 1000})).unwrap();
        let r = crate::api::create_invoice(State(st.clone()), h, Json(b)).await;
        assert_eq!(
            r.err().unwrap().into_response().status(),
            StatusCode::FORBIDDEN
        );
    }
}
