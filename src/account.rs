use crate::api::{bad, bearer, parse_viewing_key, rand_hex, sha_hex, AppErr, R};
use crate::{now, Lk, St};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Arc;
use zcash_protocol::consensus::Network;

pub type S = State<Arc<St>>;
type NoBody = Result<StatusCode, AppErr>;

const SESSION_SECS: i64 = 7 * 86400;

pub fn norm_email(e: &str) -> Option<String> {
    let e = e.trim().to_lowercase();
    let ok = e.len() <= 254
        && e.split_once('@').is_some_and(|(l, d)| {
            !l.is_empty() && d.contains('.') && !d.starts_with('.') && !d.ends_with('.')
        })
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    ok.then_some(e)
}

pub fn ct_eq(a: &str, b: &str) -> bool {
    use sha2::Digest;
    let (x, y) = (Sha256::digest(a), Sha256::digest(b));
    x.iter().zip(y.iter()).fold(0u8, |d, (p, q)| d | (p ^ q)) == 0
}

fn new_session(st: &St, mid: i64) -> anyhow::Result<Value> {
    let t = rand_hex();
    st.db.lk().execute(
        "INSERT INTO sessions(token_hash,merchant_id,expires_at) VALUES(?1,?2,?3)",
        params![sha_hex(&t), mid, now() + SESSION_SECS],
    )?;
    Ok(json!({"token": t}))
}

pub fn auth(st: &St, h: &HeaderMap) -> Result<i64, AppErr> {
    let t = bearer(h).ok_or_else(|| bad(StatusCode::UNAUTHORIZED, "missing session token"))?;
    st.db
        .lk()
        .query_row(
            "SELECT merchant_id FROM sessions WHERE token_hash=?1 AND expires_at>?2",
            params![sha_hex(t), now()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| bad(StatusCode::UNAUTHORIZED, "invalid or expired session"))
}

pub async fn removed() -> AppErr {
    bad(
        StatusCode::GONE,
        "password sign-in was removed; sign in with your email in the dashboard",
    )
}

#[derive(Deserialize)]
pub struct Exchange {
    email: String,
}

pub async fn exchange(State(st): S, h: HeaderMap, Json(b): Json<Exchange>) -> R {
    let Some(want) = &st.internal else {
        return Err(bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "internal auth not configured",
        ));
    };
    if !bearer(&h).is_some_and(|t| ct_eq(t, want)) {
        return Err(bad(StatusCode::UNAUTHORIZED, "invalid internal token"));
    }
    let email =
        norm_email(&b.email).ok_or_else(|| bad(StatusCode::BAD_REQUEST, "invalid email"))?;
    if !st.limits.hit(&format!("exch:{email}"), 20, 900, now()) {
        return Err(bad(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts, try again later",
        ));
    }
    let db = st.db.lk();
    // INSERT OR IGNORE keeps create-or-reuse atomic under concurrent exchanges.
    let new = db.execute(
        "INSERT OR IGNORE INTO merchants(email,password_hash,name,webhook_secret) VALUES(?1,'','',?2)",
        params![email, rand_hex()],
    )? == 1;
    let mid: i64 = db.query_row("SELECT id FROM merchants WHERE email=?1", [&email], |r| {
        r.get(0)
    })?;
    drop(db);
    let mut v = new_session(&st, mid)?;
    v["new_account"] = new.into();
    v["merchant_id"] = mid.into();
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct SetName {
    name: String,
}

pub async fn set_name(State(st): S, h: HeaderMap, Json(b): Json<SetName>) -> NoBody {
    let mid = auth(&st, &h)?;
    let n = b.name.trim();
    if n.is_empty() || n.chars().count() > 80 {
        return Err(bad(StatusCode::BAD_REQUEST, "name must be 1-80 characters"));
    }
    st.db
        .lk()
        .execute("UPDATE merchants SET name=?1 WHERE id=?2", params![n, mid])?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn logout(State(st): S, h: HeaderMap) -> NoBody {
    auth(&st, &h)?;
    st.db.lk().execute(
        "DELETE FROM sessions WHERE token_hash=?1",
        [sha_hex(bearer(&h).unwrap())],
    )?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn account(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let net = if matches!(st.net, Network::MainNetwork) {
        "main"
    } else {
        "test"
    };
    let db = st.db.lk();
    let mut v = db.query_row("SELECT id, email, name, ufvk IS NOT NULL, webhook_url FROM merchants WHERE id=?1", [mid], |r| {
        Ok(json!({"id": r.get::<_, i64>(0)?, "email": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?, "network": net,
            "ufvk_set": r.get::<_, bool>(3)?, "viewing_key_set": r.get::<_, bool>(3)?, "webhook_url": r.get::<_, Option<String>>(4)?}))
    })?;
    v["plan"] = crate::billing::plan_of(&st, &db, mid)?.id.clone().into();
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct SetUfvk {
    #[serde(alias = "ufvk")]
    viewing_key: String,
}

pub async fn set_ufvk(State(st): S, h: HeaderMap, Json(b): Json<SetUfvk>) -> NoBody {
    let mid = auth(&st, &h)?;
    if b.viewing_key.len() > 2048 {
        return Err(bad(StatusCode::BAD_REQUEST, "viewing key is too long"));
    }
    // Only the incoming key is stored (a UFVK is reduced to its UIVK).
    let u = parse_viewing_key(&st.net, &b.viewing_key)
        .map_err(|e| bad(StatusCode::BAD_REQUEST, &e.to_string()))?;
    // Conditional update keeps set-once atomic.
    // Two accounts sharing a wallet would derive identical invoice addresses; UNIQUE(orchard_ivk_hash) also catches a re-encoded key.
    let n = match st.db.lk().execute(
        "UPDATE merchants SET ufvk=?1, orchard_ivk_hash=?3 WHERE id=?2 AND ufvk IS NULL",
        params![u.encode(&st.net), mid, crate::api::orchard_ivk_hash(&u)],
    ) {
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            return Err(bad(
                StatusCode::CONFLICT,
                "viewing key is already used by another account",
            ));
        }
        r => r?,
    };
    if n == 0 {
        return Err(bad(StatusCode::CONFLICT, "viewing key already set"));
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_keys(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lk();
    let mut q = db.prepare("SELECT id, name, prefix, created_at, last_used_at, revoked_at FROM api_keys WHERE merchant_id=?1 ORDER BY id DESC")?;
    let v = q
        .query_map([mid], |r| {
            Ok(json!({"id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "prefix": r.get::<_, String>(2)?, "created_at": r.get::<_, i64>(3)?,
                "last_used_at": r.get::<_, Option<i64>>(4)?, "revoked_at": r.get::<_, Option<i64>>(5)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(v.into()))
}

#[derive(Deserialize)]
pub struct NewKey {
    name: String,
}

pub async fn create_key(
    State(st): S,
    h: HeaderMap,
    Json(b): Json<NewKey>,
) -> Result<(StatusCode, Json<Value>), AppErr> {
    let mid = auth(&st, &h)?;
    let n = b.name.trim().chars().count();
    if n == 0 || n > 80 {
        return Err(bad(StatusCode::BAD_REQUEST, "name must be 1-80 characters"));
    }
    let key = format!("lz_{}", rand_hex());
    let prefix = &key[..12];
    let db = st.db.lk();
    crate::billing::check_keys(&st, &db, mid)?;
    db.execute(
        "INSERT INTO api_keys(merchant_id,name,prefix,key_hash,created_at) VALUES(?1,?2,?3,?4,?5)",
        params![mid, b.name.trim(), prefix, sha_hex(&key), now()],
    )?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"id": db.last_insert_rowid(), "name": b.name.trim(), "prefix": prefix, "key": key}),
        ),
    ))
}

pub async fn revoke_key(State(st): S, h: HeaderMap, Path(id): Path<i64>) -> NoBody {
    let mid = auth(&st, &h)?;
    let n = st.db.lk().execute(
        "UPDATE api_keys SET revoked_at=COALESCE(revoked_at,?1) WHERE id=?2 AND merchant_id=?3",
        params![now(), id, mid],
    )?;
    if n == 0 {
        return Err(bad(StatusCode::NOT_FOUND, "no such api key"));
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_webhook(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let v = st.db.lk().query_row(
        "SELECT webhook_url, webhook_secret FROM merchants WHERE id=?1",
        [mid],
        |r| Ok(json!({"url": r.get::<_, Option<String>>(0)?, "secret": r.get::<_, String>(1)?})),
    )?;
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct SetWebhook {
    url: Option<String>,
}

pub async fn set_webhook(State(st): S, h: HeaderMap, Json(b): Json<SetWebhook>) -> NoBody {
    let mid = auth(&st, &h)?;
    if let Some(u) = &b.url {
        crate::hook::check_url(u, &st.hook).map_err(|m| bad(StatusCode::BAD_REQUEST, m))?;
    }
    st.db.lk().execute(
        "UPDATE merchants SET webhook_url=?1 WHERE id=?2",
        params![b.url, mid],
    )?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn rotate_webhook(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let secret = rand_hex();
    st.db.lk().execute(
        "UPDATE merchants SET webhook_secret=?1 WHERE id=?2",
        params![secret, mid],
    )?;
    Ok(Json(json!({"secret": secret})))
}

pub async fn test_webhook(State(st): S, h: HeaderMap) -> Result<(StatusCode, Json<Value>), AppErr> {
    let mid = auth(&st, &h)?;
    let url: Option<String> = st.db.lk().query_row(
        "SELECT webhook_url FROM merchants WHERE id=?1",
        [mid],
        |r| r.get(0),
    )?;
    url.ok_or_else(|| bad(StatusCode::BAD_REQUEST, "webhook url not set"))?;
    if !st.limits.hit(&format!("whtest:{mid}"), 10, 900, now()) {
        return Err(bad(
            StatusCode::TOO_MANY_REQUESTS,
            "too many webhook tests, try again later",
        ));
    }
    let body = json!({"type": "test", "invoice_id": null, "status": "paid", "amount_zat": 0, "received_zat": 0, "pending_zat": 0, "overpaid_zat": 0, "txid": null, "swap": null}).to_string();
    Ok(match crate::hook::send_test(&st, mid, body).await? {
        Ok(s) => (StatusCode::OK, Json(json!({"status": s}))),
        Err(e) => (StatusCode::OK, Json(json!({"error": e}))),
    })
}

#[derive(Deserialize)]
pub struct Lim {
    limit: Option<i64>,
}

pub async fn list_invoices(State(st): S, h: HeaderMap, Query(q): Query<Lim>) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lk();
    let mut s = db.prepare(
        "SELECT id, status, amount_zat, (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=invoices.id AND height IS NOT NULL), address, txid, created_at, expires_at, paid_at,
         (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=invoices.id AND height IS NULL)
         FROM invoices WHERE merchant_id=?1 ORDER BY created_at DESC, div_index DESC LIMIT ?2",
    )?;
    let v = s
        .query_map(params![mid, q.limit.unwrap_or(50).clamp(1, 200)], |r| {
            Ok(json!({"id": r.get::<_, String>(0)?, "status": r.get::<_, String>(1)?, "amount_zat": r.get::<_, i64>(2)?, "received_zat": r.get::<_, i64>(3)?, "pending_zat": r.get::<_, i64>(9)?, "overpaid_zat": (r.get::<_, i64>(3)? - r.get::<_, i64>(2)?).max(0),
                "address": r.get::<_, String>(4)?, "txid": r.get::<_, Option<String>>(5)?, "created_at": r.get::<_, i64>(6)?,
                "expires_at": r.get::<_, i64>(7)?, "paid_at": r.get::<_, Option<i64>>(8)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(v.into()))
}

pub async fn list_deliveries(State(st): S, h: HeaderMap, Query(q): Query<Lim>) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lk();
    let mut s = db.prepare(
        "SELECT id, invoice_id, type, url, status_code, error, attempt, created_at, event_id FROM webhook_deliveries WHERE merchant_id=?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let v = s
        .query_map(params![mid, q.limit.unwrap_or(50).clamp(1, 200)], |r| {
            Ok(json!({"id": r.get::<_, i64>(0)?, "invoice_id": r.get::<_, Option<String>>(1)?, "type": r.get::<_, String>(2)?, "url": r.get::<_, String>(3)?,
                "status_code": r.get::<_, Option<i64>>(4)?, "error": r.get::<_, Option<String>>(5)?, "attempt": r.get::<_, i64>(6)?, "created_at": r.get::<_, i64>(7)?, "event_id": r.get::<_, Option<String>>(8)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(v.into()))
}

#[derive(Deserialize)]
pub struct EventsQ {
    status: Option<String>,
    limit: Option<i64>,
}

fn event_json(db: &rusqlite::Connection, mid: i64, id: &str) -> rusqlite::Result<Option<Value>> {
    let ev = db
        .query_row(
            "SELECT id, type, invoice_id, status, attempts, next_attempt_at, last_status_code, last_error, created_at, updated_at
             FROM webhook_events WHERE id=?1 AND merchant_id=?2",
            params![id, mid],
            |r| {
                Ok(json!({"id": r.get::<_, String>(0)?, "type": r.get::<_, String>(1)?, "invoice_id": r.get::<_, Option<String>>(2)?,
                    "status": r.get::<_, String>(3)?, "attempts": r.get::<_, i64>(4)?, "max_attempts": crate::hook::MAX_ATTEMPTS,
                    "next_attempt_at": r.get::<_, Option<i64>>(5)?, "last_status_code": r.get::<_, Option<i64>>(6)?,
                    "last_error": r.get::<_, Option<String>>(7)?, "created_at": r.get::<_, i64>(8)?, "updated_at": r.get::<_, i64>(9)?}))
            },
        )
        .optional()?;
    let Some(mut ev) = ev else { return Ok(None) };
    ev["deliveries"] = db
        .prepare("SELECT attempt, status_code, error, created_at FROM webhook_deliveries WHERE event_id=?1 ORDER BY id")?
        .query_map([id], |r| {
            Ok(json!({"attempt": r.get::<_, i64>(0)?, "status_code": r.get::<_, Option<i64>>(1)?, "error": r.get::<_, Option<String>>(2)?, "created_at": r.get::<_, i64>(3)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into();
    Ok(Some(ev))
}

pub async fn list_events(State(st): S, h: HeaderMap, Query(q): Query<EventsQ>) -> R {
    let mid = auth(&st, &h)?;
    if q.status
        .as_deref()
        .is_some_and(|s| !["pending", "delivered", "failed"].contains(&s))
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "status must be pending, delivered or failed",
        ));
    }
    let db = st.db.lk();
    let ids: Vec<String> = db
        .prepare("SELECT id FROM webhook_events WHERE merchant_id=?1 AND (?2 IS NULL OR status=?2) ORDER BY created_at DESC, rowid DESC LIMIT ?3")?
        .query_map(params![mid, q.status, q.limit.unwrap_or(50).clamp(1, 200)], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let v = ids
        .iter()
        .filter_map(|i| event_json(&db, mid, i).transpose())
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(v.into()))
}

pub async fn retry_event(State(st): S, h: HeaderMap, Path(id): Path<String>) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lk();
    if !crate::hook::retry(&db, mid, &id)? {
        let found = event_json(&db, mid, &id)?.is_some();
        return Err(if found {
            bad(StatusCode::CONFLICT, "only failed events can be retried")
        } else {
            bad(StatusCode::NOT_FOUND, "no such event")
        });
    }
    Ok(Json(event_json(&db, mid, &id)?.unwrap_or_default()))
}

pub async fn retry_failed(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let n = crate::hook::retry_failed(&st.db.lk(), mid)?;
    Ok(Json(json!({"retried": n})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_and_token() {
        assert_eq!(norm_email("  A@B.Co "), Some("a@b.co".into()));
        for bad in ["", "a", "a@b", "@b.co", "a b@c.co", "a@.co", "a@b."] {
            assert_eq!(norm_email(bad), None, "{bad}");
        }
        assert!(ct_eq("abc", "abc") && !ct_eq("abc", "abd") && !ct_eq("abc", "abcd"));
    }
}
