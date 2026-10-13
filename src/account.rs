use crate::api::{bad, bearer, parse_ufvk, rand_hex, sha_hex, AppErr, R};
use crate::{now, St};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use hmac::{Hmac, Mac};
use rusqlite::{params, ErrorCode, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::{Arc, LazyLock};
use zcash_protocol::consensus::Network;

pub type S = State<Arc<St>>;
type NoBody = Result<StatusCode, AppErr>;

const SESSION_SECS: i64 = 30 * 86400;

/// 10 attempts per email and 30 per client IP per 15 min on login/signup.
// ponytail: behind a reverse proxy the IP is the proxy's, so the IP bucket is shared by everyone
fn throttle(st: &St, ip: std::net::SocketAddr, email: &str) -> Result<(), AppErr> {
    let t = now();
    let email: String = email.chars().take(254).collect();
    let l = &st.limits;
    if l.hit(&format!("ip:{}", ip.ip()), 30, 900, t) && l.hit(&format!("email:{email}"), 10, 900, t)
    {
        return Ok(());
    }
    Err(bad(
        StatusCode::TOO_MANY_REQUESTS,
        "too many attempts, try again later",
    ))
}

pub fn hash_pw(pw: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_string())
}
pub fn check_pw(pw: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}
// Verified against when the email is unknown, so both paths cost the same.
static DUMMY: LazyLock<String> = LazyLock::new(|| hash_pw("dummy").unwrap());

fn new_session(st: &St, mid: i64) -> anyhow::Result<Value> {
    let t = rand_hex();
    st.db.lock().unwrap().execute(
        "INSERT INTO sessions(token_hash,merchant_id,expires_at) VALUES(?1,?2,?3)",
        params![sha_hex(&t), mid, now() + SESSION_SECS],
    )?;
    Ok(json!({"token": t}))
}

pub fn auth(st: &St, h: &HeaderMap) -> Result<i64, AppErr> {
    let t = bearer(h).ok_or_else(|| bad(StatusCode::UNAUTHORIZED, "missing session token"))?;
    st.db
        .lock()
        .unwrap()
        .query_row(
            "SELECT merchant_id FROM sessions WHERE token_hash=?1 AND expires_at>?2",
            params![sha_hex(t), now()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| bad(StatusCode::UNAUTHORIZED, "invalid or expired session"))
}

#[derive(Deserialize)]
pub struct Signup {
    email: String,
    name: String,
    password: String,
}

pub async fn signup(
    State(st): S,
    ConnectInfo(ip): ConnectInfo<std::net::SocketAddr>,
    Json(b): Json<Signup>,
) -> Result<(StatusCode, Json<Value>), AppErr> {
    let email = b.email.trim().to_lowercase();
    throttle(&st, ip, &email)?;
    let err = |m| Err(bad(StatusCode::BAD_REQUEST, m));
    if !email.contains('@') || email.len() > 254 {
        return err("invalid email");
    }
    if b.password.len() < 8 {
        return err("password must be at least 8 characters");
    }
    if b.name.trim().is_empty() {
        return err("name required");
    }
    let pw = b.password.clone();
    let (hash, secret) = (
        tokio::task::spawn_blocking(move || hash_pw(&pw)).await??,
        rand_hex(),
    );
    let ins = st.db.lock().unwrap().execute(
        "INSERT INTO merchants(email,password_hash,name,webhook_secret) VALUES(?1,?2,?3,?4)",
        params![email, hash, b.name.trim(), secret],
    );
    match ins {
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::ConstraintViolation => {
            Err(bad(StatusCode::CONFLICT, "email already registered"))
        }
        Err(e) => Err(e.into()),
        Ok(_) => {
            let mid = st.db.lock().unwrap().last_insert_rowid();
            Ok((StatusCode::CREATED, Json(new_session(&st, mid)?)))
        }
    }
}

#[derive(Deserialize)]
pub struct Login {
    email: String,
    password: String,
}

pub async fn login(
    State(st): S,
    ConnectInfo(ip): ConnectInfo<std::net::SocketAddr>,
    Json(b): Json<Login>,
) -> R {
    throttle(&st, ip, &b.email.trim().to_lowercase())?;
    let row: Option<(i64, String)> = st
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id, password_hash FROM merchants WHERE email=?1",
            [b.email.trim().to_lowercase()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let phc = row.as_ref().map_or(DUMMY.clone(), |r| r.1.clone());
    let ok = tokio::task::spawn_blocking(move || check_pw(&b.password, &phc)).await?;
    match row {
        Some((mid, _)) if ok => Ok(Json(new_session(&st, mid)?)),
        _ => Err(bad(StatusCode::UNAUTHORIZED, "invalid email or password")),
    }
}

pub async fn logout(State(st): S, h: HeaderMap) -> NoBody {
    auth(&st, &h)?;
    st.db.lock().unwrap().execute(
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
    let db = st.db.lock().unwrap();
    let mut v = db.query_row("SELECT id, email, name, ufvk IS NOT NULL, webhook_url FROM merchants WHERE id=?1", [mid], |r| {
        Ok(json!({"id": r.get::<_, i64>(0)?, "email": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?, "network": net,
            "ufvk_set": r.get::<_, bool>(3)?, "webhook_url": r.get::<_, Option<String>>(4)?}))
    })?;
    v["plan"] = crate::billing::plan_of(&st, &db, mid)?.id.clone().into();
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct SetUfvk {
    ufvk: String,
}

pub async fn set_ufvk(State(st): S, h: HeaderMap, Json(b): Json<SetUfvk>) -> NoBody {
    let mid = auth(&st, &h)?;
    parse_ufvk(&st.net, &b.ufvk).map_err(|e| bad(StatusCode::BAD_REQUEST, &e.to_string()))?;
    // Conditional update keeps set-once atomic.
    // Two accounts sharing a UFVK would derive identical invoice addresses.
    let n = match st.db.lock().unwrap().execute(
        "UPDATE merchants SET ufvk=?1 WHERE id=?2 AND ufvk IS NULL",
        params![b.ufvk, mid],
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
    let db = st.db.lock().unwrap();
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
    if b.name.trim().is_empty() {
        return Err(bad(StatusCode::BAD_REQUEST, "name required"));
    }
    let key = format!("lz_{}", rand_hex());
    let prefix = &key[..12];
    let db = st.db.lock().unwrap();
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
    let n = st.db.lock().unwrap().execute(
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
    let v = st.db.lock().unwrap().query_row(
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
    if b.url
        .as_ref()
        .is_some_and(|u| !(u.starts_with("http://") || u.starts_with("https://")))
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "url must start with http:// or https://",
        ));
    }
    st.db.lock().unwrap().execute(
        "UPDATE merchants SET webhook_url=?1 WHERE id=?2",
        params![b.url, mid],
    )?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn rotate_webhook(State(st): S, h: HeaderMap) -> R {
    let mid = auth(&st, &h)?;
    let secret = rand_hex();
    st.db.lock().unwrap().execute(
        "UPDATE merchants SET webhook_secret=?1 WHERE id=?2",
        params![secret, mid],
    )?;
    Ok(Json(json!({"secret": secret})))
}

/// Signs `body` with HMAC-SHA256 and POSTs it; returns the HTTP status code.
pub async fn send_webhook(
    http: &reqwest::Client,
    url: &str,
    secret: &str,
    body: String,
) -> anyhow::Result<u16> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    let r = http
        .post(url)
        .header("content-type", "application/json")
        .header("X-Lunaz-Signature", sig)
        .body(body)
        .send()
        .await?;
    Ok(r.status().as_u16())
}

pub async fn test_webhook(State(st): S, h: HeaderMap) -> Result<(StatusCode, Json<Value>), AppErr> {
    let mid = auth(&st, &h)?;
    let (url, secret): (Option<String>, String) = st.db.lock().unwrap().query_row(
        "SELECT webhook_url, webhook_secret FROM merchants WHERE id=?1",
        [mid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let url = url.ok_or_else(|| bad(StatusCode::BAD_REQUEST, "webhook url not set"))?;
    let body = json!({"type": "test", "invoice_id": null, "status": "paid", "amount_zat": 0, "received_zat": 0, "overpaid_zat": 0, "txid": null, "swap": null}).to_string();
    Ok(
        match crate::hook::deliver(&st, mid, None, "test", (&url, &secret), body, false).await {
            Ok(s) => (StatusCode::OK, Json(json!({"status": s}))),
            Err(e) => (StatusCode::OK, Json(json!({"error": e.to_string()}))),
        },
    )
}

#[derive(Deserialize)]
pub struct Lim {
    limit: Option<i64>,
}

pub async fn list_invoices(State(st): S, h: HeaderMap, Query(q): Query<Lim>) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lock().unwrap();
    let mut s = db.prepare(
        "SELECT id, status, amount_zat, (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=invoices.id), address, txid, created_at, expires_at, paid_at
         FROM invoices WHERE merchant_id=?1 ORDER BY created_at DESC, div_index DESC LIMIT ?2",
    )?;
    let v = s
        .query_map(params![mid, q.limit.unwrap_or(50).clamp(1, 200)], |r| {
            Ok(json!({"id": r.get::<_, String>(0)?, "status": r.get::<_, String>(1)?, "amount_zat": r.get::<_, i64>(2)?, "received_zat": r.get::<_, i64>(3)?, "overpaid_zat": (r.get::<_, i64>(3)? - r.get::<_, i64>(2)?).max(0),
                "address": r.get::<_, String>(4)?, "txid": r.get::<_, Option<String>>(5)?, "created_at": r.get::<_, i64>(6)?,
                "expires_at": r.get::<_, i64>(7)?, "paid_at": r.get::<_, Option<i64>>(8)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(v.into()))
}

pub async fn list_deliveries(State(st): S, h: HeaderMap, Query(q): Query<Lim>) -> R {
    let mid = auth(&st, &h)?;
    let db = st.db.lock().unwrap();
    let mut s = db.prepare(
        "SELECT id, invoice_id, type, url, status_code, error, attempt, created_at FROM webhook_deliveries WHERE merchant_id=?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let v = s
        .query_map(params![mid, q.limit.unwrap_or(50).clamp(1, 200)], |r| {
            Ok(json!({"id": r.get::<_, i64>(0)?, "invoice_id": r.get::<_, Option<String>>(1)?, "type": r.get::<_, String>(2)?, "url": r.get::<_, String>(3)?,
                "status_code": r.get::<_, Option<i64>>(4)?, "error": r.get::<_, Option<String>>(5)?, "attempt": r.get::<_, i64>(6)?, "created_at": r.get::<_, i64>(7)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(v.into()))
}
