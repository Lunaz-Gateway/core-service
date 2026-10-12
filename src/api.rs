use crate::{now, St};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zcash_address::ZcashAddress;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};
use zcash_protocol::{consensus::Network, memo::MemoBytes, value::Zatoshis};
use zip32::DiversifierIndex;
use zip321::{Payment, TransactionRequest};

pub struct AppErr(StatusCode, String);
impl IntoResponse for AppErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl<E: Into<anyhow::Error>> From<E> for AppErr {
    fn from(e: E) -> Self {
        let e: anyhow::Error = e.into();
        tracing::error!("{e:#}");
        AppErr(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}
impl AppErr {
    pub fn new(c: StatusCode, m: String) -> Self {
        AppErr(c, m)
    }
}
pub fn bad(c: StatusCode, m: &str) -> AppErr {
    AppErr(c, m.into())
}
pub type R = Result<Json<Value>, AppErr>;

pub fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
pub fn rand_hex() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}
pub fn sha_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

pub fn parse_ufvk(net: &Network, s: &str) -> anyhow::Result<UnifiedFullViewingKey> {
    let u =
        UnifiedFullViewingKey::decode(net, s).map_err(|e| anyhow::anyhow!("invalid ufvk: {e}"))?;
    anyhow::ensure!(u.orchard().is_some(), "ufvk has no orchard component");
    Ok(u)
}

// Invoice addresses live far above the low indices the merchant's own wallet hands out.
pub const INDEX_BASE: u128 = 1 << 80;

fn invoice_address(net: &Network, ufvk: &UnifiedFullViewingKey, n: u64) -> anyhow::Result<String> {
    let idx = DiversifierIndex::try_from(INDEX_BASE + n as u128)?;
    Ok(ufvk
        .address(idx, UnifiedAddressRequest::ORCHARD)?
        .encode(net))
}

fn zip321_uri(address: &str, amount: u64, memo: &str) -> anyhow::Result<String> {
    let addr: ZcashAddress = address.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    let p = Payment::new(
        addr,
        Some(Zatoshis::from_u64(amount)?),
        Some(MemoBytes::from_bytes(memo.as_bytes())?),
        None,
        None,
        vec![],
    )?;
    Ok(TransactionRequest::new(vec![p])?.to_uri())
}

#[derive(Deserialize)]
pub struct NewInvoice {
    amount_zat: u64,
    expires_in_secs: Option<i64>,
}

pub async fn create_invoice(
    State(st): State<Arc<St>>,
    h: HeaderMap,
    Json(b): Json<NewInvoice>,
) -> R {
    let key = bearer(&h).ok_or_else(|| bad(StatusCode::UNAUTHORIZED, "missing api key"))?;
    if b.amount_zat == 0 || Zatoshis::from_u64(b.amount_zat).is_err() {
        return Err(bad(StatusCode::BAD_REQUEST, "invalid amount_zat"));
    }
    let ttl = b.expires_in_secs.unwrap_or(900);
    if ttl <= 0 {
        return Err(bad(StatusCode::BAD_REQUEST, "invalid expires_in_secs"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let (created, expires) = (now(), now() + ttl);
    let db = st.db.lock().unwrap();
    // Allocation and insert share one lock, so a failed insert cannot burn an index unnoticed.
    let kh = sha_hex(key);
    let mid: i64 = db
        .query_row("UPDATE api_keys SET last_used_at=?1 WHERE key_hash=?2 AND revoked_at IS NULL RETURNING merchant_id", params![now(), kh], |r| r.get(0))
        .optional()?
        .ok_or_else(|| bad(StatusCode::UNAUTHORIZED, "bad api key"))?;
    let (ufvk, idx): (String, u64) = db
        .query_row(
            "UPDATE merchants SET next_index=next_index+1 WHERE id=?1 AND ufvk IS NOT NULL RETURNING ufvk, next_index-1",
            [mid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| bad(StatusCode::BAD_REQUEST, "viewing key not set"))?;
    let address = invoice_address(&st.net, &parse_ufvk(&st.net, &ufvk)?, idx)?;
    let uri = zip321_uri(&address, b.amount_zat, &format!("lunaz:{id}"))?;
    db.execute(
        "INSERT INTO invoices(id,merchant_id,div_index,address,amount_zat,status,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,'pending',?6,?7)",
        params![id, mid, idx, address, b.amount_zat, created, expires],
    )?;
    Ok(Json(
        json!({"id": id, "address": address, "amount_zat": b.amount_zat, "zip321_uri": uri, "status": "pending", "expires_at": expires}),
    ))
}

fn status_of(st: &St, id: &str) -> rusqlite::Result<Option<String>> {
    st.db
        .lock()
        .unwrap()
        .query_row("SELECT status FROM invoices WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional()
}

pub async fn get_invoice(State(st): State<Arc<St>>, Path(id): Path<String>) -> R {
    let db = st.db.lock().unwrap();
    let mut v = db
        .query_row(
            "SELECT status, amount_zat, expires_at, txid, (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=invoices.id)
             FROM invoices WHERE id=?1",
            [&id],
            |r| {
                Ok(json!({"id": id, "status": r.get::<_, String>(0)?, "amount_zat": r.get::<_, i64>(1)?,
                    "expires_at": r.get::<_, i64>(2)?, "txid": r.get::<_, Option<String>>(3)?, "received_zat": r.get::<_, i64>(4)?}))
            },
        )
        .optional()?
        .ok_or_else(|| bad(StatusCode::NOT_FOUND, "no such invoice"))?;
    v["swap"] = crate::swap::swap_json(&db, &id).unwrap_or(Value::Null);
    Ok(Json(v))
}

pub async fn invoice_ws(
    State(st): State<Arc<St>>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |sock| async move {
        let _ = watch(st, id, sock).await;
    })
}

async fn watch(st: Arc<St>, id: String, mut sock: WebSocket) -> anyhow::Result<()> {
    let mut rx = st.events.subscribe(); // subscribe before reading so no change is missed
    let mut cur = status_of(&st, &id)?.unwrap_or_else(|| "not_found".into());
    loop {
        let sw: Option<String> = st
            .db
            .lock()
            .unwrap()
            .query_row("SELECT status FROM swaps WHERE invoice_id=?1", [&id], |r| {
                r.get(0)
            })
            .optional()?;
        let mut m = json!({"status": cur});
        if let Some(sw) = sw {
            m["swap_status"] = sw.into();
        }
        sock.send(Message::text(m.to_string())).await?;
        if matches!(cur.as_str(), "paid" | "expired" | "not_found") {
            return Ok(());
        }
        cur = loop {
            match rx.recv().await {
                Ok((i, s)) if i == id => break s,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    break status_of(&st, &id)?.unwrap_or_default()
                }
                Err(_) => return Ok(()),
                _ => {}
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::Scope;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;

    #[test]
    fn address_roundtrip() {
        let net = Network::TestNetwork;
        let usk = UnifiedSpendingKey::from_seed(&net, &[7u8; 32], AccountId::ZERO).unwrap();
        let s = usk.to_unified_full_viewing_key().encode(&net);
        println!("UFVK={s}");
        let ufvk = parse_ufvk(&net, &s).unwrap();
        let addr = invoice_address(&net, &ufvk, 5).unwrap();
        let ua = match zcash_keys::address::Address::decode(&net, &addr).unwrap() {
            zcash_keys::address::Address::Unified(u) => u,
            _ => panic!(),
        };
        let ivk = ufvk.orchard().unwrap().to_ivk(Scope::External);
        assert_eq!(
            u128::from(ivk.diversifier_index(ua.orchard().unwrap()).unwrap()),
            INDEX_BASE + 5
        );
        assert_ne!(
            addr,
            ufvk.address(DiversifierIndex::from(5u32), UnifiedAddressRequest::ORCHARD)
                .unwrap()
                .encode(&net)
        );
        assert!(zip321_uri(&addr, 1000, "lunaz:x")
            .unwrap()
            .starts_with("zcash:utest"));
    }
}
