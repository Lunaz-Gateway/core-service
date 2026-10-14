use crate::{now, Lk, St};
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
use std::{sync::Arc, time::Duration};
use zcash_address::ZcashAddress;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_protocol::{consensus::Network, memo::MemoBytes, value::Zatoshis};
use zip32::DiversifierIndex;
use zip321::{Payment, TransactionRequest};

pub struct AppErr(StatusCode, String, Value);
impl IntoResponse for AppErr {
    fn into_response(self) -> Response {
        let mut b = json!({"error": self.1});
        if let (Some(m), Some(x)) = (b.as_object_mut(), self.2.as_object()) {
            m.extend(x.clone());
        }
        (self.0, Json(b)).into_response()
    }
}
impl<E: Into<anyhow::Error>> From<E> for AppErr {
    fn from(e: E) -> Self {
        let e: anyhow::Error = e.into();
        tracing::error!("{e:#}");
        AppErr(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error".into(),
            Value::Null,
        )
    }
}
impl AppErr {
    /// Error with extra top-level JSON fields.
    pub fn with(c: StatusCode, m: String, extra: Value) -> Self {
        AppErr(c, m, extra)
    }
}
pub fn bad(c: StatusCode, m: &str) -> AppErr {
    AppErr(c, m.into(), Value::Null)
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

fn decode_vk(net: &Network, s: &str) -> Option<UnifiedIncomingViewingKey> {
    UnifiedFullViewingKey::decode(net, s)
        .map(|u| u.to_unified_incoming_viewing_key())
        .ok()
        .or_else(|| UnifiedIncomingViewingKey::decode(net, s).ok())
}

/// Accepts a UIVK or UFVK; a UFVK is reduced to its incoming key.
pub fn parse_viewing_key(net: &Network, s: &str) -> anyhow::Result<UnifiedIncomingViewingKey> {
    let s = s.trim();
    let Some(u) = decode_vk(net, s) else {
        let other = match net {
            Network::MainNetwork => Network::TestNetwork,
            _ => Network::MainNetwork,
        };
        if decode_vk(&other, s).is_some() {
            anyhow::bail!("viewing key is for a different network");
        }
        anyhow::bail!("invalid viewing key: expected a unified incoming viewing key (uivk…) or full viewing key (uview…)");
    };
    anyhow::ensure!(
        u.orchard().is_some(),
        "viewing key has no Orchard component"
    );
    Ok(u)
}

/// Wallet identity for duplicate detection: the Orchard incoming viewing key, whatever else the UIVK carries.
pub fn orchard_ivk_hash(u: &UnifiedIncomingViewingKey) -> String {
    let ivk = u
        .orchard()
        .as_ref()
        .expect("parse_viewing_key requires Orchard");
    hex::encode(Sha256::digest(ivk.to_bytes()))
}

// Invoice addresses live far above the low indices the merchant's own wallet hands out.
pub const INDEX_BASE: u128 = 1 << 80;

fn invoice_address(
    net: &Network,
    uivk: &UnifiedIncomingViewingKey,
    n: u64,
) -> anyhow::Result<String> {
    let idx = DiversifierIndex::try_from(INDEX_BASE + n as u128)?;
    Ok(uivk
        .address(idx, UnifiedAddressRequest::ORCHARD)?
        .encode(net))
}

/// One ZIP-321 request; each entry is (address, amount, memo).
fn zip321_uri(pays: &[(&str, u64, &str)]) -> anyhow::Result<String> {
    let ps = pays
        .iter()
        .map(|&(a, z, m)| {
            let addr: ZcashAddress = a.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(Payment::new(
                addr,
                Some(Zatoshis::from_u64(z)?),
                Some(MemoBytes::from_bytes(m.as_bytes())?),
                None,
                None,
                vec![],
            )?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(TransactionRequest::new(ps)?.to_uri())
}

/// Pays the merchant, plus the Lunaz fee as a second payment when the invoice has one.
fn invoice_uri(
    id: &str,
    address: &str,
    amount: u64,
    memo: &str,
    fee: Option<(&str, u64)>,
) -> anyhow::Result<String> {
    let fee_memo = format!("lunaz-fee:{id}");
    let mut pays = vec![(address, amount, memo)];
    pays.extend(fee.map(|(a, z)| (a, z, fee_memo.as_str())));
    zip321_uri(&pays)
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
    let ttl = b.expires_in_secs.unwrap_or(900).clamp(60, 86400);
    let db = st.db.lk();
    let kh = sha_hex(key);
    let mid: i64 = db
        .query_row("UPDATE api_keys SET last_used_at=?1 WHERE key_hash=?2 AND revoked_at IS NULL RETURNING merchant_id", params![now(), kh], |r| r.get(0))
        .optional()?
        .ok_or_else(|| bad(StatusCode::UNAUTHORIZED, "bad api key"))?;
    if !st.limits.hit(&format!("inv:{kh}"), 60, 60, now()) {
        return Err(bad(
            StatusCode::TOO_MANY_REQUESTS,
            "too many invoices for this api key, try again in a minute",
        ));
    }
    Ok(Json(new_invoice(&st, &db, mid, b.amount_zat, ttl, None)?))
}

/// Allocates the merchant's next diversifier index and inserts a pending invoice; the caller holds the db lock.
// Allocation and insert share one lock, so a failed insert cannot burn an index unnoticed.
pub fn new_invoice(
    st: &St,
    db: &rusqlite::Connection,
    mid: i64,
    amount: u64,
    ttl: i64,
    memo: Option<&str>,
) -> Result<Value, AppErr> {
    let id = uuid::Uuid::new_v4().to_string();
    let (created, expires) = (now(), now() + ttl);
    let (ufvk, idx) =
        alloc(db, mid)?.ok_or_else(|| bad(StatusCode::BAD_REQUEST, "viewing key not set"))?;
    let address = invoice_address(&st.net, &parse_viewing_key(&st.net, &ufvk)?, idx)?;
    // Fee address on the treasury; none for the treasury's own invoices or without a treasury key.
    let fee = match st.fee.merchant.filter(|&t| t != mid && st.fee.bps > 0) {
        Some(t) => alloc(db, t)?,
        None => None,
    };
    let (fee_zat, fee_idx, fee_address) = match fee {
        Some((k, i)) => (
            st.fee.fee_zat(amount),
            Some(i),
            Some(invoice_address(
                &st.net,
                &parse_viewing_key(&st.net, &k)?,
                i,
            )?),
        ),
        None => (0, None, None),
    };
    let uri = invoice_uri(
        &id,
        &address,
        amount,
        &memo.map_or(format!("lunaz:{id}"), String::from),
        fee_address.as_deref().map(|a| (a, fee_zat)),
    )?;
    db.execute(
        "INSERT INTO invoices(id,merchant_id,div_index,address,amount_zat,status,created_at,expires_at,fee_zat,fee_div_index,fee_address) VALUES(?1,?2,?3,?4,?5,'pending',?6,?7,?8,?9,?10)",
        params![id, mid, idx, address, amount, created, expires, fee_zat, fee_idx, fee_address],
    )?;
    Ok(
        json!({"id": id, "address": address, "amount_zat": amount, "fee_zat": fee_zat, "zip321_uri": uri, "status": "pending", "expires_at": expires}),
    )
}

/// Next diversifier index and viewing key of a merchant; None without a viewing key.
fn alloc(db: &rusqlite::Connection, mid: i64) -> rusqlite::Result<Option<(String, u64)>> {
    db.query_row(
        "UPDATE merchants SET next_index=next_index+1 WHERE id=?1 AND ufvk IS NOT NULL RETURNING ufvk, next_index-1",
        [mid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

fn status_of(st: &St, id: &str) -> rusqlite::Result<Option<String>> {
    st.db
        .lk()
        .query_row("SELECT status FROM invoices WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional()
}

pub async fn get_invoice(State(st): State<Arc<St>>, Path(id): Path<String>) -> R {
    let db = st.db.lk();
    let mut v = db
        .query_row(
            "SELECT status, amount_zat, expires_at, txid, (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=invoices.id AND height IS NOT NULL), address,
             (SELECT 'lunaz-settle:' || id FROM fee_settlements WHERE invoice_id=invoices.id),
             (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=invoices.id AND height IS NULL), fee_zat, fee_address
             FROM invoices WHERE id=?1",
            [&id],
            |r| {
                let (amount, address) = (r.get::<_, i64>(1)?, r.get::<_, String>(5)?);
                let memo = r.get::<_, Option<String>>(6)?.unwrap_or(format!("lunaz:{id}"));
                let (fee, fee_address) = (r.get::<_, i64>(8)?, r.get::<_, Option<String>>(9)?);
                let uri = invoice_uri(&id, &address, amount as u64, &memo, fee_address.as_deref().map(|a| (a, fee as u64))).ok();
                Ok(json!({"id": id, "status": r.get::<_, String>(0)?, "amount_zat": amount, "fee_zat": fee, "address": address, "zip321_uri": uri,
                    "expires_at": r.get::<_, i64>(2)?, "txid": r.get::<_, Option<String>>(3)?, "received_zat": r.get::<_, i64>(4)?, "pending_zat": r.get::<_, i64>(7)?, "overpaid_zat": (r.get::<_, i64>(4)? - amount).max(0)}))
            },
        )
        .optional()?
        .ok_or_else(|| bad(StatusCode::NOT_FOUND, "no such invoice"))?;
    v["swap"] = crate::swap::swap_json(&db, &id).unwrap_or(Value::Null);
    Ok(Json(v))
}

const WS_PER_INVOICE: usize = 5;
const WS_PING: Duration = Duration::from_secs(30);
const WS_MAX_LIFE: Duration = Duration::from_secs(3600);

/// Holds a global and a per-invoice WebSocket slot until dropped.
struct WsSlot {
    st: Arc<St>,
    id: String,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl WsSlot {
    fn take(st: &Arc<St>, id: &str) -> Option<WsSlot> {
        let permit = st.ws.clone().try_acquire_owned().ok()?;
        let mut m = st.ws_per.lk();
        let n = m.entry(id.to_string()).or_default();
        if *n >= WS_PER_INVOICE {
            return None;
        }
        *n += 1;
        Some(WsSlot {
            st: st.clone(),
            id: id.to_string(),
            _permit: permit,
        })
    }
}

impl Drop for WsSlot {
    fn drop(&mut self) {
        let mut m = self.st.ws_per.lk();
        if let Some(n) = m.get_mut(&self.id) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.id);
            }
        }
    }
}

pub async fn invoice_ws(
    State(st): State<Arc<St>>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(slot) = WsSlot::take(&st, &id) else {
        return bad(
            StatusCode::TOO_MANY_REQUESTS,
            "too many websocket connections",
        )
        .into_response();
    };
    ws.on_upgrade(move |sock| async move {
        let _ = watch(st, id, sock).await;
        drop(slot);
    })
}

async fn watch(st: Arc<St>, id: String, mut sock: WebSocket) -> anyhow::Result<()> {
    let mut rx = st.events.subscribe(); // subscribe before reading so no change is missed
    let mut cur = status_of(&st, &id)?.unwrap_or_else(|| "not_found".into());
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + WS_PING, WS_PING);
    let end = tokio::time::sleep(WS_MAX_LIFE);
    tokio::pin!(end);
    loop {
        let sw: Option<String> = st
            .db
            .lk()
            .query_row("SELECT status FROM swaps WHERE invoice_id=?1", [&id], |r| {
                r.get(0)
            })
            .optional()?;
        let mut m = json!({"status": cur});
        if let Some(sw) = sw {
            m["swap_status"] = sw.into();
        }
        sock.send(Message::text(m.to_string())).await?;
        if matches!(cur.as_str(), "paid" | "underpaid" | "expired" | "not_found") {
            break;
        }
        let next = loop {
            tokio::select! {
                m = sock.recv() => match m {
                    None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return Ok(()),
                    _ => {}
                },
                r = rx.recv() => match r {
                    Ok((i, s)) if i == id => break Some(s),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        break Some(status_of(&st, &id)?.unwrap_or_default())
                    }
                    Err(_) => return Ok(()),
                    _ => {}
                },
                _ = ping.tick() => sock.send(Message::Ping(Default::default())).await?,
                _ = &mut end => break None, // max lifetime
            }
        };
        match next {
            Some(s) => cur = s,
            None => break,
        }
    }
    sock.send(Message::Close(None)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;

    fn fvk(net: &Network, seed: u8) -> UnifiedFullViewingKey {
        UnifiedSpendingKey::from_seed(net, &[seed; 32], AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key()
    }

    #[test]
    fn address_roundtrip() {
        let net = Network::TestNetwork;
        let ufvk = fvk(&net, 7);
        let uivk = parse_viewing_key(&net, &ufvk.encode(&net).unwrap()).unwrap();
        let addr = invoice_address(&net, &uivk, 5).unwrap();
        let ua = match zcash_keys::address::Address::decode(&net, &addr).unwrap() {
            zcash_keys::address::Address::Unified(u) => u,
            _ => panic!(),
        };
        let ivk = uivk.orchard().as_ref().unwrap();
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
        assert!(zip321_uri(&[(&addr, 1000, "lunaz:x")])
            .unwrap()
            .starts_with("zcash:utest"));
    }

    #[test]
    fn ufvk_and_uivk_derive_same_addresses() {
        for net in [Network::TestNetwork, Network::MainNetwork] {
            let ufvk = fvk(&net, 9);
            let uivk = ufvk.to_unified_incoming_viewing_key();
            let parsed = parse_viewing_key(&net, &uivk.encode(&net).unwrap()).unwrap();
            assert_eq!(parsed.encode(&net).unwrap(), uivk.encode(&net).unwrap());
            assert_eq!(
                parse_viewing_key(&net, &ufvk.encode(&net).unwrap())
                    .unwrap()
                    .encode(&net)
                    .unwrap(),
                uivk.encode(&net).unwrap()
            );
            for n in [0u64, 1, 5, 1000, u32::MAX as u64] {
                let idx = DiversifierIndex::try_from(INDEX_BASE + n as u128).unwrap();
                let from_ufvk = ufvk
                    .address(idx, UnifiedAddressRequest::ORCHARD)
                    .unwrap()
                    .encode(&net);
                assert_eq!(from_ufvk, invoice_address(&net, &parsed, n).unwrap());
            }
        }
    }

    #[test]
    fn ws_caps() {
        let st = crate::tests::test_st();
        let mut v: Vec<_> = (0..WS_PER_INVOICE)
            .map(|_| WsSlot::take(&st, "a").unwrap())
            .collect();
        assert!(WsSlot::take(&st, "a").is_none());
        assert!(WsSlot::take(&st, "b").is_some());
        v.pop();
        assert!(WsSlot::take(&st, "a").is_some());
        v.clear();
        assert!(st.ws_per.lk().is_empty());
        assert_eq!(st.ws.available_permits(), 2000);
    }

    #[test]
    fn rejects_bad_keys() {
        let (t, m) = (Network::TestNetwork, Network::MainNetwork);
        let uivk = fvk(&t, 3)
            .to_unified_incoming_viewing_key()
            .encode(&t)
            .unwrap();
        let e = |net, s: &str| parse_viewing_key(net, s).unwrap_err().to_string();
        assert!(uivk.starts_with("uivktest"));
        assert!(e(&m, &uivk).contains("different network"));
        assert!(e(&m, &fvk(&t, 3).encode(&t).unwrap()).contains("different network"));
        assert!(e(&t, "garbage").starts_with("invalid viewing key"));
    }
}
