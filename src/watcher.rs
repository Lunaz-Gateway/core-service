use crate::{now, St};
use anyhow::Result;
use orchard::{
    keys::{IncomingViewingKey, PreparedIncomingViewingKey, Scope},
    note_encryption::{CompactAction, IronwoodDomain, OrchardDomain},
};
use rusqlite::{params, Connection, OptionalExtension};
use std::{sync::Arc, time::Duration};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec, Empty,
};
use zcash_note_encryption::{try_compact_note_decryption, try_note_decryption};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId};

type Client = CompactTxStreamerClient<Channel>;

// Ironwood (NU6.3) actions share the payments key space with Orchard, so offset their index.
const IRONWOOD_IDX: usize = 1 << 20;

struct Key {
    merchant: i64,
    ivk: IncomingViewingKey,
    pivk: PreparedIncomingViewingKey,
}

fn keys(st: &St) -> Result<Vec<Key>> {
    let db = st.db.lock().unwrap();
    let mut q = db.prepare("SELECT id, ufvk FROM merchants WHERE ufvk IS NOT NULL")?;
    let rows = q.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = vec![];
    for r in rows {
        let (merchant, ufvk) = r?;
        let ivk = crate::api::parse_ufvk(&st.net, &ufvk)?
            .orchard()
            .unwrap()
            .to_ivk(Scope::External);
        out.push(Key {
            merchant,
            pivk: PreparedIncomingViewingKey::new(&ivk),
            ivk,
        });
    }
    Ok(out)
}

async fn connect(st: &St) -> Result<Client> {
    let ch = Endpoint::from_shared(st.lwd.clone())?
        .tls_config(ClientTlsConfig::new().with_webpki_roots())?
        .connect()
        .await?;
    Ok(CompactTxStreamerClient::new(ch))
}

fn txid_hex(hash: &[u8]) -> String {
    hex::encode(hash.iter().rev().copied().collect::<Vec<_>>())
}

pub async fn scanner(st: Arc<St>) {
    loop {
        expire(&st);
        if let Err(e) = scan_once(&st).await {
            tracing::warn!("scan: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

fn expire(st: &Arc<St>) {
    sweep(st);
    let _ = st
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM sessions WHERE expires_at<?1", [now()]);
    st.limits.purge(now());
    let ids: Vec<String> = (|| -> Result<_> {
        let db = st.db.lock().unwrap();
        let mut q = db.prepare("UPDATE invoices SET status='expired' WHERE status='pending' AND expires_at<?1 RETURNING id")?;
        let ids = q.query_map([now()], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(ids)
    })()
    .unwrap_or_default();
    for id in ids {
        let _ = st.events.send((id, "expired".into()));
    }
}

// Re-evaluates detected invoices: expiry turns them underpaid, or expired if never mined.
fn sweep(st: &Arc<St>) {
    let db = st.db.lock().unwrap();
    let ids: Vec<String> = db
        .prepare("SELECT id FROM invoices WHERE status='detected'")
        .and_then(|mut q| q.query_map([], |r| r.get(0))?.collect())
        .unwrap_or_default();
    for id in ids {
        if let Err(e) = transition(st, &db, &id, None) {
            tracing::warn!("sweep {id}: {e:#}");
        }
    }
}

async fn scan_once(st: &Arc<St>) -> Result<()> {
    let mut c = connect(st).await?;
    let tip = c.get_latest_block(ChainSpec {}).await?.into_inner().height;
    let synced: Option<u64> = st
        .db
        .lock()
        .unwrap()
        .query_row("SELECT height FROM sync_state", [], |r| r.get(0))
        .optional()?;
    let Some(mut h) = synced else {
        st.db
            .lock()
            .unwrap()
            .execute("INSERT INTO sync_state(id,height) VALUES(1,?1)", [tip])?;
        tracing::info!("first start, syncing from tip {tip}");
        return Ok(());
    };
    while h < tip {
        let end = (h + 500).min(tip);
        let keys = keys(st)?;
        let id = |height| {
            Some(BlockId {
                height,
                hash: vec![],
            })
        };
        let mut s = c
            .get_block_range(BlockRange {
                start: id(h + 1),
                end: id(end),
                pool_types: vec![],
            })
            .await?
            .into_inner();
        while let Some(b) = s.message().await? {
            for tx in &b.vtx {
                let txid = txid_hex(&tx.txid);
                let actions = tx.actions.iter().enumerate().map(|(i, a)| (i, a, false));
                let ironwood = tx
                    .ironwood_actions
                    .iter()
                    .enumerate()
                    .map(|(i, a)| (i + IRONWOOD_IDX, a, true));
                for (i, a, iw) in actions.chain(ironwood) {
                    let Ok(ca) = CompactAction::try_from(a) else {
                        continue;
                    };
                    for k in &keys {
                        let dec = if iw {
                            try_compact_note_decryption(
                                &IronwoodDomain::for_compact_action(&ca),
                                &k.pivk,
                                &ca,
                            )
                        } else {
                            try_compact_note_decryption(
                                &OrchardDomain::for_compact_action(&ca),
                                &k.pivk,
                                &ca,
                            )
                        };
                        if let Some((note, addr)) = dec {
                            if let Some(d) = k.ivk.diversifier_index(&addr) {
                                record(
                                    st,
                                    k.merchant,
                                    u128::from(d),
                                    &txid,
                                    i,
                                    note.value().inner(),
                                    Some(b.height),
                                )?;
                            }
                        }
                    }
                }
            }
        }
        h = end;
        st.db
            .lock()
            .unwrap()
            .execute("UPDATE sync_state SET height=?1", [h])?;
        tracing::info!("scanned to {h} (tip {tip})");
    }
    Ok(())
}

pub async fn mempool(st: Arc<St>) {
    loop {
        if let Err(e) = mempool_once(&st).await {
            tracing::warn!("mempool: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn mempool_once(st: &Arc<St>) -> Result<()> {
    let mut c = connect(st).await?;
    let tip = c.get_latest_block(ChainSpec {}).await?.into_inner().height;
    let branch = BranchId::for_height(&st.net, BlockHeight::from_u32(tip as u32 + 1));
    let mut s = c.get_mempool_stream(Empty {}).await?.into_inner();
    tracing::info!("mempool stream connected (tip {tip})");
    while let Some(raw) = s.message().await? {
        let Ok(tx) = Transaction::read(&raw.data[..], branch) else {
            continue;
        };
        let txid = tx.txid().to_string();
        let keys = keys(st)?;
        let actions = tx
            .orchard_bundle()
            .into_iter()
            .flat_map(|b| b.actions().iter().enumerate().map(|(i, a)| (i, a, false)));
        let ironwood = tx.ironwood_bundle().into_iter().flat_map(|b| {
            b.actions()
                .iter()
                .enumerate()
                .map(|(i, a)| (i + IRONWOOD_IDX, a, true))
        });
        for (i, a, iw) in actions.chain(ironwood) {
            for k in &keys {
                let dec = if iw {
                    try_note_decryption(&IronwoodDomain::for_action(a), &k.pivk, a)
                } else {
                    try_note_decryption(&OrchardDomain::for_action(a), &k.pivk, a)
                };
                if let Some((note, addr, _)) = dec {
                    if let Some(d) = k.ivk.diversifier_index(&addr) {
                        record(
                            st,
                            k.merchant,
                            u128::from(d),
                            &txid,
                            i,
                            note.value().inner(),
                            None,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

// ponytail: reorgs ignored; a mined payment is final once seen
fn record(
    st: &Arc<St>,
    merchant: i64,
    div: u128,
    txid: &str,
    idx: usize,
    value: u64,
    height: Option<u64>,
) -> Result<()> {
    let Some(Ok(div)) = div.checked_sub(crate::api::INDEX_BASE).map(i64::try_from) else {
        return Ok(());
    };
    let db = st.db.lock().unwrap();
    let Some(id) = db
        .query_row(
            "SELECT id FROM invoices WHERE merchant_id=?1 AND div_index=?2",
            params![merchant, div],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    else {
        return Ok(());
    };
    db.execute(
        "INSERT INTO payments(txid,action_idx,invoice_id,value_zat,height) VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(txid,action_idx) DO UPDATE SET height=COALESCE(excluded.height, height)",
        params![txid, idx, id, value, height],
    )?;
    transition(st, &db, &id, Some(txid))
}

/// Next invoice status given what was received (mempool + mined) and mined only; None = unchanged.
fn next_status(
    old: &str,
    amount: i64,
    received: i64,
    mined: i64,
    expires: i64,
    now: i64,
) -> Option<&'static str> {
    match old {
        "paid" => None,
        _ if mined >= amount => Some("paid"), // also tops up an underpaid or expired invoice
        "underpaid" => None,
        _ if mined > 0 && now > expires => Some("underpaid"),
        "pending" if received > 0 => Some("detected"),
        // mempool-only payment that never confirmed: assume the tx was dropped
        "detected" if mined == 0 && now > expires + DROPPED_AFTER => Some("expired"),
        _ => None,
    }
}

const DROPPED_AFTER: i64 = 3600;

fn transition(st: &Arc<St>, db: &Connection, id: &str, txid: Option<&str>) -> Result<()> {
    let (amount, old, expires): (i64, String, i64) = db.query_row(
        "SELECT amount_zat, status, expires_at FROM invoices WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let (received, mined): (i64, i64) = db.query_row(
        "SELECT COALESCE(SUM(value_zat),0), COALESCE(SUM(CASE WHEN height IS NOT NULL THEN value_zat END),0) FROM payments WHERE invoice_id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let Some(new) = next_status(&old, amount, received, mined, expires, now()) else {
        return Ok(());
    };
    db.execute(
        "UPDATE invoices SET status=?1, txid=COALESCE(?2, txid, (SELECT txid FROM payments WHERE invoice_id=?4 ORDER BY height IS NULL, height DESC LIMIT 1)),
         paid_at=CASE WHEN ?1='paid' THEN ?3 ELSE paid_at END WHERE id=?4",
        params![new, txid, now(), id],
    )?;
    tracing::info!("invoice {id} -> {new} ({received}/{amount} zat)");
    let _ = st.events.send((id.into(), new.into()));
    if let Some(t) = hook_type(new) {
        crate::hook::notify(st, db, id, t)?;
    }
    Ok(())
}

fn hook_type(status: &str) -> Option<&'static str> {
    match status {
        "paid" => Some("invoice.paid"),
        "underpaid" => Some("invoice.underpaid"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Router};

    #[test]
    fn status_transitions() {
        let n = next_status;
        // (old, amount, received, mined, expires, now)
        assert_eq!(n("pending", 100, 100, 0, 1000, 500), Some("detected"));
        assert_eq!(n("pending", 100, 0, 0, 1000, 500), None);
        assert_eq!(n("detected", 100, 100, 100, 1000, 500), Some("paid"));
        assert_eq!(n("detected", 100, 107, 107, 1000, 500), Some("paid")); // overpaid
        assert_eq!(n("detected", 100, 60, 60, 1000, 500), None); // partial, can still top up
        assert_eq!(n("detected", 100, 60, 60, 1000, 1001), Some("underpaid"));
        assert_eq!(n("underpaid", 100, 60, 60, 1000, 2000), None);
        assert_eq!(n("underpaid", 100, 100, 100, 1000, 2000), Some("paid")); // late top-up
        assert_eq!(n("expired", 100, 100, 100, 1000, 2000), Some("paid"));
        assert_eq!(n("paid", 100, 200, 200, 1000, 2000), None);
        // mempool only: expired only an hour after expiry
        assert_eq!(n("detected", 100, 100, 0, 1000, 1000 + DROPPED_AFTER), None);
        assert_eq!(
            n("detected", 100, 100, 0, 1000, 1001 + DROPPED_AFTER),
            Some("expired")
        );
    }

    fn setup(st: &St, url: &str, amount: i64, expires: i64) {
        let db = st.db.lock().unwrap();
        db.execute("INSERT INTO merchants(id,email,password_hash,name,webhook_url,webhook_secret) VALUES(1,'a@b.co','x','n',?1,'s')", [url]).unwrap();
        db.execute("INSERT INTO invoices(id,merchant_id,div_index,address,amount_zat,status,created_at,expires_at) VALUES('inv',1,0,'addr',?1,'pending',0,?2)", params![amount, expires]).unwrap();
    }

    fn status(st: &St) -> String {
        let db = st.db.lock().unwrap();
        db.query_row("SELECT status FROM invoices WHERE id='inv'", [], |r| {
            r.get(0)
        })
        .unwrap()
    }

    // Receiver that collects webhook bodies.
    async fn receiver() -> (String, Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
        let got = Arc::new(std::sync::Mutex::new(vec![]));
        let g = got.clone();
        let app = Router::new().route(
            "/",
            post(move |b: String| async move {
                g.lock().unwrap().push(serde_json::from_str(&b).unwrap());
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, got)
    }

    async fn wait(got: &std::sync::Mutex<Vec<serde_json::Value>>, n: usize) {
        for _ in 0..50 {
            if got.lock().unwrap().len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    const D: u128 = crate::api::INDEX_BASE;

    #[tokio::test]
    async fn overpaid_and_topup_sum() {
        let st = crate::tests::test_st();
        let (url, got) = receiver().await;
        setup(&st, &url, 100_000, now() + 900);
        record(&st, 1, D, "t1", 0, 40_000, None).unwrap();
        assert_eq!(status(&st), "detected");
        record(&st, 1, D, "t1", 0, 40_000, Some(5)).unwrap(); // mined
        assert_eq!(status(&st), "detected"); // 40k < 100k, still open for a top-up
        record(&st, 1, D, "t2", 0, 67_000, Some(6)).unwrap(); // second payment adds up
        assert_eq!(status(&st), "paid");
        wait(&got, 1).await;
        let g = got.lock().unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0]["type"], "invoice.paid");
        assert_eq!(
            (g[0]["received_zat"].as_i64(), g[0]["overpaid_zat"].as_i64()),
            (Some(107_000), Some(7_000))
        );
        assert_eq!(g[0]["txid"], "t2");
    }

    #[tokio::test]
    async fn underpaid_on_expiry_then_topup() {
        let st = crate::tests::test_st();
        let (url, got) = receiver().await;
        setup(&st, &url, 100_000, now() + 900);
        record(&st, 1, D, "t1", 0, 60_000, Some(5)).unwrap();
        sweep(&st);
        assert_eq!(status(&st), "detected");
        st.db
            .lock()
            .unwrap()
            .execute("UPDATE invoices SET expires_at=?1", [now() - 1])
            .unwrap();
        sweep(&st);
        assert_eq!(status(&st), "underpaid");
        wait(&got, 1).await;
        {
            let g = got.lock().unwrap();
            assert_eq!(g[0]["type"], "invoice.underpaid");
            assert_eq!(
                (g[0]["status"].as_str(), g[0]["overpaid_zat"].as_i64()),
                (Some("underpaid"), Some(0))
            );
        }
        sweep(&st); // final: no second webhook
        record(&st, 1, D, "t2", 0, 40_000, Some(9)).unwrap();
        assert_eq!(status(&st), "paid");
    }

    #[tokio::test]
    async fn mempool_only_expires() {
        let st = crate::tests::test_st();
        setup(&st, "", 100_000, now() - 7200);
        st.db
            .lock()
            .unwrap()
            .execute("UPDATE invoices SET status='detected'", [])
            .unwrap();
        st.db
            .lock()
            .unwrap()
            .execute("INSERT INTO payments VALUES('t1',0,'inv',100000,NULL)", [])
            .unwrap();
        sweep(&st);
        assert_eq!(status(&st), "expired");
    }
}
