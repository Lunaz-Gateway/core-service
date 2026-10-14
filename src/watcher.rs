use crate::{now, Lk, St};
use anyhow::Result;
use orchard::{
    keys::{IncomingViewingKey, PreparedIncomingViewingKey},
    note_encryption::{CompactAction, IronwoodDomain, OrchardDomain},
};
use rusqlite::{params, Connection, OptionalExtension};
use std::{collections::hash_map::Entry, sync::Arc, time::Duration};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec, Empty,
};
use zcash_note_encryption::batch;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId};

type Client = CompactTxStreamerClient<Channel>;

// Ironwood (NU6.3) actions share the payments key space with Orchard, so offset their index.
pub const IRONWOOD_IDX: usize = 1 << 20;

pub struct Key {
    merchant: i64,
    ivk: IncomingViewingKey,
    pivk: PreparedIncomingViewingKey,
}

/// Invoices stay watched this long after expiry, for late payments and top-ups.
const GRACE: i64 = 48 * 3600;

/// Keys of merchants that can still receive an invoice payment, plus the treasury.
// ponytail: payments to an invoice address after GRACE are not recorded, and block catch-up after >48 h downtime uses the current live set
fn keys(st: &St) -> Result<Vec<Arc<Key>>> {
    let rows: Vec<(i64, String)> = {
        let db = st.db.lk();
        let mut q = db.prepare(
            "SELECT id, ufvk FROM merchants WHERE ufvk IS NOT NULL AND (id=?2 OR id IN (
               SELECT merchant_id FROM invoices WHERE status IN ('pending','detected') OR expires_at>?1))",
        )?;
        let rows = q.query_map(params![now() - GRACE, st.fee.merchant], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let mut cache = st.keys.lk();
    let mut out = vec![];
    for (merchant, ufvk) in rows {
        let k = match cache.entry(merchant) {
            Entry::Occupied(e) => e.get().clone(),
            Entry::Vacant(e) => {
                let ivk = crate::api::parse_viewing_key(&st.net, &ufvk)?
                    .orchard()
                    .clone()
                    .unwrap();
                let pivk = PreparedIncomingViewingKey::new(&ivk);
                let k = Key {
                    merchant,
                    ivk,
                    pivk,
                };
                e.insert(Arc::new(k)).clone()
            }
        };
        out.push(k);
    }
    Ok(out)
}

/// A decrypted payment: (index into acts, merchant, diversifier index, value).
type Hit = (usize, i64, u128, u64);

/// Batch trial decryption on one thread; an action is (compact action, is Ironwood).
fn decrypt(acts: &[(CompactAction, bool)], keys: &[Arc<Key>]) -> Vec<Hit> {
    let ivks: Vec<_> = keys.iter().map(|k| k.pivk.clone()).collect();
    let (iw, or): (Vec<usize>, Vec<usize>) = (0..acts.len()).partition(|&i| acts[i].1);
    let or_out: Vec<_> = or
        .iter()
        .map(|&i| {
            (
                OrchardDomain::for_compact_action(&acts[i].0),
                acts[i].0.clone(),
            )
        })
        .collect();
    let iw_out: Vec<_> = iw
        .iter()
        .map(|&i| {
            (
                IronwoodDomain::for_compact_action(&acts[i].0),
                acts[i].0.clone(),
            )
        })
        .collect();
    let found = batch::try_compact_note_decryption(&ivks, &or_out)
        .into_iter()
        .zip(or)
        .chain(
            batch::try_compact_note_decryption(&ivks, &iw_out)
                .into_iter()
                .zip(iw),
        );
    let mut hits: Vec<Hit> = found
        .filter_map(|(r, i)| {
            let ((note, addr), j) = r?;
            let d = keys[j].ivk.diversifier_index(&addr)?;
            Some((i, keys[j].merchant, u128::from(d), note.value().inner()))
        })
        .collect();
    hits.sort_by_key(|h| h.0);
    hits
}

// Below this many (action x key) pairs, spawning threads costs more than it saves.
const PAR_MIN: usize = 256;

/// `decrypt` split across `threads`, along actions (blocks) or keys (single txs); hits in action order.
fn trial(acts: &[(CompactAction, bool)], keys: &[Arc<Key>], threads: usize) -> Vec<Hit> {
    if acts.len() * keys.len() < PAR_MIN || threads <= 1 {
        return decrypt(acts, keys);
    }
    let mut hits: Vec<Hit> = std::thread::scope(|s| {
        let hs: Vec<_> = if acts.len() >= keys.len() {
            let c = acts.len().div_ceil(threads);
            acts.chunks(c)
                .enumerate()
                .map(|(n, a)| {
                    s.spawn(move || {
                        decrypt(a, keys)
                            .into_iter()
                            .map(|h| (h.0 + n * c, h.1, h.2, h.3))
                            .collect()
                    })
                })
                .collect()
        } else {
            keys.chunks(keys.len().div_ceil(threads))
                .map(|k| s.spawn(move || decrypt(acts, k)))
                .collect()
        };
        hs.into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect::<Vec<Hit>>()
    });
    hits.sort_by_key(|h| h.0);
    hits
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
    crate::offramp::expire(st);
    crate::hook::purge(&st.db.lk());
    let _ = st
        .db
        .lk()
        .execute("DELETE FROM sessions WHERE expires_at<?1", [now()]);
    st.limits.purge(now());
    let ids: Vec<String> = (|| -> Result<_> {
        let db = st.db.lk();
        let mut q = db.prepare("UPDATE invoices SET status='expired' WHERE status='pending' AND expires_at<?1 RETURNING id")?;
        let ids = q.query_map([now()], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(ids)
    })()
    .unwrap_or_default();
    for id in ids {
        let _ = crate::fees::on_invoice(&st.db.lk(), &id, "expired");
        let _ = st.events.send((id, "expired".into()));
    }
}

// Re-evaluates detected invoices: expiry turns them underpaid, or expired if never mined.
fn sweep(st: &Arc<St>) {
    let db = st.db.lk();
    // An unmined payment not mined within the hour was most likely dropped.
    let _ = db.execute(
        "DELETE FROM payments WHERE height IS NULL AND COALESCE(seen_at,0)<?1",
        [now() - DROPPED_AFTER],
    );
    let _ = db.execute(
        "DELETE FROM fee_payments WHERE height IS NULL AND seen_at<?1",
        [now() - DROPPED_AFTER],
    );
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
        .lk()
        .query_row("SELECT height FROM sync_state", [], |r| r.get(0))
        .optional()?;
    let Some(mut h) = synced else {
        st.db
            .lk()
            .execute("INSERT INTO sync_state(id,height) VALUES(1,?1)", [tip])?;
        tracing::info!("first start, syncing from tip {tip}");
        return Ok(());
    };
    while h < tip {
        let end = (h + 500).min(tip);
        let keys = Arc::new(keys(st)?);
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
            let mut txids = vec![];
            let mut acts = vec![];
            for tx in &b.vtx {
                let orchard = tx.actions.iter().enumerate().map(|(i, a)| (i, a, false));
                let ironwood = tx.ironwood_actions.iter().enumerate();
                for (i, a, iw) in orchard.chain(ironwood.map(|(i, a)| (i + IRONWOOD_IDX, a, true)))
                {
                    if let Ok(ca) = CompactAction::try_from(a) {
                        txids.push((txid_hex(&tx.txid), i));
                        acts.push((ca, iw));
                    }
                }
            }
            let (k, n) = (keys.clone(), st.scan_threads);
            let hits = tokio::task::spawn_blocking(move || trial(&acts, &k, n)).await?;
            for (a, merchant, div, value) in hits {
                let (txid, i) = &txids[a];
                record(st, merchant, div, txid, *i, value, Some(b.height))?;
            }
        }
        h = end;
        st.db.lk().execute("UPDATE sync_state SET height=?1", [h])?;
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
        let orchard = tx
            .orchard_bundle()
            .into_iter()
            .flat_map(|b| b.actions().iter().enumerate());
        let ironwood = tx
            .ironwood_bundle()
            .into_iter()
            .flat_map(|b| b.actions().iter().enumerate());
        // Compact decryption finds the same notes (cmx is checked); the memo is not needed.
        let (idx, acts): (Vec<_>, Vec<_>) = orchard
            .map(|(i, a)| (i, (CompactAction::from(a), false)))
            .chain(ironwood.map(|(i, a)| (i + IRONWOOD_IDX, (CompactAction::from(a), true))))
            .unzip();
        let (k, n) = (keys(st)?, st.scan_threads);
        let hits = tokio::task::spawn_blocking(move || trial(&acts, &k, n)).await?;
        for (a, merchant, div, value) in hits {
            record(st, merchant, div, &txid, idx[a], value, None)?;
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
    let db = st.db.lk();
    let Some((id, status)) = db
        .query_row(
            "SELECT id, status FROM invoices WHERE merchant_id=?1 AND div_index=?2",
            params![merchant, div],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?
    else {
        if st.fee.merchant == Some(merchant) {
            record_fee(&db, div, txid, idx, value, height)?;
        }
        return Ok(());
    };
    if height.is_none() && is_final(&status) {
        return Ok(());
    }
    db.execute(
        "INSERT INTO payments(txid,action_idx,invoice_id,value_zat,height,seen_at) VALUES(?1,?2,?3,?4,?5,?6)
         ON CONFLICT(txid,action_idx) DO UPDATE SET height=COALESCE(excluded.height, height)",
        params![txid, idx, id, value, height, now()],
    )?;
    transition(st, &db, &id, Some(txid))
}

/// A payment to an invoice's fee address on the treasury; never changes the invoice status.
// ponytail: fee_div_index is matched without the treasury id, so changing LUNAZ_BILLING_MERCHANT_ID can mismatch old fee addresses
fn record_fee(
    db: &Connection,
    div: i64,
    txid: &str,
    idx: usize,
    value: u64,
    height: Option<u64>,
) -> Result<()> {
    let Some(id) = db
        .query_row(
            "SELECT id FROM invoices WHERE fee_div_index=?1",
            [div],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    else {
        return Ok(());
    };
    db.execute(
        "INSERT INTO fee_payments(txid,action_idx,invoice_id,value_zat,height,seen_at) VALUES(?1,?2,?3,?4,?5,?6)
         ON CONFLICT(txid,action_idx) DO UPDATE SET height=COALESCE(excluded.height, height)",
        params![txid, idx, id, value, height, now()],
    )?;
    Ok(())
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
        "UPDATE invoices SET status=?1, txid=COALESCE(?2, (SELECT txid FROM payments WHERE invoice_id=?4 AND height IS NOT NULL ORDER BY height DESC LIMIT 1), txid),
         paid_at=CASE WHEN ?1='paid' THEN ?3 ELSE paid_at END WHERE id=?4",
        params![new, txid, now(), id],
    )?;
    if is_final(new) {
        db.execute(
            "DELETE FROM payments WHERE invoice_id=?1 AND height IS NULL",
            [id],
        )?;
    }
    tracing::info!("invoice {id} -> {new} ({received}/{amount} zat)");
    if matches!(new, "paid" | "underpaid") {
        // Rate lookup must never block the transition, so it runs detached.
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            let (st, id) = (st.clone(), id.to_string());
            h.spawn(async move {
                if let Some(p) = crate::swap::zec_price(&st).await {
                    let _ = st.db.lk().execute(
                        "UPDATE invoices SET paid_usd_rate=?1 WHERE id=?2",
                        params![p, id],
                    );
                }
            });
        }
    }
    let _ = st.events.send((id.into(), new.into()));
    if let Some(t) = hook_type(new) {
        crate::hook::notify(st, db, id, t)?;
    }
    crate::fees::on_invoice(db, id, new)?;
    Ok(())
}

fn is_final(status: &str) -> bool {
    matches!(status, "paid" | "underpaid" | "expired")
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
        let db = st.db.lk();
        db.execute("INSERT INTO merchants(id,email,password_hash,name,webhook_url,webhook_secret) VALUES(1,'a@b.co','x','n',?1,'s')", [url]).unwrap();
        db.execute("INSERT INTO invoices(id,merchant_id,div_index,address,amount_zat,status,created_at,expires_at) VALUES('inv',1,0,'addr',?1,'pending',0,?2)", params![amount, expires]).unwrap();
    }

    fn status(st: &St) -> String {
        let db = st.db.lk();
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
                g.lk().push(serde_json::from_str(&b).unwrap());
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, got)
    }

    async fn wait(st: &Arc<St>, got: &std::sync::Mutex<Vec<serde_json::Value>>, n: usize) {
        for _ in 0..50 {
            crate::hook::tick(st.clone()).await;
            if got.lk().len() >= n {
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
        wait(&st, &got, 1).await;
        let g = got.lk();
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
            .lk()
            .execute("UPDATE invoices SET expires_at=?1", [now() - 1])
            .unwrap();
        sweep(&st);
        assert_eq!(status(&st), "underpaid");
        wait(&st, &got, 1).await;
        {
            let g = got.lk();
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

    async fn amounts(st: &Arc<St>) -> (i64, i64, i64) {
        let v = crate::api::get_invoice(
            axum::extract::State(st.clone()),
            axum::extract::Path("inv".into()),
        )
        .await
        .ok()
        .unwrap()
        .0;
        let n = |k: &str| v[k].as_i64().unwrap();
        (n("received_zat"), n("pending_zat"), n("overpaid_zat"))
    }

    // A dropped mempool tx plus the conflicting mined one must not count twice.
    #[tokio::test]
    async fn dropped_mempool_not_counted() {
        let st = crate::tests::test_st();
        let (url, got) = receiver().await;
        setup(&st, &url, 100_000, now() + 900);
        record(&st, 1, D, "txA", 0, 100_000, None).unwrap();
        record(&st, 1, D, "txC", 0, 30_000, None).unwrap();
        assert_eq!(status(&st), "detected");
        assert_eq!(amounts(&st).await, (0, 130_000, 0));
        st.db
            .lk()
            .execute(
                "UPDATE payments SET seen_at=?1 WHERE txid='txC'",
                [now() - 7200],
            )
            .unwrap();
        sweep(&st); // stale unmined row is dropped
        assert_eq!(
            (status(&st).as_str(), amounts(&st).await),
            ("detected", (0, 100_000, 0))
        );
        record(&st, 1, D, "txB", 0, 100_000, Some(7)).unwrap();
        assert_eq!(status(&st), "paid");
        assert_eq!(amounts(&st).await, (100_000, 0, 0)); // final: unmined rows removed
        record(&st, 1, D, "txA", 0, 100_000, None).unwrap(); // re-seen in mempool
        assert_eq!(amounts(&st).await, (100_000, 0, 0));
        wait(&st, &got, 1).await;
        let g = got.lk();
        assert_eq!(
            (
                g[0]["received_zat"].as_i64(),
                g[0]["pending_zat"].as_i64(),
                g[0]["overpaid_zat"].as_i64()
            ),
            (Some(100_000), Some(0), Some(0))
        );
        assert_eq!(g[0]["txid"], "txB");
    }

    #[tokio::test]
    async fn mined_upgrades_in_place() {
        let st = crate::tests::test_st();
        setup(&st, "", 100_000, now() + 900);
        record(&st, 1, D, "t1", 0, 100_000, None).unwrap();
        record(&st, 1, D, "t1", 0, 100_000, Some(3)).unwrap();
        assert_eq!(status(&st), "paid");
        assert_eq!(amounts(&st).await, (100_000, 0, 0));
    }

    // Merchant 2 invoices carry a fee to treasury 1; fee payments never touch the invoice status.
    #[tokio::test]
    async fn fee_payments_and_outstanding() {
        use zcash_keys::keys::UnifiedSpendingKey;
        let mut st = Arc::into_inner(crate::tests::test_st()).unwrap();
        st.fee.merchant = Some(1);
        let st = Arc::new(st);
        let net = st.net;
        let db = st.db.lk();
        for (id, seed) in [(1, 1u8), (2, 2u8)] {
            let k = UnifiedSpendingKey::from_seed(&net, &[seed; 32], zip32::AccountId::ZERO)
                .unwrap()
                .to_unified_full_viewing_key()
                .to_unified_incoming_viewing_key()
                .encode(&net);
            db.execute("INSERT INTO merchants(id,email,password_hash,name,ufvk,webhook_secret) VALUES(?1,?2,'','',?3,'s')", params![id, format!("{id}@b.co"), k]).unwrap();
        }
        let inv = |m, amount| {
            crate::api::new_invoice(&st, &db, m, amount, 900, None)
                .ok()
                .unwrap()
        };
        let (a, b) = (inv(2, 10_000_000), inv(2, 100_000));
        assert_eq!(
            (a["fee_zat"].as_i64(), b["fee_zat"].as_i64()),
            (Some(50_000), Some(1000))
        );
        assert!(a["zip321_uri"].as_str().unwrap().contains("address.1="));
        assert_eq!(inv(1, 5000)["fee_zat"], 0); // treasury invoice: no fee
        drop(db);
        let fee_div = |id: &serde_json::Value| -> u128 {
            let i: i64 = st
                .db
                .lk()
                .query_row(
                    "SELECT fee_div_index FROM invoices WHERE id=?1",
                    [id.as_str()],
                    |r| r.get(0),
                )
                .unwrap();
            D + i as u128
        };
        let owed = || crate::fees::owed(&st.db.lk(), 2).unwrap();
        // fee paid in the same tx (overpaid on a), merchant paid on a and b
        record(&st, 1, fee_div(&a["id"]), "t1", 1, 60_000, Some(5)).unwrap();
        assert_eq!(owed(), (0, 0, 0, 0)); // nothing charged until paid
        record(&st, 2, D, "t1", 0, 10_000_000, Some(5)).unwrap();
        record(&st, 2, D + 1, "t2", 0, 100_000, Some(5)).unwrap();
        record(&st, 1, fee_div(&b["id"]), "t3", 0, 400, None).unwrap(); // mempool only
        let paid: i64 = st
            .db
            .lk()
            .query_row(
                "SELECT COUNT(*) FROM invoices WHERE merchant_id=2 AND status='paid'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(paid, 2);
        assert_eq!(owed(), (51_000, 50_000, 0, 1000)); // a's extra 10k does not cover b
                                                       // a swap that carried the Lunaz fee in its app fee waives b's in-tx fee
        let swap = |q: &str| st.db.lk().execute(q, [b["id"].as_str()]).unwrap();
        swap("INSERT INTO swaps(id,invoice_id,origin_asset,symbol,blockchain,deposit_address,amount_in,amount_in_formatted,refund_to,deadline,status,created_at,updated_at,lunaz_fee_bps)
              VALUES('sw',?1,'x','X','x','d','1','1','r','',  'SUCCESS',0,0,50)");
        assert_eq!(owed(), (50_000, 50_000, 0, 0));
        swap("DELETE FROM swaps WHERE invoice_id=?1");
        // settlement: underpaid credits what was mined, a top-up raises it
        {
            let db = st.db.lk();
            db.execute("INSERT INTO invoices(id,merchant_id,div_index,address,amount_zat,status,created_at,expires_at) VALUES('s',1,99,'a',1000,'pending',0,?1)", [now() - 1]).unwrap();
            db.execute("INSERT INTO fee_settlements(id,merchant_id,invoice_id,amount_zat,status,created_at) VALUES('fs',2,'s',1000,'pending',0)", []).unwrap();
        }
        record(&st, 1, D + 99, "t4", 0, 600, Some(6)).unwrap();
        assert_eq!(owed(), (51_000, 50_000, 600, 400));
        record(&st, 1, D + 99, "t5", 0, 700, Some(7)).unwrap();
        assert_eq!(owed(), (51_000, 50_000, 1000, 0));
    }

    #[tokio::test]
    async fn mempool_only_expires() {
        let st = crate::tests::test_st();
        setup(&st, "", 100_000, now() - 7200);
        st.db
            .lk()
            .execute("UPDATE invoices SET status='detected'", [])
            .unwrap();
        st.db
            .lk()
            .execute("INSERT INTO payments(txid,action_idx,invoice_id,value_zat,seen_at) VALUES('t1',0,'inv',100000,?1)", [now()])
            .unwrap();
        sweep(&st);
        assert_eq!(status(&st), "expired");
    }

    fn uivk(net: &zcash_protocol::consensus::Network, seed: u8) -> String {
        zcash_keys::keys::UnifiedSpendingKey::from_seed(net, &[seed; 32], zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key()
            .to_unified_incoming_viewing_key()
            .encode(net)
    }

    #[test]
    fn live_keys() {
        let mut st = Arc::into_inner(crate::tests::test_st()).unwrap();
        st.fee.merchant = Some(1);
        let db = st.db.lk();
        for id in 1..=5 {
            let k = (id != 5).then(|| uivk(&st.net, id as u8));
            db.execute("INSERT INTO merchants(id,email,password_hash,name,ufvk,webhook_secret) VALUES(?1,?2,'','',?3,'s')", params![id, format!("{id}@b.co"), k]).unwrap();
        }
        let n = now();
        // 1 treasury without invoices, 2 old final, 3 pending, 4 expired an hour ago, 5 no key
        for (m, status, exp) in [
            (2, "paid", n - 3 * 86400),
            (3, "pending", n + 900),
            (4, "expired", n - 3600),
            (5, "pending", n + 900),
        ] {
            db.execute("INSERT INTO invoices(id,merchant_id,div_index,address,amount_zat,status,created_at,expires_at) VALUES(?1,?1,0,'a',1,?2,0,?3)", params![m, status, exp]).unwrap();
        }
        drop(db);
        let live = |st: &St| {
            keys(st)
                .unwrap()
                .iter()
                .map(|k| k.merchant)
                .collect::<Vec<_>>()
        };
        assert_eq!(live(&st), [1, 3, 4]);
        assert_eq!(live(&st), [1, 3, 4]); // from cache
        st.fee.merchant = None;
        assert_eq!(live(&st), [3, 4]);
    }

    // cargo test --release -- --ignored --nocapture trial_decrypt_bench
    #[test]
    #[ignore]
    fn trial_decrypt_bench() {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        use orchard::note::Nullifier;
        use orchard::note_encryption::testing::fake_compact_action;
        use orchard::value::NoteValue;
        use rand::RngCore;
        use std::time::Instant;
        let mut rng = rand::thread_rng();
        let mut fvk = || loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(b)) {
                break FullViewingKey::from(&sk);
            }
        };
        let keys: Vec<Arc<Key>> = (0..1000)
            .map(|m| {
                let ivk = fvk().to_ivk(Scope::External);
                let pivk = PreparedIncomingViewingKey::new(&ivk);
                Arc::new(Key {
                    merchant: m,
                    ivk,
                    pivk,
                })
            })
            .collect();
        let mut rng = rand::thread_rng();
        // half Orchard, half Ironwood domain (same cost for a non-matching key)
        let mut acts: Vec<(CompactAction, bool)> = (0..5000)
            .map(|i| {
                let nf = loop {
                    let mut b = [0u8; 32];
                    rng.fill_bytes(&mut b);
                    if let Some(nf) = Option::<Nullifier>::from(Nullifier::from_bytes(&b)) {
                        break nf;
                    }
                };
                let to = fvk().address_at(0u32, Scope::External);
                let a = fake_compact_action(&mut rng, nf, to, NoteValue::from_raw(1), None).0;
                (a, i % 2 == 1)
            })
            .collect();
        // one real payment to key 7 at diversifier 5
        let to = keys[7].ivk.address_at(5u32);
        let nf = acts[0].0.nullifier();
        let a = fake_compact_action(&mut rng, nf, to, NoteValue::from_raw(42), None).0;
        acts[4320] = (a, false);

        let (sa, sk) = (200, 1000);
        let t = Instant::now();
        std::hint::black_box(decrypt(&acts[..sa], &keys[..sk]));
        let single = t.elapsed().as_secs_f64() * 1e6 / (sa * sk) as f64;
        println!("1 thread: {single:.2} us/pair; 5000 actions x 1000 keys ~ {:.1} s, x 50 keys ~ {:.1} s", single * 5e3 * 1000.0 / 1e6, single * 5e3 * 50.0 / 1e6);
        let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
        for (name, n) in [("default", (cores / 2).max(1)), ("all cores", cores)] {
            // a 2-action mempool tx splits along keys
            let t = Instant::now();
            assert_eq!(trial(&acts[4319..4321], &keys, n), [(1, 7, 5, 42)]);
            let tx = t.elapsed().as_secs_f64() * 1e3;
            for nk in [1000, 50] {
                let t = Instant::now();
                assert_eq!(trial(&acts, &keys[..nk], n), [(4320, 7, 5, 42)]);
                let el = t.elapsed().as_secs_f64();
                println!(
                    "{name}, {n} threads: 5000 actions x {nk} keys = {el:.2} s, {:.2} us/pair",
                    el * 1e6 / (5000 * nk) as f64
                );
            }
            println!("{name}, {n} threads: mempool tx 2 actions x 1000 keys = {tx:.1} ms");
        }
    }
}
