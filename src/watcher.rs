use crate::{now, St};
use anyhow::Result;
use orchard::{
    keys::{IncomingViewingKey, PreparedIncomingViewingKey, Scope},
    note_encryption::{CompactAction, IronwoodDomain, OrchardDomain},
};
use rusqlite::{params, OptionalExtension};
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

fn expire(st: &St) {
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
    let Some((id, amount, old)) = db
        .query_row(
            "SELECT id, amount_zat, status FROM invoices WHERE merchant_id=?1 AND div_index=?2",
            params![merchant, div],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
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
    let (received, mined): (i64, i64) = db.query_row(
        "SELECT COALESCE(SUM(value_zat),0), COALESCE(SUM(CASE WHEN height IS NOT NULL THEN value_zat END),0) FROM payments WHERE invoice_id=?1",
        [&id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let new = match old.as_str() {
        "paid" => return Ok(()),
        _ if mined >= amount => "paid",
        "pending" => "detected",
        _ => return Ok(()),
    };
    db.execute(
        "UPDATE invoices SET status=?1, txid=?2, paid_at=CASE WHEN ?1='paid' THEN ?3 END WHERE id=?4",
        params![new, txid, now(), id],
    )?;
    tracing::info!("invoice {id} -> {new} ({received}/{amount} zat)");
    let _ = st.events.send((id.clone(), new.into()));
    if let Some(t) = hook_type(new) {
        crate::hook::notify(st, &db, &id, t)?;
    }
    Ok(())
}

fn hook_type(status: &str) -> Option<&'static str> {
    match status {
        "paid" => Some("invoice.paid"),
        _ => None,
    }
}
