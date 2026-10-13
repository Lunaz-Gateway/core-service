mod account;
mod api;
mod billing;
mod export;
mod hook;
mod limit;
mod offramp;
mod swap;
mod watcher;

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use zcash_protocol::consensus::Network;

pub struct St {
    pub db: Mutex<Connection>,
    pub net: Network,
    pub lwd: String,
    pub events: broadcast::Sender<(String, String)>,
    pub http: reqwest::Client,
    pub jwt: Option<String>,
    pub assets: Mutex<Option<(i64, Vec<serde_json::Value>)>>,
    pub limits: limit::Limiter,
    pub zec_price: Mutex<Option<f64>>,
    pub off: offramp::Cfg,
    pub bill: billing::Cfg,
    pub internal: Option<String>,
    pub ws: Arc<tokio::sync::Semaphore>,
    pub ws_per: Mutex<std::collections::HashMap<String, usize>>,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn app(st: Arc<St>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/auth/signup", post(account::removed))
        .route("/v1/auth/login", post(account::removed))
        .route("/v1/auth/logout", post(account::logout))
        .route("/v1/auth/exchange", post(account::exchange))
        .route("/v1/account", get(account::account).put(account::set_name))
        .route("/v1/account/ufvk", put(account::set_ufvk))
        .route("/v1/account/viewing-key", put(account::set_ufvk))
        .route(
            "/v1/account/api-keys",
            get(account::list_keys).post(account::create_key),
        )
        .route("/v1/account/api-keys/{id}", delete(account::revoke_key))
        .route(
            "/v1/account/webhook",
            get(account::get_webhook).put(account::set_webhook),
        )
        .route("/v1/account/webhook/rotate", post(account::rotate_webhook))
        .route("/v1/account/webhook/test", post(account::test_webhook))
        .route("/v1/account/webhook/events", get(account::list_events))
        .route(
            "/v1/account/webhook/events/retry-failed",
            post(account::retry_failed),
        )
        .route(
            "/v1/account/webhook/events/{id}/retry",
            post(account::retry_event),
        )
        .route(
            "/v1/account/webhook/deliveries",
            get(account::list_deliveries),
        )
        .route("/v1/plans", get(billing::plans))
        .route("/v1/account/plan", get(billing::my_plan))
        .route("/v1/account/billing", get(billing::list))
        .route("/v1/account/billing/checkout", post(billing::checkout))
        .route(
            "/v1/account/billing/{id}/simulate-paid",
            post(billing::simulate_paid),
        )
        .route("/v1/account/invoices", get(account::list_invoices))
        .route("/v1/account/export.csv", get(export::export_csv))
        .route("/v1/account/offramp", get(offramp::info))
        .route("/v1/account/withdrawals/quote", post(offramp::quote_h))
        .route(
            "/v1/account/withdrawals",
            get(offramp::list).post(offramp::create),
        )
        .route("/v1/account/withdrawals/{id}", get(offramp::get_one))
        .route("/v1/account/withdrawals/{id}/kyc", post(offramp::kyc))
        .route(
            "/v1/account/withdrawals/{id}/simulate-deposit",
            post(offramp::simulate_deposit),
        )
        .route("/v1/account/withdrawals/{id}/cancel", post(offramp::cancel))
        .route("/v1/invoices", post(api::create_invoice))
        .route("/v1/invoices/{id}", get(api::get_invoice))
        .route("/v1/invoices/{id}/swap", post(swap::create_swap))
        .route("/v1/swap/assets", get(swap::list_assets))
        .route("/v1/invoices/{id}/ws", get(api::invoice_ws))
        .with_state(st)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS merchants(id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, name TEXT NOT NULL,
  ufvk TEXT UNIQUE, webhook_url TEXT, webhook_secret TEXT NOT NULL, next_index INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS api_keys(id INTEGER PRIMARY KEY, merchant_id INTEGER NOT NULL, name TEXT NOT NULL, prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, merchant_id INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS invoices(id TEXT PRIMARY KEY, merchant_id INTEGER NOT NULL, div_index INTEGER NOT NULL,
  address TEXT NOT NULL, amount_zat INTEGER NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, paid_at INTEGER, txid TEXT, UNIQUE(merchant_id, div_index));
CREATE TABLE IF NOT EXISTS payments(txid TEXT NOT NULL, action_idx INTEGER NOT NULL, invoice_id TEXT NOT NULL,
  value_zat INTEGER NOT NULL, height INTEGER, PRIMARY KEY(txid, action_idx));
CREATE TABLE IF NOT EXISTS sync_state(id INTEGER PRIMARY KEY CHECK(id=1), height INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS swaps(id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL, origin_asset TEXT NOT NULL, symbol TEXT NOT NULL, blockchain TEXT NOT NULL,
  deposit_address TEXT NOT NULL, deposit_memo TEXT, amount_in TEXT NOT NULL, amount_in_formatted TEXT NOT NULL, amount_in_usd TEXT, refund_to TEXT NOT NULL,
  deadline TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING_DEPOSIT', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS swaps_invoice ON swaps(invoice_id);
CREATE TABLE IF NOT EXISTS webhook_deliveries(id INTEGER PRIMARY KEY, merchant_id INTEGER NOT NULL, invoice_id TEXT, type TEXT NOT NULL, url TEXT NOT NULL,
  status_code INTEGER, error TEXT, attempt INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS webhook_deliveries_merchant ON webhook_deliveries(merchant_id, id);
CREATE TABLE IF NOT EXISTS webhook_events(id TEXT PRIMARY KEY, merchant_id INTEGER NOT NULL, invoice_id TEXT, type TEXT NOT NULL, body TEXT NOT NULL,
  status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER, last_status_code INTEGER, last_error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS webhook_events_merchant ON webhook_events(merchant_id, created_at);
CREATE INDEX IF NOT EXISTS webhook_events_due ON webhook_events(status, next_attempt_at);
CREATE TABLE IF NOT EXISTS withdrawals(id TEXT PRIMARY KEY, merchant_id INTEGER NOT NULL, provider TEXT NOT NULL, status TEXT NOT NULL, amount_zat INTEGER NOT NULL,
  fiat_currency TEXT NOT NULL, fiat_amount TEXT NOT NULL, rate_zec_fiat TEXT NOT NULL, fee_fiat TEXT NOT NULL, network_fee_zat INTEGER NOT NULL,
  deposit_address TEXT NOT NULL, deposit_uri TEXT NOT NULL, bank_label TEXT, provider_ref TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS withdrawals_merchant ON withdrawals(merchant_id, created_at);
CREATE TABLE IF NOT EXISTS withdrawal_events(id INTEGER PRIMARY KEY, withdrawal_id TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS withdrawal_events_w ON withdrawal_events(withdrawal_id, id);
CREATE TABLE IF NOT EXISTS subscriptions(id TEXT PRIMARY KEY, merchant_id INTEGER NOT NULL, plan TEXT NOT NULL, months INTEGER NOT NULL, price_usd REAL NOT NULL,
  amount_zat INTEGER NOT NULL, zec_usd REAL NOT NULL, invoice_id TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL, paid_at INTEGER, period_start INTEGER, period_end INTEGER);
CREATE INDEX IF NOT EXISTS subscriptions_invoice ON subscriptions(invoice_id);
CREATE INDEX IF NOT EXISTS subscriptions_merchant ON subscriptions(merchant_id, created_at);";

/// Idempotent column additions for databases created by older versions.
fn migrate(db: &Connection, net: &Network) -> rusqlite::Result<()> {
    for (table, col, ddl) in [
        ("invoices", "paid_usd_rate", "REAL"),
        ("merchants", "plan", "TEXT NOT NULL DEFAULT 'free'"),
        ("merchants", "plan_expires_at", "INTEGER"),
        ("webhook_deliveries", "event_id", "TEXT"),
        ("payments", "seen_at", "INTEGER"),
    ] {
        let has: bool = db.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info(?1) WHERE name=?2",
            [table, col],
            |r| r.get(0),
        )?;
        if !has {
            db.execute(&format!("ALTER TABLE {table} ADD COLUMN {col} {ddl}"), [])?;
        }
    }
    // merchants.ufvk now holds the UIVK; reduce any stored UFVK in place.
    let rows: Vec<(i64, String)> = db
        .prepare("SELECT id, ufvk FROM merchants WHERE ufvk LIKE 'uview%'")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut n = 0;
    for (id, k) in rows {
        match api::parse_viewing_key(net, &k) {
            Ok(u) => {
                db.execute(
                    "UPDATE merchants SET ufvk=?1 WHERE id=?2",
                    rusqlite::params![u.encode(net), id],
                )?;
                n += 1;
            }
            Err(e) => tracing::warn!("merchant {id}: viewing key not converted: {e}"),
        }
    }
    if n > 0 {
        tracing::info!("converted {n} stored UFVK(s) to UIVK");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    if std::env::args().nth(1).as_deref() != Some("healthcheck") {
        tracing::info!("starting lunaz-core {}", env!("CARGO_PKG_VERSION"));
    }
    let env = |k: &str| std::env::var(k).ok();
    // Hidden subcommand for container HEALTHCHECK (distroless has no curl).
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        let port = env("LUNAZ_BIND").unwrap_or("0.0.0.0:8080".into());
        let port = port.rsplit(':').next().unwrap_or("8080").to_string();
        let ok = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/healthz"))
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        std::process::exit(if ok { 0 } else { 1 });
    }
    let (net, default_lwd) = match env("LUNAZ_NETWORK").as_deref().unwrap_or("test") {
        "main" => (Network::MainNetwork, "https://zec.rocks:443"),
        "test" => (Network::TestNetwork, "https://testnet.zec.rocks:443"),
        v => anyhow::bail!("LUNAZ_NETWORK must be test or main, got {v}"),
    };
    let internal = env("LUNAZ_INTERNAL_TOKEN").filter(|t| !t.is_empty());
    if internal.as_ref().is_some_and(|t| t.len() < 32) {
        anyhow::bail!("LUNAZ_INTERNAL_TOKEN must be at least 32 characters");
    }
    let db = Connection::open(env("LUNAZ_DB").unwrap_or("lunaz.db".into()))?;
    db.execute_batch(SCHEMA)?;
    migrate(&db, &net)?;
    let st = Arc::new(St {
        db: Mutex::new(db),
        net,
        lwd: env("LUNAZ_LWD_URL").unwrap_or(default_lwd.into()),
        events: broadcast::channel(256).0,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?,
        jwt: env("LUNAZ_ONECLICK_JWT").filter(|j| !j.is_empty()),
        assets: Mutex::new(None),
        limits: Default::default(),
        zec_price: Mutex::new(None),
        off: offramp::Cfg::from_env(env)?,
        bill: billing::Cfg::from_env(env)?,
        internal,
        ws: Arc::new(tokio::sync::Semaphore::new(
            env("LUNAZ_MAX_WS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(2000),
        )),
        ws_per: Default::default(),
    });

    tokio::spawn(watcher::scanner(st.clone()));
    tokio::spawn(watcher::mempool(st.clone()));
    tokio::spawn(swap::poller(st.clone()));
    tokio::spawn(hook::run(st.clone()));

    let app = app(st);
    let bind = env("LUNAZ_BIND").unwrap_or("0.0.0.0:8080".into());
    tracing::info!("listening on {bind}");
    axum::serve(
        tokio::net::TcpListener::bind(bind).await?,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}

/// Resolves on ctrl-c or SIGTERM (docker stop).
async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("sigterm handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::{json, Value};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;

    pub fn test_st() -> Arc<St> {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        migrate(&db, &Network::TestNetwork).unwrap();
        Arc::new(St {
            db: Mutex::new(db),
            net: Network::TestNetwork,
            lwd: String::new(),
            events: broadcast::channel(16).0,
            http: reqwest::Client::new(),
            jwt: None,
            assets: Mutex::new(None),
            limits: Default::default(),
            zec_price: Mutex::new(None),
            off: Default::default(),
            bill: Default::default(),
            internal: Some("t".repeat(32)),
            ws: Arc::new(tokio::sync::Semaphore::new(2000)),
            ws_per: Default::default(),
        })
    }

    #[tokio::test]
    async fn revoked_key_blocks_invoices() {
        let (net, st) = (Network::TestNetwork, test_st());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(
                l,
                app(st).into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap()
        });
        let c = reqwest::Client::new();
        let call = |m: reqwest::Method, p: &str, tok: &str, b: Value| {
            let r = c.request(m, format!("{base}{p}")).bearer_auth(tok).json(&b);
            async move {
                let r = r.send().await.unwrap();
                (
                    r.status().as_u16(),
                    r.json::<Value>().await.unwrap_or_default(),
                )
            }
        };
        let post = reqwest::Method::POST;
        let it = "t".repeat(32);
        let ex = json!({"email": " A@b.co "});
        assert_eq!(
            call(post.clone(), "/v1/auth/exchange", "x", ex.clone())
                .await
                .0,
            401
        );
        let (s, v) = call(post.clone(), "/v1/auth/exchange", &it, ex.clone()).await;
        assert!(s == 200 && v["new_account"] == true);
        let tok = v["token"].as_str().unwrap().to_string();
        let (_, v2) = call(post.clone(), "/v1/auth/exchange", &it, ex).await;
        assert!(v2["new_account"] == false && v2["merchant_id"] == v["merchant_id"]);
        assert_eq!(
            call(post.clone(), "/v1/auth/login", "", json!({})).await.0,
            410
        );
        let inv = json!({"amount_zat": 1000});
        let (s, v) = call(
            post.clone(),
            "/v1/account/api-keys",
            &tok,
            json!({"name": "k"}),
        )
        .await;
        assert_eq!(s, 201);
        let (id, key) = (
            v["id"].as_i64().unwrap(),
            v["key"].as_str().unwrap().to_string(),
        );
        assert_eq!(
            call(post.clone(), "/v1/invoices", &key, inv.clone())
                .await
                .0,
            400
        ); // no ufvk yet
        let ufvk = UnifiedSpendingKey::from_seed(&net, &[7u8; 32], AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key()
            .encode(&net);
        assert_eq!(
            call(
                reqwest::Method::PUT,
                "/v1/account/ufvk",
                &tok,
                json!({"ufvk": ufvk})
            )
            .await
            .0,
            204
        );
        // Same wallet as a UIVK on another account is a duplicate.
        let uivk = UnifiedSpendingKey::from_seed(&net, &[7u8; 32], AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key()
            .to_unified_incoming_viewing_key()
            .encode(&net);
        let (_, v3) = call(
            post.clone(),
            "/v1/auth/exchange",
            &it,
            json!({"email": "c@d.co"}),
        )
        .await;
        let tok2 = v3["token"].as_str().unwrap().to_string();
        assert_eq!(
            call(
                reqwest::Method::PUT,
                "/v1/account/viewing-key",
                &tok2,
                json!({"viewing_key": uivk})
            )
            .await
            .0,
            409
        );
        assert_eq!(
            call(post.clone(), "/v1/invoices", &key, inv.clone())
                .await
                .0,
            200
        );
        assert_eq!(
            call(
                reqwest::Method::DELETE,
                &format!("/v1/account/api-keys/{id}"),
                &tok,
                json!({})
            )
            .await
            .0,
            204
        );
        assert_eq!(call(post, "/v1/invoices", &key, inv).await.0, 401);
    }

    #[test]
    fn migrate_converts_ufvk_once() {
        let net = Network::TestNetwork;
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        let fvk = UnifiedSpendingKey::from_seed(&net, &[1u8; 32], AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        db.execute(
            "INSERT INTO merchants(email,password_hash,name,ufvk,webhook_secret) VALUES('a','','',?1,'')",
            [fvk.encode(&net)],
        )
        .unwrap();
        for _ in 0..2 {
            migrate(&db, &net).unwrap();
            let k: String = db
                .query_row("SELECT ufvk FROM merchants", [], |r| r.get(0))
                .unwrap();
            assert_eq!(k, fvk.to_unified_incoming_viewing_key().encode(&net));
        }
    }
}
