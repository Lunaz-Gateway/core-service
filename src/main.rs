mod api;
mod watcher;

use axum::{routing::{get, post}, Router};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use zcash_protocol::consensus::Network;

pub struct St {
    pub db: Mutex<Connection>,
    pub net: Network,
    pub lwd: String,
    pub admin: String,
    pub events: broadcast::Sender<(String, String)>,
    pub http: reqwest::Client,
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS merchants(id INTEGER PRIMARY KEY, name TEXT NOT NULL, ufvk TEXT NOT NULL,
  api_key_hash TEXT NOT NULL UNIQUE, webhook_url TEXT, webhook_secret TEXT NOT NULL, next_index INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS invoices(id TEXT PRIMARY KEY, merchant_id INTEGER NOT NULL, div_index INTEGER NOT NULL,
  address TEXT NOT NULL, amount_zat INTEGER NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, paid_at INTEGER, txid TEXT, UNIQUE(merchant_id, div_index));
CREATE TABLE IF NOT EXISTS payments(txid TEXT NOT NULL, action_idx INTEGER NOT NULL, invoice_id TEXT NOT NULL,
  value_zat INTEGER NOT NULL, height INTEGER, PRIMARY KEY(txid, action_idx));
CREATE TABLE IF NOT EXISTS sync_state(id INTEGER PRIMARY KEY CHECK(id=1), height INTEGER NOT NULL);";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let env = |k: &str| std::env::var(k).ok();
    let (net, default_lwd) = match env("LUNAZ_NETWORK").as_deref().unwrap_or("test") {
        "main" => (Network::MainNetwork, "https://zec.rocks:443"),
        "test" => (Network::TestNetwork, "https://testnet.zec.rocks:443"),
        v => anyhow::bail!("LUNAZ_NETWORK must be test or main, got {v}"),
    };
    let db = Connection::open(env("LUNAZ_DB").unwrap_or("lunaz.db".into()))?;
    db.execute_batch(SCHEMA)?;
    let st = Arc::new(St {
        db: Mutex::new(db),
        net,
        lwd: env("LUNAZ_LWD_URL").unwrap_or(default_lwd.into()),
        admin: env("LUNAZ_ADMIN_TOKEN").ok_or_else(|| anyhow::anyhow!("LUNAZ_ADMIN_TOKEN is required"))?,
        events: broadcast::channel(256).0,
        http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build()?,
    });

    tokio::spawn(watcher::scanner(st.clone()));
    tokio::spawn(watcher::mempool(st.clone()));

    let app = Router::new()
        .route("/v1/merchants", post(api::create_merchant))
        .route("/v1/invoices", post(api::create_invoice))
        .route("/v1/invoices/{id}", get(api::get_invoice))
        .route("/v1/invoices/{id}/ws", get(api::invoice_ws))
        .with_state(st);
    let bind = env("LUNAZ_BIND").unwrap_or("0.0.0.0:8080".into());
    tracing::info!("listening on {bind}");
    axum::serve(tokio::net::TcpListener::bind(bind).await?, app).await?;
    Ok(())
}
