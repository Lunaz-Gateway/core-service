mod account;
mod api;
mod hook;
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
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn app(st: Arc<St>) -> Router {
    Router::new()
        .route("/v1/auth/signup", post(account::signup))
        .route("/v1/auth/login", post(account::login))
        .route("/v1/auth/logout", post(account::logout))
        .route("/v1/account", get(account::account))
        .route("/v1/account/ufvk", put(account::set_ufvk))
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
        .route(
            "/v1/account/webhook/deliveries",
            get(account::list_deliveries),
        )
        .route("/v1/account/invoices", get(account::list_invoices))
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
CREATE INDEX IF NOT EXISTS webhook_deliveries_merchant ON webhook_deliveries(merchant_id, id);";

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
        events: broadcast::channel(256).0,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?,
        jwt: env("LUNAZ_ONECLICK_JWT").filter(|j| !j.is_empty()),
        assets: Mutex::new(None),
    });

    tokio::spawn(watcher::scanner(st.clone()));
    tokio::spawn(watcher::mempool(st.clone()));
    tokio::spawn(swap::poller(st.clone()));

    let app = app(st);
    let bind = env("LUNAZ_BIND").unwrap_or("0.0.0.0:8080".into());
    tracing::info!("listening on {bind}");
    axum::serve(tokio::net::TcpListener::bind(bind).await?, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;

    #[test]
    fn password_roundtrip() {
        let h = account::hash_pw("hunter2hunter2").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(account::check_pw("hunter2hunter2", &h) && !account::check_pw("wrong", &h));
    }

    #[tokio::test]
    async fn revoked_key_blocks_invoices() {
        let net = Network::TestNetwork;
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        let st = Arc::new(St {
            db: Mutex::new(db),
            net,
            lwd: String::new(),
            events: broadcast::channel(4).0,
            http: reqwest::Client::new(),
            jwt: None,
            assets: Mutex::new(None),
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
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
        let (s, v) = call(
            post.clone(),
            "/v1/auth/signup",
            "",
            json!({"email": "A@b.co", "name": "n", "password": "password1"}),
        )
        .await;
        assert_eq!(s, 201);
        let tok = v["token"].as_str().unwrap().to_string();
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
}
