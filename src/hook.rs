//! Webhook delivery: persisted events, a background loop sends them, every attempt logged in `webhook_deliveries`.
use crate::{now, Lk, St};
use hmac::{Hmac, Mac};
use reqwest::{dns, Url};
use rusqlite::{params, Connection};
use serde_json::json;
use sha2::Sha256;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

/// Webhook HTTP client and URL policy.
pub struct Cfg {
    http: reqwest::Client,
    /// Dev only: private/loopback targets, any port, plain http.
    pub allow_private: bool,
    pub allow_http: bool,
}

impl Cfg {
    pub fn new(allow_private: bool, allow_http: bool) -> reqwest::Result<Cfg> {
        let mut b = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .no_proxy();
        if !allow_private {
            b = b.dns_resolver(Arc::new(PublicOnly));
        }
        Ok(Cfg {
            http: b.build()?,
            allow_private,
            allow_http,
        })
    }
}

/// False for loopback, private, link-local, CGNAT, reserved, multicast and documentation ranges.
pub fn is_public(ip: IpAddr) -> bool {
    const V4: [(u32, u32); 13] = [
        (0x0000_0000, 8),  // 0/8
        (0x0a00_0000, 8),  // 10/8
        (0x6440_0000, 10), // 100.64/10
        (0x7f00_0000, 8),  // 127/8
        (0xa9fe_0000, 16), // 169.254/16
        (0xac10_0000, 12), // 172.16/12
        (0xc000_0000, 24), // 192.0.0/24
        (0xc000_0200, 24), // 192.0.2/24
        (0xc0a8_0000, 16), // 192.168/16
        (0xc612_0000, 15), // 198.18/15
        (0xc633_6400, 24), // 198.51.100/24
        (0xcb00_7100, 24), // 203.0.113/24
        (0xe000_0000, 3),  // 224/4 multicast, 240/4 reserved + broadcast
    ];
    match ip {
        IpAddr::V4(v) => {
            let n = u32::from(v);
            !V4.iter()
                .any(|&(net, len)| n >> (32 - len) == net >> (32 - len))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            let o = v.octets();
            if let Some(v4) = v.to_ipv4() {
                return is_public(v4.into()); // mapped, compatible, :: and ::1
            }
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return is_public(Ipv4Addr::new(o[12], o[13], o[14], o[15]).into());
            }
            !(s[0] & 0xfe00 == 0xfc00 // fc00::/7
                || s[0] & 0xffc0 == 0xfe80 // fe80::/10
                || s[0] & 0xffc0 == 0xfec0 // fec0::/10
                || s[0] & 0xff00 == 0xff00 // ff00::/8
                || (s[0], s[1]) == (0x2001, 0xdb8))
        }
    }
}

#[derive(Debug)]
struct Blocked;
impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(BLOCKED)
    }
}
impl std::error::Error for Blocked {}

/// Resolver that fails when any address of the host is not public (also covers DNS rebinding).
struct PublicOnly;
impl dns::Resolve for PublicOnly {
    fn resolve(&self, name: dns::Name) -> dns::Resolving {
        Box::pin(async move {
            let addrs: Vec<_> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            if addrs.iter().any(|a| !is_public(a.ip())) {
                return Err(Box::new(Blocked) as _);
            }
            Ok(Box::new(addrs.into_iter()) as dns::Addrs)
        })
    }
}

const BLOCKED: &str = "blocked address";
const PRIVATE_IP: &str = "webhook URL points to a private or reserved address";

/// Validates a webhook URL; the error is a message for the merchant.
pub fn check_url(s: &str, cfg: &Cfg) -> Result<Url, &'static str> {
    if s.len() > 2048 {
        return Err("webhook URL is longer than 2048 characters");
    }
    let u = Url::parse(s).map_err(|_| "webhook URL is not a valid URL")?;
    match u.scheme() {
        "https" => {}
        "http" if cfg.allow_http || cfg.allow_private => {}
        _ => return Err("webhook URL must use https"),
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("webhook URL must not contain credentials");
    }
    let host = u
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or("webhook URL needs a host")?;
    if cfg.allow_private {
        return Ok(u);
    }
    if u.port().is_some() {
        return Err("webhook URL must use the default port (443, or 80 for http)");
    }
    let ip = host.trim_matches(['[', ']']).parse::<IpAddr>();
    if ip.is_ok_and(|ip| !is_public(ip)) {
        return Err(PRIVATE_IP);
    }
    Ok(u)
}

/// Coarse delivery error: never exposes raw network errors to the merchant.
fn coarse(e: &reqwest::Error) -> &'static str {
    let mut c: Option<&dyn std::error::Error> = Some(e);
    while let Some(x) = c {
        if x.is::<Blocked>() {
            return BLOCKED;
        }
        c = x.source();
    }
    if e.is_timeout() {
        "timed out"
    } else if e.is_builder() {
        "invalid URL"
    } else {
        "connection failed"
    }
}

/// Signs `body` with HMAC-SHA256 and POSTs it once; returns the HTTP status (redirects are not followed).
pub async fn post(cfg: &Cfg, url: &str, secret: &str, body: String) -> Result<u16, &'static str> {
    let url = check_url(url, cfg).map_err(|m| {
        if m == PRIVATE_IP {
            BLOCKED
        } else {
            "invalid URL"
        }
    })?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| "invalid URL")?;
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    let r = cfg
        .http
        .post(url)
        .header("content-type", "application/json")
        .header("X-Lunaz-Signature", sig)
        .body(body)
        .send()
        .await
        .map_err(|e| coarse(&e))?;
    Ok(r.status().as_u16())
}

/// Delay in seconds before retry n; the first send is immediate, so attempts in total = len + 1.
const RETRY_DELAYS: [i64; 2] = [10, 60];
pub const MAX_ATTEMPTS: i64 = RETRY_DELAYS.len() as i64 + 1;
/// A claimed event is not picked again for this long (crash safety).
const LEASE: i64 = 30;
const DAY: i64 = 86400;

/// Outcome of an attempt: (status, delay before the next attempt).
fn decide(attempts: i64, ok: bool, retry: bool) -> (&'static str, Option<i64>) {
    let delay = RETRY_DELAYS.get(attempts as usize - 1).copied();
    match (ok, retry, delay) {
        (true, ..) => ("delivered", None),
        (false, true, Some(d)) => ("pending", Some(d)),
        _ => ("failed", None),
    }
}

/// Persists an event for the merchant's webhook (skipped when no URL is set) and wakes the sender.
pub fn enqueue(
    st: &Arc<St>,
    db: &Connection,
    mid: i64,
    invoice: Option<&str>,
    typ: &str,
    body: String,
) -> anyhow::Result<()> {
    let has_url: bool = db.query_row(
        "SELECT webhook_url IS NOT NULL FROM merchants WHERE id=?1",
        [mid],
        |r| r.get(0),
    )?;
    if has_url {
        insert(db, mid, invoice, typ, &body, Some(now()))?;
        tokio::spawn(tick(st.clone()));
    }
    Ok(())
}

fn insert(
    db: &Connection,
    mid: i64,
    invoice: Option<&str>,
    typ: &str,
    body: &str,
    next: Option<i64>,
) -> rusqlite::Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO webhook_events(id,merchant_id,invoice_id,type,body,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,'pending',0,?6,?7,?7)",
        params![id, mid, invoice, typ, body, next, now()],
    )?;
    Ok(id)
}

/// One attempt for event `id`; records the delivery and the new event state.
/// Outer error: database; inner: the HTTP status or a coarse delivery error.
async fn send(st: &St, id: &str, retry: bool) -> anyhow::Result<Result<u16, &'static str>> {
    let (mid, invoice, typ, body, attempts, url, secret): (i64, Option<String>, String, String, i64, Option<String>, String) =
        st.db.lk().query_row(
            "SELECT e.merchant_id, e.invoice_id, e.type, e.body, e.attempts, m.webhook_url, m.webhook_secret
             FROM webhook_events e JOIN merchants m ON m.id=e.merchant_id WHERE e.id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
        )?;
    let attempt = attempts + 1;
    let Some(url) = url else {
        let e = "no webhook URL configured";
        st.db.lk().execute(
            "UPDATE webhook_events SET status='failed', attempts=?1, next_attempt_at=NULL, last_status_code=NULL, last_error=?2, updated_at=?3 WHERE id=?4",
            params![attempt, e, now(), id],
        )?;
        return Ok(Err(e));
    };
    let r = post(&st.hook, &url, &secret, body).await;
    let ok = matches!(r, Ok(s) if (200..300).contains(&s));
    let err = match r {
        Err(e) => Some(e.to_string()),
        Ok(s) if !ok => Some(format!("HTTP {s}")),
        _ => None,
    };
    let (status, delay) = decide(attempt, ok, retry);
    let t = now();
    let db = st.db.lk();
    db.execute(
        "INSERT INTO webhook_deliveries(merchant_id,invoice_id,type,url,status_code,error,attempt,created_at,event_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![mid, invoice, typ, url, r.ok(), r.err(), attempt, t, id],
    )?;
    db.execute(
        "UPDATE webhook_events SET status=?1, attempts=?2, next_attempt_at=?3, last_status_code=?4, last_error=?5, updated_at=?6 WHERE id=?7",
        params![status, attempt, delay.map(|d| t + d), r.ok(), err, t, id],
    )?;
    Ok(r)
}

/// Sends one `test` event synchronously (no retries); the event keeps its final status.
pub async fn send_test(
    st: &St,
    mid: i64,
    body: String,
) -> anyhow::Result<Result<u16, &'static str>> {
    let id = insert(&st.db.lk(), mid, None, "test", &body, None)?;
    send(st, &id, false).await
}

/// Claims due pending events (lease) and sends each one.
pub async fn tick(st: Arc<St>) {
    let ids: Vec<String> = (|| -> rusqlite::Result<_> {
        let db = st.db.lk();
        let t = now();
        let mut q = db.prepare(
            "UPDATE webhook_events SET next_attempt_at=?1 WHERE id IN
             (SELECT id FROM webhook_events WHERE status='pending' AND next_attempt_at<=?2 ORDER BY next_attempt_at LIMIT 50) RETURNING id",
        )?;
        let v = q.query_map(params![t + LEASE, t], |r| r.get(0))?.collect();
        v
    })()
    .unwrap_or_default();
    for id in ids {
        match send(&st, &id, true).await {
            Err(e) => tracing::warn!("webhook event {id}: {e:#}"),
            Ok(Err(e)) => tracing::warn!("webhook event {id}: {e}"),
            Ok(Ok(_)) => {}
        }
    }
}

/// Background sender: survives restarts because all state is in the database.
pub async fn run(st: Arc<St>) {
    loop {
        tick(st.clone()).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Drops delivered events after 30 days and failed ones after 90 (with their attempt logs).
pub fn purge(db: &Connection) {
    let t = now();
    let _ = db.execute(
        "DELETE FROM webhook_deliveries WHERE event_id IN (SELECT id FROM webhook_events WHERE (status='delivered' AND updated_at<?1) OR (status='failed' AND updated_at<?2))",
        params![t - 30 * DAY, t - 90 * DAY],
    );
    let _ = db.execute(
        "DELETE FROM webhook_events WHERE (status='delivered' AND updated_at<?1) OR (status='failed' AND updated_at<?2)",
        params![t - 30 * DAY, t - 90 * DAY],
    );
}

/// Queues the invoice event `typ` for the merchant's webhook.
pub fn notify(st: &Arc<St>, db: &Connection, id: &str, typ: &str) -> anyhow::Result<()> {
    let (mid, status, amount, txid, received, pending): (i64, String, i64, Option<String>, i64, i64) = db
        .query_row(
            "SELECT i.merchant_id, i.status, i.amount_zat, i.txid,
            (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=i.id AND height IS NOT NULL),
            (SELECT COALESCE(SUM(value_zat),0) FROM payments WHERE invoice_id=i.id AND height IS NULL)
         FROM invoices i WHERE i.id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )?;
    let body = json!({"type": typ, "invoice_id": id, "status": status, "amount_zat": amount, "received_zat": received, "pending_zat": pending,
        "overpaid_zat": (received - amount).max(0), "txid": txid, "swap": crate::swap::webhook_json(db, id)}).to_string();
    enqueue(st, db, mid, Some(id), typ, body)
}

/// Requeues one failed event of the merchant; false if it is not failed (or not theirs).
pub fn retry(db: &Connection, mid: i64, id: &str) -> rusqlite::Result<bool> {
    Ok(db.execute(
        "UPDATE webhook_events SET status='pending', attempts=0, next_attempt_at=?1, updated_at=?1 WHERE id=?2 AND merchant_id=?3 AND status='failed'",
        params![now(), id, mid],
    )? > 0)
}

/// Requeues the merchant's failed events from the last 7 days (max 100).
pub fn retry_failed(db: &Connection, mid: i64) -> rusqlite::Result<usize> {
    db.execute(
        "UPDATE webhook_events SET status='pending', attempts=0, next_attempt_at=?1, updated_at=?1 WHERE id IN
         (SELECT id FROM webhook_events WHERE merchant_id=?2 AND status='failed' AND created_at>=?3 ORDER BY created_at DESC LIMIT 100)",
        params![now(), mid, now() - 7 * DAY],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{response::Redirect, routing::any, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn public_addresses() {
        let p = |s: &str| is_public(s.parse().unwrap());
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "2001:db8::1",
        ] {
            assert!(!p(ip), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "100.128.0.1",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(p(ip), "{ip}");
        }
    }

    #[test]
    fn url_rules() {
        let strict = Cfg::new(false, false).unwrap();
        let ok = |u: &str| check_url(u, &strict).is_ok();
        assert!(ok("https://example.com/hook") && ok("https://8.8.8.8/x"));
        for u in [
            "http://example.com/",
            "ftp://example.com/",
            "https://u:p@example.com/",
            "https://example.com:8443/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://169.254.169.254/",
            "https://10.0.0.1/",
            "https://0x7f.1/",
            "https://[::ffff:7f00:1]/",
            "not a url",
            "https://",
        ] {
            assert!(!ok(u), "{u}");
        }
        assert!(!ok(&format!("https://example.com/{}", "a".repeat(2048))));
        let http = Cfg::new(false, true).unwrap();
        assert!(check_url("http://example.com/", &http).is_ok());
        assert!(check_url("http://127.0.0.1/", &http).is_err());
        let dev = Cfg::new(true, false).unwrap();
        assert!(check_url("http://127.0.0.1:3000/x", &dev).is_ok());
        assert!(check_url("http://u@127.0.0.1:3000/x", &dev).is_err());
    }

    #[tokio::test]
    async fn strict_blocks_private_targets() {
        let strict = Cfg::new(false, false).unwrap();
        let b = |u: &'static str| post(&strict, u, "s", "{}".into());
        assert_eq!(b("https://localhost/").await, Err(BLOCKED)); // resolver
        assert_eq!(b("https://127.0.0.1/").await, Err(BLOCKED));
        assert_eq!(b("https://[::1]/").await, Err(BLOCKED));
        assert_eq!(b("http://example.com/").await, Err("invalid URL"));
    }

    async fn serve(app: Router) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{a}")
    }

    // Redirects are recorded, never followed; errors stay coarse.
    #[tokio::test]
    async fn no_redirect_and_coarse_errors() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let b = serve(Router::new().route(
            "/internal",
            any(move || {
                h.fetch_add(1, Ordering::SeqCst);
                async { "secret" }
            }),
        ))
        .await;
        let target = format!("{b}/internal");
        let a = serve(Router::new().route(
            "/",
            any(move || {
                let t = target.clone();
                async move { Redirect::to(&t) }
            }),
        ))
        .await;
        let st = crate::tests::test_st();
        st.db.lk().execute("INSERT INTO merchants(id,email,password_hash,name,webhook_url,webhook_secret) VALUES(1,'a','','',?1,'s')", [format!("{a}/")]).unwrap();
        assert_eq!(send_test(&st, 1, "{}".into()).await.unwrap(), Ok(303));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        st.db
            .lk()
            .execute("UPDATE merchants SET webhook_url='http://127.0.0.1:1/'", [])
            .unwrap();
        assert_eq!(
            send_test(&st, 1, "{}".into()).await.unwrap(),
            Err("connection failed")
        );
        let errs: Vec<Option<String>> = st
            .db
            .lk()
            .prepare("SELECT error FROM webhook_deliveries ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(errs, [None, Some("connection failed".into())]);
    }

    #[tokio::test]
    async fn slow_target_times_out() {
        let a = serve(Router::new().route(
            "/",
            any(|| async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                ""
            }),
        ))
        .await;
        let dev = Cfg::new(true, false).unwrap();
        assert_eq!(post(&dev, &a, "s", "{}".into()).await, Err("timed out"));
    }

    #[test]
    fn schedule() {
        assert_eq!(MAX_ATTEMPTS, 3);
        // three failures end failed, delays 10 s then 60 s
        assert_eq!(decide(1, false, true), ("pending", Some(10)));
        assert_eq!(decide(2, false, true), ("pending", Some(60)));
        assert_eq!(decide(3, false, true), ("failed", None));
        // success on attempt 2
        assert_eq!(decide(2, true, true), ("delivered", None));
        // test events never retry
        assert_eq!(decide(1, false, false), ("failed", None));
    }

    #[test]
    fn retry_resets() {
        let st = crate::tests::test_st();
        let db = st.db.lk();
        db.execute("INSERT INTO merchants(id,email,password_hash,name,webhook_secret) VALUES(1,'a','','','s')", []).unwrap();
        let id = insert(&db, 1, None, "test", "{}", None).unwrap();
        assert!(!retry(&db, 1, &id).unwrap()); // pending: not retryable
        db.execute("UPDATE webhook_events SET status='failed', attempts=3", [])
            .unwrap();
        assert!(!retry(&db, 2, &id).unwrap()); // other merchant
        assert_eq!(retry_failed(&db, 1).unwrap(), 1);
        let (s, a, n): (String, i64, Option<i64>) = db
            .query_row(
                "SELECT status, attempts, next_attempt_at FROM webhook_events",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((s.as_str(), a), ("pending", 0));
        assert!(n.is_some());
    }
}
