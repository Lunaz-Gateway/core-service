# Lunaz core-service

Non-custodial shielded Zcash payment gateway. Merchants sign up, register a Unified Incoming Viewing Key (UIVK) once, and create API keys. Each invoice gets its own shielded address, and the service detects payments by trial decryption. It holds incoming viewing keys only and cannot spend funds. A UFVK is also accepted, but it is reduced to its incoming key on save, so the server never stores the outgoing viewing key.

## Architecture

- **Invoice addresses.** Each invoice address is derived from the merchant's UIVK at a fresh diversifier index, starting at an offset of 2^80 so it never collides with addresses the merchant uses elsewhere.
- **Watcher.** A scanner reads compact blocks from lightwalletd (gRPC over TLS) and trial-decrypts Orchard and Ironwood actions with every merchant's viewing key. A second task does the same for the mempool, so payments show as `detected` before they are mined.
- **Cross-chain.** A buyer can pay in another asset through NEAR Intents 1Click. The buyer sends funds on their own chain and 1Click delivers ZEC to the invoice address. The watcher sees the ZEC as usual. Swap status is polled every 10 s.
- **Webhooks.** Signed POSTs on invoice, swap and withdrawal events. Every event is stored, retried up to 3 times and keeps a final status; failed ones can be retried by hand.
- **Storage.** One SQLite file (bundled rusqlite) in WAL mode with a 5 s busy timeout, so the CSV export reads on its own read-only connection while the service keeps writing. Tables and indexes (payments by invoice, invoices by merchant and created_at, invoices by status, API keys by merchant, webhook deliveries by event) are created on start; older databases are migrated in place.

## Privacy and security model

- Lunaz needs only an incoming viewing key. The server can see incoming payments to invoice addresses (amounts, txids); it cannot see outgoing payments, spends or the wallet balance.
- Nothing on chain links invoices to each other or to the merchant. Only the logged-in merchant sees the ledger and CSV export.
- Cross-chain payments: the origin-chain leg is public. Only the final shielded leg is private.
- Passwords are hashed with Argon2id. Session tokens and API keys are stored as hashes. API keys (`lz_...`) can create invoices only. The viewing key can be set once.
- The invoice id is the capability for the public endpoints (`GET /v1/invoices/{id}`, WebSocket, swap).
- Webhooks are sent only to public addresses over https, without following redirects, and report coarse errors only (see Webhooks), so they cannot be used to probe the internal network.
- Received amounts count mined payments only; unconfirmed ones are reported separately as `pending_zat`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `LUNAZ_NETWORK` | `test` (Docker image: `main`) | `test` or `main`; anything else aborts startup. The default stays `test` so a bare `cargo run` never touches real funds; production sets `main` explicitly |
| `LUNAZ_LWD_URL` | `https://zec.rocks:443` (main), `https://testnet.zec.rocks:443` (test) | lightwalletd endpoint |
| `LUNAZ_DB` | `lunaz.db` (Docker image: `/data/lunaz.db`) | SQLite path |
| `LUNAZ_BIND` | `127.0.0.1:8080` (Docker image: `0.0.0.0:8080`) | listen address |
| `LUNAZ_ONECLICK_JWT` | unset | 1Click token; without it 1Click adds a 0.25% fee |
| `LUNAZ_APP_FEE_RECIPIENT` | unset | NEAR account that receives the cross-chain app fee (1Click `appFees`); set together with `LUNAZ_APP_FEE_BPS` |
| `LUNAZ_APP_FEE_BPS` | unset | app fee in basis points, 0-1000 (50 = 0.5%); the buyer pays it on top of the swap, the invoice still receives its full amount. When the Lunaz fee is active, `LUNAZ_FEE_BPS` is added to it and that invoice's in-payment fee is waived (production: 25, giving 0.75% in total) |
| `LUNAZ_OFFRAMP` | `mock` | off-ramp provider: `mock` or `transfi` (not implemented yet: off-ramp requests return 501) |
| `LUNAZ_MOCK_FX` | `{"IDR":16400,"USD":1}` | mock only: USD -> fiat rates (indicative), also defines the supported currencies |
| `LUNAZ_MOCK_ZEC_USD` | unset | mock off-ramp only (ignored otherwise): fixed ZEC/USD price instead of the 1Click price |
| `LUNAZ_FEE_BPS` | `50` | Lunaz per-payment fee in basis points, 0-1000 (50 = 0.5%); other values abort startup. Active only with `LUNAZ_BILLING_MERCHANT_ID` set (see Fees) |
| `LUNAZ_FEE_MIN_ZAT` | `1000` | minimum fee per invoice in zatoshi |
| `LUNAZ_INTERNAL_TOKEN` | unset | secret (>=32 chars) for `/v1/auth/exchange`; unset = endpoint returns 503; shorter aborts startup |
| `LUNAZ_BILLING_MERCHANT_ID` | unset | id of the treasury merchant that receives fees and fee settlements; the fee is charged only when it is set and that merchant has a viewing key. Unset = no fee, settle returns 503 |
| `LUNAZ_BILLING_SANDBOX` | unset | `1` enables `simulate-paid` (demos/tests) |
| `LUNAZ_DEV` | unset | `1` marks a local development instance: allows the dev options below on mainnet and logs a WARN listing them |
| `LUNAZ_ALLOW_MOCK_ON_MAINNET` | unset | `1` allows the mock off-ramp on mainnet without `LUNAZ_DEV` |
| `LUNAZ_WEBHOOK_ALLOW_HTTP` | unset | `1` also accepts plain `http://` webhook URLs (still public hosts, default port) |
| `LUNAZ_WEBHOOK_ALLOW_PRIVATE` | unset | development only: `1` allows webhooks to private/loopback addresses, any port, `http` |
| `LUNAZ_MAX_WS` | `2000` | maximum concurrent invoice WebSockets |
| `RUST_LOG` | tracing default | log filter |

Mainnet guards: with `LUNAZ_NETWORK=main` the service refuses to start when `LUNAZ_BILLING_SANDBOX` is on, when the off-ramp is `mock` (the default) without `LUNAZ_ALLOW_MOCK_ON_MAINNET=1`, or when `LUNAZ_WEBHOOK_ALLOW_PRIVATE` is on, unless `LUNAZ_DEV=1` is set. Boolean variables accept `1`, `true`, `yes` or `on`.

## Run locally

    cargo run                      # testnet, ./lunaz.db
    LUNAZ_NETWORK=main cargo run
    cargo test

`GET /healthz` returns `200 ok` with no DB or network access. `lunaz-core healthcheck` (hidden subcommand) calls it on `127.0.0.1` at the port of `LUNAZ_BIND` with a 2 s timeout and exits 0 or 1.

## Run with Docker (hardened)

The image is multi-stage: Rust build, then `gcr.io/distroless/cc-debian12:nonroot` (no shell, no package manager) containing only the binary. It runs as uid 65532, stores data in the `/data` volume, and handles SIGTERM with a graceful shutdown.

    docker build -t lunaz-core .
    docker run -d --name lunaz-core --read-only --tmpfs /tmp --cap-drop ALL \
      --security-opt no-new-privileges:true --pids-limit 256 --memory 512m \
      -p 127.0.0.1:8080:8080 -v lunaz-data:/data -e LUNAZ_NETWORK=main -e LUNAZ_OFFRAMP=transfi \
      --restart unless-stopped lunaz-core

Compose:

    services:
      lunaz-core:
        image: lunaz-core
        build: .
        read_only: true
        tmpfs: [/tmp]
        cap_drop: [ALL]
        security_opt: ["no-new-privileges:true"]
        pids_limit: 256
        mem_limit: 512m
        ports: ["127.0.0.1:8080:8080"]
        volumes: ["lunaz-data:/data"]
        environment:
          LUNAZ_NETWORK: main
          LUNAZ_OFFRAMP: transfi
        restart: unless-stopped
        healthcheck:
          test: ["CMD", "/lunaz-core", "healthcheck"]
          interval: 30s
          timeout: 3s
          retries: 3
          start_period: 10s
    volumes:
      lunaz-data:

Put it behind a TLS reverse proxy (Caddy or nginx). Proxy `/v1/invoices/{id}/ws` as a WebSocket (nginx needs the `Upgrade` and `Connection` headers). Block `/v1/auth/exchange` from the public internet.

If the service sits under a path prefix (for example `https://example.com/api`), the proxy must strip the prefix: routes start at `/v1` and `/healthz` (Dokploy/Traefik: enable Strip Path). Clients then use the prefixed base URL without `/v1`.

Common errors:
- `POST /v1/auth/exchange` -> 503 `internal auth not configured`: `LUNAZ_INTERNAL_TOKEN` is not set on this service.
- `POST /v1/auth/exchange` -> 401: the token differs from the one the dashboard sends.
- 404 on every path through the domain: the path prefix is not stripped.
- The container health turns `healthy` after the first check (30 s interval), even though the server is up within a second.

## API

JSON; errors are `{"error": ...}`. Session token: `Authorization: Bearer <token>`, valid 7 days. The merchant API uses an API key as the Bearer token.

### Limits and headers

- Request bodies: at most 64 KiB, larger -> 413.
- HTTP requests time out after 15 s -> 503 `request timed out`. The invoice WebSocket has no request timeout (see its own limits).
- Rate limits (429 with the usual JSON error): `POST /v1/invoices` 60 per minute per API key, CSV export 5 per minute per merchant, `POST /v1/account/withdrawals` 10 per hour per merchant, plus the per-endpoint limits listed below.
- Input sizes: account name and API key name 1-80 characters, viewing key at most 2048 characters, webhook URL at most 2048, email at most 254, swap `refund_to` 1-128. List `limit` parameters are clamped to 1..200 (default 50).
- Every response has `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`. Everything except `GET`/`HEAD` on `/healthz`, `/v1/pricing` and `/v1/swap/assets` also has `Cache-Control: no-store`.

### Auth

Sign-in is delegated to an identity provider (Magic, magic.link; email only). The browser logs in with an email OTP and gets a DID token; the landing server verifies it with `@magic-sdk/admin` and calls the exchange endpoint. core-service never sees provider tokens.

- `POST /v1/auth/exchange` `{email}` with `Authorization: Bearer <LUNAZ_INTERNAL_TOKEN>` -> `{token, new_account, merchant_id}`. The email is trimmed and lowercased; the merchant is found or created (empty name). 401 on a wrong internal token, 503 `internal auth not configured` if the env is unset, 429 after 20 per email per 15 min.
- `POST /v1/auth/signup` and `POST /v1/auth/login` -> 410 (password sign-in was removed). Existing accounts sign in by email.
- `POST /v1/auth/logout` -> 204

**Security:** the exchange endpoint mints a session for any email, so it must only be reachable from the landing server: keep core-service internal or block `/v1/auth/exchange` at the proxy. `LUNAZ_INTERNAL_TOKEN` is a secret (min 32 chars).

### Account (session auth)

- `GET /v1/account` -> `{id, email, name, network, viewing_key_set, ufvk_set, webhook_url}` (`name` may be empty)
- `PUT /v1/account` `{name}` (1-80 chars) -> 204
- `PUT /v1/account/viewing-key` `{viewing_key}` -> 204; set once (at most 2048 chars), 409 if already set or used by another account (`viewing key is already used by another account`). Duplicates are detected by wallet, not by string: `merchants.orchard_ivk_hash` (SHA-256 of the Orchard incoming viewing key bytes) is UNIQUE, so the same wallet re-encoded (e.g. an Orchard-only UIVK) is refused too. Accepts a UIVK (`uivk...`) or a UFVK (`uview...`); a UFVK is reduced to its UIVK and only the UIVK is stored. `PUT /v1/account/ufvk` is the legacy alias and also accepts `{ufvk}`.
- `GET /v1/account/api-keys`; `POST` `{name}` (1-80 chars) -> 201 `{id, name, prefix, key}` (key shown once); `DELETE /v1/account/api-keys/{id}` -> 204 (revoke)
- `GET /v1/account/invoices?limit=50` (max 200) -> `[{id, status, amount_zat, fee_zat, received_zat, pending_zat, overpaid_zat, address, txid, created_at, expires_at, paid_at}]`

### Invoices

- `POST /v1/invoices` (API key; 400 until a viewing key is set) `{amount_zat, expires_in_secs?=900}`. `expires_in_secs` is clamped to 60..86400, `amount_zat` must be 1..21e14. -> `{id, address, amount_zat, fee_zat, zip321_uri, status, expires_at}`; `fee_zat` is the Lunaz fee carried as a second payment in `zip321_uri` (see Fees)
- `GET /v1/invoices/{id}` (public) -> `{status, amount_zat, fee_zat, received_zat, pending_zat, overpaid_zat, txid, expires_at, swap}`; `swap` is null or `{status, symbol, blockchain, deposit_address, amount_in_formatted, deadline}`
- `GET /v1/invoices/{id}/ws` WebSocket: `{"status":...}` now and on each change, plus `"swap_status"` (1Click status) when a swap exists. Closes on paid, underpaid or expired, and after 1 h at most. The server sends a Ping every 30 s and drops the socket when the client goes away. Limits: 5 sockets per invoice and `LUNAZ_MAX_WS` (default 2000) in total; over a limit the upgrade is refused with 429.

Statuses: `pending` -> `detected` (seen in mempool or mined) -> `paid` (mined sum >= amount) | `underpaid` | `expired`.

- Payments to one address add up, so a buyer can top up a `detected` invoice before it expires.
- `received_zat` counts mined payments only; `pending_zat` is the sum still in the mempool (unconfirmed, may never be mined). `overpaid_zat` = max(received - amount, 0). The merchant refunds any excess manually.
- Unmined payment rows are removed when the invoice reaches a final status, and after 1 h without being mined (the tx was probably dropped).
- `underpaid` (final): a mined payment exists, the sum is below the amount, and the invoice expired. Lunaz cannot refund; the merchant does. A late top-up that reaches the amount turns `underpaid`/`expired` into `paid`.
- `detected` from the mempool only and expired for over 1 h becomes `expired` (the tx was probably dropped).

### Swaps (cross-chain)

- `GET /v1/swap/assets` (public) -> `[{asset_id, symbol, blockchain, decimals, price_usd}]`: USDC/USDT/SOL/ETH/BTC/wNEAR on the main chains, cached 5 min.
- `POST /v1/invoices/{id}/swap` (public) `{asset_id, refund_to}` -> 201 `{swap_id, deposit_address, deposit_memo, amount_in, amount_in_formatted, amount_in_usd, symbol, blockchain, deadline, time_estimate}`. 409 unless the invoice is pending; 429 after 5 requests per invoice per 10 min; 400 for an unknown asset, a `refund_to` over 128 chars, or a quote 1Click rejects. 1Click rejections are mapped to fixed messages (`refund address is not valid for this asset`, `amount is too small to swap with this asset`, `swap quote rejected, try another asset or pay in ZEC`); the raw message is logged only, with the refund address masked.
- The quote is EXACT_OUTPUT for the invoice amount; 1Click's fee is added to `amount_in`. Minimum invoice for a swap is about 100000 zat.
- Deadline = min(invoice expiry, now+30 min). If the invoice expires within 10 min, `expires_at` is extended to now+30 min so the swap can finish. This happens at most once per invoice (`invoices.extended_at`) and never past the original expiry + 30 min; after that a swap on an invoice expiring within 10 min gets 409. Fee settlement invoices are never extended: 409, start a new settlement.
- One active swap per invoice: a new request replaces the old row only while it is `PENDING_DEPOSIT`, `REFUNDED` or `FAILED`, and the old deposit address is abandoned (do not send to it). Otherwise 409 `a swap is already in progress`. This is checked again atomically after the 1Click quote returns, so a swap that received a deposit meanwhile (or a concurrent request) is never dropped; the unused quote simply expires.
- The swap may deliver slightly more or less ZEC than the invoice (see over/underpayment above).

### Webhooks

- `GET /v1/account/webhook` -> `{url, secret}`; `PUT` `{url|null}` -> 204, 400 with a reason when the URL breaks the rules below; `POST /v1/account/webhook/rotate` -> `{secret}`; `POST /v1/account/webhook/test` -> `{status: <http code>}` or `{error: "connection failed" | "timed out" | "blocked address" | "invalid URL"}` (single attempt; 429 after 10 per merchant per 15 min)
- URL rules (checked on save and again at send time): `https` only (`http` too with `LUNAZ_WEBHOOK_ALLOW_HTTP=1`), no `user:pass@`, default port, at most 2048 chars, and the host must not be a private or reserved IP (loopback, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, 0/8, 192.0.0/24, 198.18/15, multicast/reserved, IPv6 loopback/ULA/link-local/multicast/documentation, and IPv4 embedded in IPv6). Host names are resolved at send time and the request fails with `blocked address` if any address is not public. Redirects are never followed (a 3xx is recorded as the status). Timeouts: 3 s connect, 5 s total; proxy env vars are ignored.
- `LUNAZ_WEBHOOK_ALLOW_PRIVATE=1` (development only) lifts the address, port and scheme rules so a local receiver such as `http://127.0.0.1:3000/hook` works; a WARN is logged at startup. On mainnet it needs `LUNAZ_DEV=1`.
- `GET /v1/account/webhook/events?status=pending|delivered|failed&limit=50` (max 200) -> newest first `[{id, type, invoice_id, status, attempts, max_attempts: 3, next_attempt_at, last_status_code, last_error, created_at, updated_at, deliveries: [{attempt, status_code, error, created_at}]}]`
- `POST /v1/account/webhook/events/{id}/retry` -> the event, now `pending` with `attempts` 0; 409 unless the event is `failed`, 404 if unknown.
- `POST /v1/account/webhook/events/retry-failed` -> `{retried: n}`; requeues the failed events of the last 7 days (max 100).
- `GET /v1/account/webhook/deliveries?limit=50` (max 200) -> newest first `[{id, invoice_id, type, url, status_code, error, attempt, created_at, event_id}]`, one row per attempt.
- Delivery: POST with headers `X-Lunaz-Event-Id: <event id>` (same on every attempt) and `X-Lunaz-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "{t}.{raw body}">`, keyed with the merchant's current webhook secret. `t` is the send time of that attempt, so every attempt is signed again; the body bytes never change. Receivers recompute `v1`, compare in constant time, reject when `|now - t| > 300` s, and de-duplicate by event id.
- Every body has `id` (the event id) and `created_at` (unix seconds of the event), plus the type's fields.
- Body always: `{id, created_at, type, invoice_id, status, amount_zat, received_zat, pending_zat, overpaid_zat, txid, swap}` (invoice events; amounts as for `GET /v1/invoices/{id}`). `swap` is `{asset, blockchain, amount_in_formatted, status}` or null.
- Types: `invoice.paid`, `invoice.underpaid`, `swap.refunded`, `swap.failed`, `swap.incomplete_deposit` (the swap ones leave the invoice `pending`; the buyer can start another swap or pay ZEC), `withdrawal.updated` and `test` (`invoice_id: null`).
- Events are stored in the database before sending, so pending events survive a restart. A background loop (every 2 s) sends due events concurrently: at most 16 in flight overall and 2 per merchant, so a slow endpoint only delays its own merchant's events. A claimed event is leased for 30 s, so it is never sent twice at once. Statuses: `pending` -> `delivered` (any 2xx) | `failed`.
- 3 attempts in total: immediately, after 10 s, after 60 s. A non-2xx or network error uses up an attempt (errors are stored in the same coarse form as the test endpoint returns, never raw network errors); after the third the event is `failed` (`next_attempt_at: null`). No webhook URL at send time -> `failed` with `last_error: "no webhook URL configured"`. Events are only created while a URL is set.
- `POST /v1/account/webhook/test` makes one synchronous attempt (no retries) and stores a `test` event with its final status.
- Delivered events are deleted after 30 days, failed ones after 90 days (with their attempt logs).

### Off-ramp (withdraw to bank, session auth)

Mocked for now; the real provider will be TransFi (`LUNAZ_OFFRAMP=transfi`, currently 501 `off-ramp provider not configured`). The merchant is the provider's customer (KYC and bank link happen with the provider). The merchant sends ZEC from their own wallet to the provider's deposit address and the provider pays fiat to their bank. Lunaz only creates the order, shows the deposit address/QR and tracks status. It never holds funds and never stores bank account numbers or KYC data (only a display label such as `BCA ••••1234`).

Privacy: the provider's deposit address is transparent, so the merchant must deshield from their shielded wallet and that leg is public on chain.

Mock mode: ZEC/USD is the cached 1Click price, USD -> fiat is `LUNAZ_MOCK_FX` (indicative, not a real rate). Fees: provider 1.5% plus 0.0001 ZEC network fee; fiat is computed in integer minor units (2 dp). The deposit address is a deliberately invalid fake (`t1SANDBOX...`, `sandbox: true`): never send funds to it.

- `GET /v1/account/offramp` -> `{provider, sandbox, currencies, min_zat, received_zat, zec_usd}`. `received_zat` is the sum of mined payments to this merchant's invoices ("received through Lunaz"), not a wallet balance.
- `POST /v1/account/withdrawals/quote` `{amount_zat, currency}` -> `{amount_zat, currency, rate, fee_fiat, network_fee_zat, fiat_amount, expires_at}`. Not persisted, valid 10 min. 400 below `min_zat` (100000), above 21e14 or for an unsupported currency; 503 without a ZEC price.
- `POST /v1/account/withdrawals` `{amount_zat, currency}` -> 201 withdrawal `{id, provider, sandbox, status, amount_zat, fiat_currency, fiat_amount, rate, fee_fiat, network_fee_zat, deposit_address, deposit_uri, bank_label, provider_ref, created_at, updated_at, expires_at, events}`; starts at `awaiting_kyc`. 429 after 10 per merchant per hour.
- `GET /v1/account/withdrawals?limit=50` (max 200, newest first) and `GET /v1/account/withdrawals/{id}`; `events` is `[{status, note, created_at}]`.
- `POST /v1/account/withdrawals/{id}/kyc` `{bank_name, account_last4}` (mock only; with TransFi the provider widget does this step and the route is 404). `account_last4` must be exactly 4 digits. Stores the label only and moves to `awaiting_deposit` with a 30 min window.
- `POST /v1/account/withdrawals/{id}/simulate-deposit` (mock only, 404 otherwise): `awaiting_deposit` -> `deposit_received`, then `converting`, `payout_processing`, `completed` at 5 s steps.
- `POST /v1/account/withdrawals/{id}/cancel`: only before `deposit_received`. Illegal transitions return 409.

Statuses: `quote` (never stored) -> `awaiting_kyc` -> `awaiting_deposit` -> `deposit_received` -> `converting` -> `payout_processing` -> `completed`; also `expired` (quote or deposit window passed, swept every 10 s), `failed`, `cancelled`. Every change is logged as an event and sent to the merchant webhook as `withdrawal.updated` (`{id, created_at, type, invoice_id: null, withdrawal_id, status, amount_zat, fiat_currency, fiat_amount}`), queued, signed and retried like the invoice events.

### Fees

Lunaz charges a per-payment fee and stays non-custodial: the fee is a second payment in the invoice's own ZIP-321 request, sent by the buyer's wallet straight to a Lunaz treasury address. There are no plans or usage limits.

- The fee is active only when `LUNAZ_BILLING_MERCHANT_ID` names a treasury merchant that has a viewing key and `LUNAZ_FEE_BPS` > 0. Otherwise invoices have `fee_zat: 0` and a single-payment URI (dev and testnet keep working without a treasury).
- `fee_zat = max(LUNAZ_FEE_MIN_ZAT, amount_zat * LUNAZ_FEE_BPS / 10000)` (integer math, rounded down). Invoices of the treasury itself (fee settlements) have no fee.
- The fee address is derived from the treasury viewing key at the treasury's next diversifier index (stored as `invoices.fee_div_index`, `fee_address`). The URI holds two payments: `[0]` merchant address, `amount_zat`, memo `lunaz:<invoice id>`; `[1]` fee address, `fee_zat`, memo `lunaz-fee:<invoice id>`. `address` and `amount_zat` in responses stay the merchant's.
- The watcher records payments to fee addresses in `fee_payments`. A fee payment never changes the invoice status; a missing fee never blocks `paid`.
- Outstanding fees per merchant: `charged` = sum of `fee_zat` over its `paid` and `underpaid` invoices; `paid_in_tx` = mined fee payments, capped per invoice at that invoice's `fee_zat` (overpaying one fee does not credit another); `settled` = paid settlements; `outstanding = max(0, charged - paid_in_tx - settled)`. Fees on invoices paid through a cross-chain swap are not paid in the tx and show up as outstanding.
- Settlement: a normal 1 h invoice on the treasury (memo `lunaz-settle:<settlement id>`). When it turns `paid` or `underpaid` the settlement becomes `paid` and credits the mined amount, capped at the invoice amount (a later top-up raises it). Expired -> settlement `expired`; a late payment still credits it.
- `GET /v1/pricing` (public) -> `{fee_bps, fee_min_zat, swap_fee_bps}`. `fee_bps` is 0 while the fee is inactive; `swap_fee_bps` is `LUNAZ_APP_FEE_BPS` or 0.
- `GET /v1/account/fees` -> `{fee_bps, fee_min_zat, charged_zat, paid_in_tx_zat, settled_zat, outstanding_zat, settlements: [{id, invoice_id, amount_zat, status (pending|paid|expired), created_at, paid_at}]}` (newest first, at most 50).
- `POST /v1/account/fees/settle` -> `{id, amount_zat, invoice: {id, address, amount_zat, zip321_uri, expires_at}}` for the whole outstanding amount. 409 `nothing to settle` when outstanding is 0, 409 `a settlement is already pending` with `{settlement}` while an earlier settlement invoice has not expired, 409 for the treasury itself, 503 `fee settlement not configured` without a treasury (or its viewing key), 429 after 10 per merchant per 15 min.
- `POST /v1/account/fees/settle/{id}/simulate-paid` -> `{status: "paid"}`; only with `LUNAZ_BILLING_SANDBOX=1`, 404 otherwise.
- Older databases keep the `subscriptions` table and `merchants.plan` columns; they are no longer used.

### Export (session auth)

`GET /v1/account/export.csv?from=<unix>&to=<unix>&kind=invoices|payments`. `kind` defaults to `invoices`; the range filters on invoice `created_at` (default all); max 50000 rows. Returns a `text/csv` attachment `lunaz-<kind>-<from>-<to>.csv` with a header row and RFC 4180 quoting. ZEC amounts are exact 8-decimal strings. Text cells starting with `=`, `+`, `-`, `@`, tab or CR (and not a number) get a leading `'` and are quoted, so spreadsheets do not run them as formulas. 429 after 5 exports per merchant per minute. The export runs on a separate read-only connection and does not block other requests.

- `invoices`: `invoice_id, created_at, paid_at, status, amount_zec, fee_zec, received_zec (mined), overpaid_zec, usd_rate, received_usd, txid, paid_with, origin_chain, origin_amount, swap_status`. Dates are ISO 8601 UTC. `usd_rate` (USD per ZEC) is recorded from the 1Click price when the invoice turns paid or underpaid; older invoices have none. `paid_with` is `ZEC` or the swap symbol once the swap succeeded.
- `payments`: `txid, action_index, pool (orchard|ironwood), invoice_id, value_zec, block_height (empty while mempool only), invoice_status`.

### Other

- `GET /healthz` -> 200 `ok`

## Known limitations

- Chain reorgs are not handled.
- Rate limits (exchange, swaps, invoices per key, export, withdrawals, fee settlements, webhook tests) are in memory: lost on restart, not shared between instances. Run a single instance.
- Swaps need an invoice of about 0.001 ZEC (100000 zat) or more.
- The viewing key cannot be changed once set. Databases from older versions are migrated on startup: stored UFVKs are converted to UIVKs in place (invoice addresses stay valid). `orchard_ivk_hash` is backfilled for existing merchants (the count is logged). If two existing accounts already share a wallet, startup continues: a WARN names both merchant ids and the later one keeps a NULL hash until resolved by hand.
