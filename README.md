# Lunaz core-service

Non-custodial shielded Zcash payment gateway. Merchants sign up, register a Unified Incoming Viewing Key (UIVK) once, and create API keys. Each invoice gets its own shielded address, and the service detects payments by trial decryption. It holds incoming viewing keys only and cannot spend funds. A UFVK is also accepted, but it is reduced to its incoming key on save, so the server never stores the outgoing viewing key.

## Architecture

- **Invoice addresses.** Each invoice address is derived from the merchant's UIVK at a fresh diversifier index, starting at an offset of 2^80 so it never collides with addresses the merchant uses elsewhere.
- **Watcher.** A scanner reads compact blocks from lightwalletd (gRPC over TLS) and trial-decrypts Orchard and Ironwood actions with every merchant's viewing key. A second task does the same for the mempool, so payments show as `detected` before they are mined.
- **Cross-chain.** A buyer can pay in another asset through NEAR Intents 1Click. The buyer sends funds on their own chain and 1Click delivers ZEC to the invoice address. The watcher sees the ZEC as usual. Swap status is polled every 10 s.
- **Webhooks.** Signed POSTs on invoice, swap, withdrawal and plan events. Every event is stored, retried up to 3 times and keeps a final status; failed ones can be retried by hand.
- **Storage.** One SQLite file (bundled rusqlite). Tables are created on start; older databases are migrated in place.

## Privacy and security model

- Lunaz needs only an incoming viewing key. The server can see incoming payments to invoice addresses (amounts, txids); it cannot see outgoing payments, spends or the wallet balance.
- Nothing on chain links invoices to each other or to the merchant. Only the logged-in merchant sees the ledger and CSV export.
- Cross-chain payments: the origin-chain leg is public. Only the final shielded leg is private.
- Passwords are hashed with Argon2id. Session tokens and API keys are stored as hashes. API keys (`lz_...`) can create invoices only. The viewing key can be set once.
- The invoice id is the capability for the public endpoints (`GET /v1/invoices/{id}`, WebSocket, swap).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `LUNAZ_NETWORK` | `test` (Docker image: `main`) | `test` or `main`; anything else aborts startup |
| `LUNAZ_LWD_URL` | `https://zec.rocks:443` (main), `https://testnet.zec.rocks:443` (test) | lightwalletd endpoint |
| `LUNAZ_DB` | `lunaz.db` (Docker image: `/data/lunaz.db`) | SQLite path |
| `LUNAZ_BIND` | `0.0.0.0:8080` | listen address |
| `LUNAZ_ONECLICK_JWT` | unset | 1Click token; without it 1Click adds a 0.25% fee |
| `LUNAZ_OFFRAMP` | `mock` | off-ramp provider: `mock` or `transfi` (not implemented yet: off-ramp requests return 501) |
| `LUNAZ_MOCK_FX` | `{"IDR":16400,"USD":1}` | mock only: USD -> fiat rates (indicative), also defines the supported currencies |
| `LUNAZ_MOCK_ZEC_USD` | unset | mock only: fixed ZEC/USD price instead of the 1Click price |
| `LUNAZ_PLANS` | built-in table below | JSON array `[{id,name,price_usd,invoices_per_month,api_keys}]` replacing the plans (`null` = unlimited / not purchasable); must include `free` |
| `LUNAZ_INTERNAL_TOKEN` | unset | secret (>=32 chars) for `/v1/auth/exchange`; unset = endpoint returns 503; shorter aborts startup |
| `LUNAZ_BILLING_MERCHANT_ID` | unset | id of the treasury merchant that receives subscription payments; unset = purchase endpoints return 503 `billing not configured` |
| `LUNAZ_BILLING_SANDBOX` | unset | `1` enables `simulate-paid` (demos/tests) |
| `RUST_LOG` | tracing default | log filter |

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
      -p 127.0.0.1:8080:8080 -v lunaz-data:/data -e LUNAZ_NETWORK=main \
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

JSON; errors are `{"error": ...}`. Session token: `Authorization: Bearer <token>`, valid 30 days. The merchant API uses an API key as the Bearer token.

### Auth

Sign-in is delegated to an identity provider (Magic, magic.link; email only). The browser logs in with an email OTP and gets a DID token; the landing server verifies it with `@magic-sdk/admin` and calls the exchange endpoint. core-service never sees provider tokens.

- `POST /v1/auth/exchange` `{email}` with `Authorization: Bearer <LUNAZ_INTERNAL_TOKEN>` -> `{token, new_account, merchant_id}`. The email is trimmed and lowercased; the merchant is found or created (free plan, empty name). 401 on a wrong internal token, 503 `internal auth not configured` if the env is unset, 429 after 20 per email per 15 min.
- `POST /v1/auth/signup` and `POST /v1/auth/login` -> 410 (password sign-in was removed). Existing accounts sign in by email.
- `POST /v1/auth/logout` -> 204

**Security:** the exchange endpoint mints a session for any email, so it must only be reachable from the landing server: keep core-service internal or block `/v1/auth/exchange` at the proxy. `LUNAZ_INTERNAL_TOKEN` is a secret (min 32 chars).

### Account (session auth)

- `GET /v1/account` -> `{id, email, name, network, viewing_key_set, ufvk_set, webhook_url, plan}` (`name` may be empty)
- `PUT /v1/account` `{name}` (1-80 chars) -> 204
- `PUT /v1/account/viewing-key` `{viewing_key}` -> 204; set once, 409 if already set or used by another account. Accepts a UIVK (`uivk...`) or a UFVK (`uview...`); a UFVK is reduced to its UIVK and only the UIVK is stored. `PUT /v1/account/ufvk` is the legacy alias and also accepts `{ufvk}`.
- `GET /v1/account/api-keys`; `POST` `{name}` -> 201 `{id, name, prefix, key}` (key shown once); `DELETE /v1/account/api-keys/{id}` -> 204 (revoke)
- `GET /v1/account/invoices?limit=50` (max 200) -> `[{id, status, amount_zat, received_zat, overpaid_zat, address, txid, created_at, expires_at, paid_at}]`

### Invoices

- `POST /v1/invoices` (API key; 400 until a viewing key is set) `{amount_zat, expires_in_secs?=900}`. `expires_in_secs` is clamped to 60..86400, `amount_zat` must be 1..21e14. -> `{id, address, amount_zat, zip321_uri, status, expires_at}`
- `GET /v1/invoices/{id}` (public) -> `{status, amount_zat, received_zat, overpaid_zat, txid, expires_at, swap}`; `swap` is null or `{status, symbol, blockchain, deposit_address, amount_in_formatted, deadline}`
- `GET /v1/invoices/{id}/ws` WebSocket: `{"status":...}` now and on each change, plus `"swap_status"` (1Click status) when a swap exists. Closes on paid, underpaid or expired.

Statuses: `pending` -> `detected` (seen in mempool or mined) -> `paid` (mined sum >= amount) | `underpaid` | `expired`.

- Payments to one address add up, so a buyer can top up a `detected` invoice before it expires.
- `overpaid_zat` = max(received - amount, 0). The merchant refunds any excess manually.
- `underpaid` (final): a mined payment exists, the sum is below the amount, and the invoice expired. Lunaz cannot refund; the merchant does. A late top-up that reaches the amount turns `underpaid`/`expired` into `paid`.
- `detected` from the mempool only and expired for over 1 h becomes `expired` (the tx was probably dropped).

### Swaps (cross-chain)

- `GET /v1/swap/assets` (public) -> `[{asset_id, symbol, blockchain, decimals, price_usd}]`: USDC/USDT/SOL/ETH/BTC/wNEAR on the main chains, cached 5 min.
- `POST /v1/invoices/{id}/swap` (public) `{asset_id, refund_to}` -> 201 `{swap_id, deposit_address, deposit_memo, amount_in, amount_in_formatted, amount_in_usd, symbol, blockchain, deadline, time_estimate}`. 409 unless the invoice is pending; 429 after 5 requests per invoice per 10 min; 400 for an unknown asset or a refund address 1Click rejects (its message is passed through).
- The quote is EXACT_OUTPUT for the invoice amount; 1Click's fee is added to `amount_in`. Minimum invoice for a swap is about 100000 zat.
- Deadline = min(invoice expiry, now+30 min). If the invoice expires within 10 min, `expires_at` is extended to now+30 min so the swap can finish.
- One active swap per invoice: a new request replaces the old row, and the old deposit address is abandoned (do not send to it).
- The swap may deliver slightly more or less ZEC than the invoice (see over/underpayment above).

### Webhooks

- `GET /v1/account/webhook` -> `{url, secret}`; `PUT` `{url|null}` -> 204; `POST /v1/account/webhook/rotate` -> `{secret}`; `POST /v1/account/webhook/test` -> `{status}` or `{error}` (single attempt)
- `GET /v1/account/webhook/events?status=pending|delivered|failed&limit=50` (max 200) -> newest first `[{id, type, invoice_id, status, attempts, max_attempts: 3, next_attempt_at, last_status_code, last_error, created_at, updated_at, deliveries: [{attempt, status_code, error, created_at}]}]`
- `POST /v1/account/webhook/events/{id}/retry` -> the event, now `pending` with `attempts` 0; 409 unless the event is `failed`, 404 if unknown.
- `POST /v1/account/webhook/events/retry-failed` -> `{retried: n}`; requeues the failed events of the last 7 days (max 100).
- `GET /v1/account/webhook/deliveries?limit=50` (max 200) -> newest first `[{id, invoice_id, type, url, status_code, error, attempt, created_at, event_id}]`, one row per attempt.
- Delivery: POST with header `X-Lunaz-Signature` = hex HMAC-SHA256 of the raw body, keyed with the merchant's current webhook secret (at send time). Compare in constant time.
- Body always: `{type, invoice_id, status, amount_zat, received_zat, overpaid_zat, txid, swap}` (invoice events). `swap` is `{asset, blockchain, amount_in_formatted, status}` or null.
- Types: `invoice.paid`, `invoice.underpaid`, `swap.refunded`, `swap.failed`, `swap.incomplete_deposit` (the swap ones leave the invoice `pending`; the buyer can start another swap or pay ZEC), `withdrawal.updated`, `plan.updated` and `test` (`invoice_id: null`).
- Events are stored in the database before sending, so pending events survive a restart. A background loop (every 2 s) sends due events. Statuses: `pending` -> `delivered` (any 2xx) | `failed`.
- 3 attempts in total: immediately, after 10 s, after 60 s. A non-2xx or network error uses up an attempt; after the third the event is `failed` (`next_attempt_at: null`). No webhook URL at send time -> `failed` with `last_error: "no webhook URL configured"`. Events are only created while a URL is set.
- `POST /v1/account/webhook/test` makes one synchronous attempt (no retries) and stores a `test` event with its final status.
- Delivered events are deleted after 30 days, failed ones after 90 days (with their attempt logs).

### Off-ramp (withdraw to bank, session auth)

Mocked for now; the real provider will be TransFi (`LUNAZ_OFFRAMP=transfi`, currently 501 `off-ramp provider not configured`). The merchant is the provider's customer (KYC and bank link happen with the provider). The merchant sends ZEC from their own wallet to the provider's deposit address and the provider pays fiat to their bank. Lunaz only creates the order, shows the deposit address/QR and tracks status. It never holds funds and never stores bank account numbers or KYC data (only a display label such as `BCA ••••1234`).

Privacy: the provider's deposit address is transparent, so the merchant must deshield from their shielded wallet and that leg is public on chain.

Mock mode: ZEC/USD is the cached 1Click price, USD -> fiat is `LUNAZ_MOCK_FX` (indicative, not a real rate). Fees: provider 1.5% plus 0.0001 ZEC network fee; fiat is computed in integer minor units (2 dp). The deposit address is a deliberately invalid fake (`t1SANDBOX...`, `sandbox: true`): never send funds to it.

- `GET /v1/account/offramp` -> `{provider, sandbox, currencies, min_zat, received_zat, zec_usd}`. `received_zat` is the sum of mined payments to this merchant's invoices ("received through Lunaz"), not a wallet balance.
- `POST /v1/account/withdrawals/quote` `{amount_zat, currency}` -> `{amount_zat, currency, rate, fee_fiat, network_fee_zat, fiat_amount, expires_at}`. Not persisted, valid 10 min. 400 below `min_zat` (100000), above 21e14 or for an unsupported currency; 503 without a ZEC price.
- `POST /v1/account/withdrawals` `{amount_zat, currency}` -> 201 withdrawal `{id, provider, sandbox, status, amount_zat, fiat_currency, fiat_amount, rate, fee_fiat, network_fee_zat, deposit_address, deposit_uri, bank_label, provider_ref, created_at, updated_at, expires_at, events}`; starts at `awaiting_kyc`.
- `GET /v1/account/withdrawals?limit=50` (max 200, newest first) and `GET /v1/account/withdrawals/{id}`; `events` is `[{status, note, created_at}]`.
- `POST /v1/account/withdrawals/{id}/kyc` `{bank_name, account_last4}` (mock only; with TransFi the provider widget does this step and the route is 404). `account_last4` must be exactly 4 digits. Stores the label only and moves to `awaiting_deposit` with a 30 min window.
- `POST /v1/account/withdrawals/{id}/simulate-deposit` (mock only, 404 otherwise): `awaiting_deposit` -> `deposit_received`, then `converting`, `payout_processing`, `completed` at 5 s steps.
- `POST /v1/account/withdrawals/{id}/cancel`: only before `deposit_received`. Illegal transitions return 409.

Statuses: `quote` (never stored) -> `awaiting_kyc` -> `awaiting_deposit` -> `deposit_received` -> `converting` -> `payout_processing` -> `completed`; also `expired` (quote or deposit window passed, swept every 10 s), `failed`, `cancelled`. Every change is logged as an event and sent to the merchant webhook as `withdrawal.updated` (`{type, invoice_id: null, withdrawal_id, status, amount_zat, fiat_currency, fiat_amount}`), queued, signed and retried like the invoice events.

### Plans and billing

All features are on every plan; only volume is limited. Existing merchants are on `free`.

| Plan | USD / month | Invoices / month | API keys |
|---|---|---|---|
| `free` | 0 | 100 | 2 |
| `pro` | 29 | 5000 | 10 |
| `platform` | 199 | unlimited | 50 |
| `enterprise` | contact us | unlimited | unlimited |

- Limits: `POST /v1/invoices` counts invoices created in the current UTC calendar month (billing invoices excluded); `POST /v1/account/api-keys` counts active keys. Over the limit -> 402 `{error, limit, used, plan}`.
- A plan is effective until `plan_expires_at`; after that the merchant is on `free`. The 10 s sweep resets the stored plan and sends the `plan.updated` webhook `{type, invoice_id: null, plan, expires_at}`.
- ZEC billing is dogfooded: the treasury (`LUNAZ_BILLING_MERCHANT_ID`) is an ordinary Lunaz merchant with a viewing key. A checkout creates a normal invoice on it (memo `lunaz:billing:<subscription id>`, 30 min), priced `ceil(price_usd * months / zec_usd * 1e8)` zat with the cached 1Click ZEC price (`LUNAZ_MOCK_ZEC_USD` as fallback; 503 without a price). The invoice is public like any other (`GET /v1/invoices/{id}`, WebSocket).
- When that invoice turns `paid` the subscription is paid, the plan runs for `months * 30` days from `max(now, current expiry)` if it is the same still-active plan, otherwise from now. Underpaid or expired -> subscription `expired` (a late top-up to the full amount still activates it).
- No proration: switching to another paid plan starts the new plan now and replaces the old one. Renewals are manual payments; nothing is charged automatically.
- `GET /v1/plans` (public) -> `[{id, name, price_usd, invoices_per_month, api_keys}]`
- `GET /v1/account/plan` -> `{plan, plan_name, expires_at, limits: {invoices_per_month, api_keys}, usage: {invoices_this_month, api_keys_active}, period_start_of_month, sandbox_billing, billing_configured}`
- `POST /v1/account/billing/checkout` `{plan, months: 1|3|12}` -> `{subscription_id, plan, months, price_usd, amount_zat, zec_usd, invoice: {id, address, zip321_uri, expires_at, status}}`. 400 for `free`, `enterprise`, unknown plans or the treasury itself.
- `GET /v1/account/billing` -> newest first `[{id, plan, months, price_usd, amount_zat, zec_usd, invoice_id, status (pending|paid|expired|cancelled), invoice_status, created_at, paid_at, period_start, period_end}]`
- `POST /v1/account/billing/{subscription_id}/simulate-paid` -> `{status: "paid"}`; only with `LUNAZ_BILLING_SANDBOX=1`, 404 otherwise.
- `GET /v1/account` also returns `plan`.

### Export (session auth)

`GET /v1/account/export.csv?from=<unix>&to=<unix>&kind=invoices|payments`. `kind` defaults to `invoices`; the range filters on invoice `created_at` (default all); max 50000 rows. Returns a `text/csv` attachment `lunaz-<kind>-<from>-<to>.csv` with a header row and RFC 4180 quoting. ZEC amounts are exact 8-decimal strings.

- `invoices`: `invoice_id, created_at, paid_at, status, amount_zec, received_zec, overpaid_zec, usd_rate, received_usd, txid, paid_with, origin_chain, origin_amount, swap_status`. Dates are ISO 8601 UTC. `usd_rate` (USD per ZEC) is recorded from the 1Click price when the invoice turns paid or underpaid; older invoices have none. `paid_with` is `ZEC` or the swap symbol once the swap succeeded.
- `payments`: `txid, action_index, pool (orchard|ironwood), invoice_id, value_zec, block_height (empty while mempool only), invoice_status`.

### Other

- `GET /healthz` -> 200 `ok`

## Known limitations

- Chain reorgs are not handled.
- Exchange limits and swap request limits are in memory: lost on restart, not shared between instances. Run a single instance.
- Swaps need an invoice of about 0.001 ZEC (100000 zat) or more.
- The viewing key cannot be changed once set. Databases from older versions are migrated on startup: stored UFVKs are converted to UIVKs in place (invoice addresses stay valid).
