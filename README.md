# Lunaz core-service

Non-custodial shielded Zcash payment gateway. Merchants sign up, register a Unified Full Viewing Key (UFVK) once, and create API keys. Each invoice gets its own shielded address, and the service detects payments by trial decryption. It holds viewing keys only and cannot spend funds.

## Architecture

- **Invoice addresses.** Each invoice address is derived from the merchant's UFVK at a fresh diversifier index, starting at an offset of 2^80 so it never collides with addresses the merchant uses elsewhere.
- **Watcher.** A scanner reads compact blocks from lightwalletd (gRPC over TLS) and trial-decrypts Orchard and Ironwood actions with every merchant's viewing key. A second task does the same for the mempool, so payments show as `detected` before they are mined.
- **Cross-chain.** A buyer can pay in another asset through NEAR Intents 1Click. The buyer sends funds on their own chain and 1Click delivers ZEC to the invoice address. The watcher sees the ZEC as usual. Swap status is polled every 10 s.
- **Webhooks.** Signed POSTs on invoice and swap events, retried in-process, every attempt logged.
- **Storage.** One SQLite file (bundled rusqlite). Tables are created on start; older databases are migrated in place.

## Privacy and security model

- The server holds viewing keys, so it can see incoming payments to its merchants' invoice addresses (amounts, txids). It cannot spend, and it cannot see outgoing payments or balances elsewhere.
- Nothing on chain links invoices to each other or to the merchant. Only the logged-in merchant sees the ledger and CSV export.
- Cross-chain payments: the origin-chain leg is public. Only the final shielded leg is private.
- Passwords are hashed with Argon2id. Session tokens and API keys are stored as hashes. API keys (`lz_...`) can create invoices only. The UFVK can be set once.
- The invoice id is the capability for the public endpoints (`GET /v1/invoices/{id}`, WebSocket, swap).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `LUNAZ_NETWORK` | `test` (Docker image: `main`) | `test` or `main`; anything else aborts startup |
| `LUNAZ_LWD_URL` | `https://zec.rocks:443` (main), `https://testnet.zec.rocks:443` (test) | lightwalletd endpoint |
| `LUNAZ_DB` | `lunaz.db` (Docker image: `/data/lunaz.db`) | SQLite path |
| `LUNAZ_BIND` | `0.0.0.0:8080` | listen address |
| `LUNAZ_ONECLICK_JWT` | unset | 1Click token; without it 1Click adds a 0.25% fee |
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

Put it behind a TLS reverse proxy (Caddy or nginx). Proxy `/v1/invoices/{id}/ws` as a WebSocket (nginx needs the `Upgrade` and `Connection` headers). The login/signup IP rate limit sees the proxy's address, not the client's.

## API

JSON; errors are `{"error": ...}`. Session token: `Authorization: Bearer <token>`, valid 30 days. The merchant API uses an API key as the Bearer token.

### Auth

- `POST /v1/auth/signup` `{email, name, password>=8}` -> 201 `{token}`; 409 if the email is taken
- `POST /v1/auth/login` `{email, password}` -> `{token}`; 401 otherwise
- `POST /v1/auth/logout` -> 204
- Limits: 10 attempts per email and 30 per client IP per 15 min (429 `too many attempts, try again later`).

### Account (session auth)

- `GET /v1/account` -> `{id, email, name, network, ufvk_set, webhook_url}`
- `PUT /v1/account/ufvk` `{ufvk}` -> 204; set once, 409 if already set
- `GET /v1/account/api-keys`; `POST` `{name}` -> 201 `{id, name, prefix, key}` (key shown once); `DELETE /v1/account/api-keys/{id}` -> 204 (revoke)
- `GET /v1/account/invoices?limit=50` (max 200) -> `[{id, status, amount_zat, received_zat, overpaid_zat, address, txid, created_at, expires_at, paid_at}]`

### Invoices

- `POST /v1/invoices` (API key; 400 until a UFVK is set) `{amount_zat, expires_in_secs?=900}`. `expires_in_secs` is clamped to 60..86400, `amount_zat` must be 1..21e14. -> `{id, address, amount_zat, zip321_uri, status, expires_at}`
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
- `GET /v1/account/webhook/deliveries?limit=50` (max 200) -> newest first `[{id, invoice_id, type, url, status_code, error, attempt, created_at}]`, one row per attempt.
- Delivery: POST with header `X-Lunaz-Signature` = hex HMAC-SHA256 of the raw body, keyed with the webhook secret. Compare in constant time.
- Body always: `{type, invoice_id, status, amount_zat, received_zat, overpaid_zat, txid, swap}`. `swap` is `{asset, blockchain, amount_in_formatted, status}` or null.
- Types: `invoice.paid`, `invoice.underpaid`, `swap.refunded`, `swap.failed`, `swap.incomplete_deposit` (the swap ones leave the invoice `pending`; the buyer can start another swap or pay ZEC), and `test` (`invoice_id: null`).
- A non-2xx or network error is retried after 10 s, 60 s and 300 s (4 attempts in total).

### Export (session auth)

`GET /v1/account/export.csv?from=<unix>&to=<unix>&kind=invoices|payments`. `kind` defaults to `invoices`; the range filters on invoice `created_at` (default all); max 50000 rows. Returns a `text/csv` attachment `lunaz-<kind>-<from>-<to>.csv` with a header row and RFC 4180 quoting. ZEC amounts are exact 8-decimal strings.

- `invoices`: `invoice_id, created_at, paid_at, status, amount_zec, received_zec, overpaid_zec, usd_rate, received_usd, txid, paid_with, origin_chain, origin_amount, swap_status`. Dates are ISO 8601 UTC. `usd_rate` (USD per ZEC) is recorded from the 1Click price when the invoice turns paid or underpaid; older invoices have none. `paid_with` is `ZEC` or the swap symbol once the swap succeeded.
- `payments`: `txid, action_index, pool (orchard|ironwood), invoice_id, value_zec, block_height (empty while mempool only), invoice_status`.

### Other

- `GET /healthz` -> 200 `ok`

## Known limitations

- Chain reorgs are not handled.
- Webhook retries, login/signup limits and swap request limits are in memory: lost on restart, not shared between instances. Run a single instance.
- Behind a proxy, the IP rate limit sees the proxy's address.
- No password reset.
- Swaps need an invoice of about 0.001 ZEC (100000 zat) or more.
- The UFVK cannot be changed once set.
