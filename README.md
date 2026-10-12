# lunaz core-service

Non-custodial Zcash shielded (Orchard) payment gateway. Developers sign up, set a UFVK once, and create API keys; each invoice gets a unique diversified address, detected by trial decryption via lightwalletd. No spending keys are held.

## Run

    cargo run

Env: `LUNAZ_NETWORK` (test|main, default test), `LUNAZ_LWD_URL` (default zec.rocks per network), `LUNAZ_DB` (lunaz.db), `LUNAZ_BIND` (0.0.0.0:8080), `LUNAZ_ONECLICK_JWT` (optional NEAR Intents 1Click token; without it 1Click adds a 0.25% fee).

Tables are created on start if missing (`CREATE TABLE IF NOT EXISTS`); there are no column migrations yet, so a breaking schema change needs a fresh DB.

## API

Dashboard (JSON, errors `{"error": ...}`). Session token = `Authorization: Bearer <token>`, valid 30 days.

- `POST /v1/auth/signup` `{email, name, password>=8}` -> 201 `{token}`; 409 if email taken
- `POST /v1/auth/login` `{email, password}` -> `{token}`; 401 otherwise
- `POST /v1/auth/logout` -> 204
- `GET /v1/account` -> `{id, email, name, network, ufvk_set, webhook_url}`
- `PUT /v1/account/ufvk` `{ufvk}` -> 204; set once, 409 if already set
- `GET|POST /v1/account/api-keys` (`{name}` -> 201 `{id, name, prefix, key}`, key shown once); `DELETE /v1/account/api-keys/{id}` -> 204 (revoke)
- `GET /v1/account/webhook` -> `{url, secret}`; `PUT` `{url|null}` -> 204; `POST .../rotate` -> `{secret}`; `POST .../test` -> `{status}` or `{error}` (single attempt)
- `GET /v1/account/webhook/deliveries?limit=50` (max 200) -> newest first `[{id, invoice_id, type, url, status_code, error, attempt, created_at}]`, one row per attempt
- `GET /v1/account/invoices?limit=50` (max 200) -> `[{id, status, amount_zat, received_zat, overpaid_zat, address, txid, created_at, expires_at, paid_at}]`

- `POST /v1/invoices` (Bearer api key `lz_...`; 400 until a UFVK is set) `{amount_zat, expires_in_secs?=900}` (`expires_in_secs` is clamped to 60..86400; `amount_zat` must be 1..21e14) -> `{id, address, amount_zat, zip321_uri, status, expires_at}`
- `GET /v1/invoices/{id}` -> `{status, amount_zat, received_zat, overpaid_zat, txid, expires_at, swap}`; `swap` is null or `{status, symbol, blockchain, deposit_address, amount_in_formatted, deadline}`
- `GET /v1/invoices/{id}/ws` WebSocket: `{"status":...}` now and on each change, plus `"swap_status"` (1Click status) when a swap exists; closes on paid/underpaid/expired.
- `GET /v1/swap/assets` (public) -> `[{asset_id, symbol, blockchain, decimals, price_usd}]`: USDC/USDT/SOL/ETH/BTC/wNEAR on the main chains, cached 5 min.
- `POST /v1/invoices/{id}/swap` (public, the invoice id is the capability) `{asset_id, refund_to}` -> 201 `{swap_id, deposit_address, deposit_memo, amount_in, amount_in_formatted, amount_in_usd, symbol, blockchain, deadline, time_estimate}`. 409 unless the invoice is pending; 429 after 5 requests per invoice per 10 min; 400 for an unknown asset or a refund address 1Click rejects (its message is passed through).

Status: `pending` -> `detected` (seen, mempool or mined) -> `paid` (mined sum >= amount) | `underpaid` | `expired`.
- Payments to one address add up, so a buyer can top up a `detected` invoice before it expires.
- `overpaid_zat` = max(received - amount, 0); the merchant refunds any excess manually.
- `underpaid` (final): a mined payment exists, the sum is below the amount and the invoice expired. Lunaz is non-custodial and cannot refund; the merchant refunds the buyer manually. A late top-up that reaches the amount still turns `underpaid`/`expired` into `paid`.
- `detected` from the mempool only (nothing mined) and expired for over 1h becomes `expired` (the tx was probably dropped).

Webhooks: POST with `X-Lunaz-Signature` = hex HMAC-SHA256(body, webhook_secret). Body always `{type, invoice_id, status, amount_zat, received_zat, overpaid_zat, txid, swap}`. Types: `invoice.paid`, `invoice.underpaid`, `swap.refunded`, `swap.failed`, `swap.incomplete_deposit` (the swap ones leave the invoice `pending`; the buyer can start another swap or pay ZEC), and `test` (`invoice_id: null`). A non-2xx or network error is retried after 10s, 60s and 300s (4 attempts); every attempt is logged in `webhook_deliveries`. Retries run in-process, so pending ones are lost on restart.

Limits: login/signup allow 10 attempts per email and 30 per client IP per 15 min (429 `too many attempts, try again later`; behind a reverse proxy the IP is the proxy's). In-memory, reset on restart.

## Cross-chain payments

A buyer can pay in another asset via NEAR Intents 1Click: they send `amount_in` to `deposit_address` (plus `deposit_memo` if set) on their own chain, and 1Click delivers ZEC to the invoice's shielded address. The ZEC arrival is detected by the normal watcher, so `detected`/`paid` are unchanged (the 1Click swap may deliver slightly more or less than the invoice, see over/underpayment above); the 1Click status (`PENDING_DEPOSIT`, `PROCESSING`, `SUCCESS`, `REFUNDED`, ...) is polled every 10s and shown as `swap_status`.

- The quote is EXACT_OUTPUT for the invoice amount; 1Click's withdraw fee is added to `amount_in`, so the invoice is paid in full. Minimum invoice for a swap is about 100000 zat (1Click rejects less).
- Deadline = min(invoice expiry, now+30min). If the invoice expires within 10 minutes, `expires_at` is extended to now+30min so the swap can finish.
- One active swap per invoice: a new request replaces the old row; the old deposit address is abandoned (do not send to it).
- Privacy: the origin-chain payment is public; only the final shielded leg is private.
- Webhooks include `swap`: `{asset, blockchain, amount_in_formatted, status}` or null.

## Notes

Reorgs are not handled. Tests: `cargo test`.
