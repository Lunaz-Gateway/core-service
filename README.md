# lunaz core-service

Non-custodial Zcash shielded (Orchard) payment gateway. Developers sign up, set a UFVK once, and create API keys; each invoice gets a unique diversified address, detected by trial decryption via lightwalletd. No spending keys are held.

## Run

    cargo run

Env: `LUNAZ_NETWORK` (test|main, default test), `LUNAZ_LWD_URL` (default zec.rocks per network), `LUNAZ_DB` (lunaz.db), `LUNAZ_BIND` (0.0.0.0:8080), `LUNAZ_ONECLICK_JWT` (optional NEAR Intents 1Click token; without it 1Click adds a 0.25% fee).

Schema changes have no migrations: delete old dev DBs (`rm lunaz.db`) after upgrading. The `swaps` table is created on start if missing.

## API

Dashboard (JSON, errors `{"error": ...}`). Session token = `Authorization: Bearer <token>`, valid 30 days.

- `POST /v1/auth/signup` `{email, name, password>=8}` -> 201 `{token}`; 409 if email taken
- `POST /v1/auth/login` `{email, password}` -> `{token}`; 401 otherwise
- `POST /v1/auth/logout` -> 204
- `GET /v1/account` -> `{id, email, name, network, ufvk_set, webhook_url}`
- `PUT /v1/account/ufvk` `{ufvk}` -> 204; set once, 409 if already set
- `GET|POST /v1/account/api-keys` (`{name}` -> 201 `{id, name, prefix, key}`, key shown once); `DELETE /v1/account/api-keys/{id}` -> 204 (revoke)
- `GET /v1/account/webhook` -> `{url, secret}`; `PUT` `{url|null}` -> 204; `POST .../rotate` -> `{secret}`; `POST .../test` -> `{status}` or `{error}`
- `GET /v1/account/invoices?limit=50` (max 200) -> `[{id, status, amount_zat, received_zat, address, txid, created_at, expires_at, paid_at}]`

- `POST /v1/invoices` (Bearer api key `lz_...`; 400 until a UFVK is set) `{amount_zat, expires_in_secs?=900}` -> `{id, address, amount_zat, zip321_uri, status, expires_at}`
- `GET /v1/invoices/{id}` -> `{status, amount_zat, received_zat, txid, expires_at, swap}`; `swap` is null or `{status, symbol, blockchain, deposit_address, amount_in_formatted, deadline}`
- `GET /v1/invoices/{id}/ws` WebSocket: `{"status":...}` now and on each change, plus `"swap_status"` (1Click status) when a swap exists; closes on paid/expired.
- `GET /v1/swap/assets` (public) -> `[{asset_id, symbol, blockchain, decimals, price_usd}]`: USDC/USDT/SOL/ETH/BTC/wNEAR on the main chains, cached 5 min.
- `POST /v1/invoices/{id}/swap` (public, the invoice id is the capability) `{asset_id, refund_to}` -> 201 `{swap_id, deposit_address, deposit_memo, amount_in, amount_in_formatted, amount_in_usd, symbol, blockchain, deadline, time_estimate}`. 409 unless the invoice is pending; 400 for an unknown asset or a refund address 1Click rejects (its message is passed through).

Status: `pending` -> `detected` (mempool) -> `paid` (mined, sum >= amount) or `expired`. A late payment still marks an expired invoice paid.

Webhook on paid: POST `{type: "invoice.paid", invoice_id, status, amount_zat, received_zat, txid, swap}` with `X-Lunaz-Signature` = hex HMAC-SHA256(body, webhook_secret). The test button sends `type: "test"`, `invoice_id: null`.

## Cross-chain payments

A buyer can pay in another asset via NEAR Intents 1Click: they send `amount_in` to `deposit_address` (plus `deposit_memo` if set) on their own chain, and 1Click delivers ZEC to the invoice's shielded address. The ZEC arrival is detected by the normal watcher, so `detected`/`paid` are unchanged; the 1Click status (`PENDING_DEPOSIT`, `PROCESSING`, `SUCCESS`, `REFUNDED`, ...) is polled every 10s and shown as `swap_status`.

- The quote is EXACT_OUTPUT for the invoice amount; 1Click's withdraw fee is added to `amount_in`, so the invoice is paid in full. Minimum invoice for a swap is about 100000 zat (1Click rejects less).
- Deadline = min(invoice expiry, now+30min). If the invoice expires within 10 minutes, `expires_at` is extended to now+30min so the swap can finish.
- One active swap per invoice: a new request replaces the old row; the old deposit address is abandoned (do not send to it).
- Privacy: the origin-chain payment is public; only the final shielded leg is private.
- Invoice webhooks include `swap`: `{asset, blockchain, amount_in_formatted}` or null.

## Notes

Reorgs are not handled. Tests: `cargo test`.
