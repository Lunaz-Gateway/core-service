# lunaz core-service

Non-custodial Zcash shielded (Orchard) payment gateway. Developers sign up, set a UFVK once, and create API keys; each invoice gets a unique diversified address, detected by trial decryption via lightwalletd. No spending keys are held.

## Run

    cargo run

Env: `LUNAZ_NETWORK` (test|main, default test), `LUNAZ_LWD_URL` (default zec.rocks per network), `LUNAZ_DB` (lunaz.db), `LUNAZ_BIND` (0.0.0.0:8080).

Schema changes have no migrations: delete old dev DBs (`rm lunaz.db`) after upgrading.

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
- `GET /v1/invoices/{id}` -> `{status, amount_zat, received_zat, txid, expires_at}`
- `GET /v1/invoices/{id}/ws` WebSocket: `{"status":...}` now and on each change; closes on paid/expired.

Status: `pending` -> `detected` (mempool) -> `paid` (mined, sum >= amount) or `expired`. A late payment still marks an expired invoice paid.

Webhook on paid: POST `{type: "invoice.paid", invoice_id, status, amount_zat, received_zat, txid}` with `X-Lunaz-Signature` = hex HMAC-SHA256(body, webhook_secret). The test button sends `type: "test"`, `invoice_id: null`.

## Notes

Reorgs are not handled. Tests: `cargo test`.
