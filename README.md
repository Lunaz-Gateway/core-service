# lunaz core-service

Non-custodial Zcash shielded (Orchard) payment gateway. Merchants register a UFVK; each invoice gets a unique diversified address, detected by trial decryption via lightwalletd. No spending keys are held.

## Run

    LUNAZ_ADMIN_TOKEN=secret cargo run

Env: `LUNAZ_NETWORK` (test|main, default test), `LUNAZ_LWD_URL` (default zec.rocks per network), `LUNAZ_DB` (lunaz.db), `LUNAZ_BIND` (0.0.0.0:8080), `LUNAZ_ADMIN_TOKEN` (required).

## API

- `POST /v1/merchants` (Bearer admin token) `{name, ufvk, webhook_url?}` -> `{id, api_key, webhook_secret}`
- `POST /v1/invoices` (Bearer api key) `{amount_zat, expires_in_secs?=900}` -> `{id, address, amount_zat, zip321_uri, status, expires_at}`
- `GET /v1/invoices/{id}` -> `{status, amount_zat, received_zat, txid, expires_at}`
- `GET /v1/invoices/{id}/ws` WebSocket: `{"status":...}` now and on each change; closes on paid/expired.

Status: `pending` -> `detected` (mempool) -> `paid` (mined, sum >= amount) or `expired`. A late payment still marks an expired invoice paid.

Webhook on paid: POST `{invoice_id, status, amount_zat, received_zat, txid}` with `X-Lunaz-Signature` = hex HMAC-SHA256(body, webhook_secret).

## Notes

Reorgs are not handled. Tests: `cargo test`.
