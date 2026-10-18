# Lunaz core-service

The gateway behind Lunaz, a non-custodial payment gateway for shielded Zcash. It creates invoices, watches the chain for payments, runs cross-chain swaps and sends webhooks. It holds incoming viewing keys only, so it can see payments but cannot spend funds.

## How it works

- **Invoice addresses.** A merchant registers an incoming viewing key once. Each invoice gets its own shielded address, derived from that key, so addresses never link.
- **Watcher.** The service reads compact blocks from lightwalletd and trial-decrypts them with each merchant's viewing key. It also scans the mempool, so a payment shows as `detected` in seconds and `paid` after one confirmation.
- **Cross-chain.** A buyer can pay in another asset through NEAR Intents 1Click, which delivers shielded ZEC to the invoice address. The watcher sees it like any other payment.
- **Fees.** The payment request carries a small Lunaz fee as a second output in the same transaction. Lunaz never holds the merchant's funds.
- **Webhooks.** Signed events for invoices, swaps and withdrawals, retried on failure.
- **Storage.** One SQLite file.

The API reference is in the [documentation](https://lunaz.alwaysbedream.dev/docs).

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
| `LUNAZ_FEE_BPS` | `50` | Lunaz per-payment fee in basis points, 0-1000 (50 = 0.5%); other values abort startup. Active only with `LUNAZ_BILLING_MERCHANT_ID` set |
| `LUNAZ_FEE_MIN_ZAT` | `1000` | minimum fee per invoice in zatoshi |
| `LUNAZ_INTERNAL_TOKEN` | unset | secret (>=32 chars) for `/v1/auth/exchange`; unset = endpoint returns 503; shorter aborts startup |
| `LUNAZ_BILLING_MERCHANT_ID` | unset | id of the treasury merchant that receives fees and fee settlements; the fee is charged only when it is set and that merchant has a viewing key. Unset = no fee, settle returns 503 |
| `LUNAZ_BILLING_SANDBOX` | unset | `1` enables `simulate-paid` (demos/tests) |
| `LUNAZ_DEV` | unset | `1` marks a local development instance: allows the dev options below on mainnet and logs a WARN listing them |
| `LUNAZ_ALLOW_MOCK_ON_MAINNET` | unset | `1` allows the mock off-ramp on mainnet without `LUNAZ_DEV` |
| `LUNAZ_WEBHOOK_ALLOW_HTTP` | unset | `1` also accepts plain `http://` webhook URLs (still public hosts, default port) |
| `LUNAZ_WEBHOOK_ALLOW_PRIVATE` | unset | development only: `1` allows webhooks to private/loopback addresses, any port, `http` |
| `LUNAZ_MAX_WS` | `2000` | maximum concurrent invoice WebSockets |
| `LUNAZ_SCAN_THREADS` | half the CPU cores (at least 1) | threads for trial decryption of blocks and mempool transactions, integer >= 1 (`1` = no extra threads); other values abort startup |
| `LUNAZ_LIMIT_NEW_XC_INVOICE_USD` | `200` | new accounts: largest cross-chain payment, USD. All `LUNAZ_LIMIT_*` values are whole numbers (others abort startup) and `0` disables that cap. A new account becomes established after `LUNAZ_LIMIT_EST_MIN_AGE_DAYS` days and `LUNAZ_LIMIT_EST_MIN_PAID` paid invoices with no outstanding fee; `merchants.verified=1` (set by hand) and the treasury merchant have no volume caps. Over a cap the API returns 403 `limit_exceeded` |
| `LUNAZ_LIMIT_NEW_XC_DAY_USD` | `300` | new accounts: cross-chain USD per rolling 24 h |
| `LUNAZ_LIMIT_NEW_XC_FIRST_USD` | `1000` | new accounts: cross-chain USD in total during the first `LUNAZ_LIMIT_EST_MIN_AGE_DAYS` days |
| `LUNAZ_LIMIT_NEW_ZEC_DAY_USD` | `1000` | new accounts: shielded invoice USD per rolling 24 h (not enforced while the ZEC price is unavailable) |
| `LUNAZ_LIMIT_EST_XC_INVOICE_USD` | `1000` | established accounts: largest cross-chain payment, USD |
| `LUNAZ_LIMIT_EST_XC_DAY_USD` | `3000` | established accounts: cross-chain USD per rolling 24 h |
| `LUNAZ_LIMIT_EST_XC_MONTH_USD` | `20000` | established accounts: cross-chain USD per rolling 30 days |
| `LUNAZ_LIMIT_INVOICES_DAY` | `500` | all accounts: invoices created per rolling 24 h |
| `LUNAZ_LIMIT_EST_MIN_AGE_DAYS` | `14` | account age in days to become established |
| `LUNAZ_LIMIT_EST_MIN_PAID` | `10` | paid invoices to become established |
| `RUST_LOG` | tracing default | log filter |

Mainnet guards: with `LUNAZ_NETWORK=main` the service refuses to start when `LUNAZ_BILLING_SANDBOX` is on, when the off-ramp is `mock` (the default) without `LUNAZ_ALLOW_MOCK_ON_MAINNET=1`, or when `LUNAZ_WEBHOOK_ALLOW_PRIVATE` is on, unless `LUNAZ_DEV=1` is set. Boolean variables accept `1`, `true`, `yes` or `on`.

## Run

    cargo run                      # testnet
    LUNAZ_NETWORK=main cargo run   # mainnet
    cargo test

With Docker:

    docker build -t lunaz-core .
    docker run -d -p 127.0.0.1:8080:8080 -v lunaz-data:/data -e LUNAZ_NETWORK=main lunaz-core

`GET /healthz` returns `200 ok` when the service is up.
