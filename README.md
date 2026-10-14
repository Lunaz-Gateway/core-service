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

## Run

Configuration comes from `LUNAZ_*` environment variables. The defaults run on testnet with a local `./lunaz.db`.

    cargo run                      # testnet
    LUNAZ_NETWORK=main cargo run   # mainnet
    cargo test

With Docker:

    docker build -t lunaz-core .
    docker run -d -p 127.0.0.1:8080:8080 -v lunaz-data:/data -e LUNAZ_NETWORK=main lunaz-core

`GET /healthz` returns `200 ok` when the service is up.
