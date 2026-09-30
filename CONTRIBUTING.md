# Contributing to Warrant Auditor

Thanks for helping improve the open-source KYI Warrant receipt auditor.

## Development setup

```bash
git clone https://github.com/Abstraxn-Labs/kyi-warrant-auditor.git
cd kyi-warrant-auditor
cp .env.example .env
npm install
npm run demo
```

Open http://localhost:5180

`.env` is optional at runtime — scripts no longer crash if it is missing — but set `PUBLIC_KEY_HEX` for offline signature checks.

### Public key (by design)

Warrant’s **Ed25519 public key is public**. Auditors are supposed to have it.
Fetch it from:

```bash
curl -sS https://api-warrant.abstraxn.com/v1/warrant/keys/receipt
```

Put `result.public_key_hex` into `.env` as `PUBLIC_KEY_HEX`, or paste it under **Public key** in the UI.
Never commit private keys. Never commit your local `.env`.

## Scripts

| Command | Purpose |
|---------|---------|
| `npm run demo` | UI + local API |
| `npm run verify -- ./examples/sample-receipt.json` | CLI verify |
| `npm run verify -- ./file.json --tamper` | CLI tamper demo |
| `npm run build:web` | Production UI build |

## Pull requests

1. Keep the UI simple (paste/upload → preview → verify)
2. Prefer small, focused PRs
3. Run locally before opening a PR:
   - `npm run verify -- ./examples/sample-receipt.json`
   - `npm run verify -- ./examples/sample-receipt.json --tamper`
4. Do not commit secrets, API keys, or real production receipts with private data unless scrubbed

## Code of conduct

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
