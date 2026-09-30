# Warrant Auditor

[![CI](https://github.com/Abstraxn-Labs/kyi-warrant-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Abstraxn-Labs/kyi-warrant-auditor/actions/workflows/ci.yml)

Open-source **KYI Warrant receipt auditor**. Anyone can run it on their machine, paste or upload a signed receipt, and verify that it is authentic — without trusting Abstraxn’s servers alone.

```
Paste / upload receipt JSON
        ↓
Preview (verdict · why · action · id)
        ↓
Verify → Ed25519 · Merkle · optional on-chain
```

## What it checks

| Step | Meaning |
|------|---------|
| **Ed25519 signature** | Warrant signed this receipt; amount / verdict were not edited |
| **Merkle inclusion** | Receipt sits in the published batch tree |
| **ReceiptLog (on-chain)** | Batch is anchored on-chain (Polygon Amoy / Base / …) |

**ALLOW** and **DENY** are both valid signed receipts. A DENY that verifies is still *real*.

Auditors need:

1. The **receipt JSON** (from the agent, merchant, or export)
2. Warrant’s **public key** (same for all receipts until key rotation)

No Abstraxn API key is required for the crypto check.

---

## Quick start

**Requirements:** Node.js ≥ 18

```bash
git clone https://github.com/Abstraxn-Labs/kyi-warrant-auditor.git
cd kyi-warrant-auditor
cp .env.example .env
npm install
npm run demo
```

Open **http://localhost:5180**

`.env.example` already includes Warrant’s **public** `PUBLIC_KEY_HEX` (safe to share — not a secret).  
Copying it to `.env` is enough for signature checks. The same key is also in `examples/warrant-public-key.hex`.

Scripts still work if `.env` is missing (you can paste a key in the UI), but `.env` is recommended.
### UI flow

1. **Paste** receipt JSON or **Upload** a `.json` file
2. Review the receipt card (Verdict / Why / Action / Receipt id)
3. Click **Verify**
4. Optionally click **Tamper** to see a forged amount fail

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

CI runs install, sample receipt verify, tamper demo, and web build on every PR.

---

## Environment

See [`.env.example`](./.env.example). Important vars:

| Variable | Purpose |
|----------|---------|
| `PUBLIC_KEY_HEX` | Warrant Ed25519 public key (**included** in `.env.example`; public by design) |
| `PUBLIC_KEY_FILE` | Optional path to hex/JSON key file (e.g. `examples/warrant-public-key.hex`) |
| `WARRANT_URL` | Used only if the key must be fetched |
| `ONCHAIN` | `1` = also check ReceiptLog via RPC; `0` = signature/Merkle only |
| `WARRANT_CHAIN_ID` | Default chain if receipt has no `onchain.chainId` (`80002` Amoy, `84532` Base Sepolia) |
| `WARRANT_RPC_URL` | RPC for on-chain checks |
| `AUDITOR_PORT` | Local API port (default `3020`; UI on `5180`) |

---

## CLI (no browser)

```bash
npm run verify -- ./examples/sample-receipt.json
npm run verify -- ./my-receipt.json --tamper
```

---

## How verification works (simple)

1. Take the receipt body (**without** the `onchain` field)
2. Canonicalize JSON fields in a fixed order
3. Verify `signature.sig` with Warrant’s public key (Ed25519)
4. If present, check Merkle proof → batch root
5. If enabled, ask the chain whether that batch is in `ReceiptLog`

If someone changes amount, verdict, or reasons after signing, step 3 fails.

The public key is **shared** across all receipts signed by the current Warrant key (`signature.key_id`). Each receipt has its own signature and leaf hash.

---

## Project layout

```
warrant-auditor/
├── web/                 # Simple auditor UI
├── lib/verify.ts        # Verification pipeline
├── server.ts            # Local API (/api/verify, /api/status)
├── cli.ts               # Headless verify
├── examples/            # Sample receipt + Warrant public key
├── .env.example
└── README.md
```

Bundled public key: filled in `.env.example` as `PUBLIC_KEY_HEX`, and also at `examples/warrant-public-key.hex` (public by design; used by CI).

Core crypto lives in [`@abstraxn/warrant-verifier`](https://www.npmjs.com/package/@abstraxn/warrant-verifier).

---

## Security notes

- Never put Warrant **private** keys in this app — only the public key
- Prefer `PUBLIC_KEY_HEX` in `.env` so signature checks work offline
- On-chain checks need a public RPC; they do not need an Abstraxn account
- This tool audits authenticity of a receipt; it does not re-run policy

---

## License

MIT — see [LICENSE](./LICENSE)

## Community

- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Code of Conduct: [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- Conduct reports: security@abstraxn.com
