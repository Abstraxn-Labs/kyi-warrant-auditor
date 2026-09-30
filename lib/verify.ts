/**
 * Receipt verification pipeline for independent auditors.
 * Uses @abstraxn/warrant-verifier — no Warrant API key required for the crypto check.
 */
import { readFileSync, existsSync } from 'node:fs';
import {
  canonicalize,
  verifyReceiptJson,
  verifyMerkleProof,
  receiptLeafBytes32,
  verifyMandateOnchain,
  verifyReceiptOnchain,
} from '@abstraxn/warrant-verifier';

export type ReceiptPayload = Record<string, unknown> & {
  receipt_id?: string;
  verdict?: string;
  reasons?: unknown;
  amount?: number;
  action?: {
    action_type?: string;
    domain?: string;
    value?: { amount?: number; currency?: string };
  };
  onchain?: {
    status?: string;
    leafHash?: string;
    batchId?: string | null;
    leafIndex?: number | null;
    proof?: string[] | null;
    root?: string | null;
    txHash?: string | null;
    manifestHash?: string | null;
    chainId?: number | null;
  } | null;
};

const CHAIN_RPC: Record<number, string> = {
  80002: 'https://poly-amoy-testnet.api.pocket.network',
  84532: 'https://sepolia.base.org',
  8453: 'https://mainnet.base.org',
};

const CHAIN_NAME: Record<number, string> = {
  80002: 'Polygon Amoy',
  84532: 'Base Sepolia',
  8453: 'Base',
};

export function resolveRpcForChain(
  chainId: number,
  envFallback?: string,
): string {
  const specific = process.env[`WARRANT_RPC_URL_${chainId}`]?.trim();
  if (specific) return specific;
  if (CHAIN_RPC[chainId]) return CHAIN_RPC[chainId];
  return envFallback?.trim() || CHAIN_RPC[80002];
}

export function chainLabel(chainId: number): string {
  return CHAIN_NAME[chainId] ?? `chain ${chainId}`;
}

export type VerifyStepId =
  | 'fetch'
  | 'ed25519'
  | 'tamper'
  | 'merkle'
  | 'receipt_log'
  | 'mandate_registry';

export type VerifyStepStatus = 'pending' | 'running' | 'ok' | 'fail' | 'skip';

export type VerifyStep = {
  id: VerifyStepId;
  title: string;
  status: VerifyStepStatus;
  summary: string;
  detail?: string;
};

export type VerifyConfig = {
  warrantUrl: string;
  apiKey: string;
  rpcUrl: string;
  chainId: number;
  mandateRegistry: string;
  receiptLog: string;
  onchain: boolean;
  mandateId?: string;
  mandateContentHash?: string;
  publicKeyFile?: string;
  publicKeyHex?: string;
};

export type VerifyInput = {
  receiptId?: string;
  receipt?: ReceiptPayload;
  tamper?: boolean;
  publicKeyHex?: string;
};

export type VerifyReport = {
  receiptId: string;
  verdict: string;
  reasons: string;
  leaf: string;
  pubkeyKeyId?: string;
  pubkeyPreview?: string;
  txHash?: string;
  batchId?: string | null;
  chainId?: number;
  steps: VerifyStep[];
  receipt: ReceiptPayload;
  overallValid: boolean;
  /** Present only for tamper demo — true if forged receipt was rejected. */
  tamperCaught?: boolean;
};

export function loadConfigFromEnv(): VerifyConfig {
  return {
    warrantUrl: (
      process.env.WARRANT_URL ?? 'https://api-warrant.abstraxn.com'
    ).replace(/\/$/, ''),
    apiKey: process.env.ABSTRAXN_API_KEY?.trim() || '',
    rpcUrl:
      process.env.WARRANT_RPC_URL?.trim() ||
      'https://poly-amoy-testnet.api.pocket.network',
    chainId: Number(process.env.WARRANT_CHAIN_ID ?? '80002'),
    mandateRegistry:
      process.env.WARRANT_MANDATE_REGISTRY?.trim() ||
      '0x9f13744Cd7ca5b7851Aa21C9607617a83904A3b5',
    receiptLog:
      process.env.WARRANT_RECEIPT_LOG?.trim() ||
      '0x65eDCae32a92eCCC47b7f0CBa06f2F924ce3A45E',
    onchain: !['0', 'false', 'off', 'no'].includes(
      (process.env.ONCHAIN ?? '1').trim().toLowerCase(),
    ),
    mandateId: process.env.MANDATE_ID?.trim() || undefined,
    mandateContentHash: process.env.MANDATE_CONTENT_HASH?.trim() || undefined,
    publicKeyFile: process.env.PUBLIC_KEY_FILE?.trim() || undefined,
    publicKeyHex: process.env.PUBLIC_KEY_HEX?.trim() || undefined,
  };
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/i, '');
  if (clean.length % 2 !== 0) throw new Error('Invalid hex public key');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function stripOnchain(receipt: ReceiptPayload): Record<string, unknown> {
  const { onchain: _onchain, ...rest } = receipt;
  return rest;
}

async function warrantGet(
  config: VerifyConfig,
  path: string,
): Promise<unknown> {
  const headers: Record<string, string> = {};
  if (config.apiKey) headers['x-api-key'] = config.apiKey;
  const res = await fetch(`${config.warrantUrl}${path}`, { headers });
  const json = (await res.json()) as {
    error?: boolean;
    message?: string;
    result?: unknown;
  };
  if (!res.ok || json.error) {
    throw new Error(json.message || `Warrant ${path} failed (${res.status})`);
  }
  return json.result;
}

export async function loadPublicKey(
  config: VerifyConfig,
  input?: Pick<VerifyInput, 'publicKeyHex'>,
): Promise<{ bytes: Uint8Array; keyId?: string; preview: string; hex: string }> {
  const hex =
    input?.publicKeyHex?.trim() ||
    config.publicKeyHex?.trim() ||
    '';
  if (hex) {
    return {
      bytes: hexToBytes(hex),
      preview: hex.slice(0, 16) + '…',
      hex,
    };
  }

  if (config.publicKeyFile && existsSync(config.publicKeyFile)) {
    const raw = readFileSync(config.publicKeyFile, 'utf8').trim();
    if (raw.startsWith('{')) {
      const j = JSON.parse(raw) as {
        public_key_hex?: string;
        publicKey?: string;
        hex?: string;
        key_id?: string;
      };
      const h = j.public_key_hex ?? j.publicKey ?? j.hex;
      if (!h) throw new Error('JSON key file missing public_key_hex');
      return {
        bytes: hexToBytes(h),
        keyId: j.key_id,
        preview: h.slice(0, 16) + '…',
        hex: h,
      };
    }
    return {
      bytes: hexToBytes(raw),
      preview: raw.slice(0, 16) + '…',
      hex: raw,
    };
  }

  try {
    const key = (await warrantGet(config, '/v1/warrant/keys/receipt')) as {
      public_key_hex?: string;
      key_id?: string;
    };
    if (!key.public_key_hex) {
      throw new Error('keys/receipt missing public_key_hex');
    }
    return {
      bytes: hexToBytes(key.public_key_hex),
      keyId: key.key_id,
      preview: key.public_key_hex.slice(0, 16) + '…',
      hex: key.public_key_hex,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Could not load Warrant public key (${msg}). ` +
        `Set PUBLIC_KEY_HEX in .env (recommended for offline audits).`,
    );
  }
}

async function loadReceipt(
  config: VerifyConfig,
  input: VerifyInput,
): Promise<ReceiptPayload> {
  if (input.receipt) return input.receipt;
  const id = input.receiptId?.trim();
  if (!id) {
    throw new Error('Paste or upload a receipt JSON file');
  }
  return (await warrantGet(
    config,
    `/v1/warrant/receipts/${encodeURIComponent(id)}`,
  )) as ReceiptPayload;
}

function step(
  id: VerifyStepId,
  title: string,
  status: VerifyStepStatus,
  summary: string,
  detail?: string,
): VerifyStep {
  return { id, title, status, summary, detail };
}

export async function runVerification(
  config: VerifyConfig,
  input: VerifyInput,
): Promise<VerifyReport> {
  const steps: VerifyStep[] = [];

  steps.push(
    step('fetch', 'Load receipt', 'running', 'Reading pasted / uploaded JSON'),
  );

  const receipt = await loadReceipt(config, input);
  const receiptId = String(receipt.receipt_id ?? input.receiptId ?? '?');
  steps[0] = step(
    'fetch',
    'Load receipt',
    'ok',
    input.receipt
      ? `Pasted JSON — ${receiptId}`
      : `Fetched ${receiptId}`,
    receipt.verdict ? `verdict=${receipt.verdict}` : undefined,
  );

  const { bytes: publicKey, keyId, preview } = await loadPublicKey(
    config,
    input,
  );
  const signedBody = stripOnchain(receipt);

  // Tamper demo: mutate amount, verify ONLY the forged copy (should fail).
  if (input.tamper) {
    const mutated = {
      ...signedBody,
      amount:
        typeof signedBody.amount === 'number'
          ? (signedBody.amount as number) + 1
          : 999999,
      action:
        signedBody.action && typeof signedBody.action === 'object'
          ? {
              ...(signedBody.action as Record<string, unknown>),
              value: {
                ...((signedBody.action as { value?: Record<string, unknown> })
                  .value ?? {}),
                amount:
                  Number(
                    (signedBody.action as { value?: { amount?: number } })
                      ?.value?.amount ?? 0,
                  ) + 1,
              },
            }
          : signedBody.action,
    };

    steps.push(
      step(
        'tamper',
        'Tamper',
        'ok',
        'Changed amount (+1) — original signature kept',
      ),
    );

    const ed = await verifyReceiptJson(mutated, publicKey);
    const caught = !ed.valid;
    steps.push(
      step(
        'ed25519',
        'Ed25519 signature',
        'fail',
        caught
          ? 'Invalid — forged amount rejected'
          : 'Unexpected: forged receipt still verified',
        ed.error || ed.reasons,
      ),
    );

    // Don't run Merkle / on-chain on a forged body — signature already failed.
    steps.push(
      step(
        'merkle',
        'Merkle inclusion',
        'skip',
        'Skipped — signature invalid after tamper',
      ),
    );
    if (config.onchain) {
      steps.push(
        step(
          'receipt_log',
          'ReceiptLog (on-chain)',
          'skip',
          'Skipped — signature invalid after tamper',
        ),
      );
    }

    const leaf =
      receipt.onchain?.leafHash ||
      receiptLeafBytes32(canonicalize(signedBody));

    return {
      receiptId,
      verdict: String(receipt.verdict ?? ed.verdict ?? '?'),
      reasons: ed.reasons || '—',
      leaf,
      pubkeyKeyId: keyId,
      pubkeyPreview: preview,
      txHash: receipt.onchain?.txHash ?? undefined,
      batchId: receipt.onchain?.batchId,
      chainId:
        receipt.onchain?.chainId && receipt.onchain.chainId > 0
          ? receipt.onchain.chainId
          : config.chainId,
      steps,
      receipt,
      // Forged receipt is never "valid". tamperCaught = forge was rejected.
      overallValid: false,
      tamperCaught: caught,
    };
  }

  const ed = await verifyReceiptJson(signedBody, publicKey);
  steps.push(
    step(
      'ed25519',
      'Ed25519 signature',
      ed.valid ? 'ok' : 'fail',
      ed.valid
        ? `Authentic — verdict=${ed.verdict}`
        : 'Invalid signature',
      ed.reasons || ed.error,
    ),
  );

  const onchain = receipt.onchain;
  const leaf =
    onchain?.leafHash || receiptLeafBytes32(canonicalize(signedBody));

  const verifyChainId =
    onchain?.chainId && onchain.chainId > 0
      ? onchain.chainId
      : config.chainId;
  const verifyRpc = resolveRpcForChain(verifyChainId, config.rpcUrl);

  if (onchain?.root && onchain.proof) {
    const merkleOk = verifyMerkleProof({
      leaf,
      proof: onchain.proof,
      root: onchain.root,
    });
    steps.push(
      step(
        'merkle',
        'Merkle inclusion',
        merkleOk ? 'ok' : 'fail',
        merkleOk
          ? 'Receipt belongs in published batch tree'
          : 'Merkle proof does not match root',
        `root=${onchain.root.slice(0, 22)}…`,
      ),
    );
  } else {
    steps.push(
      step(
        'merkle',
        'Merkle inclusion',
        'skip',
        'No proof/root yet — receipt batch may still be pending',
      ),
    );
  }

  if (config.onchain && onchain?.proof && (onchain.batchId || onchain.root)) {
    const rpc = await verifyReceiptOnchain({
      rpcUrl: verifyRpc,
      receiptLog: config.receiptLog,
      leaf,
      proof: onchain.proof,
      batchId: onchain.batchId,
      root: onchain.root,
      chainId: verifyChainId,
    });

    let detail =
      rpc.error ?? onchain.txHash ?? undefined;
    if (!rpc.included && !rpc.error) {
      // Help diagnose wrong-chain / wrong-batch vs proof issues
      try {
        const { Contract, JsonRpcProvider } = await import('ethers');
        const provider = new JsonRpcProvider(verifyRpc, verifyChainId);
        const log = new Contract(
          config.receiptLog,
          ['function rootOf(uint256 batchId) view returns (bytes32)'],
          provider,
        );
        if (onchain.batchId != null && onchain.batchId !== '') {
          const onchainRoot = String(await log.rootOf(onchain.batchId));
          const want = String(onchain.root ?? '').toLowerCase();
          const got = onchainRoot.toLowerCase();
          if (want && got && want !== got) {
            detail =
              `batch ${onchain.batchId} on ${chainLabel(verifyChainId)} has different root ` +
              `(chain=${onchainRoot.slice(0, 18)}… receipt=${String(onchain.root).slice(0, 18)}…). ` +
              `Wrong batch or this receipt was anchored on another chain. ` +
              (onchain.txHash ? `tx=${onchain.txHash}` : '');
          } else {
            detail =
              `Leaf not in batch ${onchain.batchId} on ${chainLabel(verifyChainId)} ` +
              `(contract ${config.receiptLog}). ` +
              (onchain.txHash ? `tx=${onchain.txHash}` : '');
          }
        }
      } catch (err) {
        detail =
          (err instanceof Error ? err.message : String(err)) +
          (onchain.txHash ? ` · tx=${onchain.txHash}` : '');
      }
    }

    steps.push(
      step(
        'receipt_log',
        'ReceiptLog (on-chain)',
        rpc.ok && rpc.included ? 'ok' : 'fail',
        rpc.included
          ? `Anchored on ${chainLabel(verifyChainId)} — batch ${rpc.batchId ?? onchain.batchId ?? '?'}`
          : `Not found on ReceiptLog (${chainLabel(verifyChainId)})`,
        detail,
      ),
    );
  } else if (config.onchain) {
    steps.push(
      step(
        'receipt_log',
        'ReceiptLog (on-chain)',
        'skip',
        'Skipped — wait for batch worker to publish',
      ),
    );
  } else {
    steps.push(
      step(
        'receipt_log',
        'ReceiptLog (on-chain)',
        'skip',
        'Offline mode — RPC checks disabled',
      ),
    );
  }

  if (config.onchain && config.mandateId && config.mandateContentHash) {
    const m = await verifyMandateOnchain({
      rpcUrl: verifyRpc,
      mandateRegistry: config.mandateRegistry,
      mandateId: config.mandateId,
      contentHashHex: config.mandateContentHash,
      chainId: verifyChainId,
    });
    steps.push(
      step(
        'mandate_registry',
        'MandateRegistry',
        m.ok && m.matches && m.active ? 'ok' : 'fail',
        m.matches && m.active
          ? `Mandate hash matches on ${chainLabel(verifyChainId)}`
          : 'Mandate mismatch or inactive',
        m.error,
      ),
    );
  }

  return {
    receiptId,
    verdict: ed.verdict,
    reasons: ed.reasons || '—',
    leaf,
    pubkeyKeyId: keyId,
    pubkeyPreview: preview,
    txHash: onchain?.txHash ?? undefined,
    batchId: onchain?.batchId,
    chainId: verifyChainId,
    steps,
    receipt,
    overallValid: ed.valid,
  };
}
