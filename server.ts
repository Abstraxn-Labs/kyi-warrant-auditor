/**
 * Local auditor API — no Abstraxn account required for signature checks.
 * Public key comes from PUBLIC_KEY_HEX / file / public Warrant endpoint.
 */
import './lib/load-env.js';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadConfigFromEnv,
  loadPublicKey,
  runVerification,
  type ReceiptPayload,
  type VerifyConfig,
} from './lib/verify.js';

const PORT = Number(process.env.AUDITOR_PORT ?? '3020');
const ROOT = fileURLToPath(new URL('.', import.meta.url));

let cachedPublicKeyHex: string | null = null;

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw.trim()) return {};
  return JSON.parse(raw) as unknown;
}

async function resolvePublicKeyHex(config: VerifyConfig): Promise<string | null> {
  if (cachedPublicKeyHex) return cachedPublicKeyHex;
  try {
    const key = await loadPublicKey(config);
    cachedPublicKeyHex = key.hex;
    return key.hex;
  } catch {
    return null;
  }
}

function mergeConfig(body: Record<string, unknown>): VerifyConfig {
  const base = loadConfigFromEnv();
  return {
    ...base,
    apiKey:
      typeof body.apiKey === 'string' && body.apiKey.trim()
        ? body.apiKey.trim()
        : base.apiKey,
    publicKeyHex:
      typeof body.publicKeyHex === 'string' && body.publicKeyHex.trim()
        ? body.publicKeyHex.trim()
        : base.publicKeyHex,
    onchain:
      typeof body.onchain === 'boolean' ? body.onchain : base.onchain,
    mandateId:
      typeof body.mandateId === 'string' && body.mandateId.trim()
        ? body.mandateId.trim()
        : base.mandateId,
    mandateContentHash:
      typeof body.mandateContentHash === 'string' &&
      body.mandateContentHash.trim()
        ? body.mandateContentHash.trim()
        : base.mandateContentHash,
  };
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.ts': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
};

function serveStatic(pathname: string, res: ServerResponse): boolean {
  let file = pathname === '/' ? '/index.html' : pathname;
  const full = join(ROOT, 'web', file);
  if (!full.startsWith(join(ROOT, 'web'))) {
    sendJson(res, 403, { error: 'Forbidden' });
    return true;
  }
  if (!existsSync(full)) return false;
  const ext = extname(full);
  res.writeHead(200, { 'content-type': MIME[ext] ?? 'application/octet-stream' });
  res.end(readFileSync(full));
  return true;
}

const server = createServer(async (req, res) => {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url ?? '/', `http://${req.headers.host}`);

  if (url.pathname === '/api/status' && req.method === 'GET') {
    const cfg = loadConfigFromEnv();
    const publicKeyHex = await resolvePublicKeyHex(cfg);
    sendJson(res, 200, {
      ok: Boolean(publicKeyHex),
      hasPublicKey: Boolean(publicKeyHex),
      onchainDefault: cfg.onchain,
      warrantUrl: cfg.warrantUrl,
      chainId: cfg.chainId,
      message: publicKeyHex
        ? undefined
        : 'Set PUBLIC_KEY_HEX in .env (see .env.example), then restart.',
    });
    return;
  }

  if (url.pathname === '/api/verify' && req.method === 'POST') {
    try {
      const body = (await readBody(req)) as Record<string, unknown>;
      const config = mergeConfig(body);
      const publicKeyHex = await resolvePublicKeyHex(config);
      if (!publicKeyHex && !(typeof body.publicKeyHex === 'string' && body.publicKeyHex.trim())) {
        sendJson(res, 400, {
          error:
            'Public key not configured. Set PUBLIC_KEY_HEX in .env or paste it under Advanced.',
        });
        return;
      }

      let receipt: ReceiptPayload | undefined;
      if (body.receipt && typeof body.receipt === 'object') {
        receipt = body.receipt as ReceiptPayload;
      }

      const receiptId =
        typeof body.receiptId === 'string' ? body.receiptId : undefined;
      if (!receipt && !receiptId) {
        sendJson(res, 400, {
          error: 'Paste or upload a receipt JSON first',
        });
        return;
      }

      const report = await runVerification(
        {
          ...config,
          publicKeyHex:
            (typeof body.publicKeyHex === 'string' && body.publicKeyHex.trim()) ||
            publicKeyHex ||
            config.publicKeyHex,
        },
        {
          receiptId,
          receipt,
          tamper: Boolean(body.tamper),
          publicKeyHex:
            typeof body.publicKeyHex === 'string'
              ? body.publicKeyHex
              : publicKeyHex ?? undefined,
        },
      );
      sendJson(res, 200, report);
    } catch (err) {
      sendJson(res, 400, {
        error: err instanceof Error ? err.message : String(err),
      });
    }
    return;
  }

  if (req.method === 'GET' && serveStatic(url.pathname, res)) return;

  sendJson(res, 404, { error: 'Not found' });
});

server.listen(PORT, async () => {
  const cfg = loadConfigFromEnv();
  const key = await resolvePublicKeyHex(cfg);
  console.log(`Warrant auditor → http://localhost:${PORT}`);
  console.log(
    key
      ? 'Ready: public key loaded'
      : 'NOT READY: set PUBLIC_KEY_HEX in .env (see .env.example)',
  );
});
