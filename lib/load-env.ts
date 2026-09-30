/**
 * Load `.env` if present. Does not fail when the file is missing
 * (so `npm run demo` works after a fresh clone before `cp .env.example .env`).
 * Existing process.env values win (CI / shell exports).
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export function loadEnvFile(filePath = resolve(process.cwd(), '.env')): boolean {
  if (!existsSync(filePath)) return false;

  const text = readFileSync(filePath, 'utf8');
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;

    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
  return true;
}

loadEnvFile();
