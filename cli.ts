/**
 * CLI: npm run verify -- path/to/receipt.json [--tamper]
 */
import './lib/load-env.js';
import { readFileSync } from 'node:fs';
import { loadConfigFromEnv, runVerification } from './lib/verify.js';

const args = process.argv.slice(2);
const tamper = args.includes('--tamper');
const file = args.find((a) => !a.startsWith('--'));

if (!file) {
  console.error('Usage: npm run verify -- ./examples/sample-receipt.json [--tamper]');
  process.exit(1);
}

const receipt = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
const config = loadConfigFromEnv();
const report = await runVerification(config, { receipt, tamper });

console.log(`receipt:  ${report.receiptId}`);
console.log(`verdict:  ${report.verdict}`);
console.log(`valid:    ${report.overallValid ? 'YES' : 'NO'}`);
if (tamper) {
  console.log(`tamper:   ${report.tamperCaught ? 'CAUGHT' : 'NOT CAUGHT'}`);
}
console.log(`reasons:  ${report.reasons}`);
console.log(`chain:    ${report.chainId ?? '—'}`);
console.log(`batch:    ${report.batchId ?? '—'}`);
console.log('--- steps ---');
for (const s of report.steps) {
  console.log(`[${s.status.padEnd(6)}] ${s.title}: ${s.summary}`);
  if (s.detail) console.log(`         ${s.detail}`);
}

if (tamper) {
  process.exit(report.tamperCaught ? 0 : 1);
}
process.exit(report.overallValid ? 0 : 1);
