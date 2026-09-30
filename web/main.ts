type VerifyStep = {
  id: string;
  title: string;
  status: 'pending' | 'running' | 'ok' | 'fail' | 'skip';
  summary: string;
  detail?: string;
};

type VerifyReport = {
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
  receipt: Record<string, unknown>;
  overallValid: boolean;
  tamperCaught?: boolean;
};

type ValidationResult =
  | { ok: true; receipt: Record<string, unknown> }
  | { ok: false; error: string };

const MAX_RECEIPT_BYTES = 512 * 1024; // 512 KB
const HEX_RE = /^[0-9a-fA-F]+$/;

const receiptJsonIn = document.getElementById('receiptJsonIn') as HTMLTextAreaElement;
const publicKeyHexEl = document.getElementById('publicKeyHex') as HTMLTextAreaElement;
const onchainEl = document.getElementById('onchain') as HTMLInputElement;
const receiptFile = document.getElementById('receiptFile') as HTMLInputElement;
const verifyBtn = document.getElementById('verifyBtn') as HTMLButtonElement;
const tamperBtn = document.getElementById('tamperBtn') as HTMLButtonElement;
const parseErr = document.getElementById('parseErr')!;
const pubkeyErr = document.getElementById('pubkeyErr')!;
const errEl = document.getElementById('err')!;
const stepsEl = document.getElementById('steps')!;
const verdictBanner = document.getElementById('verdictBanner')!;
const verdictLabel = document.getElementById('verdictLabel')!;
const verdictReason = document.getElementById('verdictReason')!;
const metaBlock = document.getElementById('metaBlock')!;
const metaList = document.getElementById('metaList')!;
const receiptJson = document.getElementById('receiptJson')!;
const setupNote = document.getElementById('setupNote')!;
const storyCard = document.getElementById('storyCard')!;
const storyLabel = document.getElementById('storyLabel')!;
const storyVerdict = document.getElementById('storyVerdict')!;
const storyReason = document.getElementById('storyReason')!;
const storyAction = document.getElementById('storyAction')!;
const storyId = document.getElementById('storyId')!;
const actionRow = document.getElementById('actionRow')!;
const flowRow = document.getElementById('flowRow')!;
const resultsPanel = document.getElementById('resultsPanel')!;
const emptyResults = document.getElementById('emptyResults')!;

const FLOW_STEPS = ['fetch', 'ed25519', 'merkle', 'receipt_log'];

const ICON: Record<string, string> = {
  ok: '✓',
  fail: '✕',
  skip: '—',
  running: '…',
  pending: '○',
};

let serverReady = true;

function explorerTxUrl(hash: string, chainId?: number): string {
  if (chainId === 84532) return `https://sepolia.basescan.org/tx/${hash}`;
  if (chainId === 8453) return `https://basescan.org/tx/${hash}`;
  return `https://amoy.polygonscan.com/tx/${hash}`;
}

function chainName(chainId?: number): string {
  if (chainId === 84532) return 'Base Sepolia';
  if (chainId === 8453) return 'Base';
  if (chainId === 80002) return 'Polygon Amoy';
  return chainId ? `chain ${chainId}` : '—';
}

function setFlowState(stepId: string, state: 'active' | 'ok' | 'fail' | 'skip' | '') {
  for (const id of FLOW_STEPS) {
    const node = document.querySelector(`.flow-node[data-step="${id}"]`);
    if (!node) continue;
    node.classList.remove('active', 'done-ok', 'done-fail', 'done-skip');
    if (id === stepId && state === 'active') node.classList.add('active');
    if (id === stepId && state === 'ok') node.classList.add('done-ok');
    if (id === stepId && state === 'fail') node.classList.add('done-fail');
    if (id === stepId && state === 'skip') node.classList.add('done-skip');
  }
}

function resetFlow() {
  for (const id of FLOW_STEPS) {
    document
      .querySelector(`.flow-node[data-step="${id}"]`)
      ?.classList.remove('active', 'done-ok', 'done-fail', 'done-skip');
  }
}

function reasonCode(receipt: Record<string, unknown>): string {
  const reasons = receipt.reasons;
  if (Array.isArray(reasons) && reasons[0] && typeof reasons[0] === 'object') {
    const r = reasons[0] as { code?: string };
    return r.code ?? '—';
  }
  if (typeof reasons === 'string') return reasons;
  return '—';
}

function actionLabel(receipt: Record<string, unknown>): string {
  const action = receipt.action as
    | { action_type?: string; value?: { amount?: number; currency?: string }; domain?: string }
    | undefined;
  if (action?.value?.amount != null) {
    return `${action.action_type ?? 'action'} · ${action.value.amount} ${action.value.currency ?? ''}`.trim();
  }
  return String(action?.domain ?? receipt.domain ?? '—');
}

function isHex(value: string): boolean {
  return HEX_RE.test(value);
}

/** Validate pasted/uploaded receipt shape before calling the API. */
function validateReceipt(raw: string): ValidationResult {
  if (!raw.trim()) {
    return { ok: false, error: 'Paste or upload a receipt JSON file.' };
  }
  if (new TextEncoder().encode(raw).length > MAX_RECEIPT_BYTES) {
    return { ok: false, error: 'Receipt JSON is too large (max 512 KB).' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, error: 'Invalid JSON.' };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: 'Receipt must be a JSON object.' };
  }

  const receipt = parsed as Record<string, unknown>;
  const missing: string[] = [];

  if (typeof receipt.receipt_id !== 'string' || !receipt.receipt_id.trim()) {
    missing.push('receipt_id');
  }
  if (typeof receipt.verdict !== 'string' || !receipt.verdict.trim()) {
    missing.push('verdict');
  }
  if (!receipt.signature || typeof receipt.signature !== 'object' || Array.isArray(receipt.signature)) {
    missing.push('signature');
  }

  if (missing.length) {
    return {
      ok: false,
      error: `Missing required field${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}.`,
    };
  }

  const verdict = String(receipt.verdict).toUpperCase();
  if (verdict !== 'ALLOW' && verdict !== 'DENY') {
    return { ok: false, error: 'verdict must be ALLOW or DENY.' };
  }

  const signature = receipt.signature as Record<string, unknown>;
  if (typeof signature.sig !== 'string' || !signature.sig.trim()) {
    return { ok: false, error: 'signature.sig is required.' };
  }

  const sigHex = signature.sig.trim().replace(/^0x/i, '');
  if (!isHex(sigHex) || sigHex.length !== 128) {
    return {
      ok: false,
      error: 'signature.sig must be 128 hex characters (Ed25519).',
    };
  }

  if (signature.alg != null && String(signature.alg) !== 'Ed25519') {
    return { ok: false, error: 'signature.alg must be Ed25519.' };
  }

  if (receipt.onchain != null) {
    if (typeof receipt.onchain !== 'object' || Array.isArray(receipt.onchain)) {
      return { ok: false, error: 'onchain must be an object when present.' };
    }
  }

  return { ok: true, receipt };
}

function validatePublicKey(raw: string): string | null {
  const hex = raw.trim().replace(/^0x/i, '');
  if (!hex) return null; // optional — server .env
  if (!isHex(hex)) return 'Public key must be hex.';
  if (hex.length !== 64) {
    return 'Public key must be 64 hex characters (Ed25519).';
  }
  return null;
}

function setActionEnabled(enabled: boolean) {
  verifyBtn.disabled = !enabled;
  tamperBtn.disabled = !enabled;
}

function fillStory(receipt: Record<string, unknown>, label = 'Receipt') {
  const verdict = String(receipt.verdict ?? '—');
  storyLabel.textContent = label;
  storyVerdict.textContent = verdict;
  storyVerdict.className = verdict === 'ALLOW' ? 'ok-text' : 'deny-text';
  storyReason.textContent = reasonCode(receipt);
  storyAction.textContent = actionLabel(receipt);
  storyId.textContent = String(receipt.receipt_id ?? '—');

  storyCard.hidden = false;
  actionRow.hidden = false;
  flowRow.hidden = false;
}

function hideReceiptUi() {
  storyCard.hidden = true;
  actionRow.hidden = true;
  flowRow.hidden = true;
}

function clearResults() {
  errEl.textContent = '';
  stepsEl.innerHTML = '';
  verdictBanner.hidden = true;
  metaBlock.hidden = true;
  resultsPanel.hidden = true;
  emptyResults.hidden = false;
  resetFlow();
}

function tryParseReceipt(): Record<string, unknown> | null {
  parseErr.textContent = '';
  receiptJsonIn.classList.remove('field-error');

  const raw = receiptJsonIn.value;
  if (!raw.trim()) {
    hideReceiptUi();
    clearResults();
    return null;
  }

  const result = validateReceipt(raw);
  if (!result.ok) {
    parseErr.textContent = result.error;
    receiptJsonIn.classList.add('field-error');
    hideReceiptUi();
    clearResults();
    return null;
  }

  fillStory(result.receipt);
  setActionEnabled(serverReady && validatePublicKey(publicKeyHexEl.value) === null);
  return result.receipt;
}

function validatePubkeyField(): boolean {
  pubkeyErr.textContent = '';
  publicKeyHexEl.classList.remove('field-error');
  const err = validatePublicKey(publicKeyHexEl.value);
  if (err) {
    pubkeyErr.textContent = err;
    publicKeyHexEl.classList.add('field-error');
    setActionEnabled(false);
    return false;
  }
  const receiptOk = Boolean(tryParseReceiptQuiet());
  setActionEnabled(serverReady && receiptOk);
  return true;
}

/** Re-validate receipt without wiping pubkey errors. */
function tryParseReceiptQuiet(): Record<string, unknown> | null {
  const raw = receiptJsonIn.value;
  if (!raw.trim()) return null;
  const result = validateReceipt(raw);
  return result.ok ? result.receipt : null;
}

function renderStep(step: VerifyStep, index: number, chainId?: number) {
  const li = document.createElement('li');
  li.className = `step-card ${step.status}`;
  li.style.animationDelay = `${index * 80}ms`;

  const mapFlow: Record<string, string> = {
    fetch: 'fetch',
    ed25519: 'ed25519',
    tamper: 'ed25519',
    merkle: 'merkle',
    receipt_log: 'receipt_log',
    mandate_registry: 'receipt_log',
  };
  const flowId = mapFlow[step.id];
  if (flowId && step.status !== 'pending' && step.status !== 'running') {
    setFlowState(
      flowId,
      step.status === 'ok' ? 'ok' : step.status === 'skip' ? 'skip' : 'fail',
    );
  }
  if (flowId && step.status === 'running') setFlowState(flowId, 'active');

  let detailHtml = step.detail ?? '';
  if (step.id === 'receipt_log' && detailHtml.startsWith('0x') && detailHtml.length > 20) {
    detailHtml = `<a href="${explorerTxUrl(detailHtml, chainId)}" target="_blank" rel="noopener">${detailHtml}</a>`;
  }

  li.innerHTML = `
    <div class="step-icon">${ICON[step.status] ?? '○'}</div>
    <div>
      <p class="step-title">${step.title}</p>
      <p class="step-summary">${step.summary}</p>
      ${detailHtml ? `<p class="step-detail">${detailHtml}</p>` : ''}
    </div>
  `;
  return li;
}

function showVerdict(report: VerifyReport, tamper: boolean) {
  verdictBanner.hidden = false;
  verdictBanner.classList.remove('allow', 'deny', 'invalid');

  if (tamper) {
    if (report.tamperCaught !== false) {
      verdictBanner.classList.add('invalid');
      verdictLabel.textContent = 'Tamper caught — signature INVALID';
      verdictReason.textContent =
        'Amount was changed. Signature no longer matches. Forgery rejected.';
      return;
    }
    verdictBanner.classList.add('invalid');
    verdictLabel.textContent = 'Unexpected — forged receipt still verified';
    verdictReason.textContent = 'Tamper check failed — signature should have been rejected.';
    return;
  }

  if (!report.overallValid) {
    verdictBanner.classList.add('invalid');
    verdictLabel.textContent = 'Invalid receipt';
    verdictReason.textContent = 'Signature verification failed';
    return;
  }

  const v = report.verdict.toUpperCase();
  if (v === 'ALLOW') {
    verdictBanner.classList.add('allow');
    verdictLabel.textContent = 'Real receipt — ALLOW';
  } else if (v === 'DENY') {
    verdictBanner.classList.add('deny');
    verdictLabel.textContent = 'Real receipt — DENY';
  } else {
    verdictLabel.textContent = `Real receipt — ${v}`;
  }
  verdictReason.textContent = `Policy reason: ${report.reasons}`;
}

function showMeta(report: VerifyReport) {
  metaBlock.hidden = false;
  const tx = report.txHash
    ? `<a href="${explorerTxUrl(report.txHash, report.chainId)}" target="_blank" rel="noopener">${report.txHash}</a>`
    : '—';

  metaList.innerHTML = `
    <dt>Receipt</dt><dd>${report.receiptId}</dd>
    <dt>Leaf</dt><dd>${report.leaf}</dd>
    <dt>Pubkey</dt><dd>${report.pubkeyKeyId ?? '?'} · ${report.pubkeyPreview ?? ''}</dd>
    <dt>Chain</dt><dd>${chainName(report.chainId)}</dd>
    <dt>Batch</dt><dd>${report.batchId ?? '—'}</dd>
    <dt>Tx</dt><dd>${tx}</dd>
  `;
  receiptJson.textContent = JSON.stringify(report.receipt, null, 2);
}

async function runVerify(tamper: boolean) {
  const receipt = tryParseReceipt();
  if (!receipt) {
    errEl.textContent = parseErr.textContent || 'Paste or upload a valid receipt JSON.';
    return;
  }

  const pkErr = validatePublicKey(publicKeyHexEl.value);
  if (pkErr) {
    pubkeyErr.textContent = pkErr;
    publicKeyHexEl.classList.add('field-error');
    errEl.textContent = pkErr;
    return;
  }

  errEl.textContent = '';
  stepsEl.innerHTML = '';
  verdictBanner.hidden = true;
  metaBlock.hidden = true;
  resultsPanel.hidden = false;
  emptyResults.hidden = true;
  resetFlow();
  setActionEnabled(false);

  setFlowState('fetch', 'active');
  stepsEl.appendChild(
    renderStep(
      {
        id: 'fetch',
        title: 'Loading…',
        status: 'running',
        summary: tamper ? 'Mutating amount, then verifying' : 'Checking signature',
      },
      0,
    ),
  );

  try {
    const body: Record<string, unknown> = {
      receipt,
      onchain: onchainEl.checked,
      tamper,
    };
    const pk = publicKeyHexEl.value.trim();
    if (pk) body.publicKeyHex = pk;

    const res = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as VerifyReport & { error?: string };
    if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);

    stepsEl.innerHTML = '';
    json.steps.forEach((s, i) => stepsEl.appendChild(renderStep(s, i, json.chainId)));
    showVerdict(json, tamper);
    showMeta(json);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    errEl.textContent = msg;
    stepsEl.innerHTML = '';
    verdictBanner.hidden = false;
    verdictBanner.classList.remove('allow', 'deny', 'invalid');
    verdictBanner.classList.add('invalid');
    verdictLabel.textContent = 'Verification failed';
    verdictReason.textContent = msg;
    setFlowState('fetch', 'fail');
  } finally {
    setActionEnabled(serverReady && Boolean(tryParseReceiptQuiet()) && !validatePublicKey(publicKeyHexEl.value));
  }
}

async function checkStatus() {
  try {
    const res = await fetch('/api/status');
    const d = (await res.json()) as {
      ok: boolean;
      message?: string;
      onchainDefault: boolean;
    };
    onchainEl.checked = d.onchainDefault;
    serverReady = d.ok;
    if (!d.ok) {
      setupNote.hidden = false;
      setupNote.textContent =
        d.message ||
        'Set PUBLIC_KEY_HEX in warrant-auditor/.env, then restart npm run demo';
      setActionEnabled(false);
    } else {
      setupNote.hidden = true;
    }
  } catch {
    serverReady = false;
    setupNote.hidden = false;
    setupNote.textContent =
      'Cannot reach auditor API (port 3020). Run: npm run demo';
    setActionEnabled(false);
  }
}

receiptJsonIn.addEventListener('input', () => {
  tryParseReceipt();
  validatePubkeyField();
});

receiptJsonIn.addEventListener('blur', () => {
  tryParseReceipt();
});

publicKeyHexEl.addEventListener('input', () => {
  validatePubkeyField();
});

receiptFile.addEventListener('change', () => {
  const file = receiptFile.files?.[0];
  if (!file) return;

  const name = file.name.toLowerCase();
  const isJson =
    name.endsWith('.json') ||
    file.type === 'application/json' ||
    file.type === 'text/json';
  if (!isJson) {
    parseErr.textContent = 'Upload a .json receipt file.';
    receiptJsonIn.classList.add('field-error');
    receiptFile.value = '';
    hideReceiptUi();
    return;
  }

  if (file.size > MAX_RECEIPT_BYTES) {
    parseErr.textContent = 'File too large (max 512 KB).';
    receiptJsonIn.classList.add('field-error');
    receiptFile.value = '';
    hideReceiptUi();
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    receiptJsonIn.value = String(reader.result ?? '');
    tryParseReceipt();
    clearResults();
  };
  reader.onerror = () => {
    parseErr.textContent = 'Could not read file.';
    receiptJsonIn.classList.add('field-error');
  };
  reader.readAsText(file);
});

verifyBtn.addEventListener('click', () => void runVerify(false));
tamperBtn.addEventListener('click', () => void runVerify(true));

void checkStatus();
