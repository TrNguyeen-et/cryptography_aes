/**
 * main.js — Frontend logic cho AES Visualizer
 *
 * Cac chuc nang chinh:
 *  - Xu ly tab navigation
 *  - Goi API Flask de ma hoa / giai ma / key schedule
 *  - Render verbose (hien thi tung vong AES voi state 4x4)
 *  - Sinh khoa / IV / Nonce ngau nhien
 */

'use strict';

// ─────────────────────────────────────────────────
//  TIEN ICH CHUNG (UTILITIES)
// ─────────────────────────────────────────────────

/** Hien thi toast ngan gon o goc man hinh */
function showToast(msg, duration = 2000) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), duration);
}

/** Copy noi dung mot element vao clipboard */
function copyText(id) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => showToast('Đã sao chép!'));
}

/** Hien thi/an element theo id */
function show(id)   { const e = document.getElementById(id); if (e) e.classList.remove('hidden'); }
function hide(id)   { const e = document.getElementById(id); if (e) e.classList.add('hidden');    }
function toggle(id, visible) { visible ? show(id) : hide(id); }

/** Lay gia tri input theo id, trim khoang trang */
function val(id)    { return document.getElementById(id)?.value.trim() || ''; }

/** Chuyen chuoi ASCII thanh HEX (cho API dung HEX lam chuan) */
function asciiToHex(str) {
  return Array.from(str).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join('');
}

/** Chuyen Base64 thanh HEX (cho API giai ma) */
function b64ToHex(b64) {
  const bin = atob(b64);
  return Array.from(bin).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join('');
}

/** Hien thi thong bao loi trong card */
function showError(containerId, msg) {
  const container = document.getElementById(containerId);
  if (!container) return;
  let errEl = container.querySelector('.error-banner');
  if (!errEl) {
    errEl = document.createElement('div');
    errEl.className = 'error-banner';
    container.appendChild(errEl);
  }
  errEl.textContent = '⚠ ' + msg;
  errEl.style.display = 'block';
}

function clearError(containerId) {
  const errEl = document.querySelector(`#${containerId} .error-banner`);
  if (errEl) errEl.style.display = 'none';
}

// ─────────────────────────────────────────────────
//  TAB NAVIGATION
// ─────────────────────────────────────────────────

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
    btn.classList.add('active');
    document.getElementById(`tab-${target}`)?.classList.remove('hidden');
  });
});

// ─────────────────────────────────────────────────
//  CHON CHE DO (MODE BUTTONS)
// ─────────────────────────────────────────────────

/** Ket noi cac nut mode trong mot container, xu ly hien/an IV/Nonce */
function initModeTabs(containerSel, ivRowId, nonceRowId, warnId) {
  const container = document.querySelector(containerSel);
  if (!container) return;

  container.querySelectorAll('.mode-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const mode = btn.dataset.mode;
      toggle(ivRowId,    mode === 'CBC');
      toggle(nonceRowId, mode === 'CTR');
      if (warnId) toggle(warnId, mode === 'ECB');
    });
  });
}

initModeTabs('#tab-encrypt .mode-tabs', 'enc-iv-row',  'enc-nonce-row', 'ecb-warn');
initModeTabs('#dec-mode-tabs',           'dec-iv-row',  'dec-nonce-row', null);

/** Lay mode dang active trong mot container */
function getActiveMode(containerSel) {
  return document.querySelector(`${containerSel} .mode-btn.active`)?.dataset.mode || 'ECB';
}

// ─────────────────────────────────────────────────
//  SINH NGAU NHIEN (RANDOM KEY / IV / NONCE)
// ─────────────────────────────────────────────────

/** Sinh khoa ngau nhien va dien vao input */
async function genKey(inputId, bitsSelectId) {
  const bits = parseInt(document.getElementById(bitsSelectId)?.value || '128');
  try {
    const res = await fetch(`/api/random/key?bits=${bits}`);
    const data = await res.json();
    document.getElementById(inputId).value = data.hex;
    showToast(`Đã sinh khóa ${bits}-bit!`);
  } catch { showToast('Lỗi khi sinh khóa', 1500); }
}

/** Sinh IV ngau nhien va dien vao input */
async function genIV(inputId) {
  try {
    const res = await fetch('/api/random/iv');
    const data = await res.json();
    document.getElementById(inputId).value = data.hex;
    showToast('Đã sinh IV ngẫu nhiên!');
  } catch { showToast('Lỗi khi sinh IV', 1500); }
}

/** Sinh Nonce ngau nhien va dien vao input */
async function genNonce(inputId) {
  try {
    const res = await fetch('/api/random/nonce');
    const data = await res.json();
    document.getElementById(inputId).value = data.hex;
    showToast('Đã sinh Nonce ngẫu nhiên!');
  } catch { showToast('Lỗi khi sinh Nonce', 1500); }
}

// ─────────────────────────────────────────────────
//  RENDER VERBOSE — STATE GRID 4x4
// ─────────────────────────────────────────────────

/** Tao HTML cho luoi trang thai 4x4 (16 byte -> state AES) */
function renderStateGrid(stateArr) {
  // stateArr: mang 16 phan tu, luu theo cot (column-major)
  const grid = document.createElement('div');
  grid.className = 'state-grid';
  for (let i = 0; i < 16; i++) {
    const cell = document.createElement('div');
    cell.className = 'state-cell';
    cell.textContent = (stateArr[i] ?? 0).toString(16).toUpperCase().padStart(2, '0');
    grid.appendChild(cell);
  }
  return grid;
}

/** Map ten buoc sang class CSS de to mau */
const STEP_CLASS = {
  'SubBytes'     : 'step-sb',
  'InvSubBytes'  : 'step-sb',
  'ShiftRows'    : 'step-sr',
  'InvShiftRows' : 'step-sr',
  'MixColumns'   : 'step-mc',
  'InvMixColumns': 'step-mc',
  'AddRoundKey'  : 'step-ark',
};

/** Render mot buoc (SubBytes / ShiftRows / ...) trong mot vong */
function renderStep(stepData) {
  const div = document.createElement('div');
  div.className = `step ${STEP_CLASS[stepData.name] || ''}`;

  const label = document.createElement('div');
  label.className = 'step-name';
  label.textContent = stepData.name;
  div.appendChild(label);
  div.appendChild(renderStateGrid(stepData.state));

  // Neu la AddRoundKey, hien them round key duoc dung
  if (stepData.name === 'AddRoundKey' && stepData.key) {
    const keyLine = document.createElement('div');
    keyLine.style.cssText = 'font-family:var(--mono);font-size:.68rem;color:var(--text3);margin-top:6px;';
    keyLine.textContent = 'RK: ' + stepData.key.map(b =>
      b.toString(16).toUpperCase().padStart(2,'0')).join(' ');
    div.appendChild(keyLine);
  }
  return div;
}

/** Render toan bo phan verbose (round keys bar + cac vong) */
function renderVerbose(verboseData, keysBarId, roundsId, metaId) {
  // Meta info
  const metaEl = document.getElementById(metaId);
  if (metaEl) {
    metaEl.textContent =
      `AES-${verboseData.key_bits}  |  ${verboseData.Nr} vòng  |  ` +
      `PT: ${verboseData.plaintext?.map(b=>b.toString(16).toUpperCase().padStart(2,'0')).join(' ')}`;
  }

  // Round keys bar
  const keysBar = document.getElementById(keysBarId);
  if (keysBar) {
    keysBar.innerHTML = '<span style="font-size:.72rem;color:var(--text3);margin-right:8px">RKs:</span>';
    verboseData.round_keys.forEach((rk, i) => {
      const chip = document.createElement('div');
      chip.className = 'rk-chip';
      chip.title = bytes2hex(rk);
      chip.textContent = `RK${i}`;
      keysBar.appendChild(chip);
    });
  }

  // Cac vong
  const container = document.getElementById(roundsId);
  if (!container) return;
  container.innerHTML = '';

  verboseData.rounds.forEach((round, idx) => {
    const block = document.createElement('div');
    block.className = 'round-block' + (idx === 0 ? ' open' : '');

    // Header cua vong
    const header = document.createElement('div');
    header.className = 'round-header';
    header.innerHTML = `
      <span class="round-badge">Vòng ${round.round}</span>
      <span class="round-label">${round.label}</span>
      <span class="round-toggle">▼</span>`;
    header.addEventListener('click', () => block.classList.toggle('open'));
    block.appendChild(header);

    // Cac buoc trong vong
    const steps = document.createElement('div');
    steps.className = 'round-steps';
    round.steps.forEach(s => steps.appendChild(renderStep(s)));
    block.appendChild(steps);

    container.appendChild(block);
  });
}

function bytes2hex(arr) {
  return arr.map(b => b.toString(16).toUpperCase().padStart(2,'0')).join(' ');
}

// ─────────────────────────────────────────────────
//  MA HOA (ENCRYPT)
// ─────────────────────────────────────────────────

async function doEncrypt() {
  clearError('tab-encrypt');
  const ptRaw    = val('enc-pt');
  const ptFmt    = val('enc-pt-fmt') || document.getElementById('enc-pt-fmt')?.value || 'ascii';
  const keyHex   = val('enc-key');
  const mode     = getActiveMode('#tab-encrypt .mode-tabs');
  const ivHex    = val('enc-iv');
  const nonceHex = val('enc-nonce');
  const verbose  = document.getElementById('enc-verbose')?.checked;

  if (!ptRaw)   { showError('tab-encrypt', 'Vui lòng nhập Plaintext.'); return; }
  if (!keyHex)  { showError('tab-encrypt', 'Vui lòng nhập hoặc sinh Key.'); return; }

  // Chuyen plaintext sang HEX
  let ptHex;
  try {
    ptHex = ptFmt === 'ascii' ? asciiToHex(ptRaw) : ptRaw.replace(/\s/g,'');
    if (!/^[0-9a-fA-F]*$/.test(ptHex)) throw new Error();
  } catch { showError('tab-encrypt', 'Plaintext HEX không hợp lệ.'); return; }

  const body = { plaintext_hex: ptHex, key_hex: keyHex, mode, verbose };
  if (mode === 'CBC') body.iv_hex    = ivHex;
  if (mode === 'CTR') body.nonce_hex = nonceHex;

  try {
    const res  = await fetch('/api/encrypt', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (data.error) { showError('tab-encrypt', data.error); return; }

    document.getElementById('enc-out-hex').textContent = data.ciphertext_hex;
    document.getElementById('enc-out-b64').textContent = data.ciphertext_b64;
    show('enc-result-content'); hide('enc-result-empty');

    // Verbose
    if (data.verbose) {
      show('verbose-section');
      renderVerbose(data.verbose, 'round-keys-bar', 'rounds-container', 'verbose-meta');
    } else {
      hide('verbose-section');
    }
  } catch (e) {
    showError('tab-encrypt', 'Lỗi kết nối server: ' + e.message);
  }
}

// ─────────────────────────────────────────────────
//  GIAI MA (DECRYPT)
// ─────────────────────────────────────────────────

async function doDecrypt() {
  clearError('tab-decrypt');
  const ctRaw    = val('dec-ct');
  const ctFmt    = document.getElementById('dec-ct-fmt')?.value || 'hex';
  const keyHex   = val('dec-key');
  const mode     = getActiveMode('#dec-mode-tabs');
  const ivHex    = val('dec-iv');
  const nonceHex = val('dec-nonce');
  const verbose  = document.getElementById('dec-verbose')?.checked;

  if (!ctRaw)   { showError('tab-decrypt', 'Vui lòng nhập Ciphertext.'); return; }
  if (!keyHex)  { showError('tab-decrypt', 'Vui lòng nhập Key.'); return; }

  // Chuyen ciphertext sang HEX
  let ctHex;
  try {
    ctHex = ctFmt === 'base64' ? b64ToHex(ctRaw) : ctRaw.replace(/\s/g,'');
    if (!/^[0-9a-fA-F]*$/.test(ctHex)) throw new Error();
  } catch { showError('tab-decrypt', 'Ciphertext không hợp lệ.'); return; }

  const body = { ciphertext_hex: ctHex, key_hex: keyHex, mode, verbose };
  if (mode === 'CBC') body.iv_hex    = ivHex;
  if (mode === 'CTR') body.nonce_hex = nonceHex;

  try {
    const res  = await fetch('/api/decrypt', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (data.error) { showError('tab-decrypt', data.error); return; }

    document.getElementById('dec-out-ascii').textContent = data.plaintext_ascii;
    document.getElementById('dec-out-hex').textContent   = data.plaintext_hex;
    show('dec-result-content'); hide('dec-result-empty');

    if (data.verbose) {
      show('dec-verbose-section');
      renderVerbose(data.verbose, 'dec-round-keys-bar', 'dec-rounds-container', 'dec-verbose-meta');
    } else {
      hide('dec-verbose-section');
    }
  } catch (e) {
    showError('tab-decrypt', 'Lỗi kết nối server: ' + e.message);
  }
}

// ─────────────────────────────────────────────────
//  KEY SCHEDULE
// ─────────────────────────────────────────────────

async function doKeySchedule() {
  const keyHex = val('ks-key');
  if (!keyHex) { showToast('Vui lòng nhập hoặc sinh Key trước!'); return; }

  try {
    const res  = await fetch('/api/key_schedule', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ key_hex: keyHex })
    });
    const data = await res.json();
    if (data.error) { showToast('Lỗi: ' + data.error, 3000); return; }

    const container = document.getElementById('ks-result');
    container.innerHTML = `
      <p style="font-size:.8rem;color:var(--text2);margin-bottom:12px">
        AES-<strong style="color:var(--accent)">${data.key_bits}</strong> bit &mdash;
        <strong style="color:var(--accent)">${data.Nr + 1}</strong> round keys
      </p>`;

    data.round_keys.forEach(rk => {
      const row = document.createElement('div');
      row.className = 'ks-row';

      // Tinh "entropy bar" dua tren trung binh cac byte (chi de minh hoa)
      const avg = rk.bytes.reduce((a, b) => a + b, 0) / rk.bytes.length;
      const pct = Math.round((avg / 255) * 100);

      row.innerHTML = `
        <div class="ks-idx">RK${rk.round}</div>
        <div class="ks-hex">${rk.hex.match(/.{2}/g).join(' ')}</div>
        <div class="ks-bar-wrap" title="Byte avg: ${avg.toFixed(0)}/255">
          <div class="ks-bar" style="width:${pct}%"></div>
        </div>`;
      container.appendChild(row);
    });

    show('ks-result');
  } catch (e) {
    showToast('Lỗi kết nối: ' + e.message, 3000);
  }
}

// ─────────────────────────────────────────────────
//  PHIM TAT (KEYBOARD SHORTCUTS)
// ─────────────────────────────────────────────────

document.addEventListener('keydown', e => {
  // Ctrl+Enter: thuc hien hanh dong chinh cua tab dang mo
  if (e.ctrlKey && e.key === 'Enter') {
    const activeTab = document.querySelector('.tab-btn.active')?.dataset.tab;
    if (activeTab === 'encrypt')     doEncrypt();
    else if (activeTab === 'decrypt') doDecrypt();
    else if (activeTab === 'keyschedule') doKeySchedule();
  }
});

// ─────────────────────────────────────────────────
//  KHOI TAO (INIT)
// ─────────────────────────────────────────────────

/** Sinh san key + IV mac dinh khi mo trang de trai nghiem nhanh */
async function initDefaults() {
  // Sinh key cho tab encrypt
  const encKeyBits = document.getElementById('enc-key-bits');
  if (encKeyBits) await genKey('enc-key', 'enc-key-bits');
  await genIV('enc-iv');
  await genNonce('enc-nonce');

  // Copy key sang tab decrypt de tien cho nguoi dung thu nghiem
  const encKey = val('enc-key');
  if (encKey) {
    const decKeyInput = document.getElementById('dec-key');
    if (decKeyInput) decKeyInput.value = encKey;
  }

  // Sinh key cho key schedule tab
  if (document.getElementById('ks-key')) await genKey('ks-key', 'ks-key-bits');
}

// Chay sau khi DOM san sang
document.addEventListener('DOMContentLoaded', initDefaults);