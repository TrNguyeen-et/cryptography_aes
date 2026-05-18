/**
 * main.js — Frontend logic cho AES Visualizer (Đã bỏ CTR, thêm Key/IV ASCII)
 */

'use strict';

// ─────────────────────────────────────────────────
//  TIEN ICH CHUNG
// ─────────────────────────────────────────────────

function showToast(msg, duration = 2000) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), duration);
}

function copyText(id) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => showToast('Đã sao chép!'));
}

function show(id)   { const e = document.getElementById(id); if (e) e.classList.remove('hidden'); }
function hide(id)   { const e = document.getElementById(id); if (e) e.classList.add('hidden');    }
function toggle(id, visible) { visible ? show(id) : hide(id); }

function val(id)    { return document.getElementById(id)?.value.trim() || ''; }

function asciiToHex(str) {
  return Array.from(str).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join('');
}

function b64ToHex(b64) {
  const bin = atob(b64);
  return Array.from(bin).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join('');
}

function showError(containerId, msg) {
  const container = document.getElementById(containerId);
  if (!container) return;
  let errEl = container.querySelector('.error-banner');
  if (!errEl) {
    errEl = document.createElement('div');
    errEl.className = 'error-banner';
    container.prepend(errEl);
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
//  CHON CHE DO (ECB / CBC)
// ─────────────────────────────────────────────────

function initModeTabs(containerSel, ivRowId, warnId) {
  const container = document.querySelector(containerSel);
  if (!container) return;

  container.querySelectorAll('.mode-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const mode = btn.dataset.mode;
      toggle(ivRowId, mode === 'CBC');
      if (warnId) toggle(warnId, mode === 'ECB');
    });
  });
}

initModeTabs('#tab-encrypt .mode-tabs', 'enc-iv-row', 'ecb-warn');
initModeTabs('#dec-mode-tabs', 'dec-iv-row', null);

function getActiveMode(containerSel) {
  return document.querySelector(`${containerSel} .mode-btn.active`)?.dataset.mode || 'ECB';
}

// ─────────────────────────────────────────────────
//  SINH NGAU NHIEN (KEY ASCII)
// ─────────────────────────────────────────────────

async function genKey(inputId, bitsSelectId) {
  const bits = parseInt(document.getElementById(bitsSelectId)?.value || '128');
  const len = bits / 8; // 16, 24, 32 ký tự
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < len; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  document.getElementById(inputId).value = result;
  showToast(`Đã sinh khóa ${bits}-bit (ASCII)!`);
}

// ─────────────────────────────────────────────────
//  RENDER VERBOSE
// ─────────────────────────────────────────────────

function renderStateGrid(stateArr) {
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

const STEP_CLASS = {
  'SubBytes'     : 'step-sb',
  'InvSubBytes'  : 'step-sb',
  'ShiftRows'    : 'step-sr',
  'InvShiftRows' : 'step-sr',
  'MixColumns'   : 'step-mc',
  'InvMixColumns': 'step-mc',
  'AddRoundKey'  : 'step-ark',
};

function renderStep(stepData) {
  const div = document.createElement('div');
  div.className = `step ${STEP_CLASS[stepData.name] || ''}`;

  const label = document.createElement('div');
  label.className = 'step-name';
  label.textContent = stepData.name;
  div.appendChild(label);
  div.appendChild(renderStateGrid(stepData.state));

  if (stepData.name === 'AddRoundKey' && stepData.key) {
    const keyLine = document.createElement('div');
    keyLine.style.cssText = 'font-family:var(--mono);font-size:.68rem;color:var(--text3);margin-top:6px;';
    keyLine.textContent = 'RK: ' + stepData.key.map(b => b.toString(16).toUpperCase().padStart(2,'0')).join(' ');
    div.appendChild(keyLine);
  }
  return div;
}

function renderVerbose(verboseData, keysBarId, roundsId, metaId) {
  const metaEl = document.getElementById(metaId);
  if (metaEl) {
    metaEl.textContent =
      `AES-${verboseData.key_bits}  |  ${verboseData.Nr} vòng  |  ` +
      `PT: ${verboseData.plaintext?.map(b=>b.toString(16).toUpperCase().padStart(2,'0')).join(' ')}`;
  }

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

  const container = document.getElementById(roundsId);
  if (!container) return;
  container.innerHTML = '';

  verboseData.rounds.forEach((round, idx) => {
    const block = document.createElement('div');
    block.className = 'round-block' + (idx === 0 ? ' open' : '');

    const header = document.createElement('div');
    header.className = 'round-header';
    header.innerHTML = `
      <span class="round-badge">Vòng ${round.round}</span>
      <span class="round-label">${round.label}</span>
      <span class="round-toggle">▼</span>`;
    header.addEventListener('click', () => block.classList.toggle('open'));
    block.appendChild(header);

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
//  MA HOA
// ─────────────────────────────────────────────────

async function doEncrypt() {
  clearError('tab-encrypt');
  const ptRaw    = val('enc-pt');
  const ptFmt    = val('enc-pt-fmt') || document.getElementById('enc-pt-fmt')?.value || 'ascii';
  const keyAscii = val('enc-key'); // Nhận ASCII
  const keyBits  = document.getElementById('enc-key-bits')?.value || '128';
  const mode     = getActiveMode('#tab-encrypt .mode-tabs');
  const ivAscii  = val('enc-iv'); // Nhận ASCII hoặc trống
  const verbose  = document.getElementById('enc-verbose')?.checked;

  if (!ptRaw)   { showError('tab-encrypt', 'Vui lòng nhập Plaintext.'); return; }
  if (!keyAscii)  { showError('tab-encrypt', 'Vui lòng nhập hoặc sinh Key.'); return; }

  let ptHex;
  try {
    ptHex = ptFmt === 'ascii' ? asciiToHex(ptRaw) : ptRaw.replace(/\s/g,'');
    if (!/^[0-9a-fA-F]*$/.test(ptHex)) throw new Error();
  } catch { showError('tab-encrypt', 'Plaintext HEX không hợp lệ.'); return; }

  const body = { plaintext_hex: ptHex, key_ascii: keyAscii, key_bits: keyBits, mode, verbose };
  if (mode === 'CBC') body.iv_ascii = ivAscii; // Gửi kèm IV (trống hoặc có)

  try {
    const res  = await fetch('/api/encrypt', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (data.error) { showError('tab-encrypt', data.error); return; }

    document.getElementById('enc-out-hex').textContent = data.ciphertext_hex;
    document.getElementById('enc-out-b64').textContent = data.ciphertext_b64;
    
    // Hiển thị IV (nếu là CBC)
    const ivRow = document.getElementById('enc-iv-result-row');
    if (data.iv_hex) {
      document.getElementById('enc-out-iv').textContent = data.iv_hex;
      ivRow.style.display = 'flex';
      if (data.iv_generated) {
        showToast('⚠️ IV đã được tự sinh ngẫu nhiên! Hãy copy IV lại để giải mã.', 4000);
      }
    } else {
      ivRow.style.display = 'none';
    }

    show('enc-result-content'); hide('enc-result-empty');

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
//  GIAI MA
// ─────────────────────────────────────────────────

async function doDecrypt() {
  clearError('tab-decrypt');
  const ctRaw    = val('dec-ct');
  const ctFmt    = document.getElementById('dec-ct-fmt')?.value || 'hex';
  const keyAscii = val('dec-key');
  const keyBits  = document.getElementById('dec-key-bits')?.value || '128';
  const mode     = getActiveMode('#dec-mode-tabs');
  const ivRaw    = val('dec-iv'); // Chấp nhận Hex hoặc ASCII
  const verbose  = document.getElementById('dec-verbose')?.checked;

  if (!ctRaw)   { showError('tab-decrypt', 'Vui lòng nhập Ciphertext.'); return; }
  if (!keyAscii)  { showError('tab-decrypt', 'Vui lòng nhập Key.'); return; }

  let ctHex;
  try {
    ctHex = ctFmt === 'base64' ? b64ToHex(ctRaw) : ctRaw.replace(/\s/g,'');
    if (!/^[0-9a-fA-F]*$/.test(ctHex)) throw new Error();
  } catch { showError('tab-decrypt', 'Ciphertext không hợp lệ.'); return; }

  const body = { ciphertext_hex: ctHex, key_ascii: keyAscii, key_bits: keyBits, mode, verbose };
  
  // Gửi IV giải mã: Backend tự nhận diện HEX hay ASCII
  if (mode === 'CBC') {
    if (!ivRaw) { showError('tab-decrypt', 'Chế độ CBC bắt buộc cần IV để giải mã.'); return; }
    // Kiểm tra xem có phải là HEX không (từ lúc copy)
    if (/^[0-9a-fA-F]{32}$/.test(ivRaw.replace(/\s/g,''))) {
        body.iv_hex = ivRaw.replace(/\s/g,'');
    } else {
        body.iv_ascii = ivRaw;
    }
  }

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
  const keyAscii = val('ks-key');
  const keyBits  = document.getElementById('ks-key-bits')?.value || '128';
  
  if (!keyAscii) { showToast('Vui lòng nhập hoặc sinh Key trước!'); return; }

  try {
    const res  = await fetch('/api/key_schedule', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ key_ascii: keyAscii, key_bits: keyBits })
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
//  PHIM TAT & INIT
// ─────────────────────────────────────────────────

document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') {
    const activeTab = document.querySelector('.tab-btn.active')?.dataset.tab;
    if (activeTab === 'encrypt')     doEncrypt();
    else if (activeTab === 'decrypt') doDecrypt();
    else if (activeTab === 'keyschedule') doKeySchedule();
  }
});

async function initDefaults() {
  await genKey('enc-key', 'enc-key-bits');
  const encKey = val('enc-key');
  if (encKey) {
    const decKeyInput = document.getElementById('dec-key');
    if (decKeyInput) decKeyInput.value = encKey;
  }
  if (document.getElementById('ks-key')) await genKey('ks-key', 'ks-key-bits');
}

document.addEventListener('DOMContentLoaded', initDefaults);