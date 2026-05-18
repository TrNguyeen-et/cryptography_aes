/**
 * main.js — Frontend logic cho AES Visualizer
 */

'use strict';

function showToast(msg, duration = 2000) {
  const t = document.getElementById('toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(t._timer); t._timer = setTimeout(() => t.classList.add('hidden'), duration);
}
function copyText(id) { const el = document.getElementById(id); if (!el) return; navigator.clipboard.writeText(el.textContent).then(() => showToast('Đã sao chép!')); }
function show(id)   { const e = document.getElementById(id); if (e) e.classList.remove('hidden'); }
function hide(id)   { const e = document.getElementById(id); if (e) e.classList.add('hidden');    }
function toggle(id, visible) { visible ? show(id) : hide(id); }
function val(id)    { return document.getElementById(id)?.value.trim() || ''; }
function asciiToHex(str) { return Array.from(str).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join(''); }
function b64ToHex(b64) { const bin = atob(b64); return Array.from(bin).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join(''); }

function showError(containerId, msg) {
  const container = document.getElementById(containerId); if (!container) return;
  let errEl = container.querySelector('.error-banner');
  if (!errEl) { errEl = document.createElement('div'); errEl.className = 'error-banner'; container.prepend(errEl); }
  errEl.textContent = '⚠ ' + msg; errEl.style.display = 'block';
}
function clearError(containerId) { const errEl = document.querySelector(`#${containerId} .error-banner`); if (errEl) errEl.style.display = 'none'; }

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
    btn.classList.add('active'); document.getElementById(`tab-${target}`)?.classList.remove('hidden');
  });
});

function initModeTabs(containerSel, ivRowId, warnId) {
  const container = document.querySelector(containerSel); if (!container) return;
  container.querySelectorAll('.mode-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active')); btn.classList.add('active');
      const mode = btn.dataset.mode; toggle(ivRowId, mode === 'CBC'); if (warnId) toggle(warnId, mode === 'ECB');
    });
  });
}
initModeTabs('#tab-encrypt .mode-tabs', 'enc-iv-row', 'ecb-warn');
initModeTabs('#dec-mode-tabs', 'dec-iv-row', null);
function getActiveMode(containerSel) { return document.querySelector(`${containerSel} .mode-btn.active`)?.dataset.mode || 'ECB'; }

async function genKey(inputId, bitsSelectId) {
  const bits = parseInt(document.getElementById(bitsSelectId)?.value || '128'); const len = bits / 8;
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = ''; for (let i = 0; i < len; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
  document.getElementById(inputId).value = result; showToast(`Đã sinh khóa ${bits}-bit (ASCII)!`);
}

function byteToHex(b) { return (b ?? 0).toString(16).toUpperCase().padStart(2, '0'); }

function renderStateGrid(stateArr) {
  const grid = document.createElement('div'); grid.className = 'state-grid';
  for (let i = 0; i < 16; i++) { const cell = document.createElement('div'); cell.className = 'state-cell'; cell.textContent = byteToHex(stateArr[i]); grid.appendChild(cell); }
  return grid;
}

const STEP_CLASS = {
  'SubBytes'     : 'step-sb', 'InvSubBytes'  : 'step-sb',
  'ShiftRows'    : 'step-sr', 'InvShiftRows' : 'step-sr',
  'MixColumns'   : 'step-mc', 'InvMixColumns': 'step-mc',
  'AddRoundKey'  : 'step-ark',
};

function renderDetailTable(stepData) {
  const container = document.createElement('div'); container.className = 'step-detail-table';
  const name = stepData.name; const details = stepData.details;
  if (name.includes('SubBytes') || name.includes('InvSubBytes')) {
    let html = '<table><tr><th>Vị trí</th><th>Đầu vào</th><th>Đầu ra (S-Box)</th></tr>';
    details.forEach(d => { html += `<tr><td>${d.pos}</td><td>${byteToHex(d.in)}</td><td class="highlight">${byteToHex(d.out)}</td></tr>`; }); container.innerHTML = html + '</table>';
  } else if (name.includes('ShiftRows') || name.includes('InvShiftRows')) {
    let html = '<table><tr><th>Hàng</th><th>Phép dịch</th><th>Trước</th><th>Sau</th></tr>';
    details.forEach(d => {
      html += `<tr><td>Hàng ${d.row}</td><td>${d.desc}</td><td>${d.before.map(b => byteToHex(b)).join(' ')}</td><td class="highlight">${d.after.map(b => byteToHex(b)).join(' ')}</td></tr>`;
    }); container.innerHTML = html + '</table>';
  } else if (name.includes('MixColumns') || name.includes('InvMixColumns')) {
    let html = '<table><tr><th>Cột</th><th>Đầu vào</th><th>Đầu ra</th></tr>';
    details.forEach(d => {
      html += `<tr><td>Cột ${d.col}</td><td>${d.input.map(b => byteToHex(b)).join(' ')}</td><td class="highlight">${d.output.map(b => byteToHex(b)).join(' ')}</td></tr>`;
    }); container.innerHTML = html + '</table>';
  } else if (name.includes('AddRoundKey')) {
    let html = '<table><tr><th>Vị trí</th><th>State</th><th>XOR</th><th>Round Key</th><th>Kết quả</th></tr>';
    details.forEach(d => {
      html += `<tr><td>${d.pos}</td><td>${byteToHex(d.state)}</td><td>⊕</td><td>${byteToHex(d.key)}</td><td class="highlight">${byteToHex(d.result)}</td></tr>`;
    }); container.innerHTML = html + '</table>';
  }
  return container;
}

function renderStep(stepData) {
  const div = document.createElement('div'); div.className = `step ${STEP_CLASS[stepData.name] || ''}`;

  const header = document.createElement('div'); header.className = 'step-header';
  const label = document.createElement('div'); label.className = 'step-name'; label.textContent = stepData.name; header.appendChild(label);
  const detailBtn = document.createElement('button'); detailBtn.className = 'detail-btn'; detailBtn.textContent = 'Chi tiết ▼'; header.appendChild(detailBtn);
  div.appendChild(header);

  // --- VÙNG VẼ LƯỚI TRỰC QUAN ---
  const gridsRow = document.createElement('div'); gridsRow.className = 'step-grids-row';

  // Nếu là AddRoundKey, vẽ State ⊕ Key = Result
  if (stepData.name.includes('AddRoundKey') && stepData.key) {
    const stateWrap = document.createElement('div'); stateWrap.className = 'grid-label-wrap'; stateWrap.innerHTML = '<span class="grid-tag">State</span>'; stateWrap.appendChild(renderStateGrid(stepData.old_state)); gridsRow.appendChild(stateWrap);
    const op1 = document.createElement('div'); op1.className = 'grid-op'; op1.textContent = '⊕'; gridsRow.appendChild(op1);
    const keyWrap = document.createElement('div'); keyWrap.className = 'grid-label-wrap'; keyWrap.innerHTML = '<span class="grid-tag">Round Key</span>'; keyWrap.appendChild(renderStateGrid(stepData.key)); gridsRow.appendChild(keyWrap);
    const op2 = document.createElement('div'); op2.className = 'grid-op'; op2.textContent = '='; gridsRow.appendChild(op2);
    const resWrap = document.createElement('div'); resWrap.className = 'grid-label-wrap'; resWrap.innerHTML = '<span class="grid-tag">Kết quả</span>'; resWrap.appendChild(renderStateGrid(stepData.state)); gridsRow.appendChild(resWrap);
  } 
  // Các hàm khác (MixColumns, SubBytes, ShiftRows), vẽ Trước -> Sau
  else if (stepData.old_state) {
    const beforeWrap = document.createElement('div'); beforeWrap.className = 'grid-label-wrap'; beforeWrap.innerHTML = '<span class="grid-tag">Trước</span>'; beforeWrap.appendChild(renderStateGrid(stepData.old_state)); gridsRow.appendChild(beforeWrap);
    const arrow = document.createElement('div'); arrow.className = 'grid-arrow'; arrow.textContent = '→'; gridsRow.appendChild(arrow);
    const afterWrap = document.createElement('div'); afterWrap.className = 'grid-label-wrap'; afterWrap.innerHTML = '<span class="grid-tag">Sau</span>'; afterWrap.appendChild(renderStateGrid(stepData.state)); gridsRow.appendChild(afterWrap);
  }
  
  div.appendChild(gridsRow);

  // Phần chứa bảng chi tiết (ẩn mặc định)
  const detailWrapper = document.createElement('div'); detailWrapper.className = 'step-detail-wrapper hidden';
  detailWrapper.appendChild(renderDetailTable(stepData)); div.appendChild(detailWrapper);

  detailBtn.addEventListener('click', () => {
    const isHidden = detailWrapper.classList.contains('hidden'); detailWrapper.classList.toggle('hidden');
    detailBtn.textContent = isHidden ? 'Chi tiết ▲' : 'Chi tiết ▼';
  });

  return div;
}

function renderVerbose(verboseData, keysBarId, roundsId, metaId) {
  const metaEl = document.getElementById(metaId);
  if (metaEl) metaEl.textContent = `AES-${verboseData.key_bits}  |  ${verboseData.Nr} vòng  |  PT: ${verboseData.plaintext?.map(b=>byteToHex(b)).join(' ')}`;
  const keysBar = document.getElementById(keysBarId);
  if (keysBar) {
    keysBar.innerHTML = '<span style="font-size:.72rem;color:var(--text3);margin-right:8px">RKs:</span>';
    verboseData.round_keys.forEach((rk, i) => { const chip = document.createElement('div'); chip.className = 'rk-chip'; chip.title = rk.map(b => byteToHex(b)).join(' '); chip.textContent = `RK${i}`; keysBar.appendChild(chip); });
  }
  const container = document.getElementById(roundsId); if (!container) return; container.innerHTML = '';
  verboseData.rounds.forEach((round, idx) => {
    const block = document.createElement('div'); block.className = 'round-block' + (idx === 0 ? ' open' : '');
    const header = document.createElement('div'); header.className = 'round-header';
    header.innerHTML = `<span class="round-badge">Vòng ${round.round}</span><span class="round-label">${round.label}</span><span class="round-toggle">▼</span>`;
    header.addEventListener('click', () => block.classList.toggle('open')); block.appendChild(header);
    const steps = document.createElement('div'); steps.className = 'round-steps';
    round.steps.forEach(s => steps.appendChild(renderStep(s))); block.appendChild(steps); container.appendChild(block);
  });
}

async function doEncrypt() {
  clearError('tab-encrypt');
  const ptRaw = val('enc-pt'); const ptFmt = val('enc-pt-fmt') || document.getElementById('enc-pt-fmt')?.value || 'ascii';
  const keyAscii = val('enc-key'); const keyBits = document.getElementById('enc-key-bits')?.value || '128';
  const mode = getActiveMode('#tab-encrypt .mode-tabs'); const ivAscii = val('enc-iv'); const verbose = document.getElementById('enc-verbose')?.checked;
  if (!ptRaw || !keyAscii) { showError('tab-encrypt', 'Vui lòng nhập Plaintext và Key.'); return; }
  let ptHex; try { ptHex = ptFmt === 'ascii' ? asciiToHex(ptRaw) : ptRaw.replace(/\s/g,''); if (!/^[0-9a-fA-F]*$/.test(ptHex)) throw new Error(); } catch { showError('tab-encrypt', 'Plaintext không hợp lệ.'); return; }
  const body = { plaintext_hex: ptHex, key_ascii: keyAscii, key_bits: keyBits, mode, verbose };
  if (mode === 'CBC') body.iv_ascii = ivAscii;
  try {
    const res = await fetch('/api/encrypt', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) }); const data = await res.json();
    if (data.error) { showError('tab-encrypt', data.error); return; }
    document.getElementById('enc-out-hex').textContent = data.ciphertext_hex; document.getElementById('enc-out-b64').textContent = data.ciphertext_b64;
    const ivRow = document.getElementById('enc-iv-result-row');
    if (data.iv_hex) { document.getElementById('enc-out-iv').textContent = data.iv_hex; ivRow.style.display = 'flex'; if (data.iv_generated) showToast('⚠️ IV tự sinh! Copy lại để giải mã.', 4000); } else { ivRow.style.display = 'none'; }
    show('enc-result-content'); hide('enc-result-empty');
    if (data.verbose) { show('verbose-section'); renderVerbose(data.verbose, 'round-keys-bar', 'rounds-container', 'verbose-meta'); } else { hide('verbose-section'); }
  } catch (e) { showError('tab-encrypt', 'Lỗi server: ' + e.message); }
}

async function doDecrypt() {
  clearError('tab-decrypt');
  const ctRaw = val('dec-ct'); const ctFmt = document.getElementById('dec-ct-fmt')?.value || 'hex';
  const keyAscii = val('dec-key'); const keyBits = document.getElementById('dec-key-bits')?.value || '128';
  const mode = getActiveMode('#dec-mode-tabs'); const ivRaw = val('dec-iv'); const verbose = document.getElementById('dec-verbose')?.checked;
  if (!ctRaw || !keyAscii) { showError('tab-decrypt', 'Vui lòng nhập Ciphertext và Key.'); return; }
  let ctHex; try { ctHex = ctFmt === 'base64' ? b64ToHex(ctRaw) : ctRaw.replace(/\s/g,''); if (!/^[0-9a-fA-F]*$/.test(ctHex)) throw new Error(); } catch { showError('tab-decrypt', 'Ciphertext không hợp lệ.'); return; }
  const body = { ciphertext_hex: ctHex, key_ascii: keyAscii, key_bits: keyBits, mode, verbose };
  if (mode === 'CBC') { if (!ivRaw) { showError('tab-decrypt', 'CBC cần IV.'); return; } if (/^[0-9a-fA-F]{32}$/.test(ivRaw.replace(/\s/g,''))) body.iv_hex = ivRaw.replace(/\s/g,''); else body.iv_ascii = ivRaw; }
  try {
    const res = await fetch('/api/decrypt', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) }); const data = await res.json();
    if (data.error) { showError('tab-decrypt', data.error); return; }
    document.getElementById('dec-out-ascii').textContent = data.plaintext_ascii; document.getElementById('dec-out-hex').textContent = data.plaintext_hex;
    show('dec-result-content'); hide('dec-result-empty');
    if (data.verbose) { show('dec-verbose-section'); renderVerbose(data.verbose, 'dec-round-keys-bar', 'dec-rounds-container', 'dec-verbose-meta'); } else { hide('dec-verbose-section'); }
  } catch (e) { showError('tab-decrypt', 'Lỗi server: ' + e.message); }
}

async function doKeySchedule() {
  const keyAscii = val('ks-key'); const keyBits = document.getElementById('ks-key-bits')?.value || '128';
  if (!keyAscii) { showToast('Nhập hoặc sinh Key trước!'); return; }
  try {
    const res = await fetch('/api/key_schedule', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ key_ascii: keyAscii, key_bits: keyBits }) }); const data = await res.json();
    if (data.error) { showToast('Lỗi: ' + data.error, 3000); return; }
    const container = document.getElementById('ks-result');
    container.innerHTML = `<p style="font-size:.8rem;color:var(--text2);margin-bottom:12px">AES-<strong style="color:var(--accent)">${data.key_bits}</strong> bit — <strong style="color:var(--accent)">${data.Nr + 1}</strong> round keys</p>`;
    data.round_keys.forEach(rk => {
      const row = document.createElement('div'); row.className = 'ks-row'; const avg = rk.bytes.reduce((a, b) => a + b, 0) / rk.bytes.length; const pct = Math.round((avg / 255) * 100);
      row.innerHTML = `<div class="ks-idx">RK${rk.round}</div><div class="ks-hex">${rk.hex.match(/.{2}/g).join(' ')}</div><div class="ks-bar-wrap"><div class="ks-bar" style="width:${pct}%"></div></div>`;
      container.appendChild(row);
    }); show('ks-result');
  } catch (e) { showToast('Lỗi: ' + e.message, 3000); }
}

document.addEventListener('keydown', e => { if (e.ctrlKey && e.key === 'Enter') { const activeTab = document.querySelector('.tab-btn.active')?.dataset.tab; if (activeTab === 'encrypt') doEncrypt(); else if (activeTab === 'decrypt') doDecrypt(); else if (activeTab === 'keyschedule') doKeySchedule(); } });
async function initDefaults() { await genKey('enc-key', 'enc-key-bits'); const encKey = val('enc-key'); if (encKey) { const decKeyInput = document.getElementById('dec-key'); if (decKeyInput) decKeyInput.value = encKey; } if (document.getElementById('ks-key')) await genKey('ks-key', 'ks-key-bits'); }
document.addEventListener('DOMContentLoaded', initDefaults);