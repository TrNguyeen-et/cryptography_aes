/**
 * main.js — Frontend logic cho AES Visualizer
 */

'use strict';

// Bảng S-Box 16x16 (dùng cho SubBytes)
const SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
];

function showToast(msg, duration = 2000) {
  const t = document.getElementById('toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(t._timer); t._timer = setTimeout(() => t.classList.add('hidden'), duration);
}
function copyText(id) { const el = document.getElementById(id); if (!el) return; navigator.clipboard.writeText(el.textContent).then(() => showToast('Đã sao chép!')); }
function show(id)   { const e = document.getElementById(id); if (e) e.classList.remove('hidden'); }
function hide(id)   { const e = document.getElementById(id); if (e) e.classList.add('hidden');    }
function toggle(id, visible) { visible ? show(id) : hide(id); }
function val(id)    { return document.getElementById(id)?.value.trim() || ''; }
// Hàm chuyển chuỗi (kể cả tiếng Việt có dấu) sang chuẩn HEX của UTF-8
function asciiToHex(str) {
  try {
    const utf8Bytes = new TextEncoder().encode(str);
    return Array.from(utf8Bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    return '';
  }
}
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
  document.getElementById(inputId).value = result; showToast(`Đã sinh khóa ${bits}-bit!`);
}

function byteToHex(b) { return (b ?? 0).toString(16).toUpperCase().padStart(2, '0'); }

function renderStateGrid(stateArr) {
  const grid = document.createElement('div'); 
  grid.className = 'state-grid';
  
  // Mảng chỉ số theo Column-Major chuẩn của AES
  // Cột 0 (0,1,2,3), Cột 1 (4,5,6,7), Cột 2 (8,9,10,11), Cột 3 (12,13,14,15)
  const colMajorIndices = [
    0, 4, 8, 12,   // Hàng 0
    1, 5, 9, 13,   // Hàng 1
    2, 6, 10, 14,  // Hàng 2
    3, 7, 11, 15   // Hàng 3
  ];
  
  for (let i = 0; i < 16; i++) { 
    const idx = colMajorIndices[i];
    const cell = document.createElement('div'); 
    cell.className = 'state-cell'; 
    cell.textContent = byteToHex(stateArr[idx]); 
    grid.appendChild(cell); 
  }
  return grid;
}

const STEP_CLASS = {
  'SubBytes'     : 'step-sb', 'InvSubBytes'  : 'step-sb',
  'ShiftRows'    : 'step-sr', 'InvShiftRows' : 'step-sr',
  'MixColumns'   : 'step-mc', 'InvMixColumns': 'step-mc',
  'AddRoundKey'  : 'step-ark',
};

// MỚI: Tạo bảng S-Box 16x16 với highlight
function renderSboxTable(inputs) {
  const container = document.createElement('div'); container.className = 'sbox-grid-container';
  const grid = document.createElement('div'); grid.className = 'sbox-table';
  
  // Header row (y-axis: 0-F)
  const emptyCorner = document.createElement('div'); emptyCorner.className = 'sbox-header'; grid.appendChild(emptyCorner);
  for (let col = 0; col < 16; col++) { const h = document.createElement('div'); h.className = 'sbox-header'; h.textContent = col.toString(16).toUpperCase(); grid.appendChild(h); }

  // Data rows (x-axis: 0-F)
  for (let row = 0; row < 16; row++) {
    const rowHeader = document.createElement('div'); rowHeader.className = 'sbox-header'; rowHeader.textContent = row.toString(16).toUpperCase(); grid.appendChild(rowHeader);
    for (let col = 0; col < 16; col++) {
      const val = SBOX[row * 16 + col];
      const cell = document.createElement('div'); cell.className = 'sbox-cell'; cell.textContent = byteToHex(val);
      // Nếu giá trị này nằm trong mảng input, highlight nó
      if (inputs.includes(val)) cell.classList.add('sbox-highlight');
      grid.appendChild(cell);
    }
  }
  container.appendChild(grid);
  return container;
}

// Thêm mảng ISBOX (Bảng thay thế ngược) ngay trên cùng file main.js hoặc gần hàm SBOX
const ISBOX = [
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
];

function renderSboxTable(inputs, isInverse = false) {
  const container = document.createElement('div'); container.className = 'sbox-grid-container';
  const grid = document.createElement('div'); grid.className = 'sbox-table';
  const tableData = isInverse ? ISBOX : SBOX;
  const tableName = isInverse ? "Inverse S-Box" : "S-Box";
  
  const emptyCorner = document.createElement('div'); emptyCorner.className = 'sbox-header'; emptyCorner.textContent = tableName; grid.appendChild(emptyCorner);
  for (let col = 0; col < 16; col++) { const h = document.createElement('div'); h.className = 'sbox-header'; h.textContent = col.toString(16).toUpperCase(); grid.appendChild(h); }

  for (let row = 0; row < 16; row++) {
    const rowHeader = document.createElement('div'); rowHeader.className = 'sbox-header'; rowHeader.textContent = row.toString(16).toUpperCase(); grid.appendChild(rowHeader);
    for (let col = 0; col < 16; col++) {
      const val = tableData[row * 16 + col];
      const cell = document.createElement('div'); cell.className = 'sbox-cell'; cell.textContent = byteToHex(val);
      if (inputs.includes(val)) cell.classList.add('sbox-highlight');
      grid.appendChild(cell);
    }
  }
  container.appendChild(grid);
  return container;
}

function renderDetailTable(stepData) {
  const wrapper = document.createElement('div'); wrapper.className = 'step-detail-flex';
  const tableContainer = document.createElement('div'); tableContainer.className = 'step-detail-table';
  const name = stepData.name; const details = stepData.details;

  if (name.includes('SubBytes') || name.includes('InvSubBytes')) {
    const isInv = name.includes('Inv');
    let html = '<table><tr><th>Vị trí</th><th>Đầu vào</th><th>Đầu ra</th></tr>';
    const inputs = details.map(d => d.in);
    details.forEach(d => { html += `<tr><td>${d.pos}</td><td>${byteToHex(d.in)}</td><td class="highlight">${byteToHex(d.out)}</td></tr>`; });
    tableContainer.innerHTML = html + '</table>';
    wrapper.appendChild(tableContainer);
    
    // Truyền biến isInv để render đúng bảng S-Box hoặc Inverse S-Box
    wrapper.appendChild(renderSboxTable(inputs, isInv));
  } else if (name.includes('ShiftRows') || name.includes('InvShiftRows')) {
    let html = '<table><tr><th>Hàng</th><th>Phép dịch</th><th>Trước</th><th>Sau</th></tr>';
    details.forEach(d => { html += `<tr><td>Hàng ${d.row}</td><td>${d.desc}</td><td>${d.before.map(b => byteToHex(b)).join(' ')}</td><td class="highlight">${d.after.map(b => byteToHex(b)).join(' ')}</td></tr>`; });
    tableContainer.innerHTML = html + '</table>'; wrapper.appendChild(tableContainer);
  } else if (name.includes('MixColumns') || name.includes('InvMixColumns')) {
    // Sửa lại ma trận trực quan sử dụng hệ số HEX chuẩn (0E, 0B, 0D, 09)
    const isInv = name.includes('Inv');
    const matrixHex = isInv 
        ? [['0E', '0B', '0D', '09'], ['09', '0E', '0B', '0D'], ['0D', '09', '0E', '0B'], ['0B', '0D', '09', '0E']] 
        : [['02', '03', '01', '01'], ['01', '02', '03', '01'], ['01', '01', '02', '03'], ['03', '01', '01', '02']];
        
    let html = '<div class="mc-detail-container">';
    details.forEach(d => {
      html += `
        <div class="mc-col-mul">
          <div class="mc-col-label">Cột ${d.col}</div>
          <div class="mc-mul-row">
            <div class="matrix-box">
              ${matrixHex.map(row => `<div class="matrix-row">${row.map(v => `<span class="m-val">${v}</span>`).join('')}</div>`).join('')}
            </div>
            <span class="mul-op">×</span>
            <div class="matrix-box vector">
              ${d.input.map(b => `<div class="matrix-row"><span class="m-val">${byteToHex(b)}</span></div>`).join('')}
            </div>
            <span class="mul-op">=</span>
            <div class="matrix-box vector highlight">
              ${d.output.map(b => `<div class="matrix-row"><span class="m-val">${byteToHex(b)}</span></div>`).join('')}
            </div>
          </div>
        </div>`;
    });
    html += '</div>';
    tableContainer.innerHTML = html; 
    wrapper.appendChild(tableContainer);
  } else if (name.includes('AddRoundKey')) {
    let html = '<table><tr><th>Vị trí</th><th>State</th><th>XOR</th><th>Round Key</th><th>Kết quả</th></tr>';
    details.forEach(d => { html += `<tr><td>${d.pos}</td><td>${byteToHex(d.state)}</td><td>⊕</td><td>${byteToHex(d.key)}</td><td class="highlight">${byteToHex(d.result)}</td></tr>`; });
    tableContainer.innerHTML = html + '</table>'; wrapper.appendChild(tableContainer);
  }
  return wrapper;
}

function renderStep(stepData) {
  const div = document.createElement('div'); div.className = `step ${STEP_CLASS[stepData.name] || ''}`;
  const header = document.createElement('div'); header.className = 'step-header';
  const label = document.createElement('div'); label.className = 'step-name'; label.textContent = stepData.name; header.appendChild(label);
  const detailBtn = document.createElement('button'); detailBtn.className = 'detail-btn'; detailBtn.textContent = 'Chi tiết ▼'; header.appendChild(detailBtn);
  div.appendChild(header);

  const gridsRow = document.createElement('div'); gridsRow.className = 'step-grids-row';
  if (stepData.name.includes('AddRoundKey') && stepData.key) {
    const stateWrap = document.createElement('div'); stateWrap.className = 'grid-label-wrap'; stateWrap.innerHTML = '<span class="grid-tag">State</span>'; stateWrap.appendChild(renderStateGrid(stepData.old_state)); gridsRow.appendChild(stateWrap);
    const op1 = document.createElement('div'); op1.className = 'grid-op'; op1.textContent = '⊕'; gridsRow.appendChild(op1);
    const keyWrap = document.createElement('div'); keyWrap.className = 'grid-label-wrap'; keyWrap.innerHTML = '<span class="grid-tag">Round Key</span>'; keyWrap.appendChild(renderStateGrid(stepData.key)); gridsRow.appendChild(keyWrap);
    const op2 = document.createElement('div'); op2.className = 'grid-op'; op2.textContent = '='; gridsRow.appendChild(op2);
    const resWrap = document.createElement('div'); resWrap.className = 'grid-label-wrap'; resWrap.innerHTML = '<span class="grid-tag">Kết quả</span>'; resWrap.appendChild(renderStateGrid(stepData.state)); gridsRow.appendChild(resWrap);
  } else if (stepData.old_state) {
    const beforeWrap = document.createElement('div'); beforeWrap.className = 'grid-label-wrap'; beforeWrap.innerHTML = '<span class="grid-tag">Trước</span>'; beforeWrap.appendChild(renderStateGrid(stepData.old_state)); gridsRow.appendChild(beforeWrap);
    const arrow = document.createElement('div'); arrow.className = 'grid-arrow'; arrow.textContent = '→'; gridsRow.appendChild(arrow);
    const afterWrap = document.createElement('div'); afterWrap.className = 'grid-label-wrap'; afterWrap.innerHTML = '<span class="grid-tag">Sau</span>'; afterWrap.appendChild(renderStateGrid(stepData.state)); gridsRow.appendChild(afterWrap);
  }
  div.appendChild(gridsRow);

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

// MỚI: Render chi tiết Key Schedule
function renderKeyScheduleSteps(data) {
  const container = document.getElementById('ks-result');
  container.innerHTML = `<p style="font-size:.8rem;color:var(--text2);margin-bottom:12px">AES-<strong style="color:var(--accent)">${data.key_bits}</strong> bit — <strong style="color:var(--accent)">${data.Nr + 1}</strong> round keys (Nk = ${data.Nk})</p>`;

  data.round_keys.forEach((rk, idx) => {
    const block = document.createElement('div'); block.className = 'round-block open';
    const header = document.createElement('div'); header.className = 'round-header'; header.style.cursor = 'default';
    header.innerHTML = `<span class="round-badge">RK${rk.round}</span><span class="round-label" style="font-family:var(--mono);font-size:.8rem;color:var(--accent)">${rk.hex.match(/.{2}/g).join(' ')}</span>`;
    block.appendChild(header);

    const content = document.createElement('div'); content.className = 'round-steps'; content.style.background = 'var(--bg2)'; content.style.padding = '12px';
    
    // Lọc các bước sinh khóa thuộc Round Key này (4 word)
    const startIdx = idx * 4;
    const endIdx = startIdx + 4;
    
    for (let i = startIdx; i < endIdx && i < data.steps.length; i++) {
      const s = data.steps[i];
      const stepDiv = document.createElement('div'); stepDiv.className = 'ks-step';

      if (s.type === 'rcon') {
        stepDiv.innerHTML = `
          <div class="ks-step-title">W[${s.i}] = W[${s.i-s.Nk}] ⊎ g(W[${s.i-1}])</div>
          <div class="ks-step-row">
            <span class="ks-label">W[${s.i-1}]:</span> <span class="ks-val">${s.w_im1.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
          <div class="ks-step-row">
            <span class="ks-label">1. RotWord:</span> <span class="ks-val">${s.rotated.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
          <div class="ks-step-row">
            <span class="ks-label">2. SubWord:</span> <span class="ks-val">${s.subbed.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
          <div class="ks-step-row">
            <span class="ks-label">3. ⊕ Rcon[${s.i/s.Nk}]:</span> <span class="ks-val">${s.rcon.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
          <div class="ks-step-row">
            <span class="ks-label">= g(W[${s.i-1}]):</span> <span class="ks-val highlight">${s.xored_rcon.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
          <div class="ks-step-row" style="border-top:1px solid var(--border);margin-top:4px;padding-top:4px;">
            <span class="ks-label">W[${s.i-s.Nk}]:</span> <span class="ks-val">${s.w_iNk.map(b=>byteToHex(b)).join(' ')}</span>
            <span class="ks-op">⊕</span>
            <span class="ks-label">g(W[${s.i-1}]):</span> <span class="ks-val">${s.xored_rcon.map(b=>byteToHex(b)).join(' ')}</span>
            <span class="ks-op">=</span>
            <span class="ks-label">W[${s.i}]:</span> <span class="ks-val highlight">${s.result.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
        `;
      } else if (s.type === 'sub') {
        stepDiv.innerHTML = `
          <div class="ks-step-title">W[${s.i}] = W[${s.i-s.Nk}] ⊕ SubWord(W[${s.i-1}])</div>
          <div class="ks-step-row">
            <span class="ks-label">W[${s.i-1}]:</span> <span class="ks-val">${s.w_im1.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
          <div class="ks-step-row">
            <span class="ks-label">SubWord:</span> <span class="ks-val">${s.subbed.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
          <div class="ks-step-row" style="border-top:1px solid var(--border);margin-top:4px;padding-top:4px;">
            <span class="ks-label">W[${s.i-s.Nk}]:</span> <span class="ks-val">${s.w_iNk.map(b=>byteToHex(b)).join(' ')}</span>
            <span class="ks-op">⊕</span>
            <span class="ks-label">SubWord:</span> <span class="ks-val">${s.subbed.map(b=>byteToHex(b)).join(' ')}</span>
            <span class="ks-op">=</span>
            <span class="ks-label">W[${s.i}]:</span> <span class="ks-val highlight">${s.result.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
        `;
      } else {
        stepDiv.innerHTML = `
          <div class="ks-step-title">W[${s.i}] = W[${s.i-s.Nk}] ⊕ W[${s.i-1}]</div>
          <div class="ks-step-row">
            <span class="ks-label">W[${s.i-s.Nk}]:</span> <span class="ks-val">${s.w_iNk.map(b=>byteToHex(b)).join(' ')}</span>
            <span class="ks-op">⊕</span>
            <span class="ks-label">W[${s.i-1}]:</span> <span class="ks-val">${s.w_im1.map(b=>byteToHex(b)).join(' ')}</span>
            <span class="ks-op">=</span>
            <span class="ks-label">W[${s.i}]:</span> <span class="ks-val highlight">${s.result.map(b=>byteToHex(b)).join(' ')}</span>
          </div>
        `;
      }
      content.appendChild(stepDiv);
    }
    block.appendChild(content);
    container.appendChild(block);
  });
  show('ks-result');
}

async function doEncrypt() {
  clearError('tab-encrypt');
  const ptRaw = val('enc-pt'); const ptFmt = val('enc-pt-fmt') || document.getElementById('enc-pt-fmt')?.value || 'ascii';
  const keyAscii = val('enc-key'); const keyBits = document.getElementById('enc-key-bits')?.value || '128';
  const mode = getActiveMode('#tab-encrypt .mode-tabs'); const ivAscii = val('enc-iv'); const verbose = document.getElementById('enc-verbose')?.checked;
  
  if (!ptRaw || !keyAscii) { showError('tab-encrypt', 'Vui lòng nhập Plaintext và Key.'); return; }
  
  let ptHex; 
  try { 
    ptHex = ptFmt === 'ascii' ? asciiToHex(ptRaw) : ptRaw.replace(/\s/g,''); 
    if (!/^[0-9a-fA-F]*$/.test(ptHex)) throw new Error(); 
  } catch { 
    showError('tab-encrypt', 'Plaintext không hợp lệ.'); return; 
  }
  
  const body = { plaintext_hex: ptHex, key_ascii: keyAscii, key_bits: keyBits, mode, verbose };
  if (mode === 'CBC') body.iv_ascii = ivAscii;
  
  try {
    const res = await fetch('/api/encrypt', { 
      method: 'POST', 
      headers: {'Content-Type':'application/json'}, 
      body: JSON.stringify(body) 
    }); 
    const data = await res.json();
    
    if (data.error) { showError('tab-encrypt', data.error); return; }
    
    document.getElementById('enc-out-hex').textContent = data.ciphertext_hex; 
    document.getElementById('enc-out-b64').textContent = data.ciphertext_b64;
    
    // SỬA LỖI HIỂN THỊ IV Ở ĐÂY
    const ivRow = document.getElementById('enc-iv-result-row');
    if (mode === 'CBC' && data.iv_hex) {
      document.getElementById('enc-out-iv').textContent = data.iv_hex;
      ivRow.style.display = 'flex'; // Hiện ô IV ra để copy
      if (data.iv_generated) {
        showToast('⚠️ IV đã tự sinh ngẫu nhiên! Hãy copy lại để giải mã.', 4000);
      }
    } else {
      ivRow.style.display = 'none'; // Ẩn ô IV nếu là ECB
    }
    
    show('enc-result-content'); 
    hide('enc-result-empty');
    
    if (data.verbose) { 
      show('verbose-section'); 
      renderVerbose(data.verbose, 'round-keys-bar', 'rounds-container', 'verbose-meta'); 
    } else { 
      hide('verbose-section'); 
    }
  } catch (e) { 
    showError('tab-encrypt', 'Lỗi server: ' + e.message); 
  }
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
    renderKeyScheduleSteps(data);
  } catch (e) { showToast('Lỗi: ' + e.message, 3000); }
}

document.addEventListener('keydown', e => { if (e.ctrlKey && e.key === 'Enter') { const activeTab = document.querySelector('.tab-btn.active')?.dataset.tab; if (activeTab === 'encrypt') doEncrypt(); else if (activeTab === 'decrypt') doDecrypt(); else if (activeTab === 'keyschedule') doKeySchedule(); } });
async function initDefaults() { await genKey('enc-key', 'enc-key-bits'); const encKey = val('enc-key'); if (encKey) { const decKeyInput = document.getElementById('dec-key'); if (decKeyInput) decKeyInput.value = encKey; } if (document.getElementById('ks-key')) await genKey('ks-key', 'ks-key-bits'); }
document.addEventListener('DOMContentLoaded', initDefaults);