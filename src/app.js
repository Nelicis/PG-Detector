import { analyzeBuffer, sanitizeBuffer } from './analyzer.js';
import { computeEntropyBlocks } from './entropy.js';
import { SAMPLES } from './samples.js';
import { formatHexWindow } from './hex.js';

const state = {
  bytes: new Uint8Array(0),
  fileName: '',
  analysis: null,
  entropyReport: null,
  hexOffset: 0,
  rowsPerPage: 64
};

function formatByteSize(bytesLength) {
  if (bytesLength < 1024) return `${bytesLength} B`;
  if (bytesLength < 1024 * 1024) return `${(bytesLength / 1024).toFixed(2)} KB (${bytesLength} B)`;
  return `${(bytesLength / (1024 * 1024)).toFixed(2)} MB (${bytesLength} B)`;
}

function toHexOffset(val, pad = 4) {
  return '0x' + val.toString(16).toUpperCase().padStart(pad, '0');
}

function buildHighlights(analysis) {
  if (!analysis) return [];
  return analysis.signatures.map(sig => ({
    start: sig.offset,
    end: sig.offset + (sig.length || 4),
    role: sig.role,
    label: sig.name
  }));
}

function switchTab(tabName) {
  const scannerBtn = document.getElementById('tab-btn-scanner');
  const labBtn = document.getElementById('tab-btn-lab');
  const scannerPanel = document.getElementById('panel-scanner');
  const labPanel = document.getElementById('panel-lab');

  const isScanner = tabName === 'scanner';
  scannerBtn.classList.toggle('active', isScanner);
  scannerBtn.setAttribute('aria-selected', String(isScanner));
  labBtn.classList.toggle('active', !isScanner);
  labBtn.setAttribute('aria-selected', String(!isScanner));

  scannerPanel.hidden = !isScanner;
  labPanel.hidden = isScanner;

  if (!isScanner) {
    renderEntropyCanvas();
    renderHexView();
  }
}

function jumpToHexOffset(offset) {
  state.hexOffset = Math.max(0, Math.min(state.bytes.length - 1, offset)) & ~0x0F;
  switchTab('lab');
  renderHexView();
}

function renderScannerView() {
  const { analysis, entropyReport } = state;
  if (!analysis) return;

  document.getElementById('meta-filename').textContent = analysis.fileName;
  document.getElementById('meta-filesize').textContent = formatByteSize(analysis.fileSize);
  document.getElementById('meta-primary').textContent = analysis.primaryFormat
    ? `${analysis.primaryFormat.id} (${analysis.primaryFormat.mime})`
    : 'UNSTRUCTURED / RAW';
  document.getElementById('meta-entropy').textContent = `${entropyReport.overallEntropy.toFixed(3)} bits/byte`;

  const banner = document.getElementById('verdict-banner');
  banner.classList.remove('verdict-clean', 'verdict-suspicious', 'verdict-polyglot');
  if (analysis.verdict === 'CLEAN') {
    banner.classList.add('verdict-clean');
  } else if (analysis.verdict === 'SUSPICIOUS') {
    banner.classList.add('verdict-suspicious');
  } else {
    banner.classList.add('verdict-polyglot');
  }

  document.getElementById('verdict-status').textContent = analysis.verdict;
  document.getElementById('verdict-summary').textContent = analysis.summary;
  document.getElementById('risk-score').textContent = `${analysis.riskScore} / 100`;

  const sanitizeBtn = document.getElementById('sanitize-btn');
  sanitizeBtn.hidden = !analysis.canSanitize;

  // Render structural byte layout bar
  const bar = document.getElementById('byte-layout-bar');
  const legend = document.getElementById('byte-layout-legend');
  bar.innerHTML = '';
  legend.innerHTML = '';

  for (const reg of analysis.regions) {
    const pct = analysis.fileSize > 0 ? Math.max(8, (reg.length / analysis.fileSize) * 100) : 100;
    const seg = document.createElement('div');
    seg.className = `byte-segment ${reg.type === 'PRIMARY' ? 'seg-primary' : 'seg-appended'}`;
    seg.style.width = `${pct}%`;
    seg.textContent = `${reg.label} (${reg.length} B)`;
    seg.title = `Click to inspect ${reg.label} at ${toHexOffset(reg.startOffset)}`;
    seg.addEventListener('click', () => jumpToHexOffset(reg.startOffset));
    bar.appendChild(seg);

    const item = document.createElement('span');
    item.textContent = `${reg.label}: ${toHexOffset(reg.startOffset)} .. ${toHexOffset(reg.endOffset)} (${reg.length} bytes)`;
    legend.appendChild(item);
  }

  // Render signatures table
  const tbody = document.getElementById('signatures-tbody');
  tbody.innerHTML = '';

  for (const sig of analysis.signatures) {
    const tr = document.createElement('tr');

    const roleTd = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = `role-pill role-${sig.role}`;
    pill.textContent = sig.role;
    roleTd.appendChild(pill);

    const nameTd = document.createElement('td');
    nameTd.textContent = sig.name;

    const offsetTd = document.createElement('td');
    offsetTd.className = 'mono-cell';
    offsetTd.textContent = `${toHexOffset(sig.offset, 6)} (${sig.offset})`;

    const hexTd = document.createElement('td');
    hexTd.className = 'mono-cell';
    hexTd.textContent = sig.hexSignature;

    const descTd = document.createElement('td');
    descTd.textContent = sig.description;

    const actionTd = document.createElement('td');
    const jumpBtn = document.createElement('button');
    jumpBtn.type = 'button';
    jumpBtn.className = 'jump-link-btn';
    jumpBtn.textContent = 'Inspect Offset';
    jumpBtn.addEventListener('click', () => jumpToHexOffset(sig.offset));
    actionTd.appendChild(jumpBtn);

    tr.append(roleTd, nameTd, offsetTd, hexTd, descTd, actionTd);
    tbody.appendChild(tr);
  }
}

function renderEntropyCanvas() {
  const canvas = document.getElementById('entropy-canvas');
  if (!canvas || !state.entropyReport) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;

  ctx.clearRect(0, 0, width, height);

  // Draw horizontal reference grid lines at 3.5 and 6.8 bits/byte
  ctx.strokeStyle = '#1f2937';
  ctx.lineWidth = 1;
  [3.5, 6.8].forEach(level => {
    const y = height - (level / 8) * (height - 20) - 10;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  });

  const blocks = state.entropyReport.blocks;
  if (blocks.length === 0) return;

  const barWidth = width / blocks.length;
  blocks.forEach((b, idx) => {
    const usableHeight = height - 20;
    const barHeight = Math.max(4, (b.entropy / 8) * usableHeight);
    const x = idx * barWidth;
    const y = height - barHeight - 4;

    if (b.classification === 'HIGH') {
      ctx.fillStyle = '#ef4444';
    } else if (b.classification === 'MEDIUM') {
      ctx.fillStyle = '#3b82f6';
    } else {
      ctx.fillStyle = '#10b981';
    }

    ctx.fillRect(x + 1, y, Math.max(1, barWidth - 2), barHeight);
  });
}

function renderHexView() {
  const highlights = buildHighlights(state.analysis);
  const rows = formatHexWindow(state.bytes, state.hexOffset, state.rowsPerPage, highlights);
  const tbody = document.getElementById('hex-tbody');
  tbody.innerHTML = '';

  const windowEnd = Math.min(
    state.bytes.length,
    state.hexOffset + state.rowsPerPage * 16
  );
  document.getElementById('hex-range-label').textContent =
    `${toHexOffset(state.hexOffset, 8)} - ${toHexOffset(Math.max(0, windowEnd - 1), 8)}`;

  for (const row of rows) {
    const tr = document.createElement('tr');

    const offsetTd = document.createElement('td');
    offsetTd.className = 'hex-offset-col';
    offsetTd.textContent = row.offsetHex;

    const hexTd = document.createElement('td');
    const asciiTd = document.createElement('td');
    asciiTd.className = 'hex-ascii-col';

    row.cells.forEach((cell, idx) => {
      const hexSpan = document.createElement('span');
      hexSpan.textContent = cell.byteHex + (idx < 15 ? ' ' : '');
      if (cell.role) {
        hexSpan.className = `hl-${cell.role}`;
        hexSpan.title = cell.label || '';
      }
      hexTd.appendChild(hexSpan);

      const asciiSpan = document.createElement('span');
      asciiSpan.textContent = cell.ascii;
      if (cell.role) {
        asciiSpan.className = `hl-${cell.role}`;
      }
      asciiTd.appendChild(asciiSpan);
    });

    tr.append(offsetTd, hexTd, asciiTd);
    tbody.appendChild(tr);
  }

  // Render landmarks sidebar
  const landmarkList = document.getElementById('landmark-list');
  landmarkList.innerHTML = '';
  if (state.analysis) {
    for (const sig of state.analysis.signatures) {
      const li = document.createElement('li');
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'landmark-btn';
      const leftSpan = document.createElement('span');
      leftSpan.textContent = sig.name;
      const rightSpan = document.createElement('span');
      rightSpan.textContent = toHexOffset(sig.offset, 4);
      btn.append(leftSpan, rightSpan);
      btn.addEventListener('click', () => jumpToHexOffset(sig.offset));
      li.appendChild(btn);
      landmarkList.appendChild(li);
    }
  }
}

function loadBuffer(bytes, fileName) {
  state.bytes = bytes;
  state.fileName = fileName;
  state.hexOffset = 0;
  state.analysis = analyzeBuffer(bytes, fileName);
  state.entropyReport = computeEntropyBlocks(bytes, 64);

  renderScannerView();
  renderEntropyCanvas();
  renderHexView();
}

function initApp() {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', async e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer?.files?.[0];
    if (file) {
      const buf = await file.arrayBuffer();
      loadBuffer(new Uint8Array(buf), file.name);
    }
  });

  fileInput.addEventListener('change', async e => {
    const file = e.target.files?.[0];
    if (file) {
      const buf = await file.arrayBuffer();
      loadBuffer(new Uint8Array(buf), file.name);
    }
  });

  document.querySelectorAll('.sample-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.sample-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const sampleKey = btn.getAttribute('data-sample');
      const sample = SAMPLES[sampleKey];
      if (sample) {
        loadBuffer(sample.build(), sample.fileName);
      }
    });
  });

  document.getElementById('tab-btn-scanner').addEventListener('click', () => switchTab('scanner'));
  document.getElementById('tab-btn-lab').addEventListener('click', () => switchTab('lab'));
  document.getElementById('open-lab-btn').addEventListener('click', () => switchTab('lab'));

  document.getElementById('sanitize-btn').addEventListener('click', () => {
    if (!state.analysis || !state.analysis.canSanitize) return;
    const cleaned = sanitizeBuffer(state.bytes, state.analysis);
    const blob = new Blob([cleaned], {
      type: state.analysis.primaryFormat?.mime || 'application/octet-stream'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sanitized_${state.fileName}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  document.getElementById('hex-prev-btn').addEventListener('click', () => {
    const step = state.rowsPerPage * 16;
    state.hexOffset = Math.max(0, state.hexOffset - step);
    renderHexView();
  });

  document.getElementById('hex-next-btn').addEventListener('click', () => {
    const step = state.rowsPerPage * 16;
    if (state.hexOffset + step < state.bytes.length) {
      state.hexOffset += step;
      renderHexView();
    }
  });

  document.getElementById('hex-jump-form').addEventListener('submit', e => {
    e.preventDefault();
    const raw = document.getElementById('hex-offset-input').value.trim().replace(/^0x/i, '');
    const parsed = parseInt(raw, 16);
    if (!Number.isNaN(parsed)) {
      jumpToHexOffset(parsed);
    }
  });

  document.getElementById('entropy-canvas').addEventListener('click', e => {
    if (!state.entropyReport || state.entropyReport.blocks.length === 0) return;
    const rect = e.target.getBoundingClientRect();
    const ratio = Math.max(0, Math.min(0.999, (e.clientX - rect.left) / rect.width));
    const idx = Math.floor(ratio * state.entropyReport.blocks.length);
    const block = state.entropyReport.blocks[idx];
    if (block) {
      jumpToHexOffset(block.startOffset);
    }
  });

  // Load default PNG + ZIP polyglot sample on startup
  const defaultBtn = document.querySelector('[data-sample="png-zip"]');
  if (defaultBtn) defaultBtn.classList.add('active');
  loadBuffer(SAMPLES['png-zip'].build(), SAMPLES['png-zip'].fileName);
}

if (typeof document !== 'undefined') {
  initApp();
}
