import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { formatHexWindow } from '../src/hex.js';

test('formatHexWindow aligns to 16-byte rows, clamps window, and tags highlighted byte ranges', () => {
  const bytes = new Uint8Array(40);
  for (let i = 0; i < 40; i++) bytes[i] = 0x41 + (i % 26);
  const rows = formatHexWindow(bytes, 19, 2, [
    { start: 0, end: 8, role: 'PRIMARY', label: 'PNG Header' },
    { start: 20, end: 24, role: 'SECONDARY', label: 'ZIP Header' }
  ]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].offset, 16);
  assert.equal(rows[0].offsetHex, '00000010');
  assert.equal(rows[0].cells[4].role, 'SECONDARY');
  assert.equal(rows[0].cells[4].label, 'ZIP Header');
});

test('all PG-Detector source and documentation files contain zero emojis and required UI elements exist', () => {
  const root = path.resolve(import.meta.dirname, '..');
  const filesToCheck = [
    'index.html',
    'styles.css',
    'README.md',
    'src/analyzer.js',
    'src/entropy.js',
    'src/samples.js',
    'src/hex.js',
    'src/app.js'
  ];
  const emojiRegex = /\p{Extended_Pictographic}/u;
  for (const rel of filesToCheck) {
    const content = fs.readFileSync(path.join(root, rel), 'utf8');
    assert.equal(emojiRegex.test(content), false, `Found prohibited emoji in ${rel}`);
  }

  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  assert.ok(html.includes('Threat Scanner'));
  assert.ok(html.includes('Forensic Hex &amp; Entropy Lab') || html.includes('Forensic Hex & Entropy Lab'));
});
