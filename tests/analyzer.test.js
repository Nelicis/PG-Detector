import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeBuffer, sanitizeBuffer } from '../src/analyzer.js';

function makeMinimalPng() {
  // 8-byte magic + IHDR (13 bytes) + IEND (0 bytes)
  return new Uint8Array([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00,
    0x90, 0x77, 0x53, 0xDE,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
    0xAE, 0x42, 0x60, 0x82
  ]);
}

function makeMinimalZip() {
  // PK\x03\x04 local header (30 bytes + 5 byte name "a.txt") + PK\x05\x06 EOCD (22 bytes)
  const local = [
    0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x61, 0x2E, 0x74, 0x78, 0x74
  ];
  const eocd = [
    0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x33, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ];
  return new Uint8Array([...local, ...eocd]);
}

test('detects a clean PNG with exact IEND boundary', () => {
  const png = makeMinimalPng();
  const res = analyzeBuffer(png, 'clean.png');
  assert.equal(res.verdict, 'CLEAN');
  assert.equal(res.primaryFormat.id, 'PNG');
  assert.equal(res.primaryFormat.endOffset, png.length);
  assert.equal(res.canSanitize, false);
});

test('detects PNG + ZIP appended polyglot and sanitizes cleanly', () => {
  const png = makeMinimalPng();
  const zip = makeMinimalZip();
  const combined = new Uint8Array(png.length + zip.length);
  combined.set(png, 0);
  combined.set(zip, png.length);

  const res = analyzeBuffer(combined, 'avatar.png');
  assert.equal(res.verdict, 'POLYGLOT DETECTED');
  assert.equal(res.canSanitize, true);
  assert.equal(res.sanitizeCutoff, png.length);
  assert.ok(res.signatures.some(s => s.id === 'ZIP' && s.offset === png.length));

  const cleaned = sanitizeBuffer(combined, res);
  assert.equal(cleaned.length, png.length);
  assert.equal(analyzeBuffer(cleaned, 'cleaned.png').verdict, 'CLEAN');
});

test('detects GIF89a + JavaScript comment polyglot', () => {
  const text = 'GIF89a/*\x00\x00\x3B*/=1;eval("alert(1)");';
  const bytes = new TextEncoder().encode(text);
  const res = analyzeBuffer(bytes, 'logo.gif');
  assert.equal(res.verdict, 'POLYGLOT DETECTED');
  assert.ok(res.signatures.some(s => s.id === 'SCRIPT'));
});

test('skips nested FF D9 inside JPEG APP1 EXIF segment before finding true EOI', () => {
  const jpegWithExif = new Uint8Array([
    0xFF, 0xD8,
    0xFF, 0xE1, 0x00, 0x08, 0x45, 0x78, 0xFF, 0xD8, 0xFF, 0xD9,
    0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00, 0x11, 0x22, 0xFF, 0x00, 0x33,
    0xFF, 0xD9
  ]);
  const res = analyzeBuffer(jpegWithExif, 'photo.jpg');
  assert.equal(res.verdict, 'CLEAN');
  assert.equal(res.primaryFormat.endOffset, jpegWithExif.length);
});

test('handles empty, tiny, and truncated PNG chunk lengths safely', () => {
  const empty = analyzeBuffer(new Uint8Array(0), 'empty.bin');
  assert.equal(empty.verdict, 'CLEAN');
  assert.equal(empty.fileSize, 0);

  const corruptPng = new Uint8Array([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    0x7F, 0xFF, 0xFF, 0xFF, 0x49, 0x48, 0x44, 0x52
  ]);
  const corruptRes = analyzeBuffer(corruptPng, 'corrupt.png');
  assert.equal(corruptRes.primaryFormat.truncated, true);
});
