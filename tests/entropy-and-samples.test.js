import test from 'node:test';
import assert from 'node:assert/strict';
import { computeShannonEntropy, computeEntropyBlocks } from '../src/entropy.js';
import { SAMPLES } from '../src/samples.js';
import { analyzeBuffer } from '../src/analyzer.js';

test('computeShannonEntropy returns 0 for uniform bytes and 8 for all 256 byte values', () => {
  assert.equal(computeShannonEntropy(new Uint8Array(0)), 0);
  assert.equal(computeShannonEntropy(new Uint8Array(128).fill(0x41)), 0);

  const fullAlphabet = new Uint8Array(256);
  for (let i = 0; i < 256; i++) fullAlphabet[i] = i;
  assert.equal(computeShannonEntropy(fullAlphabet), 8);
});

test('computeEntropyBlocks partitions buffer and classifies block entropy', () => {
  const lowPart = new Uint8Array(512).fill(0x00);
  const highPart = new Uint8Array(512);
  for (let i = 0; i < 512; i++) highPart[i] = i & 0xFF;
  const combined = new Uint8Array(1024);
  combined.set(lowPart, 0);
  combined.set(highPart, 512);

  const report = computeEntropyBlocks(combined, 2);
  assert.equal(report.blocks.length, 2);
  assert.equal(report.blocks[0].classification, 'LOW');
  assert.equal(report.blocks[1].classification, 'HIGH');
});

test('built-in synthetic samples trigger expected analyzer verdicts', () => {
  const pngZip = analyzeBuffer(SAMPLES['png-zip'].build(), SAMPLES['png-zip'].fileName);
  assert.equal(pngZip.verdict, 'POLYGLOT DETECTED');
  assert.equal(pngZip.canSanitize, true);

  const gifJs = analyzeBuffer(SAMPLES['gif-js'].build(), SAMPLES['gif-js'].fileName);
  assert.equal(gifJs.verdict, 'POLYGLOT DETECTED');

  const jpegPhp = analyzeBuffer(SAMPLES['jpeg-php'].build(), SAMPLES['jpeg-php'].fileName);
  assert.equal(jpegPhp.verdict, 'POLYGLOT DETECTED');

  const cleanPng = analyzeBuffer(SAMPLES['clean-png'].build(), SAMPLES['clean-png'].fileName);
  assert.equal(cleanPng.verdict, 'CLEAN');
});
