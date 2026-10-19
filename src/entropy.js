export function computeShannonEntropy(slice) {
  if (!slice || slice.length === 0) return 0;

  const counts = new Uint32Array(256);
  const len = slice.length;
  for (let i = 0; i < len; i++) {
    counts[slice[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c > 0) {
      const p = c / len;
      entropy -= p * Math.log2(p);
    }
  }

  return Math.round(entropy * 1000) / 1000;
}

function classifyEntropy(value) {
  if (value < 3.5) return 'LOW';
  if (value <= 6.8) return 'MEDIUM';
  return 'HIGH';
}

export function computeEntropyBlocks(inputBytes, targetBlocks = 64) {
  const bytes = inputBytes instanceof Uint8Array ? inputBytes : new Uint8Array(inputBytes || 0);
  if (bytes.length === 0) {
    return {
      overallEntropy: 0,
      blockSize: 0,
      blocks: []
    };
  }

  const overallEntropy = computeShannonEntropy(bytes);
  const blockCount = Math.max(1, Math.min(targetBlocks, bytes.length));
  const blockSize = Math.max(1, Math.ceil(bytes.length / blockCount));
  const blocks = [];

  for (let startOffset = 0, index = 0; startOffset < bytes.length; startOffset += blockSize, index++) {
    const endOffset = Math.min(bytes.length, startOffset + blockSize);
    const slice = bytes.subarray(startOffset, endOffset);
    const entropy = computeShannonEntropy(slice);
    blocks.push({
      index,
      startOffset,
      endOffset,
      entropy,
      classification: classifyEntropy(entropy)
    });
  }

  return {
    overallEntropy,
    blockSize,
    blocks
  };
}
