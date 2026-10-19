export function formatHexWindow(inputBytes, startOffset = 0, rowCount = 64, highlights = []) {
  const bytes = inputBytes instanceof Uint8Array ? inputBytes : new Uint8Array(inputBytes || 0);
  if (bytes.length === 0) return [];

  const maxAlignedStart = Math.max(0, (bytes.length - 1) & ~0x0F);
  const alignedStart = Math.min(maxAlignedStart, Math.max(0, startOffset & ~0x0F));
  const rows = [];

  for (let r = 0; r < rowCount; r++) {
    const rowOffset = alignedStart + r * 16;
    if (rowOffset >= bytes.length) break;

    const cells = [];
    for (let c = 0; c < 16; c++) {
      const bytePos = rowOffset + c;
      if (bytePos >= bytes.length) {
        cells.push({
          empty: true,
          byteHex: '  ',
          ascii: ' ',
          role: null,
          label: null
        });
        continue;
      }

      const val = bytes[bytePos];
      const byteHex = val.toString(16).toUpperCase().padStart(2, '0');
      const ascii = val >= 0x20 && val <= 0x7E ? String.fromCharCode(val) : '.';

      let role = null;
      let label = null;
      for (let h = 0; h < highlights.length; h++) {
        const hl = highlights[h];
        if (bytePos >= hl.start && bytePos < hl.end) {
          role = hl.role;
          label = hl.label;
          break;
        }
      }

      cells.push({
        empty: false,
        offset: bytePos,
        byteHex,
        ascii,
        role,
        label
      });
    }

    rows.push({
      offset: rowOffset,
      offsetHex: rowOffset.toString(16).toUpperCase().padStart(8, '0'),
      cells
    });
  }

  return rows;
}
