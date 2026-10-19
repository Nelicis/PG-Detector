function readUint32BE(bytes, offset) {
  if (offset + 4 > bytes.length) return -1;
  return (
    ((bytes[offset] << 24) >>> 0) +
    ((bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3])
  ) >>> 0;
}

function readUint16BE(bytes, offset) {
  if (offset + 2 > bytes.length) return -1;
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function readUint16LE(bytes, offset) {
  if (offset + 2 > bytes.length) return -1;
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function matchesAt(bytes, offset, pattern) {
  if (offset < 0 || offset + pattern.length > bytes.length) return false;
  for (let i = 0; i < pattern.length; i++) {
    if (bytes[offset + i] !== pattern[i]) return false;
  }
  return true;
}

function toHexSlice(bytes, offset, len) {
  const end = Math.min(bytes.length, offset + len);
  const parts = [];
  for (let i = offset; i < end; i++) {
    parts.push(bytes[i].toString(16).toUpperCase().padStart(2, '0'));
  }
  return parts.join(' ');
}

function parsePngContainer(bytes) {
  const magic = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
  if (!matchesAt(bytes, 0, magic)) return null;

  const signatures = [
    {
      id: 'PNG',
      name: 'PNG Header',
      offset: 0,
      length: 8,
      hexSignature: '89 50 4E 47 0D 0A 1A 0A',
      role: 'PRIMARY',
      description: 'Valid PNG 8-byte file signature'
    }
  ];

  let pos = 8;
  let endOffset = bytes.length;
  let truncated = false;
  let foundIend = false;

  while (pos + 8 <= bytes.length) {
    const chunkLen = readUint32BE(bytes, pos);
    const typeA = bytes[pos + 4];
    const typeB = bytes[pos + 5];
    const typeC = bytes[pos + 6];
    const typeD = bytes[pos + 7];
    const chunkTotal = 12 + chunkLen;

    if (chunkLen < 0 || pos + chunkTotal > bytes.length) {
      truncated = true;
      endOffset = bytes.length;
      break;
    }

    // Check for IEND (0x49 0x45 0x4E 0x44)
    if (typeA === 0x49 && typeB === 0x45 && typeC === 0x4E && typeD === 0x44) {
      foundIend = true;
      endOffset = pos + chunkTotal;
      signatures.push({
        id: 'PNG_IEND',
        name: 'PNG IEND Trailer',
        offset: pos + 4,
        length: 8,
        hexSignature: toHexSlice(bytes, pos + 4, 8),
        role: 'BOUNDARY',
        description: 'PNG IEND chunk marking true end of PNG stream'
      });
      break;
    }

    pos += chunkTotal;
  }

  if (!foundIend) {
    truncated = true;
  }

  return {
    primaryFormat: {
      id: 'PNG',
      name: 'Portable Network Graphics (PNG)',
      mime: 'image/png',
      startOffset: 0,
      endOffset,
      truncated
    },
    signatures
  };
}

function parseJpegContainer(bytes) {
  if (!matchesAt(bytes, 0, [0xFF, 0xD8])) return null;

  const signatures = [
    {
      id: 'JPEG',
      name: 'JPEG SOI Header',
      offset: 0,
      length: 2,
      hexSignature: 'FF D8',
      role: 'PRIMARY',
      description: 'JPEG Start of Image (SOI) marker'
    }
  ];

  let pos = 2;
  let endOffset = bytes.length;
  let truncated = true;
  let inEntropyScan = false;

  while (pos < bytes.length) {
    if (!inEntropyScan) {
      if (bytes[pos] !== 0xFF) {
        pos++;
        continue;
      }
      while (pos < bytes.length && bytes[pos] === 0xFF) {
        pos++;
      }
      if (pos >= bytes.length) break;
      const marker = bytes[pos];
      pos++;

      if (marker === 0xD9) {
        endOffset = pos;
        truncated = false;
        signatures.push({
          id: 'JPEG_EOI',
          name: 'JPEG EOI Trailer',
          offset: pos - 2,
          length: 2,
          hexSignature: 'FF D9',
          role: 'BOUNDARY',
          description: 'JPEG End of Image (EOI) marker'
        });
        break;
      }

      // Standalone markers without length
      if (marker === 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker === 0x01 || marker === 0x00) {
        continue;
      }

      const segLen = readUint16BE(bytes, pos);
      if (segLen < 2 || pos + segLen > bytes.length) {
        truncated = true;
        break;
      }

      pos += segLen;
      if (marker === 0xDA) {
        inEntropyScan = true;
      }
    } else {
      if (bytes[pos] === 0xFF) {
        if (pos + 1 >= bytes.length) break;
        const next = bytes[pos + 1];
        if (next === 0x00) {
          pos += 2;
          continue;
        }
        if (next >= 0xD0 && next <= 0xD7) {
          pos += 2;
          continue;
        }
        if (next === 0xFF) {
          pos++;
          continue;
        }
        // Any other marker exits entropy scan
        inEntropyScan = false;
        continue;
      }
      pos++;
    }
  }

  return {
    primaryFormat: {
      id: 'JPEG',
      name: 'JPEG Image',
      mime: 'image/jpeg',
      startOffset: 0,
      endOffset,
      truncated
    },
    signatures
  };
}

function parseGifContainer(bytes) {
  const is87a = matchesAt(bytes, 0, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]);
  const is89a = matchesAt(bytes, 0, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);
  if (!is87a && !is89a) return null;

  const signatures = [
    {
      id: 'GIF',
      name: is89a ? 'GIF89a Header' : 'GIF87a Header',
      offset: 0,
      length: 6,
      hexSignature: toHexSlice(bytes, 0, 6),
      role: 'PRIMARY',
      description: 'Graphics Interchange Format header'
    }
  ];

  // Check for GIF89a/* comment polyglot trick right after header
  if (bytes.length >= 8 && bytes[6] === 0x2F && bytes[7] === 0x2A) {
    signatures.push({
      id: 'SCRIPT',
      name: 'GIF Comment Script Opener (/*)',
      offset: 6,
      length: 2,
      hexSignature: '2F 2A',
      role: 'SECONDARY',
      description: 'C/JavaScript multi-line comment opener embedded inside GIF screen descriptor'
    });
  }

  let endOffset = bytes.length;
  let truncated = true;
  for (let i = bytes.length - 1; i >= 6; i--) {
    if (bytes[i] === 0x3B) {
      endOffset = i + 1;
      truncated = false;
      signatures.push({
        id: 'GIF_EOF',
        name: 'GIF Trailer (0x3B)',
        offset: i,
        length: 1,
        hexSignature: '3B',
        role: 'BOUNDARY',
        description: 'GIF terminator byte'
      });
      break;
    }
  }

  return {
    primaryFormat: {
      id: 'GIF',
      name: 'GIF Image',
      mime: 'image/gif',
      startOffset: 0,
      endOffset,
      truncated
    },
    signatures
  };
}

function parsePdfContainer(bytes) {
  const pdfPattern = [0x25, 0x50, 0x44, 0x46, 0x2D]; // %PDF-
  if (!matchesAt(bytes, 0, pdfPattern)) return null;

  const signatures = [
    {
      id: 'PDF',
      name: 'PDF Header (%PDF-)',
      offset: 0,
      length: 5,
      hexSignature: '25 50 44 46 2D',
      role: 'PRIMARY',
      description: 'Portable Document Format header'
    }
  ];

  const eofPattern = [0x25, 0x25, 0x45, 0x4F, 0x46]; // %%EOF
  let endOffset = bytes.length;
  let truncated = true;

  for (let i = bytes.length - eofPattern.length; i >= 5; i--) {
    if (matchesAt(bytes, i, eofPattern)) {
      let after = i + eofPattern.length;
      while (after < bytes.length && (bytes[after] === 0x0D || bytes[after] === 0x0A)) {
        after++;
      }
      endOffset = after;
      truncated = false;
      signatures.push({
        id: 'PDF_EOF',
        name: 'PDF %%EOF Trailer',
        offset: i,
        length: 5,
        hexSignature: '25 25 45 4F 46',
        role: 'BOUNDARY',
        description: 'PDF end-of-file marker'
      });
      break;
    }
  }

  return {
    primaryFormat: {
      id: 'PDF',
      name: 'PDF Document',
      mime: 'application/pdf',
      startOffset: 0,
      endOffset,
      truncated
    },
    signatures
  };
}

function parseZipPrimary(bytes) {
  if (!matchesAt(bytes, 0, [0x50, 0x4B, 0x03, 0x04])) return null;
  return {
    primaryFormat: {
      id: 'ZIP',
      name: 'PKZIP Archive',
      mime: 'application/zip',
      startOffset: 0,
      endOffset: bytes.length,
      truncated: false
    },
    signatures: [
      {
        id: 'ZIP',
        name: 'ZIP Local File Header',
        offset: 0,
        length: 4,
        hexSignature: '50 4B 03 04',
        role: 'PRIMARY',
        description: 'PKZIP archive local header'
      }
    ]
  };
}

function findEocdOffset(bytes) {
  const eocdSig = [0x50, 0x4B, 0x05, 0x06];
  const minPos = Math.max(0, bytes.length - 65557);
  for (let i = bytes.length - 22; i >= minPos; i--) {
    if (matchesAt(bytes, i, eocdSig)) {
      return i;
    }
  }
  return -1;
}

function scanSecondarySignatures(bytes, primaryFormat) {
  const found = [];
  const eocdOffset = findEocdOffset(bytes);

  for (let i = 0; i < bytes.length - 3; i++) {
    // ZIP Local Header: 50 4B 03 04
    if (i > 0 && matchesAt(bytes, i, [0x50, 0x4B, 0x03, 0x04])) {
      const nameLen = readUint16LE(bytes, i + 26);
      const validHeader = nameLen > 0 && nameLen < 512 && i + 30 + nameLen <= bytes.length;
      if (validHeader || eocdOffset !== -1) {
        found.push({
          id: 'ZIP',
          name: 'Hidden PKZIP Archive Header',
          offset: i,
          length: 4,
          hexSignature: '50 4B 03 04',
          role: 'SECONDARY',
          description: 'Embedded or appended ZIP archive local file header (PK\x03\x04)'
        });
      }
    }

    // ZIP EOCD: 50 4B 05 06 when primary format is not ZIP
    if ((!primaryFormat || primaryFormat.id !== 'ZIP') && matchesAt(bytes, i, [0x50, 0x4B, 0x05, 0x06])) {
      found.push({
        id: 'ZIP_EOCD',
        name: 'ZIP End of Central Directory',
        offset: i,
        length: 4,
        hexSignature: '50 4B 05 06',
        role: 'SECONDARY',
        description: 'Bottom-up ZIP central directory trailer enabling archive polyglots'
      });
    }

    // RAR Archive: 52 61 72 21 1A 07
    if (i > 0 && matchesAt(bytes, i, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])) {
      found.push({
        id: 'RAR',
        name: 'Embedded RAR Archive',
        offset: i,
        length: 6,
        hexSignature: '52 61 72 21 1A 07',
        role: 'SECONDARY',
        description: 'RAR archive header detected inside file'
      });
    }

    // 7z Archive: 37 7A BC AF 27 1C
    if (i > 0 && matchesAt(bytes, i, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) {
      found.push({
        id: '7Z',
        name: 'Embedded 7-Zip Archive',
        offset: i,
        length: 6,
        hexSignature: '37 7A BC AF 27 1C',
        role: 'SECONDARY',
        description: '7-Zip archive signature detected inside file'
      });
    }

    // PDF Header inside another file (first 1024 bytes or after EOF)
    if (i > 0 && matchesAt(bytes, i, [0x25, 0x50, 0x44, 0x46, 0x2D])) {
      found.push({
        id: 'PDF',
        name: 'Embedded PDF Header (%PDF-)',
        offset: i,
        length: 5,
        hexSignature: '25 50 44 46 2D',
        role: 'SECONDARY',
        description: 'PDF document header shifted past offset 0 (polyglot PDF container)'
      });
    }

    // ELF Header: 7F 45 4C 46
    if (matchesAt(bytes, i, [0x7F, 0x45, 0x4C, 0x46]) && (i === 0 || (primaryFormat && i >= primaryFormat.endOffset))) {
      found.push({
        id: 'ELF',
        name: 'ELF Executable Header',
        offset: i,
        length: 4,
        hexSignature: '7F 45 4C 46',
        role: i === 0 ? 'PRIMARY' : 'SECONDARY',
        description: 'Linux/Unix ELF binary header'
      });
    }

    // WebAssembly Binary: 00 61 73 6D (\0asm)
    if (matchesAt(bytes, i, [0x00, 0x61, 0x73, 0x6D]) && (i === 0 || (primaryFormat && i >= primaryFormat.endOffset))) {
      found.push({
        id: 'WASM',
        name: 'WebAssembly Module Header',
        offset: i,
        length: 4,
        hexSignature: '00 61 73 6D',
        role: i === 0 ? 'PRIMARY' : 'SECONDARY',
        description: 'WebAssembly binary module magic bytes'
      });
    }

    // PE / MZ Header at or after primary EOF
    if (primaryFormat && i >= primaryFormat.endOffset && matchesAt(bytes, i, [0x4D, 0x5A])) {
      found.push({
        id: 'PE',
        name: 'Appended Windows PE/MZ Header',
        offset: i,
        length: 2,
        hexSignature: '4D 5A',
        role: 'SECONDARY',
        description: 'DOS/Windows executable header (MZ) appended after container EOF'
      });
    }

    // Embedded PHP tag: <?php (3C 3F 70 68 70)
    if (matchesAt(bytes, i, [0x3C, 0x3F, 0x70, 0x68, 0x70])) {
      found.push({
        id: 'SCRIPT',
        name: 'Embedded PHP Payload (<?php)',
        offset: i,
        length: 5,
        hexSignature: '3C 3F 70 68 70',
        role: 'SECONDARY',
        description: 'Executable PHP code block embedded in file'
      });
    }

    // Embedded HTML/JS <script (3C 73 63 72 69 70 74)
    if (matchesAt(bytes, i, [0x3C, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74])) {
      found.push({
        id: 'SCRIPT',
        name: 'Embedded HTML Script Tag (<script)',
        offset: i,
        length: 7,
        hexSignature: '3C 73 63 72 69 70 74',
        role: 'SECONDARY',
        description: 'HTML script tag hidden inside binary stream'
      });
    }

    // Embedded JS eval( (65 76 61 6C 28)
    if (matchesAt(bytes, i, [0x65, 0x76, 0x61, 0x6C, 0x28])) {
      found.push({
        id: 'SCRIPT',
        name: 'Embedded JavaScript eval() Call',
        offset: i,
        length: 5,
        hexSignature: '65 76 61 6C 28',
        role: 'SECONDARY',
        description: 'Dynamic code execution call (eval) inside binary file'
      });
    }

    // Shell shebang #!/bin/ (23 21 2F 62 69 6E 2F)
    if (i > 0 && matchesAt(bytes, i, [0x23, 0x21, 0x2F, 0x62, 0x69, 0x6E, 0x2F])) {
      found.push({
        id: 'SCRIPT',
        name: 'Embedded Shell Script (#!/bin/)',
        offset: i,
        length: 7,
        hexSignature: '23 21 2F 62 69 6E 2F',
        role: 'SECONDARY',
        description: 'Unix shell script shebang hidden in file'
      });
    }
  }

  return found;
}

export function analyzeBuffer(inputBytes, fileName = 'sample.bin') {
  const bytes = inputBytes instanceof Uint8Array ? inputBytes : new Uint8Array(inputBytes || 0);

  if (bytes.length === 0) {
    return {
      fileName,
      fileSize: 0,
      verdict: 'CLEAN',
      riskScore: 0,
      summary: 'Empty file buffer (0 bytes). No polyglot structures or hidden signatures detected.',
      primaryFormat: null,
      regions: [],
      signatures: [],
      canSanitize: false,
      sanitizeCutoff: null
    };
  }

  const parsed =
    parsePngContainer(bytes) ||
    parseJpegContainer(bytes) ||
    parseGifContainer(bytes) ||
    parsePdfContainer(bytes) ||
    parseZipPrimary(bytes);

  const primaryFormat = parsed ? parsed.primaryFormat : null;
  const signatures = parsed ? [...parsed.signatures] : [];
  const secondary = scanSecondarySignatures(bytes, primaryFormat);

  for (const sig of secondary) {
    if (!signatures.some(existing => existing.offset === sig.offset && existing.id === sig.id)) {
      signatures.push(sig);
    }
  }

  signatures.sort((a, b) => a.offset - b.offset);

  const regions = [];
  let trailingLength = 0;

  if (primaryFormat) {
    regions.push({
      type: 'PRIMARY',
      format: primaryFormat.id,
      label: `${primaryFormat.id} Container`,
      startOffset: 0,
      endOffset: primaryFormat.endOffset,
      length: primaryFormat.endOffset
    });

    if (!primaryFormat.truncated && primaryFormat.endOffset < bytes.length) {
      trailingLength = bytes.length - primaryFormat.endOffset;
      const appendedSigs = secondary.filter(s => s.offset >= primaryFormat.endOffset);
      const appendedFormat = appendedSigs.length > 0 ? appendedSigs[0].id : 'DATA';
      regions.push({
        type: 'APPENDED',
        format: appendedFormat,
        label: appendedSigs.length > 0 ? `Appended ${appendedFormat} Payload` : 'Trailing Unindexed Bytes',
        startOffset: primaryFormat.endOffset,
        endOffset: bytes.length,
        length: trailingLength
      });
    }
  } else {
    regions.push({
      type: 'PRIMARY',
      format: 'RAW',
      label: 'Unstructured / Raw Binary',
      startOffset: 0,
      endOffset: bytes.length,
      length: bytes.length
    });
  }

  const hasSecondaryFormat = signatures.some(s => s.role === 'SECONDARY');
  const canSanitize = Boolean(primaryFormat && !primaryFormat.truncated && trailingLength > 0);
  const sanitizeCutoff = canSanitize ? primaryFormat.endOffset : null;

  let verdict = 'CLEAN';
  let riskScore = 5;
  let summary = primaryFormat
    ? `Valid ${primaryFormat.name} structure with no secondary signatures or trailing data.`
    : 'No overlapping container formats or hidden payload signatures detected.';

  if (hasSecondaryFormat) {
    verdict = 'POLYGLOT DETECTED';
    const secondaryNames = [...new Set(signatures.filter(s => s.role === 'SECONDARY').map(s => s.id))].join(' + ');
    riskScore = canSanitize ? 92 : 85;
    summary = primaryFormat
      ? `File claims to be ${primaryFormat.id} (0x0000..0x${primaryFormat.endOffset.toString(16).toUpperCase()}) but contains secondary ${secondaryNames} structures.`
      : `Multiple or hidden format signatures (${secondaryNames}) detected inside binary stream.`;
  } else if (trailingLength > 0) {
    verdict = 'SUSPICIOUS';
    riskScore = 60;
    summary = `${trailingLength} unexpected trailing bytes found after ${primaryFormat.id} end-of-file boundary at offset 0x${primaryFormat.endOffset.toString(16).toUpperCase()}.`;
  } else if (primaryFormat && primaryFormat.truncated) {
    verdict = 'SUSPICIOUS';
    riskScore = 45;
    summary = `${primaryFormat.name} header detected, but container stream is truncated or has malformed chunk lengths.`;
  }

  return {
    fileName,
    fileSize: bytes.length,
    verdict,
    riskScore,
    summary,
    primaryFormat,
    regions,
    signatures,
    canSanitize,
    sanitizeCutoff
  };
}

export function sanitizeBuffer(inputBytes, analysis = null) {
  const bytes = inputBytes instanceof Uint8Array ? inputBytes : new Uint8Array(inputBytes || 0);
  const report = analysis || analyzeBuffer(bytes);
  if (!report.canSanitize || report.sanitizeCutoff === null) {
    return bytes.slice();
  }
  return bytes.slice(0, report.sanitizeCutoff);
}
