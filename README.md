# PG Detector

**PG Detector** is a client-side polyglot file and binary forensic inspector built with vanilla ES6+ JavaScript. It analyzes raw binary buffers directly in browser memory to detect overlapping container structures, hidden archives, embedded script payloads, and Shannon entropy anomalies without uploading files to any external server.

## Key Capabilities

- **Two-Mode Forensic Interface:**
  - **Threat Scanner:** Provides an immediate risk verdict (`CLEAN`, `SUSPICIOUS`, `POLYGLOT DETECTED`), a proportional byte-range layout bar, a table of primary/secondary magic byte signatures with exact hex offsets, and one-click payload sanitization.
  - **Forensic Hex & Entropy Lab:** Computes block-level Shannon entropy (`0.00` to `8.00` bits/byte) on an interactive `<canvas>` and pairs it with a virtualized 64-row hex/ASCII viewer that highlights container headers, EOF boundaries, and hidden payloads.
- **Container EOF Boundary Walkers:**
  - **PNG:** Walks length-prefixed chunks (`IHDR`, `IDAT`, etc.) to locate the exact end of the `IEND` chunk and 4-byte CRC (`89 50 4E 47 ... 49 45 4E 44 AE 42 60 82`).
  - **JPEG:** Parses segment lengths across `APPn`/`SOFn`/`DQT`/`DHT` headers (avoiding false positives from nested EXIF thumbnail `FF D9` markers) and scans entropy-coded data past byte-stuffed `FF 00` sequences to locate the true `FF D9` End of Image marker.
  - **GIF:** Detects `GIF87a`/`GIF89a` headers, trailer boundaries (`0x3B`), and `GIF89a/*` header-comment script polyglots.
  - **PDF:** Identifies `%PDF-` headers and `%%EOF` trailers, including shifted headers inside hybrid containers.
  - **Secondary Archive & Executable Detection:** Scans for embedded or appended PKZIP (`50 4B 03 04` / `50 4B 05 06` EOCD), RAR, 7-Zip, ELF, PE/MZ, and script payloads (`<?php`, `<script`, `eval(`, `#!/bin/`).
- **One-Click Payload Sanitization:** Truncates appended chameleon/polyglot payloads cleanly at the primary container's verified EOF offset and exports a sanitized copy.
- **Built-in Synthetic Test Vectors:** Includes in-memory sample generators (`PNG + ZIP Polyglot`, `GIF89a + JS Polyglot`, `JPEG + PHP Payload`, and `Clean PNG Baseline`) for immediate evaluation on GitHub Pages.

## Project Structure

```text
PG-Detector/
├── index.html                      # Main two-tab application shell
├── styles.css                      # Dark forensic stylesheet
├── package.json                    # ES module configuration and test script
├── src/
│   ├── analyzer.js                 # Container chunk walkers, signature scanner, and sanitizer
│   ├── entropy.js                  # Shannon entropy block calculator (0 - 8 bits/byte)
│   ├── hex.js                      # Virtualized 16-byte aligned hex/ASCII window formatter
│   ├── samples.js                  # Deterministic in-memory polyglot sample builders
│   └── app.js                      # Browser DOM controller and canvas renderer
└── tests/
    ├── analyzer.test.js            # Unit tests for format parsers and payload sanitization
    ├── entropy-and-samples.test.js # Unit tests for Shannon entropy and synthetic samples
    └── hex-and-project.test.js     # Unit tests for hex windowing and project constraints
```

## Running Locally & Testing

1. **Run the Unit Test Suite (Node.js 18+):**
   ```bash
   cd PG-Detector
   npm test
   ```
2. **Launch in the Browser:**
   Serve the `PG-Detector` directory with any static file server (for example `npx serve .` or Python `python -m http.server 8080`) or deploy directly to **GitHub Pages**.
