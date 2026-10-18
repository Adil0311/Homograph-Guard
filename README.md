# Homograph Guard 🛡️

[![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Privacy: 100% Local](https://img.shields.io/badge/Privacy-100%25%20Local-success.svg)](#-privacy-by-design)
[![Unicode](https://img.shields.io/badge/Unicode-UTS%20%2339-orange.svg)](https://www.unicode.org/reports/tr39/)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)](#-automated-tests)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Client-side browser extension for real-time defense against Internationalized Domain Name (IDN) Homograph attacks and domain spoofing.**  
> *Engineered with a Privacy-by-Design approach: 100% local execution, zero network requests, and zero telemetry.*

---

## 🔍 The Threat: What is an IDN Homograph Attack?

The Domain Name System (DNS) supports **Internationalized Domain Names (IDN)**, allowing non-ASCII characters to accommodate global scripts like Cyrillic, Greek, Armenian, Hebrew, Arabic, and Chinese.

However, many glyphs from foreign alphabets are **visually identical or indistinguishable** from standard Latin letters:
- `a` (Latin, `U+0061`) vs `а` (Cyrillic, `U+0430`)
- `o` (Latin, `U+006F`) vs `ο` (Greek, `U+03BF`) vs `օ` (Armenian, `U+0585`)
- `p` (Latin, `U+0070`) vs `р` (Cyrillic, `U+0440`)
- `c` (Latin, `U+0063`) vs `с` (Cyrillic, `U+0441`)

An attacker can register a malicious domain such as `pаypal.com` (replacing the first Latin `a` with Cyrillic `U+0430`). To the human eye in a modern browser address bar, the domain appears completely authentic, deceiving victims into credential harvesting and phishing traps.

While browsers serialize these domains using **Punycode** (`xn--...`), everyday users rarely understand raw encoded labels or what specific glyph has been spoofed.

---

## 🚀 The Solution: How Homograph Guard Works

**Homograph Guard** inspects the hostname of the active browser tab using a lightweight 3-tier heuristic engine aligned with **Unicode Technical Standard #39 (UTS #39 - Unicode Security Mechanisms)**:

```text
[Active Tab URL]
       │
       ▼
1. ASCII FAST-PATH
   │  Checks if the domain consists strictly of standard ASCII characters.
   ├─► YES: Risk = 0 (Instant validation, zero overhead)
   │
   ▼ NO (Presence of non-ASCII Unicode or Punycode "xn--")
2. PUNYCODE UNMASKING (RFC 3492)
   │  Decodes encoded Punycode labels into their authentic Unicode glyphs.
   │
   ▼
3. SCRIPT BOUNDARY & LOOKALIKE ANALYSIS
   ├─► Mixed-Script Detection: Flags labels interleaving Latin with other alphabets.
   ├─► Confusables Mapping: Pinpoints the exact lookalike glyph and what Latin letter it imitates.
   └─► Single-Script Context: Distinguishes legitimate foreign websites (e.g. 100% Cyrillic) from targeted brand spoofing.
```

---

## ✨ Key Features

- **Proactive Pre-Click Hover Inspection:** Flags deceptive links in real time as you hover over them across emails (Gmail/Outlook), social feeds (LinkedIn/X), forums, and search results — warning you *before* navigation.
- **Direct Visual Unmasking:** Highlights the exact spoofed character, its Unicode codepoint, and its imitated Latin counterpart (e.g., `а (Cyrillic U+0430) → 'a'`).
- **Comprehensive Confusables Coverage (142 Characters, 5 Scripts):** Derived from official [Unicode confusables.txt](https://www.unicode.org/Public/security/latest/confusables.txt) (UTS #39 v18.0.0), covering all 26 Latin letters (a–z) across **Cyrillic, Greek, Armenian, Cherokee, and Georgian**.
- **Dual-Layer Defense:**
  1. *Layer 1 (Preventative):* In-page hover tooltip for instant link inspection.
  2. *Layer 2 (Detective):* Comprehensive active tab popup analysis with risk score meter.
- **Zero External Dependencies:** Standalone RFC 3492 Punycode decoder and heuristics implemented in pure, readable JavaScript.
- **Privacy by Design:**
  - 100% client-side local analysis.
  - Zero outgoing HTTP/HTTPS network requests.
  - No analytics, tracking, or persistent browsing history logging.
- **Manifest V3 Compliant:** Fully compatible with current browser extension standards for Google Chrome, Brave, Edge, and Chromium-based browsers.

---

## 📁 Repository Structure

```text
homograph-guard/
├── manifest.json         # Chrome extension configuration (Manifest V3)
├── punycode.js           # Isolated RFC 3492 Punycode decoder
├── detector.js           # Core analysis engine (Mixed-Script & Confusables)
├── content.js            # Content script for proactive link hover inspection
├── tooltip.css           # Styling for in-page link warning tooltip
├── popup.html            # Extension popup user interface
├── popup.css             # Visual risk badges and chip styling
├── popup.js              # Tab scanning and UI rendering logic
├── options.html          # Documentation and architectural details page
└── tests/
    └── detector.test.js  # Automated unit test suite (Node.js)
```

---

## 🛠️ Installation (Developer Mode)

You can load and test the extension on any Chromium-based browser (Google Chrome, Brave, Microsoft Edge, Opera):

1. Clone or download this repository:
   ```bash
   git clone https://github.com/your-username/homograph-guard.git
   ```
2. Navigate to your browser's extension management page:
   - Chrome: `chrome://extensions/`
   - Brave: `brave://extensions/`
   - Edge: `edge://extensions/`
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** (Carica estensione non pacchettizzata).
5. Select the `homograph-guard` folder (containing `manifest.json`).
6. Click the **Homograph Guard** extension icon in your browser toolbar to analyze any webpage!

---

## 🧪 Automated Tests

The detection engine includes a comprehensive test suite executable with Node.js:

```bash
node tests/detector.test.js
```

### Test Scenarios Covered:
- 🟢 **Benign Standard ASCII:** `https://example.com` (Risk Score: 0)
- 🔴 **Cyrillic Spoofing Amazon:** `https://аmazon.com` (Detects mixed-script label & lookalike `а`)
- 🔴 **Multi-Character Spoofing PayPal:** `https://раypal.com` (Detects Cyrillic `р` and `а`)
- 🔴 **Punycode Encoded Domain:** `https://xn--pple-43d.com` (Decodes to `аpple.com` and unmasks `а`)
- 🔴 **Greek & Armenian Spoofing:** `https://gοοgle.com` and `https://micrօsoft.com` (Unmasks Greek `ο` and Armenian `օ`)
- ⚪ **Legitimate Internationalized Domain:** `https://яндекс.рф` (Recognized as consistent whole-script Cyrillic without false alarms)
- ⚙️ **RFC 3492 Decoder Unit Verification & Malformed URL Rejection**

---

## 🛡️ Cybersecurity Threat Model & Scope

- **Scope:** This tool focuses on the **IDN Homograph** vector. It is not intended to replace reputation-based filters for pure ASCII typo-squatting or phishing domains (e.g., `paypal-security-update.com`).
- **Standard References:** Built in accordance with [Unicode Technical Standard #39 (Unicode Security Mechanisms)](https://www.unicode.org/reports/tr39/) and [IETF RFC 3492 (Punycode)](https://datatracker.ietf.org/doc/html/rfc3492).

---

## 📄 License

Distributed under the MIT License. Free to use, inspect, study, and enhance.
