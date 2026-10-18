/* Punycode RFC 3492 Decoder
 * Decodes Internationalized Domain Names (IDN) prefixed with 'xn--'
 * into their native Unicode representation.
 */
(() => {
  "use strict";

  const BASE = 36;
  const TMIN = 1;
  const TMAX = 26;
  const SKEW = 38;
  const DAMP = 700;
  const INITIAL_BIAS = 72;
  const INITIAL_N = 128; // 0x80
  const DELIMITER = "-";

  function decodeDigit(cp) {
    if (cp >= 48 && cp <= 57) return cp - 22; // 0-9 -> 26-35
    if (cp >= 65 && cp <= 90) return cp - 65; // A-Z -> 0-25
    if (cp >= 97 && cp <= 122) return cp - 97; // a-z -> 0-25
    return BASE;
  }

  function adapt(delta, numPoints, isFirst) {
    delta = isFirst ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
      delta = Math.floor(delta / (BASE - TMIN));
      k += BASE;
    }
    return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
  }

  /**
   * Decodes a single Punycode label (e.g. "xn--pple-43d" -> "аpple")
   */
  function decodeLabel(label) {
    const lower = label.toLowerCase();
    if (!lower.startsWith("xn--")) {
      return label;
    }

    const input = lower.slice(4);
    const output = [];
    let n = INITIAL_N;
    let i = 0;
    let bias = INITIAL_BIAS;

    const delimPos = input.lastIndexOf(DELIMITER);
    let pos = 0;

    if (delimPos > 0) {
      for (let j = 0; j < delimPos; j++) {
        const cp = input.charCodeAt(j);
        if (cp >= 0x80) return label; // invalid
        output.push(cp);
      }
      pos = delimPos + 1;
    }

    while (pos < input.length) {
      const oldI = i;
      let w = 1;

      for (let k = BASE; ; k += BASE) {
        if (pos >= input.length) return label; // invalid
        const digit = decodeDigit(input.charCodeAt(pos++));
        if (digit >= BASE) return label;

        i += digit * w;
        const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
        if (digit < t) break;

        w *= BASE - t;
      }

      const numPoints = output.length + 1;
      bias = adapt(i - oldI, numPoints, oldI === 0);
      n += Math.floor(i / numPoints);
      i %= numPoints;

      output.splice(i, 0, n);
      i++;
    }

    try {
      return String.fromCodePoint(...output);
    } catch (_) {
      return label;
    }
  }

  /**
   * Converts a full domain from Punycode to Unicode (e.g. "xn--e1afmkfd.example" -> "пример.example")
   */
  function toUnicode(domain) {
    if (!domain || typeof domain !== "string") return "";
    return domain.split(".").map(decodeLabel).join(".");
  }

  const api = { decodeLabel, toUnicode };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    globalThis.PunycodeDecoder = api;
  }
})();
