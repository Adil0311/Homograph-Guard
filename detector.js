/* Homograph Guard - Local IDN Homograph Attack Detector
 * Analyzes domain names, identifies mixed-script labels,
 * and unmasks deceptive Unicode lookalike characters (confusables).
 * Compliant with Unicode Technical Standard #39 (UTS #39) security recommendations.
 * 100% local execution with zero network requests and zero telemetry.
 */
(() => {
  "use strict";

  // When running in Node.js, require the Punycode decoder
  const punycode = typeof require !== "undefined"
    ? require("./punycode.js")
    : (globalThis.PunycodeDecoder || { toUnicode: (d) => d });

  /**
   * Unicode Confusable Characters Map (Lookalikes / Confusables).
   * Sourced directly from official Unicode UTS #39 (confusables.txt v18.0.0).
   * Maps 142 characters from 5 non-Latin scripts visually similar to ASCII Latin letters.
   * Source: https://www.unicode.org/Public/security/latest/confusables.txt
   */
  const CONFUSABLES = {
    // ── Cyrillic (47 characters) ──────────────────────────────────────────────
    // Lowercase
    "а": { latin: "a", script: "Cyrillic", code: "U+0430" },
    "с": { latin: "c", script: "Cyrillic", code: "U+0441" },
    "ᲃ": { latin: "c", script: "Cyrillic", code: "U+1C83" },
    "ԁ": { latin: "d", script: "Cyrillic", code: "U+0501" },
    "е": { latin: "e", script: "Cyrillic", code: "U+0435" },
    "ҽ": { latin: "e", script: "Cyrillic", code: "U+04BD" },
    "һ": { latin: "h", script: "Cyrillic", code: "U+04BB" },
    "і": { latin: "i", script: "Cyrillic", code: "U+0456" },
    "ꙇ": { latin: "i", script: "Cyrillic", code: "U+A647" },
    "ј": { latin: "j", script: "Cyrillic", code: "U+0458" },
    "ӏ": { latin: "l", script: "Cyrillic", code: "U+04CF" },
    "о": { latin: "o", script: "Cyrillic", code: "U+043E" },
    "ᲂ": { latin: "o", script: "Cyrillic", code: "U+1C82" },
    "р": { latin: "p", script: "Cyrillic", code: "U+0440" },
    "ԛ": { latin: "q", script: "Cyrillic", code: "U+051B" },
    "г": { latin: "r", script: "Cyrillic", code: "U+0433" },
    "ѕ": { latin: "s", script: "Cyrillic", code: "U+0455" },
    "ѵ": { latin: "v", script: "Cyrillic", code: "U+0475" },
    "ѡ": { latin: "w", script: "Cyrillic", code: "U+0461" },
    "ш": { latin: "w", script: "Cyrillic", code: "U+0448" },
    "ԝ": { latin: "w", script: "Cyrillic", code: "U+051D" },
    "х": { latin: "x", script: "Cyrillic", code: "U+0445" },
    "у": { latin: "y", script: "Cyrillic", code: "U+0443" },
    "ү": { latin: "y", script: "Cyrillic", code: "U+04AF" },
    // Uppercase
    "А": { latin: "A", script: "Cyrillic", code: "U+0410" },
    "Ь": { latin: "b", script: "Cyrillic", code: "U+042C" },
    "В": { latin: "B", script: "Cyrillic", code: "U+0412" },
    "С": { latin: "C", script: "Cyrillic", code: "U+0421" },
    "Е": { latin: "E", script: "Cyrillic", code: "U+0415" },
    "Ԍ": { latin: "G", script: "Cyrillic", code: "U+050C" },
    "Н": { latin: "H", script: "Cyrillic", code: "U+041D" },
    "Һ": { latin: "h", script: "Cyrillic", code: "U+04BA" },
    "Ј": { latin: "J", script: "Cyrillic", code: "U+0408" },
    "К": { latin: "K", script: "Cyrillic", code: "U+041A" },
    "І": { latin: "l", script: "Cyrillic", code: "U+0406" },
    "Ӏ": { latin: "l", script: "Cyrillic", code: "U+04C0" },
    "М": { latin: "M", script: "Cyrillic", code: "U+041C" },
    "О": { latin: "O", script: "Cyrillic", code: "U+041E" },
    "Р": { latin: "P", script: "Cyrillic", code: "U+0420" },
    "Ԛ": { latin: "Q", script: "Cyrillic", code: "U+051A" },
    "Ѕ": { latin: "S", script: "Cyrillic", code: "U+0405" },
    "Т": { latin: "T", script: "Cyrillic", code: "U+0422" },
    "Ѵ": { latin: "V", script: "Cyrillic", code: "U+0474" },
    "Ԝ": { latin: "W", script: "Cyrillic", code: "U+051C" },
    "Х": { latin: "X", script: "Cyrillic", code: "U+0425" },
    "У": { latin: "Y", script: "Cyrillic", code: "U+0423" },
    "Ү": { latin: "Y", script: "Cyrillic", code: "U+04AE" },

    // ── Greek (35 characters) ──────────────────────────────────────────────────
    // Lowercase
    "α": { latin: "a", script: "Greek", code: "U+03B1" },
    "ϲ": { latin: "c", script: "Greek", code: "U+03F2" },
    "ι": { latin: "i", script: "Greek", code: "U+03B9" },
    "ϳ": { latin: "j", script: "Greek", code: "U+03F3" },
    "κ": { latin: "k", script: "Greek", code: "U+03BA" },
    "ο": { latin: "o", script: "Greek", code: "U+03BF" },
    "σ": { latin: "o", script: "Greek", code: "U+03C3" },
    "ρ": { latin: "p", script: "Greek", code: "U+03C1" },
    "ϱ": { latin: "p", script: "Greek", code: "U+03F1" },
    "ϸ": { latin: "p", script: "Greek", code: "U+03F8" },
    "ᴦ": { latin: "r", script: "Greek", code: "U+1D26" },
    "τ": { latin: "t", script: "Greek", code: "U+03C4" },
    "υ": { latin: "u", script: "Greek", code: "U+03C5" },
    "ν": { latin: "v", script: "Greek", code: "U+03BD" },
    "χ": { latin: "x", script: "Greek", code: "U+03C7" },
    "γ": { latin: "y", script: "Greek", code: "U+03B3" },
    // Uppercase
    "Α": { latin: "A", script: "Greek", code: "U+0391" },
    "Β": { latin: "B", script: "Greek", code: "U+0392" },
    "Ϲ": { latin: "C", script: "Greek", code: "U+03F9" },
    "Ε": { latin: "E", script: "Greek", code: "U+0395" },
    "Ϝ": { latin: "F", script: "Greek", code: "U+03DC" },
    "Η": { latin: "H", script: "Greek", code: "U+0397" },
    "Ι": { latin: "I", script: "Greek", code: "U+0399" },
    "Ϳ": { latin: "J", script: "Greek", code: "U+037F" },
    "Κ": { latin: "K", script: "Greek", code: "U+039A" },
    "Μ": { latin: "M", script: "Greek", code: "U+039C" },
    "Ϻ": { latin: "M", script: "Greek", code: "U+03FA" },
    "Ν": { latin: "N", script: "Greek", code: "U+039D" },
    "Ο": { latin: "O", script: "Greek", code: "U+039F" },
    "Ρ": { latin: "P", script: "Greek", code: "U+03A1" },
    "Τ": { latin: "T", script: "Greek", code: "U+03A4" },
    "Υ": { latin: "Y", script: "Greek", code: "U+03A5" },
    "ϒ": { latin: "Y", script: "Greek", code: "U+03D2" },
    "Χ": { latin: "X", script: "Greek", code: "U+03A7" },
    "Ζ": { latin: "Z", script: "Greek", code: "U+0396" },

    // ── Armenian (15 characters) ───────────────────────────────────────────────
    "ք": { latin: "f", script: "Armenian", code: "U+0584" },
    "ց": { latin: "g", script: "Armenian", code: "U+0581" },
    "հ": { latin: "h", script: "Armenian", code: "U+0570" },
    "ւ": { latin: "i", script: "Armenian", code: "U+0582" },
    "յ": { latin: "j", script: "Armenian", code: "U+0575" },
    "ո": { latin: "n", script: "Armenian", code: "U+0578" },
    "ռ": { latin: "n", script: "Armenian", code: "U+057C" },
    "օ": { latin: "o", script: "Armenian", code: "U+0585" },
    "Օ": { latin: "O", script: "Armenian", code: "U+0555" },
    "գ": { latin: "q", script: "Armenian", code: "U+0563" },
    "զ": { latin: "q", script: "Armenian", code: "U+0566" },
    "Տ": { latin: "S", script: "Armenian", code: "U+054F" },
    "ս": { latin: "u", script: "Armenian", code: "U+057D" },
    "Ս": { latin: "U", script: "Armenian", code: "U+054D" },
    "ա": { latin: "w", script: "Armenian", code: "U+0561" },

    // ── Cherokee (36 characters) ───────────────────────────────────────────────
    // Lowercase
    "ꮟ": { latin: "b", script: "Cherokee", code: "U+13CF" },
    "ꮯ": { latin: "c", script: "Cherokee", code: "U+ABAF" },
    "ꭵ": { latin: "i", script: "Cherokee", code: "U+AB75" },
    "ꮁ": { latin: "r", script: "Cherokee", code: "U+AB81" },
    "ꮪ": { latin: "s", script: "Cherokee", code: "U+ABAA" },
    "ꮩ": { latin: "v", script: "Cherokee", code: "U+ABA9" },
    "ꮃ": { latin: "w", script: "Cherokee", code: "U+AB83" },
    "ꮤ": { latin: "w", script: "Cherokee", code: "U+ABA4" },
    "ꮓ": { latin: "z", script: "Cherokee", code: "U+AB93" },
    // Uppercase
    "Ꭺ": { latin: "A", script: "Cherokee", code: "U+13AA" },
    "Ᏼ": { latin: "B", script: "Cherokee", code: "U+13F4" },
    "Ꮯ": { latin: "C", script: "Cherokee", code: "U+13DF" },
    "Ꭰ": { latin: "D", script: "Cherokee", code: "U+13A0" },
    "Ꮷ": { latin: "d", script: "Cherokee", code: "U+13E7" },
    "Ꭼ": { latin: "E", script: "Cherokee", code: "U+13AC" },
    "Ꮐ": { latin: "G", script: "Cherokee", code: "U+13C0" },
    "Ᏻ": { latin: "G", script: "Cherokee", code: "U+13F3" },
    "Ꮒ": { latin: "h", script: "Cherokee", code: "U+13C2" },
    "Ꮋ": { latin: "H", script: "Cherokee", code: "U+13BB" },
    "Ꭵ": { latin: "i", script: "Cherokee", code: "U+13A5" },
    "Ꭻ": { latin: "J", script: "Cherokee", code: "U+13AB" },
    "Ꮶ": { latin: "K", script: "Cherokee", code: "U+13E6" },
    "Ꮮ": { latin: "L", script: "Cherokee", code: "U+13DE" },
    "Ꮇ": { latin: "M", script: "Cherokee", code: "U+13B7" },
    "Ꮲ": { latin: "P", script: "Cherokee", code: "U+13E2" },
    "Ꭱ": { latin: "R", script: "Cherokee", code: "U+13A1" },
    "Ꮢ": { latin: "R", script: "Cherokee", code: "U+13D2" },
    "Ꮥ": { latin: "S", script: "Cherokee", code: "U+13D5" },
    "Ꮪ": { latin: "S", script: "Cherokee", code: "U+13DA" },
    "Ꭲ": { latin: "T", script: "Cherokee", code: "U+13A2" },
    "Ꮩ": { latin: "V", script: "Cherokee", code: "U+13D9" },
    "Ꮃ": { latin: "W", script: "Cherokee", code: "U+13B3" },
    "Ꮤ": { latin: "W", script: "Cherokee", code: "U+13D4" },
    "Ꭹ": { latin: "Y", script: "Cherokee", code: "U+13A9" },
    "Ꮍ": { latin: "Y", script: "Cherokee", code: "U+13BD" },
    "Ꮓ": { latin: "Z", script: "Cherokee", code: "U+13C3" },

    // ── Georgian (9 characters) ────────────────────────────────────────────────
    "Ⴙ": { latin: "h", script: "Georgian", code: "U+10B9" },
    "ჿ": { latin: "o", script: "Georgian", code: "U+10FF" },
    "Ჿ": { latin: "O", script: "Georgian", code: "U+1CBF" },
    "Ⴝ": { latin: "S", script: "Georgian", code: "U+10BD" },
    "ჽ": { latin: "S", script: "Georgian", code: "U+10FD" },
    "Ჽ": { latin: "S", script: "Georgian", code: "U+1CBD" },
    "ყ": { latin: "y", script: "Georgian", code: "U+10E7" },
    "ⴭ": { latin: "z", script: "Georgian", code: "U+2D2D" },
    "Ⴭ": { latin: "Z", script: "Georgian", code: "U+10CD" }
  };

  /**
   * Unicode Script identification regexes.
   * Covers the 5 primary homograph attack scripts + most common global web scripts.
   */
  const SCRIPTS = [
    { name: "Latin",      regex: /\p{Script=Latin}/u },
    { name: "Cyrillic",   regex: /\p{Script=Cyrillic}/u },
    { name: "Greek",      regex: /\p{Script=Greek}/u },
    { name: "Armenian",   regex: /\p{Script=Armenian}/u },
    { name: "Cherokee",   regex: /\p{Script=Cherokee}/u },
    { name: "Georgian",   regex: /\p{Script=Georgian}/u },
    { name: "Arabic",     regex: /\p{Script=Arabic}/u },
    { name: "Hebrew",     regex: /\p{Script=Hebrew}/u },
    { name: "Han",        regex: /\p{Script=Han}/u },
    { name: "Hiragana",   regex: /\p{Script=Hiragana}/u },
    { name: "Katakana",   regex: /\p{Script=Katakana}/u },
    { name: "Devanagari", regex: /\p{Script=Devanagari}/u }
  ];

  /**
   * Returns all Unicode script names identified in a given string.
   */
  function getScripts(text) {
    const found = new Set();
    for (const char of text) {
      if (/[\p{N}\p{P}\p{S}\p{M}]/u.test(char)) continue;
      for (const { name, regex } of SCRIPTS) {
        if (regex.test(char)) {
          found.add(name);
          break;
        }
      }
    }
    return [...found];
  }

  /**
   * Extracts and normalizes the hostname from an URL.
   */
  function extractHostname(inputUrl) {
    const url = new URL(inputUrl);
    return url.hostname.replace(/\.$/, "").toLowerCase();
  }

  /**
   * Analyzes an URL for IDN Homograph attacks.
   * Returns a structured evaluation object with risk score and findings.
   */
  function analyze(inputUrl) {
    const url = new URL(inputUrl);
    const rawHost = extractHostname(inputUrl);

    // 1. Check for Punycode encoding (xn--)
    const isPunycode = rawHost.split(".").some(label => label.startsWith("xn--"));
    
    // 2. Unmasking: decode domain into native Unicode representation
    const unicodeHost = isPunycode ? punycode.toUnicode(rawHost) : rawHost;

    // 3. FAST PATH: Pure standard ASCII domain without Punycode is 100% safe from homographs
    const isPureAscii = /^[\x00-\x7F]+$/.test(rawHost) && !isPunycode;
    if (isPureAscii) {
      return {
        url: url.href,
        hostname: rawHost,
        asciiHost: rawHost,
        isPunycode: false,
        score: 0,
        level: "low",
        findings: ["Standard ASCII domain: no homograph indicators detected."],
        chars: [],
        scripts: ["Latin"],
        isMixedScript: false
      };
    }

    // 4. Detailed label-by-label inspection (e.g. "sub", "domain", "com")
    const labels = unicodeHost.split(".");
    const findings = [];
    const detectedConfusables = [];
    const nonAsciiChars = [];
    let isMixedScript = false;
    let score = 0;

    if (isPunycode) {
      findings.push("Domain uses Punycode encoding ('xn--'), typically indicating an Internationalized Domain Name (IDN).");
    }

    // Identify all scripts present across the entire domain
    const domainScripts = new Set();
    const scriptsPerLabel = labels.map(label => {
      const s = getScripts(label);
      s.forEach(script => domainScripts.add(script));
      return { label, scripts: s };
    });

    const allScripts = [...domainScripts];
    const hasLatin = allScripts.includes("Latin");

    // Scan label by label
    for (const { label, scripts } of scriptsPerLabel) {
      // Check for MIXED SCRIPTS inside the same label (e.g. "pаypal": Latin + Cyrillic)
      if (scripts.length > 1) {
        isMixedScript = true;
        findings.push(
          `Suspicious mixed-script label: "${label}" combines ${scripts.join(" + ")} characters.`
        );
        score += 50; // Primary IDN homograph attack indicator
      }

      // Character-by-character analysis
      for (const char of label) {
        const codePointNum = char.codePointAt(0);
        if (codePointNum > 127) {
          const hexCode = "U+" + codePointNum.toString(16).toUpperCase().padStart(4, "0");
          const confusableMatch = CONFUSABLES[char];

          // A character is treated as a confusable (imitating Latin) when Latin is present in the domain
          // (mixed-script label or Latin TLD such as .com/.org with non-Latin label)
          if (confusableMatch && hasLatin) {
            detectedConfusables.push({
              char,
              codePoint: hexCode,
              imitates: confusableMatch.latin,
              script: confusableMatch.script,
              label
            });
          } else {
            nonAsciiChars.push({
              char,
              codePoint: hexCode,
              imitates: null,
              script: getScripts(char)[0] || "Unicode",
              label
            });
          }
        }
      }
    }

    // Report detected lookalike characters
    if (detectedConfusables.length > 0) {
      const unmaskedList = detectedConfusables.map(
        c => `"${c.char}" (${c.script} ${c.codePoint} → imitates Latin letter "${c.imitates}")`
      );
      findings.push(`Detected deceptive characters imitating Latin letters: ${unmaskedList.join(", ")}.`);
      score += Math.min(45, 25 + detectedConfusables.length * 10);
    }

    // Handle legitimate whole-script non-Latin domains (e.g. "яндекс.рф" or 100% Arabic/Han domains)
    if (!hasLatin && allScripts.length === 1) {
      findings.push(`Consistent internationalized domain: written entirely in ${allScripts[0]} script.`);
      score = 15; // Informational, not an attack against Latin users
    } else if (isPunycode && score === 0) {
      score = 20;
    }

    // Normalize final score between 0 and 100
    score = Math.min(100, Math.max(0, score));

    let level = "low";
    if (score >= 70) level = "critical";
    else if (score >= 45) level = "high";
    else if (score >= 20) level = "medium";

    // Deduplicate character list for the user interface
    const allChars = [...detectedConfusables, ...nonAsciiChars];
    const uniqueCharsMap = new Map();
    for (const item of allChars) {
      if (!uniqueCharsMap.has(item.char)) {
        uniqueCharsMap.set(item.char, item);
      }
    }

    return {
      url: url.href,
      hostname: unicodeHost,
      asciiHost: rawHost,
      isPunycode,
      score,
      level,
      findings,
      chars: [...uniqueCharsMap.values()],
      scripts: allScripts,
      isMixedScript
    };
  }

  const api = { analyze, getScripts, extractHostname, CONFUSABLES };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    globalThis.HomographDetector = api;
  }
})();