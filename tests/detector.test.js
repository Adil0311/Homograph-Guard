const assert = require("node:assert/strict");
const { analyze, getScripts, CONFUSABLES } = require("../detector.js");
const punycode = require("../punycode.js");

function run(name, fn) {
  try {
    fn();
    console.log("PASS", name);
  } catch (e) {
    console.error("FAIL", name, "-", e.message);
    process.exitCode = 1;
  }
}

// 1. Benign standard ASCII domain
run("benign standard ASCII domain", () => {
  const r = analyze("https://example.com/");
  assert.equal(r.hostname, "example.com");
  assert.equal(r.score, 0);
  assert.equal(r.level, "low");
  assert.equal(r.isMixedScript, false);
  assert.equal(r.chars.length, 0);
});

// 2. Homograph attack on Amazon with Cyrillic 'а' (U+0430)
run("Cyrillic IDN spoofing amazon (аmazon.com)", () => {
  const r = analyze("https://аmazon.com/");
  assert.ok(r.score >= 70, "Score should be critical or high");
  assert.equal(r.isMixedScript, true, "Should detect mixed-script label");
  assert.ok(r.findings.some(x => /mixed-script/i.test(x)));
  assert.ok(r.chars.some(c => c.char === "а" && c.imitates === "a" && c.script === "Cyrillic"));
});

// 3. Multi-character homograph attack on PayPal (раypal.com)
run("multiple mixed-script lookalikes (раypal.com)", () => {
  const r = analyze("https://раypal.com/");
  assert.equal(r.isMixedScript, true);
  assert.ok(r.score >= 70);
  const chars = r.chars.map(c => c.char);
  assert.ok(chars.includes("р"));
  assert.ok(chars.includes("а"));
});

// 4. Punycode encoded domain decoded and unmasked (xn--pple-43d.com -> аpple.com)
run("Punycode detected and unmasked", () => {
  const r = analyze("https://xn--pple-43d.com/");
  assert.equal(r.isPunycode, true);
  assert.equal(r.hostname, "аpple.com");
  assert.ok(r.chars.some(c => c.char === "а" && c.imitates === "a"));
  assert.ok(r.score >= 70);
});

// 5. Armenian and Greek lookalikes detection
run("Greek and Armenian lookalikes detection", () => {
  // Greek omicron 'ο' (U+03BF) imitating 'o' in "gοοgle.com"
  const rGreek = analyze("https://gοοgle.com/");
  assert.ok(rGreek.chars.some(c => c.char === "ο" && c.imitates === "o" && c.script === "Greek"));

  // Armenian 'օ' (U+0585) imitating 'o' in "micrօsoft.com"
  const rArmenian = analyze("https://micrօsoft.com/");
  assert.ok(rArmenian.chars.some(c => c.char === "օ" && c.imitates === "o" && c.script === "Armenian"));
});

// 6. Legitimate single-script non-Latin domain (e.g. яндекс.рф)
run("consistent whole-script Cyrillic domain (яндекс.рф)", () => {
  const r = analyze("https://яндекс.рф/");
  assert.equal(r.isMixedScript, false, "Should not trigger mixed-script alarm");
  assert.ok(r.score <= 25, "Score should remain low/informational");
  assert.ok(r.findings.some(x => /consistent/i.test(x)));
});

// 7. Direct Punycode RFC 3492 decoder unit test
run("Punycode decoder unit test", () => {
  assert.equal(punycode.decodeLabel("xn--pple-43d"), "аpple");
  assert.equal(punycode.decodeLabel("normal"), "normal");
  assert.equal(punycode.toUnicode("xn--e1afmkfd.example"), "пример.example");
});

// 8. Malformed URL rejection
run("malformed URL rejected", () => {
  assert.throws(() => analyze("not-a-url"));
});
