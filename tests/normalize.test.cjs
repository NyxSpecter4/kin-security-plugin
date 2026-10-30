/**
 * Normalization tests — the finding contract + reproducibility.
 *
 *   [ ] KIN engine normalized (deterministic kind, observed confidence)
 *   [ ] same fixture x10 -> identical normalized findings
 *   [ ] stable sorting, stable fingerprints
 *   [ ] filesystem ordering irrelevant
 *   [ ] findings never contain raw source
 */

const test = require("node:test");
const assert = require("node:assert");
const { normalizeScan } = require("../lib/findings/normalize.cjs");
const { ruleBasedScan } = require("../lib/scanners/kin-rules.cjs");

const SQLI_FIXTURE = [
  "const id = req.params.id;",
  "db.query(`SELECT * FROM users WHERE id = '${id}'`);",
  "",
].join("\n");

test("normalize: SQLi fixture -> exactly one CWE-89 critical finding, confidence observed", () => {
  const findings = normalizeScan(SQLI_FIXTURE, "src/db.ts");
  assert.strictEqual(findings.length, 1);
  const f = findings[0];
  assert.strictEqual(f.schema, "kin.security.finding/v1");
  assert.strictEqual(f.claim.cwe, "CWE-89");
  assert.strictEqual(f.claim.severity, "critical");
  assert.strictEqual(f.confidence, "observed");
  assert.strictEqual(f.source.kind, "deterministic");
  assert.strictEqual(f.source.engine, "kin-rule");
  assert.match(f.finding_id, /^[0-9a-f]{64}$/);
});

test("normalize: evidence carries coordinates, not source code", () => {
  const findings = normalizeScan(SQLI_FIXTURE, "src/db.ts");
  assert.strictEqual(findings[0].evidence.file, "src/db.ts");
  assert.strictEqual(findings[0].evidence.line, 2);
  assert.match(findings[0].evidence.snippet_sha256, /^[0-9a-f]{64}$/);
  const serialized = JSON.stringify(findings);
  assert.ok(!serialized.includes("SELECT"), "raw SQL leaked into finding");
  assert.ok(!serialized.includes("db.query"), "raw source leaked into finding");
});

test("normalize: same fixture x10 -> byte-identical normalized findings", () => {
  let first = null;
  for (let i = 0; i < 10; i++) {
    const serialized = JSON.stringify(normalizeScan(SQLI_FIXTURE, "src/db.ts"));
    if (first === null) first = serialized;
    assert.strictEqual(serialized, first, `run ${i} diverged`);
  }
});

test("normalize: filesystem ordering irrelevant (per-file fingerprints stable across scan orders)", () => {
  const fixtures = [
    ["a.ts", SQLI_FIXTURE],
    ["b.ts", "const el = document.getElementById('x'); el.innerHTML = userInput;"],
    ["c.ts", "const cmd = execSync(`cat ${file}`);"],
  ];
  const forward = fixtures.map(([file, code]) => normalizeScan(code, file).map((f) => f.finding_id));
  const reversed = [...fixtures].reverse().map(([file, code]) => normalizeScan(code, file).map((f) => f.finding_id));
  const forwardFlat = forward.flat().sort();
  const reversedFlat = reversed.flat().sort();
  assert.deepStrictEqual(forwardFlat, reversedFlat);
  // Same file scanned alone vs. in a batch: identical ids.
  assert.deepStrictEqual(normalizeScan(SQLI_FIXTURE, "a.ts").map((f) => f.finding_id), forward[0]);
});

test("normalize: rule firing matches the legacy engine exactly (no rebuilt scanner)", () => {
  const cases = [
    SQLI_FIXTURE,
    "execSync(`rm -rf ${dir}`)",
    "res.send(`<div>${comment}</div>`) // innerHTML sink via document.write below\ndocument.write(userHtml);",
    "const clean = 1 + 1;",
    "JSON.parse(req.body.payload);",
    "res.redirect(req.query.next);",
  ];
  for (const code of cases) {
    const legacy = ruleBasedScan(code).map((f) => f.rule_id).sort();
    const normalized = normalizeScan(code, "t.ts").map((f) => f.claim.cwe).sort();
    assert.deepStrictEqual(normalized, legacy, `rule set diverged for: ${code.slice(0, 40)}`);
  }
});

test("normalize: zero findings on clean code, and the empty result is stable", () => {
  const clean = "const answer = 42;\nmodule.exports = { answer };\n";
  assert.deepStrictEqual(normalizeScan(clean, "clean.ts"), []);
  assert.deepStrictEqual(normalizeScan(clean, "clean.ts"), []);
});

test("normalize: rejects non-string code (fail-closed)", () => {
  assert.throws(() => normalizeScan(null, "x.ts"), /must be a string/);
  assert.throws(() => normalizeScan(42, "x.ts"), /must be a string/);
});
