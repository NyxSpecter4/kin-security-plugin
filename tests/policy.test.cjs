/**
 * Policy tests — decisions, suppressions, explicit defaults.
 *
 *   [ ] high -> block
 *   [ ] medium -> configurable
 *   [ ] expired suppression ignored
 *   [ ] suppression preserved in receipt
 *   [ ] missing policy behaves according to explicit default
 *   [ ] requested-but-missing policy file = hard error (never silent)
 *   [ ] suppression preserved in the receipt decisions
 */

const test = require("node:test");
const assert = require("node:assert");
const os = require("os");
const fs = require("fs");
const path = require("path");
const { normalizeScan } = require("../lib/findings/normalize.cjs");
const { loadPolicy, policyFingerprint, BUILT_IN_DEFAULT } = require("../lib/policy/load.cjs");
const { evaluate } = require("../lib/policy/evaluate.cjs");
const { attest } = require("../lib/pipeline/attest.cjs");
const { generateKeyPair, loadPrivateForName } = require("../lib/evidence/signer.cjs");

const SQLI_FIXTURE = "db.query(`SELECT * FROM users WHERE id = '${req.params.id}'`);\n";
const REDIRECT_FIXTURE = "res.redirect(req.query.next);\n"; // CWE-601, Medium

function makeKey() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kin-policy-"));
  generateKeyPair("captain", dir);
  return { privateKey: loadPrivateForName("captain", dir) };
}

function writePolicy(object) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "kin-policy-json-")), "policy.json");
  fs.writeFileSync(file, JSON.stringify(object, null, 2));
  return file;
}

test("policy: high -> block (built-in default)", () => {
  const { privateKey } = makeKey();
  const result = attest({ code: SQLI_FIXTURE, filename: "db.ts", privateKey });
  assert.strictEqual(result.evaluation.outcome, "block");
  assert.strictEqual(result.receipt.policy.outcome, "block");
});

test("policy: critical -> block, high -> block, medium -> warn, low -> pass (default table)", () => {
  const policy = loadPolicy(null);
  const mk = (severity) => ({
    finding_id: "f".repeat(64),
    claim: { cwe: "CWE-X", severity, name: "test" },
    evidence: { file: "x.ts", line: 1, snippet_sha256: null },
  });
  const at = (severity) => evaluate(policy, [mk(severity)]).decisions[0];
  assert.strictEqual(at("critical").outcome, "block");
  assert.strictEqual(at("high").outcome, "block");
  assert.strictEqual(at("medium").outcome, "warn");
  assert.strictEqual(at("low").outcome, "pass");
  assert.strictEqual(evaluate(policy, [mk("critical"), mk("low")]).outcome, "block");
});

test("policy: medium is configurable (warn -> block via policy file)", () => {
  const { privateKey } = makeKey();
  const file = writePolicy({ name: "strict", rules: [{ severity: ["medium", "high", "critical"], outcome: "block" }] });
  const result = attest({ code: REDIRECT_FIXTURE, filename: "redirect.ts", policyFile: file, privateKey });
  assert.strictEqual(result.evaluation.outcome, "block");
  assert.strictEqual(result.receipt.policy.name, "strict");

  const laxFile = writePolicy({ name: "lax", rules: [{ severity: ["medium"], outcome: "pass" }] });
  const laxResult = attest({ code: REDIRECT_FIXTURE, filename: "redirect.ts", policyFile: laxFile, privateKey });
  assert.strictEqual(laxResult.evaluation.outcome, "pass");
});

test("policy: expired suppression ignored (finding blocks anyway)", () => {
  const { privateKey } = makeKey();
  const file = writePolicy({
    name: "with-expired-sup",
    rules: [{ severity: ["critical", "high"], outcome: "block" }],
    suppressions: [{ cwe: "CWE-89", reason: "legacy app", expires: "2020-01-01T00:00:00.000Z" }],
  });
  const result = attest({ code: SQLI_FIXTURE, filename: "db.ts", policyFile: file, privateKey });
  assert.strictEqual(result.evaluation.outcome, "block");
  const decision = result.evaluation.decisions[0];
  assert.strictEqual(decision.outcome, "block");
  assert.strictEqual(decision.basis, "rule");
  assert.strictEqual(decision.expired_suppressions_ignored, 1);
  assert.strictEqual(decision.suppressed_by, undefined);
  // the expired suppression is recorded as ignored, even in the receipt
  const receiptDecision = result.receipt.policy.decisions[0];
  assert.strictEqual(receiptDecision.expired_suppressions_ignored, 1);
});

test("policy: active suppression passes AND is preserved in the receipt", () => {
  const { privateKey } = makeKey();
  const file = writePolicy({
    name: "with-sup",
    rules: [{ severity: ["critical", "high"], outcome: "block" }],
    suppressions: [{ cwe: "CWE-89", reason: "audited, parameterized at the driver layer", expires: "2099-01-01T00:00:00.000Z" }],
  });
  const result = attest({ code: SQLI_FIXTURE, filename: "db.ts", policyFile: file, privateKey });
  assert.strictEqual(result.evaluation.outcome, "pass");
  const decision = result.evaluation.decisions[0];
  assert.strictEqual(decision.outcome, "pass");
  assert.strictEqual(decision.basis, "suppression");
  assert.strictEqual(decision.suppressed_by.reason, "audited, parameterized at the driver layer");
  // preserved in the SIGNED receipt:
  const receiptDecision = result.receipt.policy.decisions.find((d) => d.finding_id === decision.finding_id);
  assert.ok(receiptDecision, "suppression decision missing from receipt");
  assert.strictEqual(receiptDecision.suppressed_by.reason, "audited, parameterized at the driver layer");
});

test("policy: suppression by exact finding fingerprint (not cwe)", () => {
  const { privateKey } = makeKey();
  const findings = normalizeScan(SQLI_FIXTURE, "db.ts");
  const file = writePolicy({
    name: "fingerprint-sup",
    rules: [{ severity: ["critical"], outcome: "block" }],
    suppressions: [{ finding: findings[0].finding_id, reason: "tracked in SEC-42", expires: "2099-01-01T00:00:00.000Z" }],
  });
  const result = attest({ code: SQLI_FIXTURE, filename: "db.ts", policyFile: file, privateKey });
  assert.strictEqual(result.evaluation.outcome, "pass");
});

test("policy: no --policy => explicit built-in default, recorded in the receipt", () => {
  const { privateKey } = makeKey();
  const result = attest({ code: "const clean = 1;\n", filename: "clean.ts", privateKey });
  assert.strictEqual(result.receipt.policy.name, "builtin-default");
  assert.strictEqual(result.receipt.policy.sha256, policyFingerprint(BUILT_IN_DEFAULT));
  assert.strictEqual(result.receipt.policy.outcome, "pass");
});

test("policy: --policy pointing at a missing file = hard error, no receipt", () => {
  const { privateKey } = makeKey();
  assert.throws(
    () => attest({ code: SQLI_FIXTURE, filename: "db.ts", policyFile: "/nonexistent/policy.json", privateKey }),
    /cannot read/
  );
});

test("policy: invalid policy file (bad outcome value) = hard error", () => {
  const { privateKey } = makeKey();
  const file = writePolicy({ rules: [{ severity: ["high"], outcome: "yolo" }] });
  assert.throws(
    () => attest({ code: SQLI_FIXTURE, filename: "db.ts", policyFile: file, privateKey }),
    /outcome must be block\|warn\|pass/
  );
});
