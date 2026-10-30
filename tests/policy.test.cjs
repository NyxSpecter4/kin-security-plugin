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
 *   [ ] advisory findings structurally cannot block (explicit V1 rule)
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

// ── V1 rule: advisory findings structurally cannot block ────────────────
// Encoded BEFORE model findings enter the receipt pipeline (Captain's
// ruling): a model opinion (confidence "advisory", source.kind "model")
// may inform, but can never be the thing that blocks a change.

function advisoryFinding(severity = "critical", cwe = "CWE-89") {
  return {
    schema: "kin.security.finding/v1",
    finding_id: "a".repeat(64),
    source: { engine: "kin-model", kind: "model", engine_version: "test" },
    claim: { cwe, severity, name: "model opinion" },
    evidence: { file: "model.ts", line: null, snippet_sha256: null },
    confidence: "advisory",
  };
}

function observedFinding(severity = "critical", cwe = "CWE-89") {
  return {
    schema: "kin.security.finding/v1",
    finding_id: "b".repeat(64),
    source: { engine: "kin-rule", kind: "deterministic", engine_version: "test" },
    claim: { cwe, severity, name: "rule observation" },
    evidence: { file: "rule.ts", line: 1, snippet_sha256: null },
    confidence: "observed",
  };
}

test("policy V1 rule: an advisory finding can NEVER block, even when a rule says block", () => {
  const policy = loadPolicy(null); // critical -> block
  const evaluation = evaluate(policy, [advisoryFinding("critical")]);
  assert.strictEqual(evaluation.outcome, "pass", "an advisory finding alone must not block");
  const decision = evaluation.decisions[0];
  assert.strictEqual(decision.outcome, "warn", "the block is capped to warn");
  assert.strictEqual(decision.advisory_block_capped, true, "the cap is recorded");
  assert.match(decision.basis, /advisory cap/);
});

test("policy V1 rule: the same rule still blocks an OBSERVED critical (the cap is advisory-only)", () => {
  const policy = loadPolicy(null);
  const evaluation = evaluate(policy, [observedFinding("critical")]);
  assert.strictEqual(evaluation.outcome, "block");
  assert.strictEqual(evaluation.decisions[0].outcome, "block");
  assert.strictEqual(evaluation.decisions[0].advisory_block_capped, undefined);
});

test("policy V1 rule: mixed findings — the block comes only from the observed finding", () => {
  const policy = loadPolicy(null);
  const evaluation = evaluate(policy, [advisoryFinding("critical"), observedFinding("critical")]);
  assert.strictEqual(evaluation.outcome, "block", "the observed finding blocks");
  const advisory = evaluation.decisions.find((d) => d.finding_id === "a".repeat(64));
  const observed = evaluation.decisions.find((d) => d.finding_id === "b".repeat(64));
  assert.strictEqual(advisory.outcome, "warn");
  assert.strictEqual(advisory.advisory_block_capped, true);
  assert.strictEqual(observed.outcome, "block");
  assert.strictEqual(observed.advisory_block_capped, undefined);
});

test("policy V1 rule: advisory findings can warn or pass, and source.kind 'model' alone triggers the cap", () => {
  const policy = loadPolicy(null);
  // medium -> warn: the rule itself says warn, no cap needed
  const warnDecision = evaluate(policy, [advisoryFinding("medium")]).decisions[0];
  assert.strictEqual(warnDecision.outcome, "warn");
  assert.strictEqual(warnDecision.advisory_block_capped, undefined);
  // a strict file policy that blocks critical + an advisory finding: capped
  const strictFile = writePolicy({ name: "strict", rules: [{ severity: ["critical"], outcome: "block" }] });
  const strictPolicy = loadPolicy(strictFile);
  const capped = evaluate(strictPolicy, [advisoryFinding("critical")]).decisions[0];
  assert.strictEqual(capped.outcome, "warn");
  assert.strictEqual(capped.advisory_block_capped, true);
  // an active suppression still passes an advisory finding (pass < warn, no cap involved)
  const suppressionPolicy = {
    schema: "kin.security.policy/v1",
    name: "advisory-sup",
    rules: [{ severity: ["critical"], outcome: "block" }],
    suppressions: [{ cwe: "CWE-89", reason: "triaged", expires: "2099-01-01T00:00:00.000Z" }],
  };
  const suppressed = evaluate(suppressionPolicy, [advisoryFinding("critical")]).decisions[0];
  assert.strictEqual(suppressed.outcome, "pass");
  assert.strictEqual(suppressed.basis, "suppression");
  assert.strictEqual(suppressed.advisory_block_capped, undefined);
  // the cap also fires on source.kind "model" even if confidence is mislabeled
  const kindOnly = { ...advisoryFinding("critical"), confidence: "observed" };
  const kindOnlyDecision = evaluate(loadPolicy(null), [kindOnly]).decisions[0];
  assert.strictEqual(kindOnlyDecision.outcome, "warn", "source.kind 'model' alone must cap");
  assert.strictEqual(kindOnlyDecision.advisory_block_capped, true);
});
