/**
 * Signature battery — every tamper must fail, every fail must be honest.
 *
 *   [ ] canonical serialization deterministic          (canonicalize.test)
 *   [ ] valid receipt verifies
 *   [ ] changed finding fails verification
 *   [ ] changed policy result fails
 *   [ ] changed commit fails
 *   [ ] wrong public key fails
 *   [ ] truncated receipt fails
 *   [ ] malformed receipt fails
 *   [ ] receipt_id substitution fails
 */

const test = require("node:test");
const assert = require("node:assert");
const crypto = require("crypto");
const os = require("os");
const fs = require("fs");
const path = require("path");
const { signReceipt } = require("../lib/evidence/receipt.cjs");
const { verifyReceipt } = require("../lib/evidence/verifier.cjs");
const { generateKeyPair, loadPublicKeys, loadPrivateForName } = require("../lib/evidence/signer.cjs");

function makeKeys(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kin-sig-test-"));
  const meta = generateKeyPair(name, dir);
  const privateKey = loadPrivateForName(name, dir);
  const keys = loadPublicKeys(dir);
  return { dir, meta, privateKey, keys };
}

function baseInput(overrides = {}) {
  return {
    created_at: "2026-10-30T00:00:00.000Z",
    subject: { repo: "NyxSpecter4/example", commit: "abc123", diff_sha256: "f".repeat(64), ...overrides.subject },
    agent: { host: "cli" },
    engines: [{ name: "kin-rule", version: "1.2.0", mode: "deterministic" }],
    findings: overrides.findings ?? [],
    policy: {
      name: "builtin-default",
      sha256: "a".repeat(64),
      outcome: overrides.policyOutcome ?? "pass",
      decisions: [],
    },
  };
}

test("signature: valid receipt verifies (all six checks)", () => {
  const { privateKey, keys } = makeKeys("captain");
  const receipt = signReceipt(baseInput(), privateKey);
  const result = verifyReceipt(receipt, keys);
  assert.strictEqual(result.valid, true, result.reason);
  assert.strictEqual(result.checks.schema, true);
  assert.strictEqual(result.checks.structure, true);
  assert.strictEqual(result.checks.hash, true);
  assert.strictEqual(result.checks.receipt_id, true);
  assert.strictEqual(result.checks.key, true);
  assert.strictEqual(result.checks.signature, true);
});

test("signature: changed finding fails verification", () => {
  const { privateKey, keys } = makeKeys("captain");
  const receipt = signReceipt(baseInput(), privateKey);
  const tampered = structuredClone(receipt);
  tampered.findings.push({
    schema: "kin.security.finding/v1",
    finding_id: "0".repeat(64),
    source: { engine: "kin-rule", kind: "deterministic", engine_version: "1.2.0" },
    claim: { cwe: "CWE-89", severity: "critical", name: "SQL Injection" },
    evidence: { file: "x.ts", line: 1, snippet_sha256: "b".repeat(64) },
    confidence: "observed",
  });
  const result = verifyReceipt(tampered, keys);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /hash mismatch/);
});

test("signature: changed policy result fails", () => {
  const { privateKey, keys } = makeKeys("captain");
  const receipt = signReceipt(baseInput(), privateKey);
  const tampered = structuredClone(receipt);
  tampered.policy.outcome = "pass" === receipt.policy.outcome ? "block" : "pass";
  const result = verifyReceipt(tampered, keys);
  assert.strictEqual(result.valid, false);
});

test("signature: changed commit fails", () => {
  const { privateKey, keys } = makeKeys("captain");
  const receipt = signReceipt(baseInput(), privateKey);
  const tampered = structuredClone(receipt);
  tampered.subject.commit = "deadbeef";
  const result = verifyReceipt(tampered, keys);
  assert.strictEqual(result.valid, false);
});

test("signature: wrong public key fails", () => {
  const { privateKey } = makeKeys("captain");
  const { keys: otherKeys } = makeKeys("impostor");
  const receipt = signReceipt(baseInput(), privateKey);
  const result = verifyReceipt(receipt, otherKeys);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /no provided public key matches/);
});

test("signature: truncated receipt fails", () => {
  const { privateKey, keys } = makeKeys("captain");
  const receipt = signReceipt(baseInput(), privateKey);
  const serialized = JSON.stringify(receipt);
  const cut = serialized.slice(0, serialized.length - 20);
  let parsed;
  try {
    parsed = JSON.parse(cut);
  } catch (err) {
    // Unparseable = the parser refuses it — that IS the failure. The CLI's
    // verify command hits the same wall (exit 1, "cannot parse receipt").
    return;
  }
  const result = verifyReceipt(parsed, keys);
  // If truncation happened to produce valid JSON, structure must still fail.
  assert.strictEqual(result.valid, false);
});

test("signature: malformed receipt fails (wrong schema / missing fields)", () => {
  const { keys } = makeKeys("captain");
  assert.strictEqual(verifyReceipt({}, keys).valid, false);
  assert.strictEqual(verifyReceipt(null, keys).valid, false);
  assert.strictEqual(verifyReceipt("not-an-object", keys).valid, false);
  assert.strictEqual(verifyReceipt({ schema: "something.else/v9" }, keys).valid, false);

  const broken = { schema: "kin.security.receipt/v1" };
  const result = verifyReceipt(broken, keys);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /malformed/);
});

test("signature: receipt_id substitution fails", () => {
  const { privateKey, keys } = makeKeys("captain");
  const receipt = signReceipt(baseInput(), privateKey);
  const tampered = structuredClone(receipt);
  tampered.receipt_id = "01" + "f".repeat(30);
  const result = verifyReceipt(tampered, keys);
  assert.strictEqual(result.valid, false);
  assert.match(result.reason, /receipt_id mismatch/);
});

test("signature: canonical_sha256 substitution fails", () => {
  const { privateKey, keys } = makeKeys("captain");
  const receipt = signReceipt(baseInput(), privateKey);
  const tampered = structuredClone(receipt);
  tampered.evidence.canonical_sha256 = "e".repeat(64);
  const result = verifyReceipt(tampered, keys);
  assert.strictEqual(result.valid, false);
});

test("signature: no keys provided fails (never verifies against nothing)", () => {
  const { privateKey } = makeKeys("captain");
  const receipt = signReceipt(baseInput(), privateKey);
  assert.strictEqual(verifyReceipt(receipt, []).valid, false);
  assert.strictEqual(verifyReceipt(receipt, undefined).valid, false);
});

test("signature: multiple keys supported, correct one selected", () => {
  const dirA = fs.mkdtempSync(path.join(os.tmpdir(), "kin-multi-"));
  const dirB = fs.mkdtempSync(path.join(os.tmpdir(), "kin-multi-"));
  generateKeyPair("captain-kiran", dirA);
  generateKeyPair("ci", dirA);
  generateKeyPair("unrelated", dirB);
  const privateKey = loadPrivateForName("ci", dirA);
  const merged = fs.mkdtempSync(path.join(os.tmpdir(), "kin-multi-"));
  for (const f of ["captain-kiran", "captain-kiran.pub", "ci", "ci.pub"]) {
    fs.copyFileSync(path.join(dirA, f), path.join(merged, f));
  }
  fs.copyFileSync(path.join(dirB, "unrelated.pub"), path.join(merged, "unrelated.pub"));
  const keys = loadPublicKeys(merged);
  assert.strictEqual(keys.length, 3);
  const receipt = signReceipt(baseInput(), privateKey);
  const result = verifyReceipt(receipt, keys);
  assert.strictEqual(result.valid, true, result.reason);
  assert.match(result.key_id, /^ed25519:/);
});
