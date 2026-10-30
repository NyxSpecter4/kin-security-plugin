/**
 * Redaction invariants — receipts must never leak.
 *
 *   [ ] known secret absent from serialized receipt
 *   [ ] source context masked (no raw scanned lines in the receipt)
 *   [ ] raw prompts never stored (agent.prompt_sha256 only, by construction)
 *   [ ] redaction gate refuses to mint a leaking receipt
 */

const test = require("node:test");
const assert = require("node:assert");
const os = require("os");
const fs = require("fs");
const path = require("path");
const { attest } = require("../lib/pipeline/attest.cjs");
const { generateKeyPair, loadPrivateForName } = require("../lib/evidence/signer.cjs");
const { scanForSecrets, assertReceiptIsRedacted } = require("../lib/evidence/redact.cjs");

function makeKey() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kin-redact-"));
  generateKeyPair("captain", dir);
  return { privateKey: loadPrivateForName("captain", dir) };
}

const CODE_WITH_SECRET = [
  'const apiKey = "kin_live_testkey_0123456789abcdef";',
  'const password = "hunter2222hunter2222";',
  "function connect(apiKey, password) { return db.connect(apiKey, password); }",
  "",
].join("\n");

test("redaction: known secret absent from serialized receipt", () => {
  const { privateKey } = makeKey();
  const result = attest({ code: CODE_WITH_SECRET, filename: "src/config.ts", privateKey });
  const serialized = JSON.stringify(result.receipt);
  assert.ok(!serialized.includes("hunter2222hunter2222"), "raw secret leaked into receipt");
  assert.ok(!serialized.includes("kin_live_testkey_0123456789abcdef"), "raw api key leaked into receipt");
});

test("redaction: no scanned source line appears in the receipt", () => {
  const { privateKey } = makeKey();
  const result = attest({ code: CODE_WITH_SECRET, filename: "src/config.ts", privateKey });
  const serialized = JSON.stringify(result.receipt);
  for (const line of CODE_WITH_SECRET.split("\n")) {
    if (line.trim().length >= 8) {
      assert.ok(!serialized.includes(line.trim()), `raw source line leaked: "${line.slice(0, 30)}…"`);
    }
  }
});

test("redaction: scanner still detects the secret (CWE-798 observed) while the receipt stays clean", () => {
  const { privateKey } = makeKey();
  const result = attest({ code: CODE_WITH_SECRET, filename: "src/config.ts", privateKey });
  const cwes = result.findings.map((f) => f.claim.cwe);
  assert.ok(cwes.includes("CWE-798"), "CWE-798 should be observed");
  const cwesInReceipt = JSON.stringify(result.receipt);
  assert.ok(!cwesInReceipt.includes("hunter2222"), "secret leaked via finding fields");
});

test("redaction: gate refuses a receipt that contains secret-shaped text", () => {
  const leaking = { note: 'password = "hunter2222hunter2222"' };
  const report = assertReceiptIsRedacted(leaking, CODE_WITH_SECRET);
  assert.strictEqual(report.ok, false);
  assert.ok(report.problems.some((p) => /secret-shaped/.test(p)));
});

test("redaction: gate flags raw source lines embedded in a payload", () => {
  const leaking = { note: JSON.stringify("const apiKey = \"kin_live_testkey_0123456789abcdef\";") };
  const report = assertReceiptIsRedacted(leaking, CODE_WITH_SECRET);
  assert.strictEqual(report.ok, false);
});

test("redaction: scanForSecrets finds secrets in arbitrary text, never echoes them fully", () => {
  const hits = scanForSecrets('token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"');
  assert.strictEqual(hits.length >= 1, true);
  assert.ok(!JSON.stringify(hits).includes("ghp_abcdefghijklmnopqrstuvwxyz0123456789"), "full secret echoed in report");
  assert.strictEqual(scanForSecrets("const clean = 1;").length, 0);
});

test("redaction: raw prompts never stored — agent block carries hashes/nulls only", () => {
  const { privateKey } = makeKey();
  const result = attest({
    code: "const x = 1;",
    filename: "a.ts",
    privateKey,
    agent: { host: "claude-code", session_id: "sess-1", model: "claude-x", prompt_sha256: "a".repeat(64) },
  });
  const agent = result.receipt.agent;
  assert.strictEqual(agent.prompt_sha256, "a".repeat(64));
  assert.ok(!JSON.stringify(result.receipt).includes("Write code that"));
});
