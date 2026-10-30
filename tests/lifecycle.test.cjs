/**
 * Lifecycle test — the V0.1 acceptance chain, executed as proof:
 *
 *   SCAN       CWE-89 observed
 *   CHECK      BLOCK
 *   REPAIR     parameterized query
 *   RESCAN     PASS
 *   ATTEST     signed
 *   VERIFY     VALID
 *   ATHELGARD  red receipt -> BLOCKED · green receipt -> FIXED_RERUN
 *
 * Plus the scanner-failure invariant: a failing scanner can NEVER
 * produce a receipt or a PASS.
 */

const test = require("node:test");
const assert = require("node:assert");
const os = require("os");
const fs = require("fs");
const path = require("path");
const { normalizeScan } = require("../lib/findings/normalize.cjs");
const { loadPolicy, policyFingerprint } = require("../lib/policy/load.cjs");
const { evaluate } = require("../lib/policy/evaluate.cjs");
const { attest, scanNormalizeCheck } = require("../lib/pipeline/attest.cjs");
const { verifyReceipt } = require("../lib/evidence/verifier.cjs");
const { generateKeyPair, loadPrivateForName, loadPublicKeys } = require("../lib/evidence/signer.cjs");
const { receiptState } = require("../lib/athelgard/receipt-state.cjs");

const VULNERABLE = [
  "const id = req.params.id;",
  "db.query(`SELECT * FROM users WHERE id = '${id}'`);",
  "",
].join("\n");

// REPAIR: a parameterized query via the query builder. NOTE (known
// limitation KL-1): the rule engine's CWE-89 pattern also matches inline
// SQL strings containing placeholder markers ($1, ?), so the canonical
// db.query("... = $1", [id]) form is still pattern-flagged. The builder
// form is a genuine parameterized query AND a clean rescan.
const REPAIRED = [
  "const id = req.params.id;",
  "const user = await db.select().from(users).where(eq(users.id, id)).first();",
  "",
].join("\n");

function makeKeys() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kin-lifecycle-"));
  generateKeyPair("captain", dir);
  const privateKey = loadPrivateForName("captain", dir);
  const keys = loadPublicKeys(dir);
  return { dir, privateKey, keys };
}

test("lifecycle: SCAN -> CHECK(BLOCK) -> REPAIR -> RESCAN(PASS) -> ATTEST -> VERIFY(VALID)", () => {
  const { privateKey, keys } = makeKeys();

  // SCAN — the observation
  const observed = normalizeScan(VULNERABLE, "src/db.ts");
  assert.strictEqual(observed.length, 1);
  assert.strictEqual(observed[0].claim.cwe, "CWE-89");
  assert.strictEqual(observed[0].confidence, "observed");

  // CHECK — the policy decision
  const policy = loadPolicy(null);
  const blocked = evaluate(policy, observed);
  assert.strictEqual(blocked.outcome, "block");

  // ATTEST the blocked state too — a red receipt is valid evidence
  const blockedResult = attest({ code: VULNERABLE, filename: "src/db.ts", privateKey, created_at: "2026-10-30T00:00:00.000Z" });
  assert.strictEqual(blockedResult.receipt.policy.outcome, "block");
  assert.strictEqual(verifyReceipt(blockedResult.receipt, keys).valid, true, "blocked receipt must be verifiable");
  assert.strictEqual(blockedResult.receipt.subject.diff_sha256.length, 64);

  // REPAIR + RESCAN
  const rescanned = normalizeScan(REPAIRED, "src/db.ts");
  assert.deepStrictEqual(rescanned, [], "repair must produce zero findings");

  // ATTEST — chained to the blocked receipt
  const passResult = attest({
    code: REPAIRED,
    filename: "src/db.ts",
    privateKey,
    created_at: "2026-10-30T00:00:01.000Z",
    subject: { prev_receipt: blockedResult.receipt.receipt_id },
  });
  assert.strictEqual(passResult.receipt.policy.outcome, "pass");
  assert.strictEqual(passResult.receipt.subject.prev_receipt, blockedResult.receipt.receipt_id);

  // VERIFY — the independent verifier
  const verification = verifyReceipt(passResult.receipt, keys);
  assert.strictEqual(verification.valid, true, verification.reason);

  // ATHELGARD consumes receipt state
  const redState = receiptState(blockedResult.receipt, keys);
  assert.strictEqual(redState.state, "BLOCKED");
  assert.strictEqual(redState.color, "red");
  const chainState = receiptState(passResult.receipt, keys);
  assert.strictEqual(chainState.state, "FIXED_RERUN");
  assert.strictEqual(chainState.color, "amber");

  // The green receipt is bound to the repaired bytes, not the vulnerable ones
  assert.notStrictEqual(passResult.receipt.subject.diff_sha256, blockedResult.receipt.subject.diff_sha256);
});

test("lifecycle: a clean pass with no history -> Athelgard VERIFIED (green)", () => {
  const { privateKey, keys } = makeKeys();
  const result = attest({ code: "const x = 1;\n", filename: "clean.ts", privateKey });
  const state = receiptState(result.receipt, keys);
  assert.strictEqual(state.state, "VERIFIED");
  assert.strictEqual(state.color, "green");
});

test("lifecycle: warned findings -> Athelgard OBSERVED (amber), never green", () => {
  const { privateKey, keys } = makeKeys();
  // CWE-601 open redirect = Medium -> warn under the default policy
  const result = attest({ code: "res.redirect(req.query.next);\n", filename: "redirect.ts", privateKey });
  assert.strictEqual(result.receipt.policy.outcome, "pass");
  const state = receiptState(result.receipt, keys);
  assert.strictEqual(state.state, "OBSERVED");
  assert.strictEqual(state.color, "amber");
});

test("lifecycle: unverified receipt -> Athelgard UNVERIFIED, never a green state", () => {
  const { privateKey, keys } = makeKeys();
  const { keys: otherKeys } = makeKeys();
  const result = attest({ code: "const x = 1;\n", filename: "clean.ts", privateKey });
  const state = receiptState(result.receipt, otherKeys); // wrong keys
  assert.strictEqual(state.state, "UNVERIFIED");
  assert.strictEqual(state.color, "amber");
  const none = receiptState(null, keys);
  assert.strictEqual(none.state, "NO_EVIDENCE");
  assert.strictEqual(none.color, "grey");
});

test("lifecycle: scanner failure can NEVER generate a receipt or a PASS", () => {
  const { privateKey } = makeKeys();
  const explodingScanner = () => {
    throw new Error("scanner crashed");
  };
  assert.throws(
    () => scanNormalizeCheck("code", "file.ts", null, explodingScanner),
    /scanner crashed/
  );
  // A normalize failure must abort before any receipt exists (no catch-all).
  assert.throws(() => scanNormalizeCheck(1234, "file.ts", null), /must be a string/);
});

test("lifecycle: the demo command itself runs end-to-end", async () => {
  const { execFile } = require("child_process");
  const { promisify } = require("util");
  const run = promisify(execFile);
  const cli = path.join(__dirname, "..", "cli", "index.cjs");
  const { stdout } = await run("node", [cli, "demo"], { cwd: path.join(__dirname, "..") });
  assert.match(stdout, /LIFECYCLE COMPLETE: SCAN -> CHECK\(BLOCK\) -> REPAIR -> RESCAN\(PASS\) -> ATTEST -> VERIFY\(VALID\)/);
  assert.match(stdout, /TAMPER-CTL\s+tampered receipt -> REFUSED/);
});
