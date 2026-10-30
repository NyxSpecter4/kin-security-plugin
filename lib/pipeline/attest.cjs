/**
 * The attest pipeline — the one chain V0.1 exists to prove:
 *
 *   scan (existing engine) -> normalize -> policy -> redaction gate -> sign
 *
 * Fail-closed laws enforced here:
 *   - scanner failure NEVER produces a receipt or a PASS (errors propagate).
 *   - a receipt is NEVER minted if the redaction invariant fails.
 *   - the receipt records policy sha + outcome + per-finding decisions.
 */

const { ruleBasedScan } = require("../scanners/kin-rules.cjs");
const { normalizeScan } = require("../findings/normalize.cjs");
const { loadPolicy, policyFingerprint } = require("../policy/load.cjs");
const { evaluate } = require("../policy/evaluate.cjs");
const { signReceipt } = require("../evidence/receipt.cjs");
const { assertReceiptIsRedacted } = require("../evidence/redact.cjs");
const { sha256Hex } = require("../evidence/hash.cjs");

const ENGINE_ENTRY = { name: "kin-rule", version: require("../../package.json").version, mode: "deterministic" };

function scanNormalizeCheck(code, filename, policyFile, scanFn = ruleBasedScan) {
  if (typeof code !== "string") {
    throw new Error("pipeline: code must be a string");
  }
  // Scanner failure propagates — it can never become a PASS or a receipt.
  scanFn(code);
  const findings = normalizeScan(code, filename);
  const policy = loadPolicy(policyFile);
  const evaluation = evaluate(policy, findings);
  return { findings, policy, evaluation };
}

function attest(input) {
  const {
    code,
    filename,
    policyFile,
    privateKey,
    subject = {},
    agent = {},
    created_at,
  } = input;

  const { findings, policy, evaluation } = scanNormalizeCheck(code, filename, policyFile);

  const receipt = signReceipt(
    {
      created_at,
      subject: { ...subject, scanned_file: filename, diff_sha256: sha256Hex(code) },
      agent,
      engines: [ENGINE_ENTRY],
      findings,
      policy: {
        name: policy.name,
        sha256: policyFingerprint(policy),
        outcome: evaluation.outcome,
        decisions: evaluation.decisions,
      },
    },
    privateKey
  );

  // Redaction gate: refuse to mint a receipt that leaks source or secrets.
  const redaction = assertReceiptIsRedacted(receipt, code);
  if (!redaction.ok) {
    throw new Error("redaction refused: " + redaction.problems.join("; "));
  }

  return { receipt, findings, policy, evaluation, redaction };
}

module.exports = { attest, scanNormalizeCheck, ENGINE_ENTRY };
