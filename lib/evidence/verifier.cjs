/**
 * Independent Ed25519 verifier for KIN Receipt v1.
 *
 * verifyReceipt(receipt, publicKeys) -> { valid, reason, key_id?, checks }
 *
 * Fail-closed by construction:
 *   - any structural problem => { valid: false, reason: "..." }
 *   - checks (all must pass):
 *       1. SCHEMA        receipt.schema === "kin.security.receipt/v1"
 *       2. STRUCTURE     required fields present with correct types
 *       3. HASH          sha256(canonical(pre-image with hash nulled))
 *                       === evidence.canonical_sha256
 *       4. RECEIPT_ID    "01" + canonical_sha256.slice(0,30) === receipt_id
 *       5. KEY           a provided public key matches signature.key_id
 *       6. SIGNATURE     ed25519.verify over canonicalSerialize(signed-body)
 *
 * The verifier NEVER trusts any field it can recompute — it recomputes
 * everything from the receipt bytes alone.
 */

const crypto = require("crypto");
const { canonicalSerialize } = require("./canonicalize.cjs");
const { sha256Hex } = require("./hash.cjs");
const { RECEIPT_SCHEMA } = require("./receipt.cjs");

function isNonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
}

function checkStructure(receipt, problems) {
  const need = (getter, label, type) => {
    try {
      const v = getter(receipt);
      if (type === "string" && !isNonEmptyString(v)) throw new Error("not a non-empty string");
      if (type === "array" && !Array.isArray(v)) throw new Error("not an array");
      if (type === "object" && (v === null || typeof v !== "object" || Array.isArray(v))) throw new Error("not an object");
      return v;
    } catch (err) {
      problems.push(`missing-or-invalid field: ${label}`);
      return undefined;
    }
  };
  need((r) => r.schema, "schema", "string");
  need((r) => r.receipt_id, "receipt_id", "string");
  need((r) => r.created_at, "created_at", "string");
  need((r) => r.producer, "producer", "object");
  need((r) => r.subject, "subject", "object");
  need((r) => r.agent, "agent", "object");
  need((r) => r.engines, "engines", "array");
  need((r) => r.findings, "findings", "array");
  need((r) => r.policy, "policy", "object");
  need((r) => r.evidence, "evidence", "object");
  need((r) => r.evidence.canonical_sha256, "evidence.canonical_sha256", "string");
  need((r) => r.evidence.signature, "evidence.signature", "object");
  need((r) => r.evidence.signature.alg, "evidence.signature.alg", "string");
  need((r) => r.evidence.signature.key_id, "evidence.signature.key_id", "string");
  need((r) => r.evidence.signature.value, "evidence.signature.value", "string");
  need((r) => r.policy.sha256, "policy.sha256", "string");
  need((r) => r.policy.outcome, "policy.outcome", "string");
}

function verifyReceipt(receipt, publicKeys) {
  const checks = {
    schema: false,
    structure: false,
    hash: false,
    receipt_id: false,
    key: false,
    signature: false,
  };

  const fail = (reason) => ({ valid: false, reason, key_id: null, checks });

  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) {
    return fail("malformed: receipt is not a JSON object");
  }
  if (receipt.schema !== RECEIPT_SCHEMA) {
    checks.schema = false;
    return { valid: false, reason: `schema mismatch: expected ${RECEIPT_SCHEMA}`, key_id: null, checks };
  }
  checks.schema = true;

  const problems = [];
  checkStructure(receipt, problems);
  if (problems.length > 0) {
    return { valid: false, reason: "malformed: " + problems.join("; "), key_id: null, checks };
  }
  checks.structure = true;

  // Rebuild the signed body: everything except receipt_id and the signature
  // object; canonical_sha256 keeps the stored value.
  const { receipt_id, evidence, ...rest } = receipt;
  const signedBody = { ...rest, evidence: { canonical_sha256: evidence.canonical_sha256 } };
  const preImageBody = { ...rest, evidence: { canonical_sha256: null } };

  let recomputedHash;
  try {
    recomputedHash = sha256Hex(canonicalSerialize(preImageBody));
  } catch (err) {
    return { valid: false, reason: "malformed: canonicalization failed: " + err.message, key_id: null, checks };
  }
  if (recomputedHash !== evidence.canonical_sha256) {
    return { valid: false, reason: "hash mismatch: evidence was modified after signing", key_id: null, checks };
  }
  checks.hash = true;

  if ("01" + recomputedHash.slice(0, 30) !== receipt_id) {
    return { valid: false, reason: "receipt_id mismatch: not content-addressed to the evidence", key_id: null, checks };
  }
  checks.receipt_id = true;

  if (evidence.signature.alg !== "ed25519") {
    return { valid: false, reason: `unsupported signature algorithm: ${evidence.signature.alg}`, key_id: null, checks };
  }

  if (!Array.isArray(publicKeys) || publicKeys.length === 0) {
    return { valid: false, reason: "no public keys provided", key_id: evidence.signature.key_id, checks };
  }
  const keyEntry = publicKeys.find((k) => k.key_id === evidence.signature.key_id);
  if (!keyEntry) {
    return {
      valid: false,
      reason: `no provided public key matches key_id ${evidence.signature.key_id}`,
      key_id: evidence.signature.key_id,
      checks,
    };
  }
  checks.key = true;

  let canonicalSigned;
  try {
    canonicalSigned = canonicalSerialize(signedBody);
  } catch (err) {
    return { valid: false, reason: "malformed: canonicalization failed: " + err.message, key_id: evidence.signature.key_id, checks };
  }

  const sigBuf = Buffer.from(evidence.signature.value, "base64");
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(canonicalSigned, "utf8"), keyEntry.publicKey, sigBuf);
  } catch (err) {
    ok = false;
  }
  if (!ok) {
    return { valid: false, reason: "signature invalid: wrong key or tampered payload", key_id: evidence.signature.key_id, checks };
  }
  checks.signature = true;

  return {
    valid: true,
    reason: "valid: evidence hash, receipt_id, and ed25519 signature all verified",
    key_id: evidence.signature.key_id,
    checks,
  };
}

module.exports = { verifyReceipt };
