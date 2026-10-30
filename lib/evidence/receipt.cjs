/**
 * KIN Receipt v1 — canonical, content-addressed, Ed25519-signed evidence envelope.
 *
 * Schema id: "kin.security.receipt/v1"
 *
 * Construction (exact, replayable by the independent verifier):
 *   pre-image = receipt body with NO receipt_id and evidence = { canonical_sha256: null }
 *   canonical_sha256 = sha256(canonicalSerialize(pre-image))
 *   signed-body  = pre-image with evidence.canonical_sha256 = canonical_sha256
 *   signature    = ed25519.sign(canonicalSerialize(signed-body), privateKey)
 *   receipt_id   = "01" + canonical_sha256.slice(0, 30)   (content-addressed)
 *   receipt      = { ...signed-body, receipt_id, evidence: { canonical_sha256, signature } }
 *
 * The independent verifier recomputes ALL of this from the receipt bytes
 * alone (fail-closed): hash, receipt_id, and signature. Any byte changed
 * anywhere in the evidence object breaks at least one of the three.
 *
 * Claim discipline (docs/ASSURANCE.md):
 *   A valid V1 receipt proves: THIS EXACT EVIDENCE OBJECT WAS SIGNED BY THIS
 *   KEY. It does NOT prove reproducible scanning. Do not say
 *   "reproducibly verified" until rerun-equivalence is demonstrated and
 *   recorded separately.
 */

const crypto = require("crypto");
const { canonicalSerialize } = require("./canonicalize.cjs");
const { sha256Hex } = require("./hash.cjs");
const { keyIdFor } = require("./signer.cjs");

const RECEIPT_SCHEMA = "kin.security.receipt/v1";
const PRODUCER_NAME = "kin-security-plugin";
const PRODUCER_VERSION = require("../../package.json").version;

function buildReceiptBody(input) {
  if (!Array.isArray(input.findings)) {
    throw new Error("receipt: findings must be an array");
  }
  if (!input.policy || typeof input.policy.sha256 !== "string" || typeof input.policy.outcome !== "string") {
    throw new Error("receipt: policy.sha256 and policy.outcome are required");
  }
  if (!Array.isArray(input.engines) || input.engines.length === 0) {
    throw new Error("receipt: engines must be a non-empty array");
  }
  return {
    schema: RECEIPT_SCHEMA,
    created_at: input.created_at || new Date().toISOString(),
    producer: {
      name: PRODUCER_NAME,
      version: PRODUCER_VERSION,
    },
    subject: {
      repo: input.subject?.repo ?? null,
      commit: input.subject?.commit ?? null,
      scanned_file: input.subject?.scanned_file ?? null,
      diff_sha256: input.subject?.diff_sha256 ?? null,
      prev_receipt: input.subject?.prev_receipt ?? null,
    },
    agent: {
      host: input.agent?.host ?? "cli",
      session_id: input.agent?.session_id ?? null,
      model: input.agent?.model ?? null,
      prompt_sha256: input.agent?.prompt_sha256 ?? null,
    },
    engines: input.engines,
    findings: input.findings,
    policy: {
      name: input.policy.name ?? null,
      sha256: input.policy.sha256,
      outcome: input.policy.outcome,
      decisions: input.policy.decisions ?? [],
    },
    evidence: {
      canonical_sha256: null, // pre-image form; filled by signReceipt
    },
  };
}

function signReceipt(input, privateKey) {
  const body = buildReceiptBody(input);

  // Pre-image hash: canonical_sha256 is the hash of the body with the
  // hash field nulled — a fixed, replayable pre-image.
  const preImage = canonicalSerialize(body);
  const canonicalSha = sha256Hex(preImage);

  const signedBody = { ...body, evidence: { canonical_sha256: canonicalSha } };
  const signedCanonical = canonicalSerialize(signedBody);
  const signature = crypto.sign(null, Buffer.from(signedCanonical, "utf8"), privateKey);
  const keyId = keyIdFor(crypto.createPublicKey(privateKey));

  return {
    ...signedBody,
    receipt_id: "01" + canonicalSha.slice(0, 30),
    evidence: {
      canonical_sha256: canonicalSha,
      signature: {
        alg: "ed25519",
        key_id: keyId,
        value: signature.toString("base64"),
      },
    },
  };
}

module.exports = { RECEIPT_SCHEMA, PRODUCER_NAME, PRODUCER_VERSION, buildReceiptBody, signReceipt };
