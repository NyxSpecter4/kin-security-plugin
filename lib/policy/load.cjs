/**
 * Policy loading — explicit default, fail-closed file handling.
 *
 * Policy schema: "kin.security.policy/v1"
 *   {
 *     schema, name,
 *     rules: [ { severity?: [...], cwe?: [...], outcome: "block"|"warn"|"pass" } ],
 *     suppressions?: [ { cwe? , file?, finding?, reason, expires } ]
 *   }
 *
 * Built-in DEFAULT policy (explicit, hashed like any other policy):
 *   critical|high -> block, medium -> warn, low -> pass.
 *
 * Missing policy file when --policy was explicitly requested = HARD ERROR.
 * Only the absence of --policy selects the built-in default, and the
 * receipt records which policy (name + sha256) was used — never silent.
 */

const fs = require("fs");
const { canonicalSerialize } = require("../evidence/canonicalize.cjs");
const { sha256Hex } = require("../evidence/hash.cjs");

const POLICY_SCHEMA = "kin.security.policy/v1";

const BUILT_IN_DEFAULT = {
  schema: POLICY_SCHEMA,
  name: "builtin-default",
  rules: [
    { severity: ["critical"], outcome: "block" },
    { severity: ["high"], outcome: "block" },
    { severity: ["medium"], outcome: "warn" },
    { severity: ["low"], outcome: "pass" },
  ],
  suppressions: [],
};

const VALID_OUTCOMES = new Set(["block", "warn", "pass"]);

function validatePolicy(policy) {
  const problems = [];
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new Error("policy: not an object");
  }
  if (policy.schema !== POLICY_SCHEMA) {
    problems.push(`schema must be ${POLICY_SCHEMA}`);
  }
  if (!Array.isArray(policy.rules) || policy.rules.length === 0) {
    problems.push("rules must be a non-empty array");
  } else {
    for (const [i, rule] of policy.rules.entries()) {
      if (!VALID_OUTCOMES.has(rule.outcome)) {
        problems.push(`rules[${i}].outcome must be block|warn|pass (got "${rule.outcome}")`);
      }
    }
  }
  if (policy.suppressions !== undefined && !Array.isArray(policy.suppressions)) {
    problems.push("suppressions must be an array when present");
  }
  if (problems.length > 0) {
    throw new Error("policy invalid: " + problems.join("; "));
  }
  return true;
}

function loadPolicyFromFile(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (err) {
    throw new Error(`policy: cannot read ${file}: ${err.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`policy: ${file} is not valid JSON: ${err.message}`);
  }
  // Normalize: file policies omit schema/name for convenience; fill them.
  const policy = {
    schema: parsed.schema || POLICY_SCHEMA,
    name: parsed.name || file,
    rules: parsed.rules,
    suppressions: parsed.suppressions || [],
  };
  validatePolicy(policy);
  return policy;
}

function loadPolicy(file) {
  if (!file) {
    // No --policy given: the EXPLICIT built-in default (recorded in receipt).
    const policy = structuredClone(BUILT_IN_DEFAULT);
    validatePolicy(policy);
    return policy;
  }
  return loadPolicyFromFile(file);
}

function policyFingerprint(policy) {
  return sha256Hex(canonicalSerialize(policy));
}

module.exports = { POLICY_SCHEMA, BUILT_IN_DEFAULT, loadPolicy, loadPolicyFromFile, policyFingerprint, validatePolicy };
