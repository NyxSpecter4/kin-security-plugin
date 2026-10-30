/**
 * Redaction invariants for KIN Receipt v1 (forward-only, fail-closed).
 *
 * The invariant that makes receipts safe to store and publish:
 *   A serialized receipt must NEVER contain:
 *     1. raw source-code lines from the scanned input (evidence is
 *        coordinates + hashes, never content), or
 *     2. secret-shaped strings (the engine's own CWE-798 patterns applied
 *        to the receipt bytes).
 *
 * JSON escaping hides secrets from naive pattern scans ("hunter2" becomes
 * \"hunter2\" inside a serialized string), so every check runs against BOTH
 * the raw serialized text AND a de-escaped form. A secret that only appears
 * once the JSON quoting is mentally removed is still a leaked secret.
 *
 * assertReceiptIsRedacted(receipt, scannedCode) -> { ok, problems[] }
 * scanForSecrets(text) -> [{ rule_id, match }]
 */

const { SECURITY_RULES } = require("../scanners/kin-rules.cjs");

const SECRET_RULE = SECURITY_RULES.find((r) => r.id === "CWE-798");

function deescape(text) {
  // Approximate the single-level JSON unescape: \" -> ", \\ -> \, \n -> n...
  // Detection-only helper — never used to reconstruct data.
  return String(text).replace(/\\(.)/g, "$1");
}

function scanForSecrets(text) {
  const hits = [];
  const forms = [String(text), deescape(text), deescape(deescape(text))];
  for (const form of forms) {
    for (const pattern of SECRET_RULE.patterns) {
      const m = pattern.exec(form);
      if (m) {
        hits.push({ rule_id: "CWE-798", match: m[0].slice(0, 12) + "…" }); // truncated — never echo the full secret
      }
    }
  }
  return hits;
}

function significantLines(code) {
  return String(code || "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length >= 8); // ignore trivial fragments that could appear anywhere
}

function assertReceiptIsRedacted(receipt, scannedCode) {
  const problems = [];
  const serialized = JSON.stringify(receipt);
  const d1 = deescape(serialized);
  const haystacks = [serialized, d1, deescape(d1)];

  // Invariant 2: no secret-shaped strings anywhere in the receipt.
  for (const hit of scanForSecrets(serialized)) {
    problems.push(`secret-shaped string present in receipt (${hit.rule_id}, starts "${hit.match}")`);
  }

  // Invariant 1: no raw source line from the scanned input (raw or escaped).
  for (const line of significantLines(scannedCode)) {
    for (const haystack of haystacks) {
      if (haystack.includes(line)) {
        problems.push(`raw source line present in receipt: "${line.slice(0, 24)}…"`);
        break;
      }
    }
  }

  return { ok: problems.length === 0, problems };
}

module.exports = { scanForSecrets, assertReceiptIsRedacted };
