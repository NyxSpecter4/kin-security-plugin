/**
 * Finding normalization — the contract between OBSERVATION and POLICY.
 *
 * Pipeline position: OBSERVATION -> [this module] -> NORMALIZED FINDING
 *                                                    -> POLICY DECISION
 *
 * Normalized finding (schema "kin.security.finding/v1"):
 *   {
 *     schema: "kin.security.finding/v1",
 *     finding_id: "<fingerprint hex>",        // content-addressed, deterministic
 *     source: { engine, kind, engine_version },
 *       kind: "deterministic" (rule engine) | "model" (KIN model output)
 *     claim: { cwe, severity, name },         // lowercase normalized severity
 *     evidence: { file, line, snippet_sha256 }, // coordinates + hash ONLY —
 *                                               // never raw code (redaction law)
 *     confidence: "observed" (deterministic) | "advisory" (model)
 *   }
 *
 * Determinism law: the same scanned bytes + filename + engine produce the
 * SAME finding_id every run (proven by the reproducibility tests). No
 * timestamps, no randomness, no filesystem ordering inside findings.
 *
 * A model opinion may NEVER silently become equivalent to scanner
 * evidence: kind="model" findings carry confidence "advisory" and are
 * marked as such through policy and receipts.
 */

const { SECURITY_RULES, ruleBasedScan } = require("../scanners/kin-rules.cjs");
const { canonicalSerialize } = require("../evidence/canonicalize.cjs");
const { sha256Hex } = require("../evidence/hash.cjs");

const FINDING_SCHEMA = "kin.security.finding/v1";
const ENGINE_NAME = "kin-rule";
const ENGINE_VERSION = require("../../package.json").version;

const SEVERITY_MAP = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

function normalizeSeverity(legacy) {
  const key = String(legacy || "").toLowerCase().trim();
  if (!SEVERITY_MAP[key]) {
    throw new Error(`normalize: unknown severity "${legacy}"`);
  }
  return SEVERITY_MAP[key];
}

/**
 * Best-effort line localization for a fired rule: the first 1-based line
 * whose text matches one of the rule's patterns. null when no single line
 * matches (multi-line pattern) — evidence stays honest rather than guessed.
 */
function locateLine(code, rule) {
  const lines = String(code || "").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    for (const pattern of rule.patterns) {
      if (pattern.test(lines[i])) return i + 1;
    }
  }
  return null;
}

/**
 * normalizeScan(code, filename) -> findings[] (schema kin.security.finding/v1)
 * Uses the EXISTING ruleBasedScan for WHICH rules fire (identical contract
 * to the MCP tool), then adds evidence coordinates + deterministic ids.
 */
function normalizeScan(code, filename) {
  if (typeof code !== "string") {
    throw new Error("normalize: scanned code must be a string");
  }
  const file = typeof filename === "string" && filename ? filename : "unknown";

  // The existing scan decides which rules fired — one finding per rule.
  const rawFindings = ruleBasedScan(code);
  const findings = [];

  for (const raw of rawFindings) {
    const rule = SECURITY_RULES.find((r) => r.id === raw.rule_id);
    if (!rule) {
      throw new Error(`normalize: scan returned unknown rule_id ${raw.rule_id}`);
    }
    const line = locateLine(code, rule);
    const matchedLine = line === null ? "" : code.split(/\r?\n/)[line - 1].trim();

    const finding = {
      schema: FINDING_SCHEMA,
      source: {
        engine: ENGINE_NAME,
        kind: "deterministic",
        engine_version: ENGINE_VERSION,
      },
      claim: {
        cwe: rule.id,
        severity: normalizeSeverity(rule.severity),
        name: rule.name,
      },
      evidence: {
        file,
        line,
        snippet_sha256: line === null ? null : sha256Hex(matchedLine),
      },
      confidence: "observed",
    };

    // Deterministic fingerprint: content of everything above, minus the id fields.
    const fingerprintPayload = {
      schema: FINDING_SCHEMA,
      source: finding.source,
      claim: finding.claim,
      evidence: finding.evidence,
      confidence: finding.confidence,
    };
    const fingerprint = sha256Hex(canonicalSerialize(fingerprintPayload));

    findings.push({
      schema: FINDING_SCHEMA,
      finding_id: fingerprint,
      source: finding.source,
      claim: finding.claim,
      evidence: finding.evidence,
      confidence: finding.confidence,
    });
  }

  return findings;
}

module.exports = { FINDING_SCHEMA, normalizeScan, normalizeSeverity, locateLine };
