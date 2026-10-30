/**
 * Policy evaluation — NORMALIZED FINDINGS -> POLICY DECISION.
 *
 * evaluate(policy, findings) -> {
 *   outcome: "pass" | "block",        // overall: block if ANY finding blocks
 *   decisions: [ { finding_id, cwe, severity, file, outcome, basis,
 *                   suppressed_by?: { id, reason, expires } } ]
 * }
 *
 * Decision order per finding (first match wins):
 *   1. ACTIVE suppression (unexpired)  -> outcome "pass", suppressed_by recorded
 *   2. EXPIRED suppression              -> ignored entirely (documented in basis)
 *   3. first policy rule matching severity or cwe
 *   4. no rule matched                  -> outcome "pass", basis "no-rule-matched"
 *
 * Model-kind findings (confidence "advisory") can never force "block" on
 * their own: they evaluate through the rules like any finding, but a
 * policy that wants them advisory-only simply does not write block rules
 * for them. The engine itself never upgrades advisory to observed.
 */

function matchesRule(rule, finding) {
  if (rule.severity && !rule.severity.includes(finding.claim.severity)) return false;
  if (rule.cwe && !rule.cwe.includes(finding.claim.cwe)) return false;
  if (!rule.severity && !rule.cwe) return false; // a rule must select something
  return true;
}

function isExpired(suppression, now) {
  if (!suppression.expires) return false;
  const expiry = Date.parse(suppression.expires);
  if (Number.isNaN(expiry)) return true; // unparseable expiry = unusable = expired
  return expiry < now.getTime();
}

function matchesSuppression(sup, finding) {
  if (sup.finding && sup.finding !== finding.finding_id) return false;
  if (sup.cwe && sup.cwe !== finding.claim.cwe) return false;
  if (sup.file && sup.file !== finding.evidence.file) return false;
  if (!sup.finding && !sup.cwe && !sup.file) return false; // must select something
  return true;
}

function evaluate(policy, findings, now = new Date()) {
  const decisions = [];
  let overall = "pass";

  for (const finding of findings) {
    const decision = {
      finding_id: finding.finding_id,
      cwe: finding.claim.cwe,
      severity: finding.claim.severity,
      file: finding.evidence.file,
      outcome: null,
      basis: null,
    };

    // Suppressions first (an active suppression overrides everything).
    let activeSup = null;
    let expiredIgnored = 0;
    for (const sup of policy.suppressions || []) {
      if (!matchesSuppression(sup, finding)) continue;
      if (isExpired(sup, now)) {
        expiredIgnored += 1; // expired suppressions are IGNORED, never applied
        continue;
      }
      activeSup = sup;
      break;
    }
    if (expiredIgnored > 0) {
      decision.expired_suppressions_ignored = expiredIgnored;
    }

    if (activeSup) {
      decision.outcome = "pass";
      decision.basis = "suppression";
      decision.suppressed_by = {
        id: activeSup.id || activeSup.finding || activeSup.cwe || activeSup.file,
        reason: activeSup.reason || "(none given)",
        expires: activeSup.expires || null,
      };
    } else {
      let matched = null;
      for (const rule of policy.rules) {
        if (matchesRule(rule, finding)) {
          matched = rule;
          break;
        }
      }
      if (matched) {
        decision.outcome = matched.outcome;
        decision.basis = "rule";
      } else {
        decision.outcome = "pass";
        decision.basis = "no-rule-matched" + (expiredIgnored > 0 ? " (expired suppression ignored)" : "");
      }
    }

    if (decision.outcome === "block") overall = "block";
    decisions.push(decision);
  }

  return { outcome: overall, decisions };
}

module.exports = { evaluate, matchesRule, matchesSuppression, isExpired };
