/**
 * Athelgard receipt-state mapping — the evidence ingest contract.
 *
 * Athelgard consumes RECEIPT STATE, never scanner output directly. This
 * module maps a (verified) KIN receipt to the Athelgard evidence ladder:
 *
 *   NO_EVIDENCE   (grey)  no receipt at all
 *   UNVERIFIED    (amber) receipt exists but signature verification failed
 *   BLOCKED       (red)   valid receipt, policy outcome "block"
 *   OBSERVED      (amber) valid receipt, outcome pass, findings present
 *                         (warned or suppressed — remediation unproven)
 *   FIXED_RERUN   (amber) valid receipt, outcome pass, prev_receipt set
 *                         (repair loop completed, verification pending chain)
 *   VERIFIED      (green) valid receipt, outcome pass, zero findings
 *
 * Law: no narrator promotes state — only the verified receipt does. An
 * unverified receipt can NEVER produce a green state.
 */

const { verifyReceipt } = require("../evidence/verifier.cjs");

const STATES = ["NO_EVIDENCE", "UNVERIFIED", "BLOCKED", "OBSERVED", "FIXED_RERUN", "VERIFIED"];
const COLORS = {
  NO_EVIDENCE: "grey",
  UNVERIFIED: "amber",
  BLOCKED: "red",
  OBSERVED: "amber",
  FIXED_RERUN: "amber",
  VERIFIED: "green",
};

function receiptState(receipt, publicKeys) {
  if (!receipt) {
    return { state: "NO_EVIDENCE", color: "grey", detail: "no receipt supplied" };
  }

  const verification = verifyReceipt(receipt, publicKeys);
  if (!verification.valid) {
    return {
      state: "UNVERIFIED",
      color: "amber",
      detail: verification.reason,
      verification,
    };
  }

  const outcome = receipt.policy.outcome;
  const findingsCount = Array.isArray(receipt.findings) ? receipt.findings.length : 0;
  const prevReceipt = receipt.subject && receipt.subject.prev_receipt;

  if (outcome === "block") {
    return {
      state: "BLOCKED",
      color: "red",
      detail: `policy outcome BLOCK on ${findingsCount} finding(s) — inspect → repair → rescan → resign → verify`,
      verification,
    };
  }
  if (prevReceipt) {
    return {
      state: "FIXED_RERUN",
      color: "amber",
      detail: `pass on rerun after blocked receipt ${String(prevReceipt).slice(0, 16)}… — chain verification pending`,
      verification,
    };
  }
  if (findingsCount > 0) {
    return {
      state: "OBSERVED",
      color: "amber",
      detail: `${findingsCount} finding(s) warned or suppressed — remediation unproven`,
      verification,
    };
  }
  return {
    state: "VERIFIED",
    color: "green",
    detail: "signed receipt + policy pass + zero findings",
    verification,
  };
}

module.exports = { receiptState, STATES, COLORS };
