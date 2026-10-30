#!/usr/bin/env node
/**
 * kin-security — the KIN Security Assurance CLI.
 *
 *   kin-security scan <file>            normalized findings (JSON)
 *   kin-security check <file> [--policy p.json]
 *                                       policy decision; exit 0 pass / 2 block / 1 error
 *   kin-security attest <file> [--policy p.json] [--key name] [--out receipt.json]
 *                                       mint a signed KIN Receipt v1; exit code as check
 *   kin-security verify <receipt.json> [--keys dir]
 *                                       VALID (exit 0) / INVALID (exit 1)
 *   kin-security state <receipt.json> [--keys dir]
 *                                       Athelgard evidence state (NO_EVIDENCE/UNVERIFIED/
 *                                       BLOCKED/OBSERVED/FIXED_RERUN/VERIFIED)
 *   kin-security keygen --name <name> [--keys dir]
 *                                       generate a local Ed25519 keypair (.attest/keys)
 *   kin-security demo                   the full lifecycle receipt:
 *                                       SCAN -> CHECK(BLOCK) -> REPAIR -> RESCAN ->
 *                                       ATTEST -> VERIFY, on the SQLi fixture
 *
 * Exit codes: 0 = pass/valid · 1 = error · 2 = policy BLOCK.
 * Fail-closed everywhere: no silent fallbacks, no minting on failure.
 */

const fs = require("fs");
const path = require("path");
const { normalizeScan } = require("../lib/findings/normalize.cjs");
const { loadPolicy, policyFingerprint } = require("../lib/policy/load.cjs");
const { evaluate } = require("../lib/policy/evaluate.cjs");
const { attest } = require("../lib/pipeline/attest.cjs");
const { verifyReceipt } = require("../lib/evidence/verifier.cjs");
const { generateKeyPair, loadPrivateForName, loadPublicKeys, resolveKeysDir } = require("../lib/evidence/signer.cjs");
const { receiptState } = require("../lib/athelgard/receipt-state.cjs");
const { sha256Hex } = require("../lib/evidence/hash.cjs");

const VERSION = require("../package.json").version;

function readCode(file) {
  if (!file) usageExit("no input file given");
  try {
    return fs.readFileSync(file, "utf8");
  } catch (err) {
    failExit(`cannot read ${file}: ${err.message}`);
  }
}

function usageExit(message, code = 1) {
  if (message) process.stderr.write(`kin-security: ${message}\n`);
  process.stderr.write(`usage: kin-security <scan|check|attest|verify|state|keygen|demo> [args]\n`);
  process.exit(code);
}

function failExit(message) {
  process.stderr.write(`kin-security: ${message}\n`);
  process.exit(1);
}

function arg(name) {
  const argv = process.argv.slice(3);
  const i = argv.indexOf(name);
  return i !== -1 && i + 1 < argv.length ? argv[i + 1] : null;
}

function positional() {
  const argv = process.argv.slice(3);
  const positionalArgs = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      i += 1; // skip the value
      continue;
    }
    positionalArgs.push(argv[i]);
  }
  return positionalArgs;
}

function cmdScan() {
  const file = positional()[0];
  const code = readCode(file);
  const findings = normalizeScan(code, file || "unknown");
  process.stdout.write(JSON.stringify({ file, sha256: sha256Hex(code), findings_count: findings.length, findings }, null, 2) + "\n");
}

function cmdCheck() {
  const file = positional()[0];
  const policyFile = arg("--policy");
  const code = readCode(file);
  let findings, policy, evaluation;
  try {
    findings = normalizeScan(code, file || "unknown");
    policy = loadPolicy(policyFile);
    evaluation = evaluate(policy, findings);
  } catch (err) {
    failExit(err.message);
  }
  process.stdout.write(
    JSON.stringify(
      {
        file,
        policy: { name: policy.name, sha256: policyFingerprint(policy) },
        outcome: evaluation.outcome,
        decisions: evaluation.decisions,
        findings_count: findings.length,
      },
      null,
      2
    ) + "\n"
  );
  process.exit(evaluation.outcome === "block" ? 2 : 0);
}

function cmdAttest() {
  const file = positional()[0];
  const policyFile = arg("--policy");
  const keyName = arg("--key") || "captain-kiran";
  const out = arg("--out");
  const repo = arg("--repo");
  const commit = arg("--commit");
  const prevReceipt = arg("--prev-receipt");
  const session = arg("--session");

  const code = readCode(file);
  let privateKey;
  try {
    privateKey = loadPrivateForName(keyName, arg("--keys"));
  } catch (err) {
    failExit(err.message + " (run: kin-security keygen --name " + keyName + ")");
  }

  let result;
  try {
    result = attest({
      code,
      filename: file || "unknown",
      policyFile,
      privateKey,
      subject: {
        repo: repo || null,
        commit: commit || null,
        prev_receipt: prevReceipt || null,
      },
      agent: { host: "cli", session_id: session || null },
    });
  } catch (err) {
    failExit(err.message); // fail-closed: no receipt, no PASS
  }

  const receiptJson = JSON.stringify(result.receipt, null, 2) + "\n";
  if (out) {
    fs.writeFileSync(out, receiptJson);
    process.stderr.write(`receipt written: ${out}\n`);
  } else {
    process.stdout.write(receiptJson);
  }
  process.exit(result.evaluation.outcome === "block" ? 2 : 0);
}

function cmdVerify() {
  const file = positional()[0];
  if (!file) usageExit("no receipt file given");
  let receipt;
  try {
    receipt = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    failExit(`cannot parse receipt ${file}: ${err.message}`);
  }
  let keys;
  try {
    keys = loadPublicKeys(arg("--keys"));
  } catch (err) {
    failExit(err.message);
  }
  const result = verifyReceipt(receipt, keys);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exit(result.valid ? 0 : 1);
}

function cmdState() {
  const file = positional()[0];
  let keys = [];
  try {
    keys = loadPublicKeys(arg("--keys"));
  } catch (err) {
    failExit(err.message);
  }
  let receipt = null;
  if (file) {
    try {
      receipt = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (err) {
      failExit(`cannot parse receipt ${file}: ${err.message}`);
    }
  }
  const state = receiptState(receipt, keys);
  process.stdout.write(JSON.stringify(state, null, 2) + "\n");
  process.exit(0);
}

function cmdKeygen() {
  const name = arg("--name") || "captain-kiran";
  try {
    const meta = generateKeyPair(name, arg("--keys"));
    process.stdout.write(JSON.stringify(meta, null, 2) + "\n");
  } catch (err) {
    failExit(err.message);
  }
}

function cmdDemo() {
  // The SQLi lifecycle fixture — the acceptance chain for V0.1.
  const vulnerable = [
    "const id = req.params.id;",
    "db.query(`SELECT * FROM users WHERE id = '${id}'`);",
    "",
  ].join("\n");

  const repaired = [
    "const id = req.params.id;",
    "const user = await db.select().from(users).where(eq(users.id, id)).first();",
    "",
  ].join("\n");

  const tmpKeys = fs.mkdtempSync(path.join(require("os").tmpdir(), "kin-demo-keys-"));
  const keyMeta = generateKeyPair("demo", tmpKeys);
  const privateKey = loadPrivateForName("demo", tmpKeys);
  const keys = loadPublicKeys(tmpKeys);
  const tmpPolicy = path.join(tmpKeys, "demo-policy.json");

  // Demo policy: block on critical+high (same as the built-in default).
  fs.writeFileSync(
    tmpPolicy,
    JSON.stringify(
      { name: "demo", rules: [{ severity: ["critical", "high"], outcome: "block" }, { severity: ["medium"], outcome: "warn" }] },
      null,
      2
    )
  );

  const lines = [];
  const log = (s) => {
    lines.push(s);
    process.stdout.write(s + "\n");
  };

  log("=== KIN SECURITY ASSURANCE V0.1 — LIFECYCLE DEMO ===");
  log(`key: ${keyMeta.key_id} (ephemeral, demo only)`);

  // SCAN — observation
  const scanFindings = normalizeScan(vulnerable, "src/db.ts");
  log(`SCAN       ${scanFindings.length} finding(s): ${scanFindings.map((f) => `${f.claim.cwe}(${f.claim.severity})@line${f.evidence.line}`).join(", ") || "none"}`);
  if (scanFindings.length !== 1 || scanFindings[0].claim.cwe !== "CWE-89") {
    failExit("demo: expected exactly one CWE-89 observation");
  }

  // CHECK — policy decision
  const policy = loadPolicy(tmpPolicy);
  const blockedEval = evaluate(policy, scanFindings);
  log(`CHECK      outcome=${blockedEval.outcome.toUpperCase()}`);
  if (blockedEval.outcome !== "block") {
    failExit("demo: expected BLOCK on the vulnerable fixture");
  }

  // ATTEST the blocked state (red receipt is valid evidence too)
  const blockedResult = attest({ code: vulnerable, filename: "src/db.ts", policyFile: tmpPolicy, privateKey, created_at: "2026-10-30T00:00:00.000Z" });
  const blockedVerification = verifyReceipt(blockedResult.receipt, keys);
  log(`ATTEST     blocked receipt ${blockedResult.receipt.receipt_id.slice(0, 12)}… valid=${blockedVerification.valid} (red evidence, valid signature)`);
  if (!blockedVerification.valid) failExit("demo: blocked receipt failed verification");

  // REPAIR — parameterized query via query builder
  const rescanFindings = normalizeScan(repaired, "src/db.ts");
  log(`REPAIR     query-builder with bound parameter`);
  log(`RESCAN     ${rescanFindings.length} finding(s)`);
  if (rescanFindings.length !== 0) {
    failExit("demo: expected zero findings after repair (got " + JSON.stringify(rescanFindings.map((f) => f.claim.cwe)) + ")");
  }

  // ATTEST — signed green receipt chained to the blocked one
  const passResult = attest({
    code: repaired,
    filename: "src/db.ts",
    policyFile: tmpPolicy,
    privateKey,
    created_at: "2026-10-30T00:00:01.000Z",
    subject: { prev_receipt: blockedResult.receipt.receipt_id },
  });

  // VERIFY — independent verifier
  const verification = verifyReceipt(passResult.receipt, keys);
  log(`ATTEST     receipt ${passResult.receipt.receipt_id.slice(0, 12)}… (chained to blocked receipt)`);
  log(`VERIFY     ${verification.valid ? "VALID" : "INVALID: " + verification.reason}`);
  if (!verification.valid) failExit("demo: verification failed");

  // Athelgard state for both receipts
  const blockedState = receiptState(blockedResult.receipt, keys);
  const passState = receiptState(passResult.receipt, keys);
  log(`ATHELGARD  blocked receipt -> ${blockedState.state} (${blockedState.color})`);
  log(`ATHELGARD  green receipt   -> ${passState.state} (${passState.color})`);

  // Negative control: tamper with the green receipt, expect refusal.
  const tampered = JSON.parse(JSON.stringify(passResult.receipt));
  tampered.findings.push(JSON.parse(JSON.stringify(scanFindings[0])));
  const tamperVerification = verifyReceipt(tampered, keys);
  log(`TAMPER-CTL tampered receipt -> ${tamperVerification.valid ? "VALID (BUG!)" : "REFUSED (" + tamperVerification.reason.slice(0, 48) + "…)"}`);
  if (tamperVerification.valid) failExit("demo: tampered receipt verified — verifier is broken");

  log("=== LIFECYCLE COMPLETE: SCAN -> CHECK(BLOCK) -> REPAIR -> RESCAN(PASS) -> ATTEST -> VERIFY(VALID) ===");
  fs.rmSync(tmpKeys, { recursive: true, force: true });
}

function main() {
  const command = process.argv[2];
  switch (command) {
    case "scan": return cmdScan();
    case "check": return cmdCheck();
    case "attest": return cmdAttest();
    case "verify": return cmdVerify();
    case "state": return cmdState();
    case "keygen": return cmdKeygen();
    case "demo": return cmdDemo();
    case "--version": return process.stdout.write(VERSION + "\n");
    case "help":
    case "--help":
    case undefined: return usageExit();
    default: return usageExit(`unknown command: ${command}`);
  }
}

main();
