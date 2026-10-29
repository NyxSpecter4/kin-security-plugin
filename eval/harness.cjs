#!/usr/bin/env node
/**
 * KIN Security Eval Harness — kin-security-eval/harness-v0.1
 * Zero-dependency. Drives the REAL MCP server artifact (mcp-server/index.cjs)
 * over JSON-RPC, exactly as a client would. No source changes to the server.
 *
 * Categories (kin-security-eval/categories-v0.1) — see eval/README.md:
 *   valid         ground-truth vulnerable, rule-covered -> expected_rule_ids must all fire (TP)
 *   clean         no security relevance -> any finding is a false positive (FP)
 *   adversarial   benign pattern-like content (comments/docs/tests) -> any finding is FP
 *   contradictory pattern fires but code is semantically safe -> designed FP (over-flag class)
 *   missing       real vulnerability of a rule-uncovered class -> expected miss = coverage gap
 *   invalid       malformed input -> must not crash; must return valid JSON
 *
 * Instrument law: the harness ships a selftest (a planted violation the
 * comparator MUST detect). If the selftest cannot fail, this harness is
 * decoration and exits 2.
 *
 * Exit codes:
 *   0  harness integrity OK and no ground-truth violations (scanner clean)
 *   1  ground-truth violations found (scanner defects — EXPECTED RED at baseline)
 *   2  selftest failed to detect the planted violation (harness broken)
 *   3  harness execution error
 */

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const HARNESS_VERSION = "kin-security-eval/harness-v0.1";
const CATEGORIES_VERSION = "kin-security-eval/categories-v0.1";
const REPORT_PATH = path.join(__dirname, "baseline-report.json");
const CASES_PATH = path.join(__dirname, "cases.json");

const cases = JSON.parse(fs.readFileSync(CASES_PATH, "utf8")).cases;

function spawnServer() {
  return spawn("node", [path.join(__dirname, "..", "mcp-server", "index.cjs")], {
    stdio: ["pipe", "pipe", "inherit"],
  });
}

function makeRpc(child) {
  let nextId = 0;
  let buf = "";
  const pending = new Map();
  child.stdout.on("data", (d) => {
    buf += d.toString();
    const lines = buf.split("\n");
    buf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    }
  });
  return (method, params) =>
    new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, resolve);
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error(`rpc timeout: ${method}`));
        }
      }, 30000);
    });
}

async function scanCode(rpc, args) {
  const res = await rpc("tools/call", { name: "kin_scan_code", arguments: args });
  if (res.error) return { serverError: res.error };
  try {
    const parsed = JSON.parse(res.result.content[0].text);
    if (!Array.isArray(parsed.findings)) return { serverError: { message: "findings array missing" } };
    return parsed;
  } catch {
    return { serverError: { message: "unparseable response payload" } };
  }
}

function evaluateCase(c, payload) {
  if (c.category === "invalid") {
    const ok = payload && !payload.serverError;
    return {
      status: ok ? "PASS" : "VIOLATION",
      matched: [],
      note: ok ? "no crash; valid JSON with findings array" : "crashed or returned invalid response",
    };
  }
  if (payload.serverError) {
    return { status: "VIOLATION", matched: [], note: `server error: ${payload.serverError.message}` };
  }
  const matched = (payload.findings || []).map((f) => f.rule_id);
  if (c.category === "valid") {
    const missing = (c.expected_rule_ids || []).filter((id) => !matched.includes(id));
    return {
      status: missing.length === 0 ? "PASS" : "VIOLATION",
      matched,
      missing,
      note: missing.length ? `false negative: expected ${missing.join(",")} not fired` : "expected rule(s) fired",
    };
  }
  if (c.category === "clean" || c.category === "adversarial" || c.category === "contradictory") {
    return {
      status: matched.length === 0 ? "PASS" : "VIOLATION",
      matched,
      note: matched.length ? `false positive: ${matched.join(",")} fired on ground-truth-negative case` : "no findings (correct)",
    };
  }
  if (c.category === "missing") {
    return {
      status: matched.length === 0 ? "EXPECTED_MISS" : "UNEXPECTED_HIT",
      matched,
      note:
        matched.length === 0
          ? "coverage gap confirmed: rule set does not cover this vulnerability class"
          : "engine flagged a documented-gap case",
    };
  }
  return { status: "VIOLATION", matched: [], note: `unknown category: ${c.category}` };
}

// ── Selftest (gate-can-fail law) ────────────────────────────────────────
// Plant a fabricated finding on a ground-truth-negative case. The comparator
// MUST flag it. If it does not, this harness cannot detect drift and is decoration.
function selftest() {
  const planted = evaluateCase(
    { id: "SELFTEST-PLANTED", category: "clean", expected_rule_ids: [] },
    { findings: [{ rule_id: "CWE-999-PLANTED" }] }
  );
  return planted.status === "VIOLATION";
}

async function main() {
  const startedAt = Date.now();
  const harnessSelftestLive = selftest();
  if (!harnessSelftestLive) {
    console.error("SELFTEST: DEAD — comparator failed to detect a planted violation. Harness is decoration.");
    process.exit(2);
  }
  console.log("SELFTEST: LIVE (planted violation detected)");

  const child = spawnServer();
  const rpc = makeRpc(child);
  const serverSpawnMs = Date.now() - startedAt;

  const results = [];
  const caseTimings = [];
  const scanStart = Date.now();
  for (const c of cases) {
    const t0 = Date.now();
    const payload = await scanCode(rpc, { code: c.code, filename: c.filename });
    const ms = Date.now() - t0;
    caseTimings.push({ id: c.id, ms });
    results.push({ id: c.id, category: c.category, name: c.name, ...evaluateCase(c, payload) });
    const tag =
      results[results.length - 1].status === "PASS"
        ? "ok  "
        : results[results.length - 1].status === "EXPECTED_MISS"
        ? "gap "
        : "FAIL";
    console.log(`[${tag}] ${c.id.padEnd(28)} (${String(ms).padStart(3)}ms) ${results[results.length - 1].note}`);
  }
  child.kill();
  const totalMs = Date.now() - startedAt;
  const scanMs = Date.now() - scanStart;

  // ── Metrics ──────────────────────────────────────────────────────────
  const tp = results.filter((r) => r.category === "valid" && r.status === "PASS").length;
  const fn = results.filter((r) => r.category === "valid" && r.status === "VIOLATION").length;
  const fp = results.filter(
    (r) => ["clean", "adversarial", "contradictory"].includes(r.category) && r.status === "VIOLATION"
  ).length;
  const tn = results.filter(
    (r) => ["clean", "adversarial", "contradictory"].includes(r.category) && r.status === "PASS"
  ).length;
  const knownGaps = results.filter((r) => r.status === "EXPECTED_MISS").length;
  const robustnessPass = results.filter((r) => r.category === "invalid" && r.status === "PASS").length;
  const unexpectedHits = results.filter((r) => r.status === "UNEXPECTED_HIT").length;
  const violations = results.filter((r) => r.status === "VIOLATION").length;

  const precision = tp + fp > 0 ? tp / (tp + fp) : null;
  const recall = tp + fn + knownGaps > 0 ? tp / (tp + fn + knownGaps) : null;

  const byCategory = {};
  for (const r of results) {
    byCategory[r.category] = byCategory[r.category] || { total: 0, pass: 0, violation: 0, expected_miss: 0 };
    byCategory[r.category].total++;
    if (r.status === "PASS") byCategory[r.category].pass++;
    else if (r.status === "VIOLATION") byCategory[r.category].violation++;
    else if (r.status === "EXPECTED_MISS") byCategory[r.category].expected_miss++;
  }

  const report = {
    report_id: "kin-security-eval/baseline-report",
    harness_version: HARNESS_VERSION,
    categories_version: CATEGORIES_VERSION,
    generated_at: new Date().toISOString(),
    environment: { node: process.version },
    status_labels: {
      measurement: "MEASURED — executed this run against the live MCP server artifact",
      scope: "deterministic rule engine (kin_scan_code) only; no model calls, no network",
      receipt_class: "BUILDER — built and measured by the same seat; no independent reproduction yet",
    },
    timing: {
      server_spawn_and_selftest_ms: serverSpawnMs,
      scan_loop_ms: scanMs,
      total_harness_ms: totalMs,
      per_case_ms: caseTimings,
      mean_case_ms: caseTimings.length ? Math.round(caseTimings.reduce((a, b) => a + b.ms, 0) / caseTimings.length) : null,
      case_count: cases.length,
    },
    metrics: {
      true_positives: tp,
      false_negatives: fn,
      false_positives: fp,
      true_negatives: tn,
      known_coverage_gaps: knownGaps,
      unexpected_hits_on_gap_cases: unexpectedHits,
      invalid_robustness: `${robustnessPass}/${results.filter((r) => r.category === "invalid").length}`,
      precision: precision,
      recall_with_known_gaps_as_fn: recall,
      violations: violations,
      by_category: byCategory,
    },
    results,
    limitations: [
      "Ground truth is author-labeled (categories v0.1); no independent review yet",
      "This case set is the development set; a held-out split ships with the backend PR",
      "Rule engine is regex-based and JS-focused; 'missing' cases document known blind spots",
      "Baseline is expected-red: adversarial and contradictory categories document measured false-positive classes",
    ],
  };
  fs.writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2) + "\n");

  console.log("\n=== SUMMARY ===");
  console.log(`cases: ${cases.length} | TP ${tp} | TN ${tn} | FP ${fp} | FN ${fn} | known gaps ${knownGaps} | violations ${violations}`);
  if (precision !== null) console.log(`precision: ${(precision * 100).toFixed(1)}%  recall (gaps=FN): ${(recall * 100).toFixed(1)}%`);
  console.log(`harness total: ${totalMs}ms (scan loop ${scanMs}ms, mean/case ${report.timing.mean_case_ms}ms)`);
  console.log(`report: eval/baseline-report.json`);
  process.exit(violations > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("HARNESS ERROR:", err.message);
  process.exit(3);
});
