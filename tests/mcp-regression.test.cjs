/**
 * MCP regression — the existing plugin must survive the Assurance Core merge.
 *
 *   [ ] the shared engine preserves the EXACT legacy finding contract
 *   [ ] the MCP server still speaks JSON-RPC: initialize / tools/list /
 *       tools/call(kin_scan_code) with the same response shape
 *   [ ] index.cjs no longer embeds its own rule array (single source of truth)
 */

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { ruleBasedScan, SECURITY_RULES } = require("../lib/scanners/kin-rules.cjs");

const SQLI = 'const q = "SELECT * FROM users WHERE username = \'" + req.body.username + "\'";';

test("mcp regression: legacy finding contract preserved", () => {
  const findings = ruleBasedScan(SQLI);
  assert.ok(findings.length >= 1);
  for (const f of findings) {
    assert.deepStrictEqual(Object.keys(f).sort(), ["explanation", "name", "remediation", "rule_id", "severity"]);
    assert.match(f.rule_id, /^CWE-\d+$/);
    assert.ok(["Critical", "High", "Medium"].includes(f.severity));
    assert.strictEqual(typeof f.explanation, "string");
    assert.strictEqual(typeof f.remediation, "string");
  }
  assert.ok(findings.some((f) => f.rule_id === "CWE-89"));
  // ten rules, still
  assert.strictEqual(SECURITY_RULES.length, 10);
});

test("mcp regression: index.cjs uses the shared engine, not an inline copy", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "mcp-server", "index.cjs"), "utf8");
  assert.ok(!source.includes("const SECURITY_RULES = ["), "inline rule array is back — single source of truth violated");
  assert.ok(source.includes('require("../lib/scanners/kin-rules.cjs")'), "shared engine not required");
});

function rpc(child, msg) {
  return new Promise((resolve, reject) => {
    const onData = (buf) => {
      for (const line of buf.toString().split("\n")) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          if (parsed.id === msg.id) {
            child.stdout.off("data", onData);
            resolve(parsed);
            return;
          }
        } catch (err) {
          /* partial line, keep waiting */
        }
      }
    };
    child.stdout.on("data", onData);
    child.stdin.write(JSON.stringify(msg) + "\n");
    setTimeout(() => reject(new Error("MCP timeout waiting for id=" + msg.id)), 15000);
  });
}

test("mcp regression: server speaks JSON-RPC and scans (subprocess)", async () => {
  const serverPath = path.join(__dirname, "..", "mcp-server", "index.cjs");
  const child = spawn("node", [serverPath], { stdio: ["pipe", "pipe", "inherit"] });

  try {
    const init = await rpc(child, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    assert.strictEqual(init.result.serverInfo.name, "kin-security");
    assert.strictEqual(init.result.serverInfo.version, "1.2.1");

    const tools = await rpc(child, { jsonrpc: "2.0", id: 2, method: "tools/list" });
    const names = tools.result.tools.map((t) => t.name).sort();
    assert.deepStrictEqual(names, ["kin_explain_cve", "kin_scan_code", "kin_triage_vulnerability"]);

    const scan = await rpc(child, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "kin_scan_code", arguments: { code: SQLI, filename: "auth.js" } },
    });
    const payload = JSON.parse(scan.result.content[0].text);
    assert.strictEqual(payload.engine, "kin-rule-engine (deterministic CWE patterns)");
    assert.strictEqual(payload.status, "RULES_MATCHED");
    assert.ok(payload.findings.some((f) => f.rule_id === "CWE-89"));
  } finally {
    child.kill();
  }
});
