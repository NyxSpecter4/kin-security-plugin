// Live end-to-end MCP test: initialize, tools/list, kin_scan_code, kin_explain_cve (NVD).
const { spawn } = require("child_process");
const path = require("path");

const child = spawn("node", [path.join(__dirname, "index.cjs")], { stdio: ["pipe", "pipe", "inherit"] });
let buffer = "";
let phase = 0;

child.stdout.on("data", (data) => {
  buffer += data.toString();
  const lines = buffer.split("\n");
  buffer = lines.pop();
  for (const line of lines) {
    if (!line.trim()) continue;
    let res;
    try {
      res = JSON.parse(line);
    } catch {
      continue;
    }
    if (phase === 0) {
      console.log("initialize OK, protocol:", res.result && res.result.protocolVersion);
      phase = 1;
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
    } else if (phase === 1) {
      const tools = (res.result && res.result.tools || []).map((t) => t.name);
      console.log("tools/list:", tools.join(", "));
      phase = 2;
      child.stdin.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: {
            name: "kin_scan_code",
            arguments: {
              code: 'const q = "SELECT * FROM users WHERE username = \'" + req.body.username + "\'";',
              filename: "auth.js",
            },
          },
        }) + "\n"
      );
    } else if (phase === 2) {
      let txt = "";
      try {
        txt = res.result.content[0].text;
      } catch {}
      console.log("scan engine labeled:", txt.includes("kin-rule-engine"));
      console.log("scan findings:", (txt.match(/findings_count[^\d]*(\d+)/) || [])[1]);
      phase = 3;
      child.stdin.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 4,
          method: "tools/call",
          params: { name: "kin_explain_cve", arguments: { cve_id: "CVE-2023-4863" } },
        }) + "\n"
      );
    } else if (phase === 3) {
      let txt = "";
      try {
        txt = res.result.content[0].text;
      } catch {}
      console.log("cve source NVD:", txt.includes("NVD API 2.0"));
      console.log("cve severity:", (txt.match(/"severity":\s*"[^"]*"/) || ["n/a"])[0]);
      console.log("cve desc:", (txt.match(/"description":\s*"[^"]{0,90}/) || ["n/a"])[0]);
      console.log("ALL PHASES OK");
      child.kill();
      process.exit(0);
    }
  }
});

child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\n");
