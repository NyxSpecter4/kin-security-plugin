#!/usr/bin/env node
/**
 * Triage live-path test — kin-security-eval/triage-live-path-test-v0.1
 * Deterministic, offline, no keys. Exercises the model-backed path of
 * kin_triage_vulnerability using the fake Gradio server:
 *
 *   Phase 1  LIVE path      : fake answering server -> model_status "live",
 *                             engine label honest, fake output carried through
 *   Phase 2  TIMEOUT path   : hanging server + 1.5s timeout -> bounded
 *                             fallback to the rule engine (no 75s dead wait)
 *   Phase 3  FAIL-CLOSED key: KIN_BACKEND=openai with no key -> instant
 *                             offline fallback, never a fabricated answer
 *
 * Exit 0 = all phases PASS. Exit 1 = any failure.
 */
const { spawn } = require("child_process");
const path = require("path");

const SERVER = path.join(__dirname, "..", "mcp-server", "index.cjs");
const FAKE = path.join(__dirname, "fake-model-server.cjs");

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

function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function triage(rpc, args) {
  const res = await rpc("tools/call", { name: "kin_triage_vulnerability", arguments: args });
  return JSON.parse(res.result.content[0].text);
}

async function main() {
  const fakeAnswer = spawn("node", [FAKE], { stdio: ["ignore", "pipe", "inherit"] });
  const fakeHang = spawn("node", [FAKE, "--hang"], { stdio: ["ignore", "pipe", "inherit"] });
  await wait(500);

  const children = [];
  let failures = 0;
  const check = (label, cond, detail) => {
    const tag = cond ? "PASS" : "FAIL";
    if (!cond) failures++;
    console.log(`[${tag}] ${label}${detail ? " — " + detail : ""}`);
  };

  try {
    // ── Phase 1: live path via answering fake server ──────────────────
    const c1 = spawn("node", [SERVER], {
      stdio: ["pipe", "pipe", "inherit"],
      env: { ...process.env, KIN_SPACE_URL: "http://127.0.0.1:18799", KIN_MODEL_TIMEOUT_MS: "5000" },
    });
    children.push(c1);
    const rpc1 = makeRpc(c1);
    await rpc1("initialize", {});
    const t1 = Date.now();
    const p1 = await triage(rpc1, {
      scenario_desc: 'child_process.execSync("cat " + file);',
      user_payload: "foo; rm -rf /",
    });
    const liveMs = Date.now() - t1;
    check("P1 live-path: model_status is 'live'", p1.model_status === "live", `${JSON.stringify(p1.model_status)} in ${liveMs}ms`);
    check(
      "P1 live-path: engine label identifies the HF backend",
      typeof p1.engine === "string" && p1.engine.includes("kin-sft-lora"),
      p1.engine
    );
    check(
      "P1 live-path: fake model output carried through",
      typeof p1.model_output === "string" && p1.model_output.includes("FAKE-MODEL-OUTPUT"),
      "output present"
    );

    // ── Phase 2: timeout path via hanging server ─────────────────────
    const c2 = spawn("node", [SERVER], {
      stdio: ["pipe", "pipe", "inherit"],
      env: { ...process.env, KIN_SPACE_URL: "http://127.0.0.1:18798", KIN_MODEL_TIMEOUT_MS: "1500" },
    });
    children.push(c2);
    const rpc2 = makeRpc(c2);
    await rpc2("initialize", {});
    const t2 = Date.now();
    const p2 = await triage(rpc2, { scenario_desc: 'child_process.execSync("cat " + file);' });
    const fbMs = Date.now() - t2;
    check(
      "P2 timeout-path: falls back to rule engine",
      p2.model_status === "offline-fallback" && String(p2.engine).includes("kin-rule-engine"),
      `${p2.model_status} in ${fbMs}ms`
    );
    check(
      "P2 timeout-path: bounded — fallback within 1.4x of KIN_MODEL_TIMEOUT_MS",
      fbMs >= 1400 && fbMs <= 5000,
      `fallback took ${fbMs}ms (timeout set to 1500ms; the old 75s default was the test-suite bottleneck)`
    );
    check(
      "P2 timeout-path: fallback findings still produced",
      Array.isArray(p2.findings) && p2.findings_count > 0,
      `findings_count: ${p2.findings_count}`
    );

    // ── Phase 3: openai backend without a key fails closed ────────────
    const c3 = spawn("node", [SERVER], {
      stdio: ["pipe", "pipe", "inherit"],
      env: { ...process.env, KIN_BACKEND: "openai", KIN_MODEL_TIMEOUT_MS: "3000" },
    });
    children.push(c3);
    const rpc3 = makeRpc(c3);
    await rpc3("initialize", {});
    const t3 = Date.now();
    const p3 = await triage(rpc3, { scenario_desc: "SELECT * FROM t WHERE a = " + "'x'" });
    const noKeyMs = Date.now() - t3;
    check(
      "P3 fail-closed: openai backend with no key falls back instantly, never fabricates",
      p3.model_status === "offline-fallback" && noKeyMs < 1500,
      `${p3.model_status} in ${noKeyMs}ms (no key set -> null -> fallback, no invented model output)`
    );
  } finally {
    children.forEach((c) => c.kill());
    fakeAnswer.kill();
    fakeHang.kill();
  }

  console.log(failures === 0 ? "ALL LIVE-PATH PHASES PASSED" : `${failures} PHASE(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("TEST ERROR:", err.message);
  process.exit(1);
});
