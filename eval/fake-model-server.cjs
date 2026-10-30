#!/usr/bin/env node
/**
 * Fake Gradio model server — kin-security-eval/fake-model-server-v0.1
 * Minimal, deterministic, offline stand-in for the HF Space Gradio API so the
 * kin_triage_vulnerability LIVE path can be tested end-to-end without network,
 * keys, or model latency. Two modes on two ports:
 *
 *   answering mode (default): mimics the Gradio protocol
 *     POST /gradio_api/call/evaluate_threat   -> {"event_id":"fake-<n>"}
 *     GET  /gradio_api/call/evaluate_threat/<event_id> -> SSE complete event
 *
 *   hanging mode (--hang): accepts connections and never responds — used to
 *   prove the client-side timeout fires (fallback path) in bounded time.
 *
 * Usage:
 *   node eval/fake-model-server.cjs            (answering, port 8199 or PORT)
 *   node eval/fake-model-server.cjs --hang     (hanging,   port 8198 or HANG_PORT)
 */
const http = require("http");
const net = require("net");

const mode = process.argv.includes("--hang") ? "hang" : "answer";

if (mode === "hang") {
  const port = Number(process.env.FAKE_HANG_PORT || 18798);
  const server = net.createServer(() => {
    /* accept and never write — forces the client timeout path */
  });
  server.listen(port, "127.0.0.1", () => {
    console.log(`FAKE-SERVER(hang) listening on 127.0.0.1:${port} (accepts, never responds)`);
  });
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
} else {
  const port = Number(process.env.FAKE_PORT || 18799);
  let n = 0;
  const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/gradio_api/call/evaluate_threat") {
      n++;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ event_id: `fake-${n}` }));
      return;
    }
    const m = req.url.match(/^\/gradio_api\/call\/evaluate_threat\/(.+)$/);
    if (req.method === "GET" && m) {
      const payload = JSON.stringify([
        `FAKE-MODEL-OUTPUT (deterministic fixture): triage analysis for event ${m[1]}.`,
      ]);
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.end(`event: complete\ndata: ${payload}\n\n`);
      return;
    }
    res.writeHead(404);
    res.end("not found");
  });
  server.listen(port, "127.0.0.1", () => {
    console.log(`FAKE-SERVER(answer) listening on 127.0.0.1:${port}`);
  });
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
}
