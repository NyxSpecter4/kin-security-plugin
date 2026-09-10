#!/usr/bin/env node
/**
 * KIN Cybersecurity MCP Server
 * Tools: kin_triage_vulnerability, kin_scan_code, kin_explain_cve
 *
 * Honest layering:
 *  - kin_scan_code: deterministic CWE rule engine (instant, offline).
 *  - kin_triage_vulnerability: live KIN model call (nyxspecter4/kin-cybersec
 *    HF Space running kin-sft-lora Q4_K_M) with rule-engine fallback; every
 *    response states which engine actually produced it.
 *  - kin_explain_cve: real CVE data from the NVD API (2.0), never invented.
 */

const readline = require("readline");

const HF_SPACE_URL = process.env.KIN_SPACE_URL || "https://nyxspecter4-kin-cybersec.hf.space";
const MODEL_TIMEOUT_MS = Number(process.env.KIN_MODEL_TIMEOUT_MS || 75000);
const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

// ── Built-in deterministic CWE rule engine ──────────────────────────────
const SECURITY_RULES = [
  {
    id: "CWE-89",
    name: "SQL Injection",
    severity: "Critical",
    patterns: [
      /SELECT\s+.*FROM\s+.*WHERE\s+.*(\$|\+|`|\?)/i,
      /INSERT\s+INTO\s+.*VALUES\s+.*(\$|\+|`)/i,
      /DELETE\s+FROM\s+.*WHERE\s+.*(\$|\+|`)/i,
      /execute\s*\(\s*["'].*\+/i,
      /raw\s*\(\s*["'].*\+/i,
    ],
    explanation: "Unparameterized database query concatenates user input directly into a SQL statement, allowing query manipulation, authentication bypass, or data exfiltration.",
    remediation: 'Use parameterized queries or prepared statements: db.query("SELECT * FROM users WHERE id = $1", [userId]);',
  },
  {
    id: "CWE-78",
    name: "OS Command Injection",
    severity: "Critical",
    patterns: [
      /exec\s*\(\s*(`|.*\+)/,
      /execSync\s*\(\s*(`|.*\+)/,
      /spawn\s*\(\s*(`|.*\+)/,
      /system\s*\(\s*(`|.*\+)/,
      /child_process.*exec/,
    ],
    explanation: "System shell commands are constructed with unsanitized user inputs, permitting arbitrary command execution on the host machine.",
    remediation: 'Avoid shell execution. Use execFile or spawn with fixed argument arrays: execFile("command", [arg1, arg2]).',
  },
  {
    id: "CWE-79",
    name: "Cross-Site Scripting (XSS)",
    severity: "High",
    patterns: [
      /innerHTML\s*=/,
      /dangerouslySetInnerHTML/,
      /document\.write\s*\(/,
      /v-html/,
    ],
    explanation: "Untrusted user input is rendered into the DOM without sanitization, permitting attacker-controlled JavaScript execution in the client browser context.",
    remediation: "Use textContent or innerText, or sanitize HTML inputs with DOMPurify before DOM insertion.",
  },
  {
    id: "CWE-22",
    name: "Path Traversal / Arbitrary File Access",
    severity: "High",
    patterns: [
      /readFile.*(\+|req\.)/,
      /createReadStream.*(\+|req\.)/,
      /path\.join\(.*req\./,
      /fs\.existsSync\(.*\+/,
    ],
    explanation: 'Filesystem operations resolve paths derived from user input without canonicalization or directory sandboxing, allowing directory traversal with "../".',
    remediation: "Normalize paths with path.resolve() and verify the result begins with the intended root directory: if (!resolved.startsWith(ALLOWED_ROOT)) throw new Error('Access Denied');",
  },
  {
    id: "CWE-918",
    name: "Server-Side Request Forgery (SSRF)",
    severity: "High",
    patterns: [
      /fetch\s*\(\s*req\./,
      /axios\.(get|post)\s*\(\s*req\./,
      /http\.get\s*\(\s*req\./,
      /request\s*\(\s*req\./,
    ],
    explanation: "Server executes outbound HTTP requests to user-supplied URLs without IP restriction, enabling cloud metadata access (169.254.169.254) or intranet traversal.",
    remediation: "Enforce strict URL allowlists, resolve DNS records to verify non-private IP addresses, and reject requests to private IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254).",
  },
  {
    id: "CWE-798",
    name: "Hardcoded Credential / Secret",
    severity: "High",
    patterns: [
      /(?:password|passwd|api_key|apikey|secret|token)\s*[:=]\s*["'][A-Za-z0-9_-]{16,}["']/i,
      /ghp_[A-Za-z0-9]{36}/,
      /hf_[A-Za-z0-9]{34}/,
    ],
    explanation: "Sensitive credentials, API keys, or authentication tokens are hardcoded in source code, risking exposure in repositories and version control history.",
    remediation: "Move secrets to environment variables (.env) and secret management vaults (e.g. AWS Secrets Manager, GitHub Secrets).",
  },
  {
    id: "CWE-287",
    name: "Improper Authentication / JWT Key Confusion",
    severity: "Critical",
    patterns: [
      /algorithms\s*:\s*\[.*"none".*\]/i,
      /jwt\.verify\(.*,\s*false\)/i,
      /verify\(.*,\s*""\)/i,
    ],
    explanation: "JWT validation accepts unsigned tokens (alg: none) or disables cryptographic signature verification.",
    remediation: 'Pin the expected signing algorithm explicitly (e.g., algorithms: ["HS256"]) and reject unsigned tokens.',
  },
];

function ruleBasedScan(code) {
  const findings = [];
  for (const rule of SECURITY_RULES) {
    for (const pat of rule.patterns) {
      if (pat.test(code)) {
        findings.push({
          rule_id: rule.id,
          name: rule.name,
          severity: rule.severity,
          explanation: rule.explanation,
          remediation: rule.remediation,
        });
        break;
      }
    }
  }
  return findings;
}

// ── Live model call (HF Space Gradio API) ───────────────────────────────
async function queryModel(scenario, payload, defense) {
  try {
    const postRes = await fetch(`${HF_SPACE_URL}/gradio_api/call/evaluate_threat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: [scenario, payload, defense] }),
      signal: AbortSignal.timeout(MODEL_TIMEOUT_MS),
    });
    if (!postRes.ok) return null;
    const { event_id } = await postRes.json();
    if (!event_id) return null;

    const streamRes = await fetch(`${HF_SPACE_URL}/gradio_api/call/evaluate_threat/${event_id}`, {
      headers: { Accept: "text/event-stream" },
      signal: AbortSignal.timeout(MODEL_TIMEOUT_MS),
    });
    if (!streamRes.ok) return null;
    const text = await streamRes.text();
    // SSE complete event carries: data: [ "..." ]
    const m = text.match(/event:\s*complete\s*\r?\ndata:\s*(\[.*\])\s*$/m);
    if (m) {
      const parsed = JSON.parse(m[1]);
      if (parsed && parsed.length > 0 && typeof parsed[0] === "string" && parsed[0].trim()) {
        return parsed[0];
      }
    }
  } catch (err) {
    // model unreachable or timed out → caller decides fallback
  }
  return null;
}

// ── NVD CVE lookup (real data, no invented text) ────────────────────────
async function lookupCve(cveId) {
  try {
    const res = await fetch(`${NVD_URL}?cveId=${encodeURIComponent(cveId)}`, {
      signal: AbortSignal.timeout(15000),
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    const data = await res.json();
    const vuln = data && data.vulnerabilities && data.vulnerabilities[0];
    if (!vuln) return null;
    const c = vuln.cve;
    const desc =
      (c.descriptions || []).find((d) => d.lang === "en") ||
      (c.descriptions || [])[0];
    const cvss = c.metrics && (c.metrics.cvssMetricV31 || c.metrics.cvssMetricV30 || c.metrics.cvssMetricV2);
    const refs = (c.references || []).slice(0, 6).map((r) => r.url);
    return {
      cve_id: c.id,
      published: c.published || null,
      last_modified: c.lastModified || null,
      description: desc ? desc.value : null,
      severity: cvss ? (cvss[0].cvssData.baseSeverity || null) : null,
      base_score: cvss ? cvss[0].cvssData.baseScore : null,
      vector: cvss ? cvss[0].cvssData.vectorString : null,
      weaknesses: (c.weaknesses || []).map((w) => (w.description || []).map((d) => d.value).join(", ")),
      references: refs,
    };
  } catch (err) {
    return null;
  }
}

// ── Tool handlers ───────────────────────────────────────────────────────
async function handleTriageVulnerability(args) {
  const scenario = args.scenario_desc || "";
  const payload = args.user_payload || "";
  const defense = args.defense_goal || "";

  // Try the live model first.
  const modelBrief = await queryModel(scenario, payload, defense);

  if (modelBrief) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              engine: "kin-sft-lora (Q4_K_M) via nyxspecter4/kin-cybersec",
              model_status: "live",
              model_output: modelBrief,
              note: "Generated by the KIN model. Treat as an AI analysis aid; validate critical findings with a replayable check.",
            },
            null,
            2
          ),
        },
      ],
    };
  }

  // Fallback: deterministic rule scan, clearly labeled.
  const findings = ruleBasedScan(scenario);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            engine: "kin-rule-engine (deterministic CWE patterns)",
            model_status: "offline-fallback",
            note: "KIN model unreachable or timed out (KIN_SPACE_URL / KIN_MODEL_TIMEOUT_MS). This is a regex-level scan, NOT model analysis.",
            findings_count: findings.length,
            findings: findings,
            hardening_hint:
              findings.length === 0
                ? "No CWE patterns triggered. Review auth, input validation, and dependencies manually."
                : "Address each rule above with the given remediation, then re-scan.",
          },
          null,
          2
        ),
      },
    ],
  };
}

async function handleScanCode(args) {
  const code = args.code || "";
  const filename = args.filename || "unknown";
  const findings = ruleBasedScan(code);

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            engine: "kin-rule-engine (deterministic CWE patterns)",
            scanned_file: filename,
            lines_analyzed: code.split("\n").length,
            status: findings.length === 0 ? "NO_RULE_MATCHES" : "RULES_MATCHED",
            findings_count: findings.length,
            findings: findings,
            note: "Rule-engine scan only. Regex patterns flag likely CWE classes; they are not a substitute for a live model review or manual audit.",
          },
          null,
          2
        ),
      },
    ],
  };
}

async function handleExplainCve(args) {
  const cveId = (args.cve_id || "").toUpperCase().trim();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { error: "Invalid CVE identifier. Expected format: CVE-YYYY-NNNN." },
            null,
            2
          ),
        },
      ],
    };
  }
  const info = await lookupCve(cveId);
  if (!info) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              cve_id: cveId,
              error: "NVD lookup failed or CVE not found (network/rate-limit or invalid id).",
            },
            null,
            2
          ),
        },
      ],
    };
  }
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            cve_id: info.cve_id,
            published: info.published,
            last_modified: info.last_modified,
            severity: info.severity,
            base_score: info.base_score,
            vector: info.vector,
            description: info.description,
            weaknesses: info.weaknesses,
            references: info.references,
            source: "NVD API 2.0 (official CVE data)",
          },
          null,
          2
        ),
      },
    ],
  };
}

// ── MCP JSON-RPC loop ───────────────────────────────────────────────────
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

rl.on("line", async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let req;
  try {
    req = JSON.parse(trimmed);
  } catch (err) {
    return;
  }
  const { id, method, params } = req;

  if (method === "initialize") {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "kin-security", version: "1.1.0" },
      },
    });
    return;
  }
  if (method === "notifications/initialized") return;

  if (method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        tools: [
          {
            name: "kin_triage_vulnerability",
            description: "Triage a code snippet or vulnerability report. Uses the live KIN model (nyxspecter4/kin-cybersec / kin-sft-lora) when reachable; falls back to a clearly-labeled deterministic CWE rule scan when the model is offline or times out.",
            inputSchema: {
              type: "object",
              properties: {
                scenario_desc: { type: "string", description: "Target code or scenario description to triage" },
                user_payload: { type: "string", description: "Optional attack payload or proof of concept to evaluate" },
                defense_goal: { type: "string", description: "Hardening requirements or defense goal" },
              },
              required: ["scenario_desc"],
            },
          },
          {
            name: "kin_scan_code",
            description: "Instant deterministic CWE rule scan of source code or a git diff (SQLi, command injection, XSS, path traversal, SSRF, secrets, JWT confusion). Regex-level; results are labeled as rule-engine output, not model analysis.",
            inputSchema: {
              type: "object",
              properties: {
                code: { type: "string", description: "Source code or git diff to scan" },
                filename: { type: "string", description: "Filename or language context" },
              },
              required: ["code"],
            },
          },
          {
            name: "kin_explain_cve",
            description: "Fetch a CVE's official record from the NVD API 2.0: description, CVSS score/vector, weaknesses, references. Never fabricates CVE facts.",
            inputSchema: {
              type: "object",
              properties: {
                cve_id: { type: "string", description: "CVE identifier (e.g. CVE-2023-4863)" },
                context: { type: "string", description: "Optional note (not sent to NVD; informational only)" },
              },
              required: ["cve_id"],
            },
          },
        ],
      },
    });
    return;
  }

  if (method === "tools/call") {
    const { name, arguments: args } = params || {};
    let result;
    if (name === "kin_triage_vulnerability") result = await handleTriageVulnerability(args || {});
    else if (name === "kin_scan_code") result = await handleScanCode(args || {});
    else if (name === "kin_explain_cve") result = await handleExplainCve(args || {});
    else {
      send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Unknown tool: ${name}` } });
      return;
    }
    send({ jsonrpc: "2.0", id, result });
    return;
  }

  if (id !== undefined) {
    send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
  }
});
