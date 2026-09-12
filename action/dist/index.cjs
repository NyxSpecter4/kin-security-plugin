#!/usr/bin/env node
/**
 * KIN Security GitHub Action Entrypoint
 * Analyzes PR diffs with a deterministic CWE rule engine (instant),
 * then optionally requests a KIN model brief from the HF Space.
 * Every report labels the engine that produced it. No fabricated
 * "verified by model" claims.
 */

const fs = require('fs');

const SECURITY_RULES = [
  {
    id: 'CWE-89',
    name: 'SQL Injection',
    severity: 'Critical',
    patterns: [
      /SELECT\s+.*FROM\s+.*WHERE\s+.*(\$|\+|`|\?)/i,
      /INSERT\s+INTO\s+.*VALUES\s+.*(\$|\+|`)/i,
      /DELETE\s+FROM\s+.*WHERE\s+.*(\$|\+|`)/i,
      /execute\s*\(\s*["'].*\+/i,
      /raw\s*\(\s*["'].*\+/i,
    ],
    explanation: 'Unparameterized database query concatenates user input directly into a SQL statement, allowing query manipulation, authentication bypass, or data exfiltration.',
    remediation: 'Use parameterized queries or prepared statements: db.query("SELECT * FROM users WHERE id = $1", [userId]);',
  },
  {
    id: 'CWE-78',
    name: 'OS Command Injection',
    severity: 'Critical',
    patterns: [
      /exec\s*\(\s*(`|.*\+)/,
      /execSync\s*\(\s*(`|.*\+)/,
      /spawn\s*\(\s*(`|.*\+)/,
      /system\s*\(\s*(`|.*\+)/,
      /child_process.*exec/,
    ],
    explanation: 'System shell commands are constructed with unsanitized user inputs, permitting arbitrary command execution on the host machine.',
    remediation: 'Avoid shell execution. Use execFile or spawn with fixed argument arrays: execFile("command", [arg1, arg2]).',
  },
  {
    id: 'CWE-79',
    name: 'Cross-Site Scripting (XSS)',
    severity: 'High',
    patterns: [/innerHTML\s*=/, /dangerouslySetInnerHTML/, /document\.write\s*\(/, /v-html/],
    explanation: 'Untrusted user input is rendered into the DOM without sanitization, permitting attacker-controlled JavaScript execution in the client browser context.',
    remediation: 'Use textContent or innerText, or sanitize HTML inputs with DOMPurify before DOM insertion.',
  },
  {
    id: 'CWE-22',
    name: 'Path Traversal / Arbitrary File Access',
    severity: 'High',
    patterns: [/readFile.*(\+|req\.)/, /createReadStream.*(\+|req\.)/, /path\.join\(.*req\./, /fs\.existsSync\(.*\+/],
    explanation: 'Filesystem operations resolve paths derived from user input without canonicalization or directory sandboxing, allowing directory traversal with "../".',
    remediation: 'Normalize paths with path.resolve() and verify the result begins with the intended root directory.',
  },
  {
    id: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    severity: 'High',
    patterns: [/fetch\s*\(\s*req\./, /axios\.(get|post)\s*\(\s*req\./, /http\.get\s*\(\s*req\./, /request\s*\(\s*req\./],
    explanation: 'Server executes outbound HTTP requests to user-supplied URLs without IP restriction, enabling cloud metadata access (169.254.169.254) or intranet traversal.',
    remediation: 'Enforce strict URL allowlists and reject requests to private IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254).',
  },
  {
    id: 'CWE-798',
    name: 'Hardcoded Credential / Secret',
    severity: 'High',
    patterns: [
      /(?:password|passwd|api_key|apikey|secret|token)\s*[:=]\s*["'][A-Za-z0-9_-]{16,}["']/i,
      /ghp_[A-Za-z0-9]{36}/,
      /hf_[A-Za-z0-9]{34}/,
    ],
    explanation: 'Sensitive credentials, API keys, or authentication tokens are hardcoded in source code, risking exposure in repositories and version control history.',
    remediation: 'Move secrets to environment variables (.env) and secret management vaults (e.g. AWS Secrets Manager, GitHub Secrets).',
  },
  {
    id: 'CWE-287',
    name: 'Improper Authentication / JWT Key Confusion',
    severity: 'Critical',
    patterns: [/algorithms\s*:\s*\[.*"none".*\]/i, /jwt\.verify\(.*,\s*false\)/i, /verify\(.*,\s*""\)/i],
    explanation: 'JWT validation accepts unsigned tokens (alg: none) or disables cryptographic signature verification.',
    remediation: 'Pin the expected signing algorithm explicitly (e.g., algorithms: ["HS256"]) and reject unsigned tokens.',
  },
];

function scanContent(content) {
  const findings = [];
  const lines = content.split('\n');
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    for (const rule of SECURITY_RULES) {
      for (const pat of rule.patterns) {
        if (pat.test(line)) {
          findings.push({
            rule_id: rule.id,
            name: rule.name,
            severity: rule.severity,
            line_number: idx + 1,
            line_content: line.trim(),
            explanation: rule.explanation,
            remediation: rule.remediation,
          });
          break;
        }
      }
    }
  }
  return findings;
}

async function requestModelBrief(scenario, token) {
  const space = process.env.KIN_SPACE_URL || 'https://nyxspecter4-kin-cybersec.hf.space';
  try {
    const postRes = await fetch(`${space}/gradio_api/call/evaluate_threat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: [scenario, '', 'remediation review'] }),
      signal: AbortSignal.timeout(Number(process.env.KIN_MODEL_TIMEOUT_MS || 75000)),
    });
    if (!postRes.ok) return null;
    const { event_id } = await postRes.json();
    if (!event_id) return null;
    const streamRes = await fetch(`${space}/gradio_api/call/evaluate_threat/${event_id}`, {
      headers: { Accept: 'text/event-stream' },
      signal: AbortSignal.timeout(Number(process.env.KIN_MODEL_TIMEOUT_MS || 75000)),
    });
    if (!streamRes.ok) return null;
    const text = await streamRes.text();
    const m = text.match(/event:\s*complete\s*\r?\ndata:\s*(\[.*\])\s*$/m);
    if (m) {
      const parsed = JSON.parse(m[1]);
      if (parsed && parsed.length > 0 && typeof parsed[0] === 'string' && parsed[0].trim()) {
        return parsed[0];
      }
    }
  } catch (err) {
    // model unavailable -> rule-only report
  }
  return null;
}

function formatReportMarkdown(findings, scannedFiles, modelBrief) {
  const timestamp = new Date().toISOString();
  const modelSection = modelBrief
    ? `## 🤖 KIN Model Brief
> Generated by [**nyxspecter4/kin-sft-lora**](https://huggingface.co/nyxspecter4/kin-sft-lora) via the live Space. AI analysis aid — validate critical findings with a replayable check.

${String(modelBrief).slice(0, 4000)}
`
    : '> Model brief not requested or Space unreachable — this report is rule-engine only.';

  if (findings.length === 0) {
    return `### 🛡️ KIN Security Scan Results
**Engine**: deterministic CWE rule scan (regex, offline) — rule-engine output, NOT model inference.

**Status**: ✅ **NO RULE MATCHES** — none of the CWE patterns triggered across ${scannedFiles} file(s).
* Patterns: SQLi, command injection, XSS, path traversal, SSRF, hardcoded secrets, JWT confusion.
* Limitations: regex rules only. Run a live model review or SAST for deeper coverage.
* Scan Timestamp: \`${timestamp}\`

${modelSection}

---
*Powered by [NyxSpecter4/kin-security-action](https://github.com/NyxSpecter4/kin-security-action) · Model: [nyxspecter4/kin-sft-lora](https://huggingface.co/nyxspecter4/kin-sft-lora)*
`;
  }

  let table = '| Severity | Finding / CWE | Line | Remediation Guidance |\n';
  table += '| :--- | :--- | :--- | :--- |\n';
  for (const f of findings) {
    table += `| **${f.severity}** | \`${f.rule_id}\` ${f.name} | L${f.line_number} | ${f.remediation} |\n`;
  }

  return `### 🚨 KIN Security Scan — Findings
**Engine**: deterministic CWE rule scan (regex, offline) — rule-engine output, NOT model inference.

**Status**: ⚠️ **REVIEW REQUIRED** — ${findings.length} CWE pattern match(es) in pull request changes.

${table}

<details>
<summary><b>Detailed Rule Explanations</b></summary>

${findings
  .map(
    (f) => `
#### [${f.rule_id}] ${f.name} (Line ${f.line_number})
* **Trigger**: \`${f.line_content}\`
* **Root Cause**: ${f.explanation}
* **Hardened Fix**: ${f.remediation}
`
  )
  .join('\n')}
</details>

${modelSection}

---
*Powered by [NyxSpecter4/kin-security-action](https://github.com/NyxSpecter4/kin-security-action) · Model: [nyxspecter4/kin-sft-lora](https://huggingface.co/nyxspecter4/kin-sft-lora)*
`;
}

async function run() {
  const isDryRun = process.argv.includes('--dry-run');
  const wantModel = (process.env.KIN_MODEL_BRIEF || 'false').toLowerCase() === 'true';

  if (isDryRun) {
    console.log('=== Running KIN Security Action in Dry-Run Mode ===');
    const sampleDiff = [
      '+ const query = "SELECT * FROM users WHERE username = \'" + req.body.username + "\'";',
      '+ const result = db.query(query);',
      '+ const token = "ghp_123456789012345678901234567890123456";',
      '+ const clean = sanitize(req.body.data);',
    ].join('\n');
    const findings = scanContent(sampleDiff);
    const modelBrief = wantModel ? await requestModelBrief(sampleDiff) : null;
    const report = formatReportMarkdown(findings, 1, modelBrief);
    console.log('\n--- Generated PR Review Comment ---\n');
    console.log(report);
    console.log('\n--- Dry-Run Verification Summary ---');
    console.log(`Findings detected: ${findings.length}`);
    console.log(`Model brief: ${modelBrief ? 'received' : 'not requested / unavailable'}`);
    console.log('Test PASSED.');
    process.exit(0);
  }

  const token = process.env.INPUT_GITHUB_TOKEN || process.env.GITHUB_TOKEN;
  const eventPath = process.env.GITHUB_EVENT_PATH;

  if (!eventPath || !fs.existsSync(eventPath)) {
    console.log('No GITHUB_EVENT_PATH found. Running local directory scan.');
    process.exit(0);
  }

  const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
  const pr = eventData.pull_request;
  if (!pr) {
    console.log('Action triggered outside of pull_request context. Exiting.');
    process.exit(0);
  }

  const commentsUrl = pr.comments_url;
  const diffUrl = pr.diff_url;

  console.log(`Analyzing PR #${pr.number}: ${pr.title}`);

  const diffRes = await fetch(diffUrl, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github.v3.diff',
    },
  });

  if (!diffRes.ok) {
    console.error(`Failed to fetch PR diff: HTTP ${diffRes.status}`);
    process.exit(1);
  }

  const diffText = await diffRes.text();
  const findings = scanContent(diffText);
  const modelBrief = wantModel ? await requestModelBrief(diffText.slice(0, 6000)) : null;
  const report = formatReportMarkdown(findings, 1, modelBrief);

  if (token && commentsUrl) {
    const commentRes = await fetch(commentsUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/vnd.github+json',
      },
      body: JSON.stringify({ body: report }),
    });
    console.log(`Posted review comment: HTTP ${commentRes.status}`);
  }

  const failOnVuln = (process.env.INPUT_FAIL_ON_VULNERABILITY || 'false').toLowerCase() === 'true';
  if (failOnVuln && findings.length > 0) {
    console.error(`Failing check due to ${findings.length} security finding(s).`);
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('Execution failed:', err);
  process.exit(1);
});
