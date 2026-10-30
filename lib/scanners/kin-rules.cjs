/**
 * KIN Rule Engine — the canonical deterministic CWE scanner.
 *
 * EXTRACTED (v1.2.0) from mcp-server/index.cjs without behavior change:
 * the same SECURITY_RULES and the same ruleBasedScan() contract the MCP
 * server has shipped since v1.0. The MCP server and the Assurance Core
 * (cli/lib) both require this module so there is exactly ONE rule set.
 *
 * Contract of ruleBasedScan(code) -> findings[]:
 *   { rule_id, name, severity, explanation, remediation }
 * Severity values: "Critical" | "High" | "Medium" (title case, legacy).
 * One finding per rule (first matching pattern wins; `break` per rule).
 */

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
  {
    id: "CWE-1321",
    name: "Prototype Pollution",
    severity: "High",
    patterns: [
      /__proto__/,
      /constructor\s*\[\s*['"]prototype['"]\s*\]/,
      /Object\.assign\s*\(\s*{},\s*req\./,
    ],
    explanation: "Untrusted input is merged into object prototypes, potentially allowing property injection that alters application behavior or enables privilege escalation.",
    remediation: "Use Object.create(null) for dictionaries, freeze prototypes, or use libraries that protect against prototype pollution (e.g. lodash with safe merges).",
  },
  {
    id: "CWE-601",
    name: "Open Redirect",
    severity: "Medium",
    patterns: [
      /res\.redirect\s*\(\s*req\./,
      /location\s*=\s*req\./,
      /window\.location\s*=\s*req\./,
    ],
    explanation: "Application redirects users to attacker-controlled URLs, enabling phishing and credential theft via trusted domain.",
    remediation: "Validate redirect targets against an allowlist of relative paths or known domains before issuing redirects.",
  },
  {
    id: "CWE-502",
    name: "Deserialization of Untrusted Data",
    severity: "Critical",
    patterns: [
      /JSON\.parse\s*\(\s*req\./,
      /unserialize\s*\(/,
      /pickle\.loads/,
    ],
    explanation: "Untrusted data is deserialized without validation, potentially allowing remote code execution via crafted payloads.",
    remediation: "Avoid deserializing untrusted input. Use safe formats (JSON with schema validation) and never deserialize binary formats from untrusted sources.",
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

module.exports = { SECURITY_RULES, ruleBasedScan };
