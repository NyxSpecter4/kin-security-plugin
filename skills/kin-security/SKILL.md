---
name: kin-security
description: Authoritative cybersecurity vulnerability triage, secure code review, and CVE analysis powered by nyxspecter4/kin-sft-lora and the verified kin-cyber-dpo-v2 benchmark dataset.
allowed-tools: kin_triage_vulnerability, kin_scan_code, kin_explain_cve
---

# KIN Cybersecurity Intelligence

This skill equips coding agents (Google Antigravity, Claude Code, Cursor, Codex) with specialized cybersecurity capabilities powered by **`nyxspecter4/kin-sft-lora`** (fine-tuned 3B Qwen2.5 on 1,635+ verified DPO pairs from `nyxspecter4/kin-cyber-dpo-v2`).

## When to Activate

Activate this skill whenever the user or task involves:
- Performing code security audits or reviewing pull requests for vulnerabilities.
- Investigating CVEs, security advisories, or bug bounty reports.
- Triage of suspicious code blocks (SQL queries, shell executions, DOM rendering, path operations, SSRF vectors).
- Generating secure, hardened remediations for identified vulnerabilities.
- Validating whether a reported vulnerability is an exploitable true positive or a benign false positive.

## Available Tools

### 1. `kin_triage_vulnerability`
Performs an in-depth 5-field triage brief on a scenario, vulnerability, or attack vector.
- **Parameters**:
  - `scenario_desc` (required): Code snippet or vulnerability description.
  - `user_payload` (optional): Potential exploit string or PoC vector to evaluate.
  - `defense_goal` (optional): Hardening goal or architecture constraint.
- **Returns**: 5-field verified triage brief including severity, primary CWE, exploitability rating, false-positive analysis, and hardened fix.

### 2. `kin_scan_code`
Scans a source file or git diff for high-severity vulnerabilities, OWASP Top 10 flaws, and hardcoded secrets.
- **Parameters**:
  - `code` (required): Code content or diff hunk.
  - `filename` (optional): Filename or language context.
- **Returns**: Finding count, rule matches, and remediation instructions.

### 3. `kin_explain_cve`
Explains known CVE mechanics, root cause analysis, and remediation steps.
- **Parameters**:
  - `cve_id` (required): CVE identifier (e.g. `CVE-2023-4863`).
  - `context` (optional): Affected library or runtime environment.

## 5-Field Triage Standard

All KIN security outputs follow the strict 5-field verification rubric:
1. **Severity & Risk Level**: Critical, High, Medium, Low, or Informational.
2. **Primary CWE**: Root cause categorization (e.g., CWE-89, CWE-78, CWE-22).
3. **Exploitability Assessment**: Realistic evaluation of attack preconditions.
4. **False-Positive Evaluation**: Defense-in-depth context explaining why common SAST scanners may over-flag benign usage.
5. **Defensive Remediation**: Concrete, production-grade code fix with parameterized or sandboxed implementations.
