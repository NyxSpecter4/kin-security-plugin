---
name: kin-security
description: Cybersecurity vulnerability triage, secure code review, and CVE lookup. Live KIN model triage when reachable; deterministic labeled rule-engine fallback; real NVD CVE data.
allowed-tools: kin_triage_vulnerability, kin_scan_code, kin_explain_cve
---

# KIN Cybersecurity Intelligence

This skill equips coding agents (Google Antigravity, Claude Code, Cursor, Codex) with cybersecurity capabilities backed by **`nyxspecter4/kin-sft-lora`** (3B Qwen2.5 + LoRA, Q4_K_M GGUF in-repo) served via the public **`nyxspecter4/kin-cybersec`** Space, plus **`nyxspecter4/kin-cyber-dpo-v2`** (1,637 DPO pairs).

## When to Activate

Activate whenever the task involves:
- Code security audits or pull-request reviews.
- CVE/advisory investigation (use `kin_explain_cve` for official NVD data).
- Triage of suspicious code blocks (SQL queries, shell executions, DOM rendering, path operations, SSRF vectors).
- Generating hardened remediations for identified vulnerabilities.

## Available Tools

### 1. `kin_triage_vulnerability`
Live KIN model triage (5-field brief). Params: `scenario_desc` (required), `user_payload`, `defense_goal`. If the model Space is unreachable or times out, it returns a **clearly-labeled rule-engine fallback** — check the `engine` field.

### 2. `kin_scan_code`
Instant deterministic CWE rule scan (offline, regex). Params: `code` (required), `filename`. Results are rule-engine output — label them accordingly; not model inference.

### 3. `kin_explain_cve`
Official NVD record: description, CVSS score/vector, weaknesses, references. Params: `cve_id` (required, e.g. `CVE-2023-4863`), `context` (informational). Never fabricate CVE facts; if NVD lookup fails, say so.

## Honesty Rules
1. **Always attribute the engine**: rule-engine results are regex-level; model results come from the live Space and are AI-analysis aids, not formal audit artifacts.
2. **Correct counts**: the dataset is `1,637` DPO pairs (not 1,635).
3. **No fake verification**: never claim a finding was "verified by the model" unless `engine` in the tool response says the model produced it.
4. Treat all KIN output as a starting point; validate critical findings with a replayable check (PoC, test, scanner) before acting.
