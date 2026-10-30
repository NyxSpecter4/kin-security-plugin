# KIN Cybersecurity Plugin (`kin-security-plugin`)

[![Model on Hugging Face](https://img.shields.io/badge/Model-nyxspecter4%2Fkin--cybersecurity--3b-blue?logo=huggingface)](https://huggingface.co/nyxspecter4/kin-cybersecurity-3b)
[![Dataset on Hugging Face](https://img.shields.io/badge/Dataset-nyxspecter4%2Fkin--cyber--dpo--v2-green?logo=huggingface)](https://huggingface.co/datasets/nyxspecter4/kin-cyber-dpo-v2)
[![Space Demo](https://img.shields.io/badge/Space-Live%20Demo-orange?logo=huggingface)](https://huggingface.co/spaces/nyxspecter4/kin-cybersec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Verification-first security tools for AI coding agents.**

A multi-agent cybersecurity triage, vulnerability verification, and code auditing plugin for **Google Antigravity**, **Claude Code**, **Cursor**, and **Codex**, powered by the KIN verification translator model.

---

## KIN Security Assurance — new in v1.2.0, claim-contract corrected in v1.2.1

The plugin now produces **signed, content-addressed, independently verifiable evidence** showing which code change was checked, which engine checked it, what was found, what policy decided, and whether remediation passed:

```bash
kin-security scan <file>                    # normalized findings (deterministic fingerprints)
kin-security check <file> [--policy p.json] # policy decision; exit 2 on BLOCK
kin-security attest <file> --key captain-kiran [--policy p.json] [--out receipt.json]
kin-security verify <receipt.json>          # independent Ed25519 verification
kin-security state <receipt.json>           # Athelgard evidence state
kin-security keygen --name captain-kiran   # local Ed25519 keypair (.attest/keys/)
kin-security demo                           # SQLi block -> repair -> pass -> signed -> verified
```

The full contract — receipt schema, claim discipline, enforcement matrix, trust model, and the known-limitation record — lives in [docs/ASSURANCE.md](docs/ASSURANCE.md).

**Claim discipline:** a valid receipt proves *this exact evidence object was signed by this key*. It does not claim reproducible scanning (yet). Receipts are content-addressed, bound to the scanned bytes, redacted (coordinates + hashes, never raw source or secrets), and independently verifiable against any matching public key.

**CI gate (honest labels):** `.github/workflows/kin-attest.yml` runs the acceptance battery — **in this repository, the acceptance battery is the merge gate**. Attestation runs in **report mode**: every JS/TS file is attested with an ephemeral per-run key and the receipts + public key are uploaded as workflow artifacts, but BLOCK receipts do not fail this repo's CI, because this repository is deliberately full of vulnerable fixtures. Product-repository hard enforcement is one change away: remove the report-mode override and make BLOCK terminal — then merge eligibility follows the receipt. `hooks/pre-commit` provides that hard gate locally today.

---

## What a Buyer Receives

- MIT-licensed MCP server that any agent can call today.
- Deterministic offline CWE rule engine (10 patterns: SQLi, command injection, XSS, path traversal, SSRF, secrets, JWT confusion, prototype pollution, open redirect, unsafe deserialization).
- Live KIN model triage via public Hugging Face Space (with clear offline fallback).
- Official NVD CVE lookups — never hallucinated CVE data.
- Host manifests for the major coding-agent platforms.
- **KIN Security Assurance**: policy engine, signed KIN Receipts (Ed25519), independent verifier, redaction invariants, and a 50-test acceptance battery (`node --test tests/*.test.cjs`).
- Passing end-to-end tests (MCP protocol + NVD + assurance battery).

**Important licensing note:** The plugin code is MIT. The underlying KIN model (nyxspecter4/kin-cybersecurity-3b) inherits the Qwen Research License (non-commercial). Commercial use of the model requires a separate license from Alibaba Cloud. The rule engine and CVE tool work fully offline without the model.

---

## Features

- **Live Model Triage**: `kin_triage_vulnerability` calls the KIN model through the public Space when reachable.
- **Deterministic Rule Scan**: `kin_scan_code` — instant offline CWE pattern scan. Clearly labeled as rule-engine results.
- **Real CVE Data**: `kin_explain_cve` fetches official NVD records.
- **Multi-Host Compatibility**: Manifests for Antigravity, Claude Code, Cursor, and Codex.
- **Honest Fallback**: If the model is unreachable, triage falls back to the rule engine and says so.
- **Signed Evidence**: `kin-security attest/verify` — content-addressed Ed25519 receipts bound to the exact scanned bytes; findings are coordinates + hashes, never raw code; the mint refuses to sign anything that leaks source or secrets.

---

## Commercial Offerings

### 1. Open-Source Plugin (this repo) — Free
Full MCP server + rule engine + NVD tool + Assurance CLI (scan / check / attest / verify). Install today.

### 2. AI Agent Reality Check — $99 Pilot
Independent verification of one authorized text-based agent or chatbot.
- Five agreed tests (up to two runs each)
- Expected-vs-observed evidence table
- PASS / FAIL / UNPROVEN findings
- Three prioritized recommendations
- Five-day turnaround, one revision

Contact: contact@bountywarz.com

### 3. Enterprise / Hosted KIN (custom)
Private model endpoint, expanded rule packs, audit trails, and integration support. Pricing on request.

---

## Installation

### 1. Google Antigravity
Place in your global plugin directory:
```bash
~/.gemini/config/plugins/kin-security
```

### 2. Claude Code
```
/plugin install NyxSpecter4/kin-security-plugin
```

### 3. Cursor
```
/add-plugin https://github.com/NyxSpecter4/kin-security-plugin
```

### 4. Custom MCP Client
Add to your `mcp.json`:
```json
{
  "mcpServers": {
    "kin-security": {
      "command": "node",
      "args": ["path/to/kin-security-plugin/mcp-server/index.cjs"]
    }
  }
}
```

---

## Tools Provided

| Tool | Parameters | Description |
| :-- | :-- | :--- |
| `kin_triage_vulnerability` | `scenario_desc`, `user_payload`, `defense_goal` | Live KIN model triage; labeled rule-engine fallback if the model is offline. |
| `kin_scan_code` | `code`, `filename` | Instant deterministic CWE rule scan (labeled as regex-level). |
| `kin_explain_cve` | `cve_id`, `context` | Official NVD record for a CVE. |

---

## Verification

```bash
node --test tests/*.test.cjs   # 50-test assurance battery (signatures, redaction, policy, lifecycle, MCP regression)
node mcp-server/test-client.cjs # legacy end-to-end MCP protocol test
node cli/index.cjs demo          # SCAN -> CHECK(BLOCK) -> REPAIR -> RESCAN(PASS) -> ATTEST -> VERIFY(VALID)
```

The assurance battery and demo pass on a clean Node 20+ environment (zero dependencies). The live test confirms NVD lookup and rule-engine labeling.

## Model Lineage
* **Canonical model**: [`nyxspecter4/kin-cybersecurity-3b`](https://huggingface.co/nyxspecter4/kin-cybersecurity-3b) (Qwen2.5-3B + LoRA SFT + DPO).
* **Dataset**: [`nyxspecter4/kin-cyber-dpo-v2`](https://huggingface.co/datasets/nyxspecter4/kin-cyber-dpo-v2).
* **Live endpoint**: [`nyxspecter4/kin-cybersec`](https://huggingface.co/spaces/nyxspecter4/kin-cybersec).

## Environment
* `KIN_SPACE_URL` — override the Space base URL.
* `KIN_MODEL_TIMEOUT_MS` — model call timeout (default 75000).
* `KIN_ATTEST_KEYS` — override the signing-keys directory (default `.attest/keys`).

---

Built at [BountyWarz](https://bountywarz.com) by Kinetigor.  
MIT © NyxSpecter4
