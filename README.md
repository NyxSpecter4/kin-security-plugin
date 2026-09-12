# KIN Cybersecurity Plugin (`kin-security-plugin`)

[![Model on Hugging Face](https://img.shields.io/badge/Model-nyxspecter4%2Fkin--sft--lora-blue?logo=huggingface)](https://huggingface.co/nyxspecter4/kin-sft-lora)
[![Dataset on Hugging Face](https://img.shields.io/badge/Dataset-nyxspecter4%2Fkin--cyber--dpo--v2-green?logo=huggingface)](https://huggingface.co/datasets/nyxspecter4/kin-cyber-dpo-v2)
[![Space Demo](https://img.shields.io/badge/Space-Live%20Demo-orange?logo=huggingface)](https://huggingface.co/spaces/nyxspecter4/kin-cybersec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A multi-agent cybersecurity triage, vulnerability verification, and code auditing plugin for **Google Antigravity**, **Claude Code**, **Cursor**, and **Codex**, powered by [`nyxspecter4/kin-sft-lora`](https://huggingface.co/nyxspecter4/kin-sft-lora).

---

## Features

- **Live Model Triage**: `kin_triage_vulnerability` calls the KIN model (`kin-sft-lora` Q4_K_M) through the public [`nyxspecter4/kin-cybersec`](https://huggingface.co/spaces/nyxspecter4/kin-cybersec) Space when reachable.
- **Deterministic Rule Scan**: `kin_scan_code` runs an instant, offline CWE pattern scan (SQLi, command injection, XSS, path traversal, SSRF, secrets, JWT confusion). Output is clearly labeled as rule-engine results, not model analysis.
- **Real CVE Data**: `kin_explain_cve` fetches official NVD records (description, CVSS, weaknesses, references) — never invented CVE facts.
- **Multi-Host Compatibility**: Manifests for Antigravity, Claude Code, Cursor, and Codex; any MCP-compliant client via `mcp.json`.
- **Honest Fallback**: If the model is unreachable, triage falls back to the rule engine and says so in the response.

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

### 4. Custom MCP Client (Claude Desktop / Continue / Roo Code)
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
| :--- | :--- | :--- |
| `kin_triage_vulnerability` | `scenario_desc`, `user_payload`, `defense_goal` | Live KIN model triage; labeled rule-engine fallback if the model is offline. |
| `kin_scan_code` | `code`, `filename` | Instant deterministic CWE rule scan (labeled as regex-level). |
| `kin_explain_cve` | `cve_id`, `context` | Official NVD record for a CVE: description, CVSS, weaknesses, references. |

---

## Architecture

```
kin-security-plugin/
├── plugin.json               # Plugin metadata
├── mcp.json                  # MCP server registry
├── .antigravity-plugin       # Antigravity host manifest
├── .claude-plugin            # Claude Code host manifest
├── .cursor-plugin            # Cursor host manifest
├── .codex-plugin             # Codex host manifest
├── mcp-server/
│   ├── index.cjs             # JSON-RPC 2.0 stdio MCP server
│   ├── test-client.cjs       # MCP smoke test
│   └── live-test.cjs         # End-to-end test incl. NVD lookup
├── skills/
│   └── kin-security/
│       └── SKILL.md          # Agent instructions & prompt engineering
└── README.md
```

## Model Lineage
* **Model**: [`nyxspecter4/kin-sft-lora`](https://huggingface.co/nyxspecter4/kin-sft-lora) (3B Qwen2.5 + LoRA; Q4_K_M GGUF in-repo).
* **Dataset**: [`nyxspecter4/kin-cyber-dpo-v2`](https://huggingface.co/datasets/nyxspecter4/kin-cyber-dpo-v2) (1,637 DPO pairs; 5 viewer configs).
* **Live endpoint**: [`nyxspecter4/kin-cybersec`](https://huggingface.co/spaces/nyxspecter4/kin-cybersec) (CPU, Q4_K_M).

## Environment
* `KIN_SPACE_URL` — override the Space base URL (default: `https://nyxspecter4-kin-cybersec.hf.space`).
* `KIN_MODEL_TIMEOUT_MS` — model call timeout (default `75000`; free-tier cold starts can take 30-60s).

---

## From the Kinetigor engine room

Built at [BountyWarz](https://bountywarz.com) — the cyber-education platform behind this tool. More from the same studio: [kin-security-action](https://github.com/NyxSpecter4/kin-security-action) · [kin-security-plugin](https://github.com/NyxSpecter4/kin-security-plugin) · [monk-plugin](https://github.com/NyxSpecter4/monk-plugin) · [Kinetigor Desk](https://kinetigor.com).

## License

MIT © [NyxSpecter4](https://github.com/NyxSpecter4)

