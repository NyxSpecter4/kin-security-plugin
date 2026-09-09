# KIN Cybersecurity Plugin (`kin-security-plugin`)

[![Model on Hugging Face](https://img.shields.io/badge/Model-nyxspecter4%2Fkin--sft--lora-blue?logo=huggingface)](https://huggingface.co/nyxspecter4/kin-sft-lora)
[![Dataset on Hugging Face](https://img.shields.io/badge/Dataset-nyxspecter4%2Fkin--cyber--dpo--v2-green?logo=huggingface)](https://huggingface.co/datasets/nyxspecter4/kin-cyber-dpo-v2)
[![Space Demo](https://img.shields.io/badge/Space-Live%20Demo-orange?logo=huggingface)](https://huggingface.co/spaces/nyxspecter4/kin-cybersec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A multi-agent cybersecurity triage, vulnerability verification, and code auditing plugin for **Google Antigravity**, **Claude Code**, **Cursor**, and **Codex**. Powered by [`nyxspecter4/kin-sft-lora`](https://huggingface.co/nyxspecter4/kin-sft-lora).

---

## Features

- **5-Field Verified Triage**: Instant analysis of severity, CWE mapping, exploitability, false-positive risk, and AST-invariant defensive patches.
- **Multi-Host Compatibility**: Works out of the box with Antigravity, Claude Code, Cursor, and any MCP-compliant client.
- **Zero-Cloud-Cost Inference**: Connects directly to the live Hugging Face Space endpoint (`nyxspecter4/kin-cybersec`) with local heuristic fallback.
- **Local Ollama Support**: Works 100% offline when paired with `ollama run hf.co/nyxspecter4/kin-sft-lora`.

---

## Installation

### 1. Google Antigravity
The plugin is automatically discovered when placed in your global config:
```bash
# Global plugin directory
~/.gemini/config/plugins/kin-security
```

### 2. Claude Code
Install via plugin command:
```text
/plugin install NyxSpecter4/kin-security-plugin
```

### 3. Cursor
Add directly from Cursor command palette or settings:
```text
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
| `kin_triage_vulnerability` | `scenario_desc`, `user_payload`, `defense_goal` | Full 5-field triage brief for code or vulnerability reports. |
| `kin_scan_code` | `code`, `filename` | Rapid scan for OWASP Top 10 vulnerabilities and hardcoded secrets. |
| `kin_explain_cve` | `cve_id`, `context` | Technical breakdown of CVE mechanics and verified remediation. |

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
│   └── test-client.cjs       # End-to-end MCP test suite
├── skills/
│   └── kin-security/
│       └── SKILL.md          # Agent instructions & prompt engineering
└── README.md
```

## Model Lineage
* **Model**: [`nyxspecter4/kin-sft-lora`](https://huggingface.co/nyxspecter4/kin-sft-lora) (3B Qwen2.5 base with LoRA weights, 1,084+ downloads).
* **Dataset**: [`nyxspecter4/kin-cyber-dpo-v2`](https://huggingface.co/datasets/nyxspecter4/kin-cyber-dpo-v2) (1,635 DPO pairs).
* **Open LLM Leaderboard**: Evaluated via Hugging Face Open LLM Leaderboard.
