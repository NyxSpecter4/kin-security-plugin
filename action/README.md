# KIN Security PR Reviewer (`kin-security-action`)

[![Model on Hugging Face](https://img.shields.io/badge/Model-nyxspecter4%2Fkin--sft--lora-blue?logo=huggingface)](https://huggingface.co/nyxspecter4/kin-sft-lora)
[![Dataset on Hugging Face](https://img.shields.io/badge/Dataset-nyxspecter4%2Fkin--cyber--dpo--v2-green?logo=huggingface)](https://huggingface.co/datasets/nyxspecter4/kin-cyber-dpo-v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Automated pull-request cybersecurity review. Scans diffs with a **deterministic CWE rule engine** (instant, offline), and can optionally request a **KIN model brief** from the live [`nyxspecter4/kin-cybersec`](https://huggingface.co/spaces/nyxspecter4/kin-cybersec) Space. Every report states exactly which engine produced it.

---

## What It Does

1. On pull_request, fetches the diff and scans changed lines for CWE patterns: SQL injection, command injection, XSS, path traversal, SSRF, hardcoded secrets, JWT confusion.
2. Optionally requests a live KIN model brief (set `KIN_MODEL_BRIEF: 'true'`).
3. Posts a PR comment with findings, line numbers, remediations — and an explicit engine label.
4. Optionally fails CI when findings are present.

**Honesty by design**: the rule scan is regex-level, offline, and labeled as such. The model brief (when requested) is labeled as model output. No fabricated "verified by model" claims.

---

## Quickstart

Add `.github/workflows/security-scan.yml` to your repository:

```yaml
name: KIN Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  pull-requests: write
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run KIN Security Action
        uses: NyxSpecter4/kin-security-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-vulnerability: 'false'
        env:
          KIN_MODEL_BRIEF: 'true'   # optional: also request a live model brief
```

---

## Configuration Inputs

| Input | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `github-token` | Yes | `${{ github.token }}` | GitHub Token used to fetch PR diffs and post comments. |
| `severity-threshold` | No | `'High'` | Minimum severity level to report (`Critical`, `High`, `Medium`). |
| `fail-on-vulnerability` | No | `'false'` | If `'true'`, terminates the workflow with exit code 1 when flaws are detected. |

Environment variables:
* `KIN_MODEL_BRIEF` — `'true'` to request a live model brief (default `'false'`).
* `KIN_SPACE_URL` — override the Space base URL.
* `KIN_MODEL_TIMEOUT_MS` — model timeout (default `75000`).

---

## License

MIT © [NyxSpecter4](https://github.com/NyxSpecter4)
