# KIN Security Eval — Rule Engine Baseline Harness

`kin-security-eval/harness-v0.1` — a zero-dependency evaluation harness that drives the **real MCP server artifact** (`mcp-server/index.cjs`) over JSON-RPC, exactly as a client would. No source changes to the server; no network; deterministic.

## Run

```
npm run test:eval        # or: node eval/harness.cjs
```

## Category definitions (categories-v0.1)

Ground truth is author-labeled in `cases.json`. A version bump (v0.2) is required for any category-definition change — never a silent edit.

| Category | Content | Ground truth | Finding means |
| --- | --- | --- | --- |
| `valid` | Real vulnerability of a rule-covered class | vulnerable | All `expected_rule_ids` must fire (TP). A miss is a false negative — violation. |
| `clean` | No security relevance | safe | Any finding is a false positive — violation. |
| `adversarial` | Benign content that *pattern-matches* (comments, docs, changelogs, test markers) | safe | Any finding is a false positive — violation. Measures resistance to surface-text fooling. |
| `contradictory` | Code that matches a pattern but is semantically safe (parameterized query, sanitized DOM insert) | safe | A finding is a *designed* false positive — documents over-flagging classes. |
| `missing` | Real vulnerability of a rule-uncovered class (CWE-502, CWE-338, CWE-601…) | vulnerable | An expected miss = a recorded coverage gap (feeds the rules backlog). A hit is an anomaly. |
| `invalid` | Malformed input (empty, whitespace, null) | n/a | Must not crash; must return valid JSON. |

## Metrics

TP/FP/FN/TN at case level; precision = TP/(TP+FP); recall counts known coverage gaps in the denominator as false negatives (they are misses). Per-case wall-clock timing and case counts are recorded in `baseline-report.json`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Harness integrity OK **and** no ground-truth violations |
| 1 | Ground-truth violations found — **expected RED at baseline** (the adversarial/contradictory cases document measured false-positive classes; future rule improvements flip them green) |
| 2 | Selftest failed — the comparator could not detect a planted violation; the harness is decoration |
| 3 | Execution error |

## Instrument law

The harness self-tests before every run: it plants a fabricated finding on a ground-truth-negative case and requires the comparator to flag it. If the comparator cannot fail, its passes mean nothing (exit 2). Same law as every other Athelgard-family gate.

## Honest limitations

- Ground truth is author-labeled v0.1 — no independent review yet (receipt class: BUILDER).
- This case set is the **development set**; a held-out split ships with the backend-abstraction work.
- The rule engine is regex-based and JS-focused; `missing` cases deliberately document blind spots.
- `BASELINE-RECEIPT-2026-10-29.json` records the pre-harness measured baseline (test-suite timing, model latency vs timeout, initial FP probes). Status labels per the estate protocol throughout.
