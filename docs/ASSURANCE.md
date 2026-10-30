# KIN Security Assurance — V0.1 Product Contract

**One sentence:** KIN Security produces signed, content-addressed, independently verifiable evidence showing which AI-assisted code change was checked, which engine checked it, what was found, what policy decided, and whether subsequent remediation passed.

KIN remains KIN. There is no `attest` product; `attest` is a command:

```bash
kin-security scan      # observation -> normalized findings
kin-security check     # policy decision (exit 2 on BLOCK)
kin-security attest    # mint a signed KIN Receipt v1
kin-security verify    # independent Ed25519 verification (fail-closed)
kin-security state     # Athelgard evidence state for a receipt
kin-security keygen    # local Ed25519 keypair (.attest/keys)
kin-security demo      # the full lifecycle, on the SQLi fixture
```

---

## The architecture (one rule)

```
OBSERVATION  ──►  NORMALIZED FINDING  ──►  POLICY DECISION  ──►  SIGNED RECEIPT
(rule engine)      (deterministic           (explicit policy,        (content-addressed,
                    fingerprints)            recorded)                Ed25519)
```

A KIN-model opinion never silently becomes scanner evidence:

| source | kind | confidence |
| :-- | :-- | :-- |
| rule engine | `deterministic` | `observed` |
| KIN model | `model` | `advisory` |

## The receipt (schema `kin.security.receipt/v1`)

- **content-addressed** — `receipt_id` = `"01"` + first 30 hex of the evidence pre-image hash; the verifier recomputes it.
- **bound to input** — `subject.diff_sha256` is the sha256 of the exact bytes scanned.
- **chained** — `subject.prev_receipt` links a repair loop (blocked receipt → fixed rerun).
- **redacted** — findings carry coordinates + hashes, never raw source; the mint itself refuses if secret-shaped text or scanned source lines appear in the receipt.
- **independently verifiable** — `kin-security verify` recomputes hash, receipt_id, and signature from the receipt bytes alone, against any public key matching the recorded `key_id`.

### What a V1 receipt proves — and what it does not

A valid V1 receipt proves: **this exact evidence object was signed by this key.**

It does **not** prove reproducible scanning (rerun equivalence is a separate, future claim — do not let any UI say "reproducibly verified" until that harness exists and its results are recorded).

## Athelgard consumes receipt state (never scanner output)

```
NO_EVIDENCE (grey)  UNVERIFIED (amber)  BLOCKED (red)
OBSERVED (amber)    FIXED_RERUN (amber) VERIFIED (green)
```

- grey — no receipt at all
- red — security gate failed (valid receipt, policy BLOCK)
- amber — evidence exists but verification incomplete (warned/suppressed findings, or a rerun whose chain is pending)
- green — signed receipt + policy pass + zero findings, signature verified

An unverified receipt can never produce a green state. `kin-security state <receipt>` emits this mapping.

## Enforcement matrix (honest labels)

| Surface | Label |
| :-- | :-- |
| GitHub Action / CI workflow | **ENFORCEMENT CAPABLE** — `kin-attest.yml` gates on exit 2 and uploads the receipt as an artifact (proven by the workflow's own runs; `.github/workflows/kin-attest.yml`) |
| git pre-commit hook | **ENFORCEMENT CAPABLE** — `hooks/pre-commit` runs `check` on staged JS/TS; fail-closed if node is missing |
| MCP tool | **TOOL-LOCAL CONTROL** — returns labeled findings; the host decides what to do |
| Claude Code | **INTEGRATION UNDER VERSIONED TEST** — hook-based blocking is documented by Anthropic ([hooks reference](https://code.claude.com/docs/en/hooks)) but exit-code-2 blocking has known edge cases; promote to VERIFIED ENFORCEMENT only after a versioned harness passes on the installed version. NOT PROVEN HERE. |
| Cursor | **ADVISORY UNTIL PROVEN**. NOT PROVEN HERE. |

## Policy (`kin.security.policy/v1`)

- Built-in default (explicit, hashed into the receipt): **critical/high → block, medium → warn, low → pass**.
- File policies select by severity and/or CWE; first match wins; `medium` is configurable either way.
- **Suppressions** carry a reason and an expiry. **Expired suppressions are ignored, never applied** — and the receipt records that one was ignored.
- **Advisory findings cannot block (explicit V1 rule, structural):** findings with `confidence: "advisory"` (model-derived, `source.kind: "model"`) are structurally prohibited from producing a BLOCK outcome. They evaluate through the rules like any finding, but a rule outcome of `block` is capped to `warn`, and the cap is recorded on the decision (`advisory_block_capped: true`). Advisory findings can still yield `pass` (suppression or no-rule-matched) or `warn` — never `block`. Only deterministic, observed findings can block. Tested in `tests/policy.test.cjs`.
- `--policy` pointing at a missing/invalid file = hard error, no receipt, no PASS. Only the absence of `--policy` selects the built-in default, and the receipt always records which policy was used (name + sha256 + decisions).

## Known limitation KL-1 (recorded, not hidden)

The CWE-89 regex flags any line containing `SELECT … FROM … WHERE …` followed by `$`, `+`, a backtick, or `?` — which includes **inline SQL with placeholder markers** (`"… id = $1"`, `"… id = ?"`). The canonical parameterized-query form therefore still pattern-matches. This is why:

- findings carry `confidence: "observed"` (a pattern observation, not ground truth), and
- the lifecycle demo's repair uses a query-builder form (`db.select().from(users).where(eq(users.id, id))`), which is a genuine parameterized query and a clean rescan.

Pattern refinement is future work; V0.1 deliberately preserves the shipped engine byte-for-byte and lets the receipt attest what the scan actually observed.

## The acceptance boundary (proven by `node --test tests/*.test.cjs`)

| Gate | Test file |
| :-- | :-- |
| canonical serialization deterministic | `canonicalize.test.cjs` |
| valid receipt verifies / changed finding, policy result, commit, receipt_id, canonical_sha256 all fail / wrong public key fails / truncated + malformed fail | `sign-verify.test.cjs` |
| known secret absent from serialized receipt / no raw source lines / redaction gate refuses leaks / prompts stored as hashes only | `redact.test.cjs` |
| KIN engine normalized, deterministic kind, observed confidence / x10 identical findings / stable fingerprints / scan-order irrelevant | `normalize.test.cjs` |
| high → block / medium configurable / expired suppression ignored / suppression preserved in receipt / missing policy = explicit default, requested-but-missing = hard error / advisory findings structurally cannot block (V1 rule) | `policy.test.cjs` |
| scanner failure never produces a receipt or PASS / SQLi block → repair → pass → attest → verify VALID / Athelgard states / tamper control refused | `lifecycle.test.cjs` |
| legacy MCP contract preserved / shared engine single-source / server JSON-RPC regression | `mcp-regression.test.cjs` |

Full lifecycle, runnable by any stranger:

```bash
git clone https://github.com/NyxSpecter4/kin-security-plugin
cd kin-security-plugin
node --test tests/*.test.cjs     # the acceptance battery
node cli/index.cjs demo          # SCAN -> CHECK(BLOCK) -> REPAIR -> RESCAN -> ATTEST -> VERIFY
```

## Trust model (V1)

Local/developer Ed25519 keys, generated by `kin-security keygen`, stored in `.attest/keys/` (gitignored, never committed). Multiple public keys are supported from day one (`captain-kiran.pub`, `ci.pub`, …). This is **not** a PKI; organizational signing/trust anchors are V2.

The CI workflow signs with an **ephemeral per-run key** and uploads the public half next to the receipts — the receipt proves what was signed, not who the CI claims to be.

## The moat (recorded position)

A signature implementation is replicable. The defensible object is the **evidence graph**: agent action → exact code mutation (content-addressed) → independent observations → policy decision → remediation → verification receipt → Athelgard durable state. This repository implements the spine of that graph; Athelgard consumes its states.
