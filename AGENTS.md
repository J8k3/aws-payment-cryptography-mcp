# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

This is an MCP server + Claude agent template that connects Claude to AWS Payment Cryptography (APC) via the Model Context Protocol. It targets acquirer/processor use cases — migrating from physical HSMs (Thales payShield, Atalla, Futurex) to APC's managed cloud HSM service. Issuer use cases (card personalization, IMK/CMK derivation) are explicitly out of scope.

## Setup and Running

```bash
pip install -e .          # installs apc-agent entry point
apc-agent                 # starts MCP server over stdio
```

AWS credentials are consumed via the standard boto3 credential chain (IAM role, `~/.aws/credentials`, environment variables). Set `AWS_REGION` — the MCP config in `.claude/settings.json` defaults to `us-east-1`.

The `.claude/settings.json` already registers the MCP server for Claude Code:
```json
{ "mcpServers": { "apc-agent": { "command": "apc-agent", "env": { "AWS_REGION": "us-east-1" } } } }
```

## Testing

```bash
pytest                          # run all tests
pytest tests/test_compliance.py # run a single file
```

Test dependencies: `pytest`, `pytest-asyncio`, `moto[payment-cryptography]` (for mocking APC). Defined in `pyproject.toml` under `[tool.hatch.envs.default]`.

## Architecture

```
src/apc_agent/
├── server.py          — FastMCP server; registers all tool groups; entry point
├── control_plane.py   — Key lifecycle tools (boto3: 'payment-cryptography')
├── data_plane.py      — Cryptographic operation tools (boto3: 'payment-cryptography-data')
├── hsm_tools.py       — HSM legacy code analysis tools (R8 — source analysis only)
├── hsm_analysis.py    — HSM command registry: Futurex + Thales patterns + regex detectors
├── system_prompt.py   — Agent domain knowledge injected as MCP instructions
└── compliance.py      — PCI guard-rail logic: prohibited algorithms, legacy constructs, key usage registry
```

**Two boto3 clients, strict boundary:**
- `payment-cryptography` — control plane (key lifecycle only)
- `payment-cryptography-data` — data plane (crypto operations only)

Tools are registered by calling `register_*_tools(mcp: FastMCP)` functions. Each function closes over a `client()` factory and decorates inner functions with `@mcp.tool()`. The `FastMCP` instance is constructed once in `server.py` with `instructions=SYSTEM_PROMPT`.

**Compliance enforcement** runs in `compliance.py` before boto3 calls:
- `PROHIBITED_ALGORITHMS` — hard stops (single DES, RSA-1024, 2-key TDES)
- `LEGACY_CONSTRUCTS` — warnings that trigger the Legacy Constraint Protocol (Format 0, CBC-MAC, TDES DUKPT, etc.)
- `KEY_USAGE_REGISTRY` — maps TR-31 usage codes to allowed APC operations; mismatch = hard stop
- `PIN_FORMAT_TRANSLATION_MATRIX` — encodes PCI PIN Req 3-3 legal translation pairs

**HSM analysis (R8)** is source-code-only. `hsm_analysis.py` holds the command registry and regex patterns. `hsm_tools.py` exposes them as MCP tools. Current coverage: Futurex (authoritative), Thales International (reference quality), Atalla (not available). Do not extend R8 to live traffic interception.

## Session Start

- At the start of a session, sync with `origin/master` before doing substantive work.
- Preferred command: `git pull --rebase origin master`
- Only do this automatically when the worktree is clean. If local changes are already present, inspect before rebasing.

**Flush pending KB contributions before doing other work:**

```bash
gh issue list --repo J8k3/aws-payment-cryptography-mcp --label kb-contribution --state open
```

For each open issue: read the `Target File` and `Content to Add` fields, apply the change to the relevant file, commit (following Commit Scope rules), and close the issue referencing the commit hash:

```bash
gh issue close <number> --comment "Applied in <commit-hash>."
```

Do not defer pending contributions to the end of the session.

## Commit Scope

- Keep commits small and reviewable by default.
- Prefer one commit per logical change — a single coherent unit a reviewer can evaluate independently.
- Group related changes (e.g., a new feature + its test + the knowledge-base entry it required) into one commit when they can't be evaluated independently.
- Prefer squash or amend for iterative follow-ups — if a second commit only fixes or extends the immediately preceding one, squash rather than leaving noise in the log.
- Do not split a change just to make it look smaller; split when a reviewer would genuinely benefit from evaluating the pieces independently.
- When CI flags a lint or test failure after a push, fix locally and **amend or squash into the failing commit** (using `git push --force-with-lease`) rather than adding a new fix commit on top.

## Knowledge Contribution (Standing Instruction)

When working in this repo or in the CyberChef payments repo, any new domain knowledge discovered — a PCI rule, an HSM command mapping, an APC API constraint, an algorithm edge case — must be written back into the relevant source file **in the same commit** as the code that revealed it:

| Discovered in | Write it to |
|---|---|
| Payment algorithm research | `payment-knowledge-base.md` |
| HSM command analysis | `hsm_analysis.py` (command registry) |
| PCI compliance rule | `compliance.py` (enforcement logic) |
| APC API constraint or gap | `AGENTS.md` → Key Constraints section, and open a GitHub issue if actionable |
| Proxy handler completed in apc-hsm-proxy | `hsm_tools.py` → `_PROXY_HANDLERS` (see Proxy Handler Wiring section) |

Do not defer knowledge updates. If the session ends without the relevant file being updated, the knowledge is lost.

**Cross-repo:** If a gap or finding also affects the CyberChef payments fork, file a GitHub issue at `J8k3/CyberChef` capturing what was learned and what needs to change there.

## After Every Code Change

Run both before reporting work done:

```bash
python -m ruff check src/ tests/
python -m pytest tests/ -q
```

Fix every ruff violation. All tests must pass. If a test catches a new bug, fix the bug — do not adjust the test to pass.

## Cross-Cutting Consistency Rules

These are non-obvious invariants that file-by-file review will miss. Apply them on every code change, not just when the directly edited code seems related.

**Generate/verify symmetry** — every compliance guard on a `generate_X` operation must have an identical guard on the corresponding `verify_X`. If `generate_pin_data` blocks ISO_FORMAT_0, `verify_pin_data` must also block it. Same applies to `generate_mac`/`verify_mac` and any future paired operations. Missing a verify-side guard silently allows the prohibited construct through.

**Exception handling uniformity** — all boto3 call sites use `_call()`. Never add a raw `client().method()` call. When adding a new tool, use `_call(client().method_name, **params)` — not `client().method_name(**params)`.

**Compliance guard → test parity** — every new compliance guard must have a test that fires the guard (no AWS call) and a test that confirms the clean path reaches the AWS layer. A guard without a test will regress silently.

**Docstring trigger sentence** — every `@mcp.tool()` must start its docstring with a "Call this when..." sentence describing the trigger condition. Claude Code uses this for tool selection; missing triggers degrade usability.

## Proxy Repo — Hands Off

`W:\apc-hsm-proxy` is owned by a separate session. Never read, edit, or touch any file under that path.

## Proxy Handler Wiring

`_PROXY_HANDLERS` in `src/apc_agent/hsm_tools.py` is the MCP server's registry of which proxy handlers exist. It is the source of truth for the `handler_exists` field returned by `hsm_analyze_discovery_log`.

**When a handler is completed in apc-hsm-proxy, update `_PROXY_HANDLERS` in this repo in the same commit.** Until that update is pushed, `hsm_analyze_discovery_log` will report `handler_exists: false` for that command even though the handler exists — misleading any session that calls the tool.

The two-repo update contract:

| Event | Update here |
|---|---|
| New command discovered in proxy discovery log | Add `HsmCommand` entry to `hsm_analysis.py` (`ALL_COMMANDS`) |
| New proxy handler completed in `apc-hsm-proxy` | Add command code to `_PROXY_HANDLERS` in `hsm_tools.py` |
| Command found to be unsupported by APC | Add `apc_operation=None, apc_key_type=None` entry with migration note in `hsm_analysis.py` |

**Consistency test:** `TestProxyHandlersConsistency` in `tests/test_hsm_tools.py` verifies that every code in `_PROXY_HANDLERS` exists in `ALL_COMMANDS`. It catches codes added to `_PROXY_HANDLERS` before their `HsmCommand` entry is written. Run it after any change to either structure.

## Pre-commit Checklist (Tool Changes)

Before committing any new or changed MCP tool, verify all of the following are in the same commit:

- If the tool exposes new domain knowledge: `payment-knowledge-base.md` updated
- If the tool detects a new HSM command: `hsm_analysis.py` updated
- If the tool enforces a new compliance rule: `compliance.py` updated and tested
- If a proxy handler was completed: `_PROXY_HANDLERS` in `hsm_tools.py` updated
- Ruff clean (`ruff check src/ tests/`)
- Tests passing (`pytest`)
- Tool docstring has a "Call this when..." trigger sentence

Do not commit the tool and defer the knowledge or test update to a follow-up.

## Critical Behavioral Rules

**PCI compliance is a hard constraint, not a preference.** Before calling any boto3 API, tools check `compliance.py`. Hard stops return an error dict — they never call boto3. Legacy construct warnings return a `confirmation_required` field and do not proceed until the user explicitly confirms.

**Legacy Constraint Protocol** — when a user needs a deprecated construct because a downstream system forces it:
1. Explain the modern alternative and why it is preferred
2. Ask: "Have you confirmed with [downstream party] that [modern alternative] is not supported?"
3. Notify: a PCI exception or QSA-documented compensating control may be required
4. Implement correctly only after confirmation
5. Generate a code comment documenting the constraint
6. Flag for future review

**Default happy path** (acquirer): AES DUKPT → ISO Format 4 PIN blocks → `translate_pin_data` → ZPK (AES P0 key) → CMAC (M6) on ISO 8583 field 64. TR-34 for KEK establishment, TR-31/X9.143 for subsequent symmetric key transport.

**Key type immutability**: A key's TR-31 usage code is set at creation and cannot change. Always validate key type against intended operation using `check_key_operation_compatibility` before generating code. APC enforces this at the API level — mismatches will be rejected.

**AES KCV**: Must use CMAC, never ANSI_X9_24 (ECB-zeros method). This is enforced in `create_key`.

## APC Data Plane Capability Catalog

`aws-payment-cryptography-data-plane-use-cases.json` (repo root) is the authoritative source of truth for APC data plane capabilities. It was generated from the official AWS Payment Cryptography Data Plane API Reference (API Version 2022-02-03) and captures all 14 operations, all documented union branches, all enum values, and documented compatibility rules.

**Use it for:**
- Verifying which fields are required vs. optional before implementing or changing a tool
- Checking which key algorithms are supported for a given operation
- Understanding documented inconsistencies (e.g., `VerifyPinData` prose vs. valid-values list for `PinBlockFormat`)
- Determining which operations support dynamic keys (`WrappedKey`) or ECDH

**Do not** infer API behavior from naming conventions or the operation list alone — always cross-check against this catalog first.

## Key Constraints and Non-obvious Behaviors

- APC is acquirer/processor scope only. Do not generate issuer functions (card personalization, IMK derivation).
- `translate_pin_data`: PAN must be identical in incoming and outgoing attributes (PCI PIN Req 3-3 — APC enforces this at the API level).
- PIN blocks must never appear in logs — mask/delete ISO 8583 field 52 before any write.
- Fixed TDEA keys for PIN have been prohibited since 1 January 2023 — treat as a hard stop.
- ISO Format 4 mandate is currently suspended in PCI PIN v3.1, but migration is strongly encouraged; recommend it for all new work.
- FF3-1 has known weaknesses under certain tweak conditions — prefer FF1 for new FPE deployments.
- TDES DUKPT uses 10-byte KSN (IPEK-based); AES DUKPT uses 12-byte KSN (IK-based). The terminology differs — do not conflate IPEK and IK.
- All API parameters and key constraints must be derived from the authoritative APC docs (URLs in `system_prompt.py`). Do not infer or extrapolate API behavior.
- **KU/KY issuer script MAC modes 1-4 require `generate_mac_emv_pin_change`, not `generate_mac`.** Mode '0' (MAC-only) maps to `generate_mac` with an MK-SMI key. Modes 1-4 add script confidentiality and/or PIN change — APC decomposes these into a distinct operation requiring two key ARNs (MK-SMI + MK-SMC) and a pre-translated PIN block. Changing `generate_mac` parameters cannot implement modes 1-4; the entire call path must switch to `generate_mac_emv_pin_change`.
- **APC `generate_mac`/`verify_mac` are stateless — continuation modes are unsupported.** Thales MU/MW/MQ/MS commands support modes '1' (first block), '2' (intermediate), '3' (final) that hold partial CBC state in the HSM between calls. APC exposes no session handle; each call is independent. Callers using continuation modes must concatenate all data blocks into a single payload and call once with mode '0'.
