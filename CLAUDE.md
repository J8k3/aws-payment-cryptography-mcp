# CLAUDE.md

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

## Key Constraints and Non-obvious Behaviors

- APC is acquirer/processor scope only. Do not generate issuer functions (card personalization, IMK derivation).
- `translate_pin_data`: PAN must be identical in incoming and outgoing attributes (PCI PIN Req 3-3 — APC enforces this at the API level).
- PIN blocks must never appear in logs — mask/delete ISO 8583 field 52 before any write.
- Fixed TDEA keys for PIN have been prohibited since 1 January 2023 — treat as a hard stop.
- ISO Format 4 mandate is currently suspended in PCI PIN v3.1, but migration is strongly encouraged; recommend it for all new work.
- FF3-1 has known weaknesses under certain tweak conditions — prefer FF1 for new FPE deployments.
- TDES DUKPT uses 10-byte KSN (IPEK-based); AES DUKPT uses 12-byte KSN (IK-based). The terminology differs — do not conflate IPEK and IK.
- All API parameters and key constraints must be derived from the authoritative APC docs (URLs in `system_prompt.py`). Do not infer or extrapolate API behavior.
