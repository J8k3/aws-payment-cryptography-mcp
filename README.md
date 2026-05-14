# AWS Payment Cryptography Claude Agent Template

An MCP server that gives Claude direct access to [AWS Payment Cryptography (APC)](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html) — both the control plane (key lifecycle) and data plane (cryptographic operations). The intent is acquirer and processor use cases: migrating from physical HSMs (Thales payShield, Futurex KMES, Atalla) to APC's managed cloud HSM service, and building new payment cryptography integrations with an AI co-pilot that understands the domain.

Issuer functions — card personalization, IMK/CMK derivation, issuer script processing — are explicitly out of scope and the agent will refuse them.

This is a template, not a production system. It ships opinionated toward modern cryptography (AES DUKPT, ISO Format 4, CMAC, TR-34), with PCI PIN v3.1 compliance checks baked in as hard constraints.

---

## Setup

```bash
pip install -e .
apc-agent        # starts the MCP server over stdio
```

The `.claude/settings.json` in this repo registers the server for Claude Code automatically. For Claude Desktop, add the same block to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "apc-agent": {
      "command": "apc-agent",
      "env": { "AWS_REGION": "us-east-1" }
    }
  }
}
```

AWS credentials are consumed via the standard boto3 chain: IAM role, `~/.aws/credentials`, or environment variables. Set `AWS_REGION` to the region where your APC resources live.

---

## What the Agent Can Do

### Key Lifecycle

Create, describe, list, delete, import, export, and alias keys. Import and export use TR-31 key blocks or TR-34 for asymmetric KEK establishment — the same mechanisms your existing HSM partner network already supports.

### Cryptographic Operations

Encrypt and decrypt card data (AES, TDES, FF1/FF3-1 FPE). Translate PIN blocks between encryption zones. Generate and verify PINs, CVV/CVV2/iCVV, CMAC and HMAC MACs, and EMV ARQC. The data plane tools map directly to the APC API — no abstraction layer between what the agent calls and what APC does.

### HSM Code Analysis

The agent can read existing payment source code, detect Futurex Excrypt and Thales payShield command patterns, and map them to the equivalent APC API call with the correct key type and parameter mapping. Current coverage: Futurex (authoritative), Thales (reference quality), Atalla (not yet available).

---

## Compliance Posture

PCI PIN v3.1 constraints run before every boto3 call and are not configurable off.

Hard stops — the agent refuses and explains:
- Single DES, RSA < 2048 bits, 2-key TDES
- Fixed TDEA keys for PIN (prohibited since January 2023)
- PAN mismatch during PIN translation (APC also enforces this at the API level)
- PIN blocks in logs
- Key usage mismatches against TR-31 usage codes

Warnings — the agent flags, explains the modern alternative, and asks for explicit confirmation before proceeding:
- TDES for new systems
- ISO Format 0 and Format 3 PIN blocks
- TDES DUKPT for new deployments
- CBC-MAC (recommend CMAC)

When a downstream system forces a deprecated construct, the agent follows the Legacy Constraint Protocol: confirm the user has verified the counterparty doesn't support the modern approach, then implement the legacy path correctly with a documented code comment and a notice that a QSA exception may be required.

AES key check values always use CMAC, never the ECB-zeros method. Key TR-31 usage codes are immutable — the agent validates compatibility before generating any code.

---

## Acquirer Reference Architecture

The agent's default for a new acquirer integration:

```
Terminal / POI
  └── AES DUKPT (BDK in APC, KSN per transaction)
        └── ISO Format 4 PIN block → translate_pin_data
              └── ZPK (AES P0) → host-to-host PIN routing
                    └── CMAC (AES M6) on ISO 8583 field 64

Key Exchange with Network / Processor
  └── TR-34 (asymmetric KEK establishment)
        └── TR-31 / X9.143 for all subsequent symmetric key transport

Card Data Protection
  └── AES (D0 key) or FF1 FPE for format-preserving tokenization
```

---

## Examples

Three runnable examples are in `examples/`. They require live AWS credentials and an active APC endpoint.

```bash
python examples/pin_processing.py     # AES DUKPT → Format 4 → translate_pin_data
python examples/cvv_generation.py     # CVK create → CVV1/CVV2 generate → verify
python examples/key_import_tr31.py    # KBPK create → TR-31 ZPK import
```

---

## Testing

```bash
pip install pytest pytest-asyncio "moto[payment-cryptography]"
pytest
```

---

## Project Structure

```
src/apc_agent/
├── server.py          — FastMCP entry point; registers all tool groups
├── control_plane.py   — Key lifecycle tools (payment-cryptography client)
├── data_plane.py      — Cryptographic operation tools (payment-cryptography-data client)
├── hsm_tools.py       — HSM code analysis MCP tools
├── hsm_analysis.py    — HSM command registry and regex patterns
├── system_prompt.py   — Domain knowledge injected as MCP instructions
└── compliance.py      — PCI guard-rail logic: hard stops, warnings, key usage registry
```

---

## Authoritative References

All APC API behavior in this codebase is derived from these sources. Do not extrapolate beyond them.

- [APC User Guide](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html)
- [Control Plane API Reference](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/Welcome.html)
- [Data Plane API Reference](https://docs.aws.amazon.com/payment-cryptography/latest/DataAPIReference/Welcome.html)
