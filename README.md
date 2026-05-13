# AWS Payment Cryptography Claude Agent Template

An MCP server + Claude agent template that connects Claude to [AWS Payment Cryptography (APC)](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html) via the Model Context Protocol. Targets acquirer and processor use cases — migrating from physical HSMs (Thales payShield, Futurex KMES, Atalla) to APC's managed cloud HSM service.

> **Scope:** Acquirer/processor only. Issuer functions (card personalization, IMK/CMK derivation, issuer script processing) are explicitly out of scope and will be refused by the agent.

---

## Prerequisites

- Python 3.11+
- AWS account with APC enabled in your target region
- AWS credentials configured via IAM role, `~/.aws/credentials`, or environment variables
- [Claude Code](https://claude.ai/code) or Claude Desktop

---

## Installation

```bash
pip install -e .
```

This installs the `apc-agent` entry point, which starts the MCP server over stdio.

---

## AWS Credentials

The server consumes credentials via the standard boto3 chain. Recommended approaches:

```bash
# IAM role (recommended for production)
# Configure your instance/task role with least-privilege APC permissions

# Named profile
export AWS_PROFILE=my-payment-profile
export AWS_REGION=us-east-1

# Environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
```

Minimum IAM permissions needed:

```json
{
  "Effect": "Allow",
  "Action": [
    "payment-cryptography:CreateKey",
    "payment-cryptography:DescribeKey",
    "payment-cryptography:ListKeys",
    "payment-cryptography:ImportKey",
    "payment-cryptography:ExportKey",
    "payment-cryptography:GetParametersForImport",
    "payment-cryptography:GetParametersForExport",
    "payment-cryptography:CreateAlias",
    "payment-cryptography:UpdateAlias",
    "payment-cryptography:DeleteAlias",
    "payment-cryptography:ListAliases",
    "payment-cryptography:TagResource",
    "payment-cryptography:UntagResource",
    "payment-cryptography:ListTagsForResource",
    "payment-cryptography-data:EncryptData",
    "payment-cryptography-data:DecryptData",
    "payment-cryptography-data:ReEncryptData",
    "payment-cryptography-data:GeneratePinData",
    "payment-cryptography-data:VerifyPinData",
    "payment-cryptography-data:TranslatePinData",
    "payment-cryptography-data:GenerateCardValidationData",
    "payment-cryptography-data:VerifyCardValidationData",
    "payment-cryptography-data:GenerateMac",
    "payment-cryptography-data:VerifyMac",
    "payment-cryptography-data:GenerateMacEmvPinChange"
  ],
  "Resource": "*"
}
```

---

## MCP Configuration

The `.claude/settings.json` in this repo already registers the server for Claude Code:

```json
{
  "mcpServers": {
    "apc-agent": {
      "command": "apc-agent",
      "env": {
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

For Claude Desktop, add the same block to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).

Change `AWS_REGION` to the region where your APC resources are located.

---

## What the Agent Can Do

### Control Plane — Key Lifecycle

| Tool | Operation |
|------|-----------|
| `create_key` | Create AES, TDES, or RSA keys with TR-31 usage codes |
| `describe_key` | Get key metadata by ARN or alias |
| `list_keys` | Enumerate keys with optional filters |
| `delete_key` | Schedule key deletion |
| `import_key` | Import via TR-31 key block or TR-34 |
| `export_key` | Export via TR-31 key block or TR-34 |
| `create_alias` / `update_alias` / `delete_alias` / `list_aliases` | Manage friendly name aliases |
| `tag_resource` / `untag_resource` / `list_tags_for_resource` | Key tagging |
| `get_parameters_for_import` / `get_parameters_for_export` | Retrieve wrapping key material |

### Data Plane — Cryptographic Operations

| Tool | Operation |
|------|-----------|
| `encrypt_data` | Encrypt card data (AES, TDES, FF1/FF3-1 FPE) |
| `decrypt_data` | Decrypt data |
| `re_encrypt_data` | Translate between encryption zones without exposing plaintext |
| `generate_pin_data` | Generate PINs and PIN offsets |
| `verify_pin_data` | Validate a PIN against a reference value |
| `translate_pin_data` | Translate PIN blocks between encryption zones (PCI PIN compliant) |
| `generate_card_validation_data` | Generate CVV, CVV2, iCVV, ARQC |
| `verify_card_validation_data` | Validate CVV/CVV2 |
| `generate_mac` | Generate CMAC or HMAC for message authentication |
| `verify_mac` | Validate a MAC |
| `generate_mac_emv_pin_change` | EMV PIN change MAC generation |

### HSM Code Analysis (R8)

The agent can analyze existing payment code for HSM vendor patterns and map them to APC equivalents:

| Tool | What it does |
|------|-------------|
| `analyze_hsm_code` | Detect HSM vendor SDK calls, host commands, and crypto patterns in source code |
| `map_hsm_command` | Map a specific Futurex or Thales command to the equivalent APC API call |
| `list_supported_vendors` | Show which vendors and command sets are recognized |

Current coverage: **Futurex** (authoritative), **Thales International** (reference quality), **Atalla** (not yet available).

---

## Reference Architecture — Acquirer Happy Path

The agent defaults to this architecture for new acquirer integrations:

```
Terminal / POI
  └── AES DUKPT (BDK stored in APC, KSN per transaction)
        └── ISO Format 4 PIN block → translate_pin_data
              └── ZPK (Zone PIN Key, AES P0) → host-to-host PIN routing
                    └── CMAC (AES M6) on ISO 8583 field 64

Key Exchange with Network / Processor
  └── TR-34 (asymmetric KEK establishment)
        └── TR-31 / X9.143 key blocks for subsequent symmetric key transport

Card Data Protection
  └── AES encryption (D0 key) or FF1 FPE for format-preserving tokenization
```

Deviations from this architecture trigger the **Legacy Constraint Protocol**: the agent explains the modern approach, asks for explicit confirmation that the downstream system doesn't support it, then helps implement the legacy path correctly with a documented code comment.

---

## Examples

Three runnable examples are in `examples/`. They require real AWS credentials and an active APC endpoint.

### PIN Processing (`examples/pin_processing.py`)

AES DUKPT → ISO Format 4 → `translate_pin_data` → ZPK. The acquirer reference flow end-to-end.

```bash
python examples/pin_processing.py
```

### CVV Generation and Verification (`examples/cvv_generation.py`)

Create a CVK (AES-128, C0), generate CVV1 and CVV2 for a test PAN, then verify both.

```bash
python examples/cvv_generation.py
```

### TR-31 Key Import (`examples/key_import_tr31.py`)

Create a KBPK (AES-256, K1), then import a partner-supplied ZPK wrapped in a TR-31 key block. This is the standard pattern for receiving working keys from an acquiring network or processor.

```bash
python examples/key_import_tr31.py
```

---

## Compliance Posture

The agent enforces PCI PIN v3.1 as hard constraints, not preferences:

- **Hard stops** (agent refuses and explains): single DES, RSA < 2048 bits, fixed TDEA PIN keys (prohibited since January 2023), PAN change during PIN translation, PIN blocks in logs, key usage mismatches
- **Warnings** (agent flags and recommends migration): TDES for new systems, Format 0 PIN blocks, TDES DUKPT, CBC-MAC, RSA raw wrap
- **AES KCV**: always CMAC — never the legacy ECB-zeros method
- **Key type immutability**: TR-31 usage codes are set at creation and enforced by APC at the API level; the agent validates compatibility before generating code

This is a template, not a certified compliance tool. Production deployments require expert review and QSA sign-off.

---

## Testing

```bash
pip install pytest pytest-asyncio "moto[payment-cryptography]"
pytest
```

---

## Project Structure

```
aws-payment-cryptography-claude-agent-template/
├── REQUIREMENTS.md            # PRFAQ and detailed requirements
├── pyproject.toml
├── src/
│   └── apc_agent/
│       ├── server.py          # FastMCP server entry point
│       ├── control_plane.py   # Key lifecycle MCP tools
│       ├── data_plane.py      # Cryptographic operation MCP tools
│       ├── hsm_tools.py       # HSM code analysis MCP tools (R8)
│       ├── hsm_analysis.py    # HSM command registry and regex patterns
│       ├── system_prompt.py   # Agent domain knowledge injected via MCP instructions
│       └── compliance.py      # PCI guard-rail logic
├── examples/
│   ├── pin_processing.py      # AES DUKPT → Format 4 → translate_pin_data
│   ├── cvv_generation.py      # CVK create → CVV1/CVV2 generate → verify
│   └── key_import_tr31.py     # KBPK create → TR-31 ZPK import
└── .claude/
    └── settings.json          # Claude Code MCP configuration
```

---

## Authoritative References

All APC API behavior is derived from these sources. Do not infer or extrapolate beyond them.

- [APC User Guide](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html)
- [Control Plane API Reference](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/Welcome.html)
- [Data Plane API Reference](https://docs.aws.amazon.com/payment-cryptography/latest/DataAPIReference/Welcome.html)
