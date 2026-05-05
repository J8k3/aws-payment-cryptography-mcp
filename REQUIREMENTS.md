# AWS Payment Cryptography Claude Agent — REQUIREMENTS

> Internal PRFAQ — Working Document

---

## Press Release

**FOR IMMEDIATE RELEASE**

**Introducing the AWS Payment Cryptography Claude Agent Template: Build and Refactor Payment Systems with AI Assistance**

*An open-source MCP server and Claude agent template that gives developers an AI-powered co-pilot for designing, building, and auditing PCI-compliant payment cryptography systems on AWS*

Today we are releasing the **AWS Payment Cryptography Claude Agent Template**, an open-source Python toolkit that connects Claude to the AWS Payment Cryptography (APC) service via the Model Context Protocol (MCP). The template enables developers and payment architects to interact with APC's control and data plane APIs through natural language — planning key hierarchies, executing cryptographic operations, validating compliance patterns, and refactoring legacy HSM-dependent payment systems to cloud-native infrastructure.

Payment cryptography is one of the most complex and compliance-sensitive domains in software engineering. Teams migrating from physical HSM vendors such as Thales, Utimaco, or Futurex to AWS Payment Cryptography face steep learning curves, opaque API surfaces, and high risk of misconfiguration. This template lowers that barrier by embedding APC domain knowledge and live API access into a Claude agent that can reason about payment standards (PCI PIN, PCI P2PE, PCI DSS), suggest architecturally correct key hierarchies, execute operations, and explain every decision.

---

## Frequently Asked Questions

### Customer FAQs

**Q: Who is this for?**
Payment engineers, solutions architects, and fintech developers who are building new payment processing systems on AWS or migrating existing systems away from on-premises HSMs (Thales Luna, Utimaco SecurityServer, Futurex KMES). It is also useful for compliance engineers who need to audit cryptographic key usage and operation logs.

**Q: What can I do with this that I couldn't do before?**
Rather than reading through dense APC API reference documentation and writing boilerplate key management code from scratch, you can describe your payment architecture in plain language and have Claude generate correct, compliant APC code, validate your key hierarchy design, and execute live operations against your AWS account.

**Q: Does this replace a payment HSM architect?**
No. It is a productivity tool and a guard-rail, not a replacement for expert judgment. It surfaces the right API calls, flags likely compliance violations, and reduces implementation time — but production payment systems still require expert review.

**Q: Is this production-ready?**
The template is a starting point, not a production system. It is designed to be forked and hardened. It ships with IAM least-privilege examples, CloudTrail logging guidance, and PCI-aligned patterns, but operators are responsible for their own compliance posture.

**Q: What AWS services does this depend on?**
Primarily AWS Payment Cryptography (control plane and data plane). Optionally: AWS CloudTrail (audit), IAM, and Secrets Manager or Parameter Store for credential management.

---

### Internal FAQs

**Q: Why MCP and not a custom CLI or SDK wrapper?**
MCP makes the APC tools reusable across any Claude interface — Claude.ai, Claude Code, Claude Managed Agents, or a custom application. A CLI wrapper would be single-use. MCP also provides a standard schema for tool inputs/outputs that Claude can reason about without additional prompting.

**Q: Why Python?**
`boto3` is the most mature AWS SDK, has first-class APC support, and is the dominant language in the payment engineering and data science communities that are most likely to adopt this tool.

**Q: What is the relationship between the control plane and data plane?**
The **control plane** (`payment-cryptography` boto3 client) manages key lifecycle: create, import, export, alias, tag, delete. The **data plane** (`payment-cryptography-data` boto3 client) uses those keys to perform cryptographic operations: encrypt, decrypt, PIN translate, generate CVV/MAC, etc. The agent must understand both and help the user orchestrate them correctly.

**Q: How does this handle the complexity of key types?**
APC enforces strict key usage separation — a key created for CVV generation cannot be used for PIN encryption. The agent will expose key type constraints as part of its tool schemas and will refuse to call operations with incompatible key/usage combinations.

**Q: What is the migration story from physical HSMs?**
On-premises HSMs (Thales, Utimaco, Futurex) require physical key components, ceremony procedures, and TR-31/TR-34 key exchange for inter-system communication. APC supports TR-31 and TR-34 for key import/export, enabling key material to be migrated electronically. The agent will include tools and prompts to guide this migration workflow.

---

## Authoritative References

All APC API structure, supported operations, parameters, and constraints must be derived from these sources. Do not infer or hallucinate API behavior.

| Source | URL | Purpose |
|--------|-----|---------|
| APC User Guide | https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html | Concepts, use cases, compliance context |
| Control Plane API Reference | https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/Welcome.html | Key management operations |
| Data Plane API Reference | https://docs.aws.amazon.com/payment-cryptography/latest/DataAPIReference/Welcome.html | Cryptographic operations |

---

## Requirements

### R1 — MCP Server: Control Plane Tools

Expose the following APC control plane operations as MCP tools:

- `create_key` — create symmetric (TDES, AES) or asymmetric (RSA) keys with specified key attributes and usage
- `describe_key` — retrieve metadata for a key by key ARN or alias
- `list_keys` — enumerate keys with optional filters
- `delete_key` — schedule key deletion
- `create_alias` / `update_alias` / `delete_alias` / `list_aliases` — manage friendly name aliases
- `import_key` — import key material via TR-31 or TR-34
- `export_key` — export key material via TR-31 or TR-34
- `tag_resource` / `untag_resource` / `list_tags_for_resource` — key tagging
- `get_parameters_for_import` / `get_parameters_for_export` — retrieve wrapping key material for key exchange

### R2 — MCP Server: Data Plane Tools

Expose the following APC data plane operations as MCP tools:

- `encrypt_data` — encrypt card data or other payment data
- `decrypt_data` — decrypt data
- `re_encrypt_data` — translate data between encryption keys without exposing plaintext
- `generate_pin_data` — generate PINs and PIN offsets
- `verify_pin_data` — validate a PIN against a reference value
- `translate_pin_data` — translate a PIN block between encryption zones (PCI PIN compliant)
- `generate_card_validation_data` — generate CVV, CVV2, or other card validation values
- `verify_card_validation_data` — validate CVV/CVV2
- `generate_mac` — generate a MAC for message authentication
- `verify_mac` — validate a MAC
- `generate_mac_emv_pin_change` — EMV PIN change MAC generation

### R3 — Agent System Prompt and Domain Knowledge

The Claude agent must be initialized with a system prompt that includes:

- APC service overview: what it is, what it replaces (physical HSMs), PCI compliance scope
- Key type taxonomy: TDES, AES, RSA; key usage constraints enforced by APC
- Key hierarchy concepts: KEK, DEK, DUKPT base key, working key derivation
- TR-31 and TR-34 key block concepts for key import/export
- Common payment cryptography workflows: PIN processing, card personalization, acquirer/issuer key exchange
- Guidance on when to use control plane vs. data plane

### R4 — Compliance and Safety Guards

- The agent must flag operations that violate PCI key usage separation
- The agent must warn when a requested operation pattern is inconsistent with PCI PIN, PCI P2PE, or PCI DSS
- No key material (clear-text or key block values) should be logged or surfaced in agent responses beyond what the user explicitly requests
- The agent should recommend CloudTrail logging for all operations

### R5 — HSM Migration Tooling

- Provide guided workflows for migrating from on-premises HSMs (Thales, Utimaco, Futurex) to APC
- Support TR-31 key block import from existing HSM exports
- Support TR-34 asymmetric KEK exchange setup
- Document key ceremony equivalents in APC terms

### R6 — Developer Experience

- Single `pip install` setup with `boto3` and the `mcp` Python SDK
- Environment-based AWS credential configuration (supports IAM roles, profiles, and environment variables)
- Example Claude Desktop / Claude Code MCP configuration
- At least one end-to-end example workflow per major use case (PIN processing, CVV generation, key import)

### R7 — Project Structure

```
aws-payment-cryptography-claude-agent-template/
├── REQUIREMENTS.md
├── README.md
├── pyproject.toml
├── src/
│   └── apc_agent/
│       ├── server.py          # MCP server entry point
│       ├── control_plane.py   # Control plane tool definitions
│       ├── data_plane.py      # Data plane tool definitions
│       ├── system_prompt.py   # Agent domain knowledge / system prompt
│       └── compliance.py      # PCI guard-rail logic
├── examples/
│   ├── pin_processing.py
│   ├── cvv_generation.py
│   └── key_import_tr31.py
└── .claude/
    └── settings.json          # Claude Code MCP configuration
```

---

## Out of Scope (v1)

- AWS CloudHSM integration (separate service, different use case)
- AWS KMS integration (general-purpose, not payment-specific)
- Card network certification or scheme-specific compliance automation
- A production-hardened deployment — this is a template, not a service
