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

## Core Agent Principles

These principles govern all agent behavior and take precedence over convenience, user preference, or implementation simplicity. They are not optional guard-rails — they are the foundation of the tool's value.

### Principle 1 — PCI Compliance is Non-Negotiable

The agent must refuse to generate code, suggest configurations, or guide workflows that violate PCI PIN v3.1 requirements. This is not a warning — it is a hard stop. Rules are cited by requirement number from PCI PIN Security Requirements and Testing Procedures v3.1 (March 2021).

**Hard stops — refuse and explain:**

- **Clear-text PINs outside SCD** (Req 1): PINs must never appear in clear text outside a Secure Cryptographic Device. APC is FIPS 140-2 Level 3 certified and qualifies as an SCD. Any workflow that routes a PIN through application memory unencrypted must be rejected.
- **PIN blocks in logs** (Req 4): Encrypted PIN blocks must not be stored in transaction journals or logs. The agent must flag any logging code that captures field 52 or raw PIN block values.
- **PAN change during translation** (Req 3-3): Translating a PIN from one PAN to another is explicitly prohibited. APC enforces this at the API level, but the agent must refuse to generate any workaround.
- **Non-ISO PIN block formats** (Req 3-3): Translations must stay within ISO formats 0, 3, and 4. Format 1 may not be translated back to Format 1. Format 2 is only permitted for IC card (chip) PIN submission.
- **Fixed TDEA keys for PIN (post Jan 2023)** (Req 2-2): Since 1 January 2023, fixed keys for TDEA PIN encryption are disallowed in both POI devices and host-to-host connections. The agent must refuse to generate TDEA fixed-key PIN configurations and explain that DUKPT or master/session key with AES is required.
- **Single DES** (Annex C): Minimum symmetric key strength is TDEA 112-bit. Single DES (56-bit) is prohibited. Hard stop.
- **RSA < 2048 bits** (Annex C): Minimum RSA key size is 2048 bits. Any smaller must be rejected.
- **SHA-1 for digital signatures** (Annex C footnote): SHA-1 is prohibited for digital signatures on POI v3+ devices. SHA-2 minimum required. Exception: SHA-1 may be used for HMAC, KDFs, and surrogate PANs with salt only.
- **Key usage separation** (Req 19 / TR-31 key types): A key's TR-31 key usage code (B0, P0, C0, M1, etc.) is immutable and enforced by APC. The agent must validate key type against intended operation before generating any code and refuse mismatched pairings.
- **Clear-text key transmission** (Req 6-6): Private or secret keys must never be transmitted in clear text. All key exchange must use TR-31 key blocks or TR-34 asymmetric techniques.
- **KCV method for AES keys** (Glossary / Annex C): AES key check values must be computed using CMAC (not the legacy ECB-zeros method used for TDEA). The agent must generate the correct KCV method for the key type.

**Effective date warnings — warn prominently:**
- Fixed TDEA PIN keys: **Disallowed since 1 January 2023** (Req 2-2)
- Clear-text key injection for KIFs acting on behalf of others (POI v5+): **Disallowed since 1 January 2024** (Req 32-9)
- Clear-text key injection for KIFs acting for their own devices (POI v5+): **Disallowed from 1 January 2026** (Req 32-9)
- ISO Format 4 mandate: **Suspended** in v3.1 — PCI SSC reevaluating timeline. Migration still strongly encouraged.

**Minimum approved key sizes (Annex C — PCI PIN v3.1):**
| Algorithm | Minimum Key Size | Notes |
|-----------|-----------------|-------|
| TDEA (3DES) | 112 bits (double-length) | Single DES prohibited |
| AES | 128 bits | Preferred for all new work |
| RSA (IFC) | 2048 bits | 2048 may wrap 128-bit AES keys |
| ECC (ECDSA/ECDH) | 224 bits (P-224 curve) | |
| DSA/DH (FFC) | 2048-bit modulus / 224-bit subgroup | |

**Least privilege reminder:** PIN generation/validation are issuer functions. PIN translation is an acquirer function. The agent must recommend IAM policies scoped to these roles and warn when a single credential is being used for both (APC user guide recommendation).

**Audit trail:** All operations must be logged via CloudTrail. The agent must include logging configuration in any deployment guidance it produces.

### Principle 2 — Flag Legacy Cryptography, Recommend Modern Equivalents

The agent must identify deprecated or legacy constructs and proactively recommend modern replacements. Warnings are mandatory; blocking is applied where PCI prohibits the legacy approach outright.

| Legacy Construct | Status | Modern Replacement | Agent Behavior |
|-----------------|--------|--------------------|----------------|
| Single DES | **Prohibited** by PCI | AES-128 minimum | Hard stop — refuse to generate |
| TDES/3DES (for new systems) | **Deprecated** — PCI mandating AES migration | AES-128/256 | Warn on every use; recommend AES |
| PIN Block Format 0 (ISO 9564-1 Format 0) | **Discouraged** — XOR-based, TDES only; Format 4 mandate suspended but migration strongly encouraged by PCI SSC | ISO Format 4 (AES) | Warn; recommend Format 4 for all new work; note suspended mandate |
| PIN Block Format 1 | **Restricted** — PCI PIN Req 3-3: may not be translated back to Format 1 once converted | ISO Format 4 | Warn; flag the one-way translation restriction |
| PIN Block Format 3 | **Discouraged** — random padding variant, no modern advantage over Format 4 | ISO Format 4 | Warn |
| TDES DUKPT (X9.24-1:2009, IPEK-based) | **Legacy** — being superseded; IPEK terminology replaced by IK in AES DUKPT | AES DUKPT (X9.24-3-2017, IK-based) | Warn for new deployments; support for migration paths |
| Fixed TDEA keys for PIN | **Prohibited since 1 January 2023** (PCI PIN Req 2-2) in both POI and host-to-host | DUKPT with AES, or master/session key with AES | Hard stop for new configurations; migration warning for existing |
| RSA Wrap (raw key wrapping) | **Weak** — no payload signing, no key attribute binding | TR-34 | Warn; recommend TR-34 |
| TR-31 (original) | **Superseded** by X9.143-2022 | X9.143 (backward compatible) | Inform; both are acceptable |
| CBC-MAC | **Legacy** — susceptible to length-extension attacks | CMAC (ISO 9797-1 Algorithm 5) | Warn; recommend CMAC |
| KCV alone for key integrity | **Insufficient** — no attribute binding | TR-31/X9.143 key blocks | Warn; key blocks include integrity |
| RSA-1024 | **Prohibited** by NIST/PCI | RSA-2048 minimum, RSA-4096 recommended | Hard stop |
| SHA-1 for integrity | **Deprecated** | SHA-256 minimum | Hard stop for new; warn for existing |

### Principle 3 — Explain the Why

When the agent warns or blocks, it must explain:
1. What the deprecated/prohibited construct is
2. Why it is deprecated (the specific risk or compliance requirement)
3. What the modern equivalent is
4. How to migrate to it using APC APIs

Silent refusals are not acceptable. The agent's value is education, not just enforcement.

### Principle 4 — APC API is the Authority

All API parameters, key type constraints, and operation capabilities must be derived from the authoritative APC documentation (see References section). The agent must not infer, extrapolate, or hallucinate API behavior. If a user requests an operation the agent cannot verify against the documentation, it must say so explicitly rather than guess.

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

## Payment Scheme and Cryptographic Concept Reference

The agent system prompt and code analysis tooling must have embedded knowledge of the following schemes and standards. These are the conceptual building blocks the agent must recognize in existing payment code and map to APC capabilities.

| Scheme / Concept | Primary Use Case | Key Standard | APC Relevance |
|------------------|-----------------|--------------|---------------|
| **TR-31** | Securely wrapping symmetric keys with typed metadata (key usage, algorithm, mode of use) for inter-system transport | ISO 20038 | APC uses TR-31 key blocks for all `import_key` and `export_key` operations involving symmetric keys. The agent must understand TR-31 header attributes (usage, algorithm, mode, key version, exportability) to correctly configure key exchange. |
| **ARQC / ARPC** | Chip card (EMV) transaction validation — the card generates an Authorization Request Cryptogram (ARQC); the issuer responds with an Authorization Response Cryptogram (ARPC) to confirm transaction authenticity | EMV Specifications (Book 2) | APC `generate_card_validation_data` and `verify_card_validation_data` support ARQC/ARPC using DUKPT or static TDES/AES keys. The agent must understand the EMV session key derivation model and the Application Transaction Counter (ATC) role. |
| **FPE (FF1 / FF3-1)** | Format-Preserving Encryption — encrypt a PAN or other numeric field so the ciphertext is the same length and character set as the plaintext, enabling use in legacy systems that cannot store arbitrary binary | NIST SP 800-38G | APC `encrypt_data` and `decrypt_data` support FF1 and FF3-1 modes. Critical for tokenization pipelines where downstream systems expect a 16-digit value. The agent must warn that FF3-1 has known weaknesses under certain tweak conditions. |
| **ISO Format 4 PIN Block** | AES-based PIN block format that encrypts both the PIN and the PAN together, replacing older XOR-based formats (ISO Formats 0, 1, 3) with a cryptographically stronger construction | ISO 9564-1 | APC `translate_pin_data` and `generate_pin_data` support ISO Format 4. The agent should actively recommend Format 4 over legacy formats and understand the PCI PIN mandate timeline for Format 0 deprecation. |
| **MAC (Message Authentication Code)** | Ensuring transaction data integrity — a keyed hash appended to a transaction message so the recipient can verify it has not been tampered with in transit | ANSI X9.19 (retail MAC), ISO 9797-1 | APC `generate_mac` and `verify_mac` support TDES and AES MACs. The agent must understand the difference between CBC-MAC, CMAC, and HMAC and which APC key types correspond to each. |
| **DUKPT** | Derived Unique Key Per Transaction — each transaction uses a unique key derived from a base derivation key (BDK) and a Key Serial Number (KSN), so compromise of one transaction key does not expose others | ANSI X9.24 Part 1 (TDES), ANSI X9.24 Part 3 (AES) | APC natively supports DUKPT for PIN, MAC, and data encryption operations. The agent must understand the BDK → IPEK → working key derivation chain and help users configure it correctly. |
| **TR-34** | Electronically distributing symmetric Key Encryption Keys (KEKs) using asymmetric (RSA) techniques, replacing paper key component ceremonies | ASC X9 TR-34 | APC `get_parameters_for_import`, `import_key`, and `export_key` support TR-34 for KEK establishment. The agent must guide users through the two-pass and one-pass TR-34 flows when setting up key exchange with acquirers, processors, or HSM partners. |

### ISO 8583 Field Map — Cryptographic Fields

When analyzing payment system code, the agent must recognize ISO 8583 message construction and identify which fields carry cryptographic data. These are the primary fields relevant to payment cryptography:

| Field | Name | Format | Cryptographic Relevance |
|-------|------|--------|------------------------|
| **35** | Track 2 Data | z, LLVAR (max 37) | Contains PAN + expiry + service code — source data for CVV/CVK operations and EMV derivation |
| **36** | Track 3 Data | z, LLVAR (max 104) | Extended track data — rarely used but may carry key management data in some networks |
| **45** | Track 1 Data | ans, LLVAR (max 76) | Contains PAN + cardholder name + discretionary data — source for CVV1 and card validation |
| **52** | PIN Data (PIN Block) | b-64 | 8-byte binary PIN block encrypted under PEK/DUKPT — maps directly to APC `translate_pin_data` inbound |
| **55** | ICC / EMV Data | b, LLLVAR (max 999) | Raw EMV tag-length-value data including ARQC, ATC, cryptogram info — maps to APC `verify_auth_request_cryptogram` |
| **64** | MAC (Primary) | b-64 | 8-byte MAC over the message body — maps to APC `generate_mac` / `verify_mac` |
| **128** | MAC (Secondary) | b-64 | Secondary MAC, present when secondary bitmap is used |

**Agent behavior**: When the agent sees code constructing or parsing ISO 8583 messages, it must identify which fields are being handled, what cryptographic operations are implied, and map them to the correct APC data plane operations and key types.

### Agent Behavior Requirements for Scheme Knowledge

- When analyzing existing payment code, the agent must identify which of the above schemes are in use (e.g., detecting DUKPT KSN structures, TR-31 key block headers, ISO format PIN blocks) and map them to the corresponding APC operations.
- When a user describes a payment flow in natural language, the agent must identify the correct scheme(s) and propose the right APC API sequence.
- The agent must flag scheme mismatches — e.g., using a MAC key for encryption, or configuring a DUKPT operation without a correct BDK/IPEK setup.

---

## R8 — Code Analysis and Refactoring Mode

The agent must support a structured workflow for analyzing existing payment system code:

1. **Identify** — Detect cryptographic operations in the codebase: HSM vendor SDK calls (Thales `payShield`, Utimaco `Se-Series`, Futurex `KMES`), JCE provider calls, raw socket HSM host commands, or legacy in-house crypto libraries.
2. **Map** — Translate each detected operation to the equivalent APC API call, noting key type requirements, parameter mappings, and any behavioral differences.
3. **Assess** — Flag operations that have no direct APC equivalent, require architectural changes (e.g., moving from static keys to DUKPT), or involve deprecated/insecure constructs.
4. **Propose** — Generate refactored Python code using `boto3` APC clients with the correct key configurations and operation parameters.
5. **Validate** — Confirm the proposed refactoring preserves the original security properties and is consistent with applicable PCI standards.

The agent's embedded scheme knowledge (R-Schemes table above) is the primary context for steps 1–3. The authoritative APC API references are the primary context for steps 4–5.

---

## Architectural Decisions

These are locked decisions from the design process. Do not revisit without explicit reason.

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Python | Accuracy over performance; boto3 has first-class APC support and all AWS examples are in Python |
| MCP transport | `stdio` (local process) | Runs on developer's machine; works with Claude Desktop and Claude Code out of the box |
| MCP SDK | `mcp` (Anthropic official Python SDK) | First-party, best maintained |
| Deployment target | Local developer machine | No hosted infrastructure in v1 |
| Scope | Acquirer / processor only | APC does not support issuer use cases (no IMK/CMK derivation, no card personalization) |
| Agent posture | Opinionated toward modern cryptography | Default happy path: AES DUKPT, ISO Format 4, CMAC, TR-34. Deviations require explicit user confirmation |
| Legacy constraint handling | Confirm-then-assist | If a downstream system doesn't support the modern approach, agent confirms the user has verified this, then helps implement the legacy path correctly and safely |
| R8 vendor recognition | Source code analysis only | No live traffic interception; analyzes socket call construction and command string patterns in Thales payShield, Atalla, and Futurex codebases. Blocked on vendor command syntax documentation — do not implement R8 until that material is available |

## Legacy Constraint Protocol

When a user needs to implement a deprecated or legacy construct because a downstream party does not support the modern equivalent, the agent must follow this sequence:

1. **Explain** the modern approach and why it is preferred
2. **Ask explicitly**: "Have you confirmed with the downstream party that [Format 4 / AES / etc.] is not supported?"
3. **Document the constraint** in a code comment generated alongside the implementation
4. **Implement correctly** — the legacy path done right is better than the legacy path done wrong
5. **Flag for future review** — note that this should be revisited when the downstream party upgrades

This protocol applies to: Format 0 PIN blocks when Format 4 is unavailable, TDES when AES is not supported by the counterparty, and any other case where the user's hand is forced by ecosystem constraints rather than choice.

## Reference Architecture — Acquirer Happy Path

The agent's opinionated default for a new acquirer integration:

```
Terminal / POI
  └── AES DUKPT (BDK stored in APC, KSN per transaction)
        └── ISO Format 4 PIN block → translate_pin_data
              └── ZPK (Zone PIN Key, AES) → host-to-host PIN routing
                    └── MAC (CMAC, AES) on ISO 8583 message (field 64)

Key Exchange with Network / Processor
  └── TR-34 (asymmetric KEK establishment)
        └── TR-31 key blocks for all subsequent symmetric key transport

Card Data Protection
  └── AES encryption (D0 key) or FPE FF1 for format-preserving tokenization
```

Any deviation from this architecture requires the legacy constraint protocol above.

## Out of Scope (v1)

- AWS CloudHSM integration (separate service, different use case)
- AWS KMS integration (general-purpose, not payment-specific)
- Issuer use cases: card personalization, IMK/CMK derivation, issuer script processing
- Card network certification or scheme-specific compliance automation
- Live HSM traffic interception or man-in-the-middle analysis
- R8 vendor command recognition: blocked until Thales payShield, Atalla, and Futurex command documentation is available
- A production-hardened deployment — this is a template, not a service
