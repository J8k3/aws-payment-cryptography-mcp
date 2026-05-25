# Example Sessions

Three end-to-end examples — one per workflow — showing real prompt → tool call → result → response excerpts. Data is synthetic; key identifiers and KSNs are illustrative only.

---

## Example 1 — Analyzing legacy HSM code before migration (Workflow 2)

A developer pastes a Python file that talks to a Thales payShield 10K. They want to know what APC calls to write before touching the application code.

---

**User**

> We're migrating off our Thales payShield. Here's the connection wrapper — `payment_host.py`. What HSM operations does it use and what are the APC equivalents?

```python
# payment_host.py
def translate_pin_zpk_to_zpk(conn, zpk_src, zpk_dst, pin_block, pan):
    cmd = "CC" + zpk_src + zpk_dst + pin_block + pan
    return conn.send(cmd)

def generate_mac(conn, mak, data):
    cmd = "M6" + mak + data
    return conn.send(cmd)

def verify_cvv(conn, cvk, pan, expiry, service_code):
    cmd = "CY" + cvk + pan + expiry + service_code
    return conn.send(cmd)
```

---

**Tool called:** `hsm_analyze_code`

```json
{
  "commands_detected": 3,
  "hsm_connection_patterns_found": true,
  "detected": [
    {
      "detected_api": "International_and_Thales_Legacy",
      "command_code": "CC",
      "match_context": "cmd = \"CC\" + zpk_src + zpk_dst + pin_block + pan",
      "known": true,
      "name": "Translate PIN from ZPK to ZPK (Fixed Key)",
      "category": "PIN",
      "apc_operation": "translate_pin_data",
      "apc_key_type": "TR31_P0_PIN_ENCRYPTION_KEY",
      "notes": "Static/fixed ZPK keys that never rotate present a PCI compliance risk...",
      "confidence": "high"
    },
    {
      "detected_api": "International_and_Thales_Legacy",
      "command_code": "M6",
      "match_context": "cmd = \"M6\" + mak + data",
      "known": true,
      "name": "Generate MAC (Extended)",
      "category": "MAC",
      "apc_operation": "generate_mac",
      "apc_key_type": "TR31_M6_ISO_9797_5_CMAC_KEY",
      "notes": null,
      "confidence": "high"
    },
    {
      "detected_api": "International_and_Thales_Legacy",
      "command_code": "CY",
      "match_context": "cmd = \"CY\" + cvk + pan + expiry + service_code",
      "known": true,
      "name": "Verify CVV",
      "category": "CVV",
      "apc_operation": "verify_card_validation_data",
      "apc_key_type": "TR31_C0_CARD_VERIFICATION_KEY",
      "notes": null,
      "confidence": "high"
    }
  ],
  "migration_notes": [
    "WARNING — Fixed Key Detection:\nIf the legacy code uses CC (ZPK-to-ZPK PIN translation) with static/fixed keys that never rotate, this is a compliance risk. APC does not prevent static key use, but you should evaluate whether AES DUKPT (translate_pin_data with a BDK-derived session key) is the right replacement for new deployments."
  ]
}
```

---

**Agent response**

Three operations in scope:

| Legacy command | APC operation | Key type (TR-31) |
|---|---|---|
| `CC` — ZPK-to-ZPK PIN translate | `translate_pin_data` | `TR31_P0_PIN_ENCRYPTION_KEY` |
| `M6` — Generate MAC | `generate_mac` | `TR31_M6_ISO_9797_5_CMAC_KEY` |
| `CY` — Verify CVV | `verify_card_validation_data` | `TR31_C0_CARD_VERIFICATION_KEY` |

One flag: `CC` with static ZPK keys is a compliance risk. If these keys never rotate, AES DUKPT (`translate_pin_data` with a session key derived per-transaction from a BDK) is the preferred replacement.

Next: I'll create the three keys in APC and draft the replacement functions. Want me to proceed?

---

## Example 2 — Compliance guard intercepts a legacy algorithm (Workflow 1)

A developer is building a new MAC integration. They ask for Retail MAC — a common choice in legacy networks that the compliance layer treats as a legacy construct requiring explicit confirmation.

---

**User**

> Create an AES-128 MAC key and generate a Retail MAC over this test message.

---

**Tool called:** `create_key`

```json
{
  "Key": {
    "KeyArn": "arn:aws:payment-cryptography:us-east-1:123456789012:key/kwapwa6qaifllw2gjjjkexpample",
    "KeyAttributes": {
      "KeyAlgorithm": "AES_128",
      "KeyClass": "SYMMETRIC_KEY",
      "KeyUsage": "TR31_M6_ISO_9797_5_CMAC_KEY",
      "KeyModesOfUse": { "Generate": true, "Verify": true }
    },
    "KeyCheckValue": "A1B2C3",
    "KeyCheckValueAlgorithm": "CMAC",
    "Enabled": true,
    "Exportable": false
  }
}
```

**Tool called:** `generate_mac` — with `Algorithm: ISO9797_ALGORITHM3`

```json
{
  "compliance_warning": "Retail MAC (ANSI X9.19 / ISO 9797-1 Algorithm 3) is a legacy algorithm still common in older acquiring networks. It is weaker than CMAC and HMAC. PCI PIN v3.1 permits Retail MAC on existing infrastructure as a compensating control but prohibits it for new deployments.",
  "recommendation": "Use CMAC (ISO9797_ALGORITHM5) for all new MAC generation. It is mandatory for AES KCV and is the default for AES DUKPT.",
  "confirmation_required": true,
  "legacy_construct": "RETAIL_MAC"
}
```

---

**Agent response**

The key was created (`TR31_M6_ISO_9797_5_CMAC_KEY`, AES-128, KCV A1B2C3).

Before generating the MAC: **Retail MAC (ISO9797_ALGORITHM3) is a legacy construct.** PCI PIN v3.1 prohibits it for new deployments. The modern replacement is CMAC — it's what APC uses for AES KCV and AES DUKPT.

A few questions before I proceed:
1. Is this for an existing network that requires Retail MAC, or a new integration?
2. Have you confirmed with your network processor that CMAC (ISO9797_ALGORITHM5) is not supported?

If you confirm the downstream system forces Retail MAC, I'll generate it with a code comment documenting the constraint and a note that a QSA-documented compensating control may be required. Otherwise I'd recommend CMAC.

---

**User**

> It's a new integration — use CMAC.

---

**Tool called:** `generate_mac`

```json
{
  "Mac": "F3A7C29B4E1D0856",
  "KeyArn": "arn:aws:payment-cryptography:us-east-1:123456789012:key/kwapwa6qaifllw2gjjjkexpample"
}
```

---

**Agent response**

MAC generated: `F3A7C29B4E1D0856` (CMAC, AES-128).

---

## Example 3 — Discovery log → proxy handler build plan (Workflow 3)

A team has run their application against the proxy in discovery mode. They paste the discovery log and ask what handlers still need to be written.

---

**User**

> Here's our discovery.jsonl from running the payment simulator for 20 minutes. Which handlers already exist in the proxy and which do we still need to write?

```jsonl
{"vendor": "thales_payshield", "cmd": "CA", "payload_len": 48}
{"vendor": "thales_payshield", "cmd": "G0", "payload_len": 64}
{"vendor": "thales_payshield", "cmd": "KQ", "payload_len": 128}
{"vendor": "thales_payshield", "cmd": "GW", "payload_len": 96}
```

---

**Tool called:** `hsm_analyze_discovery_log`

```json
{
  "commands_observed": 4,
  "mapped_to_apc": 4,
  "handlers_already_exist": 3,
  "handlers_needed": 1,
  "unknown_commands": 0,
  "parse_errors": 0,
  "commands": [
    {
      "cmd": "CA",
      "vendor": "thales_payshield",
      "handler_exists": true,
      "known": true,
      "name": "Translate PIN from TPK to ZPK (ISO Format 0/1)",
      "category": "PIN",
      "apc_operation": "translate_pin_data",
      "apc_key_type": "TR31_P0_PIN_ENCRYPTION_KEY",
      "confidence": "high"
    },
    {
      "cmd": "G0",
      "vendor": "thales_payshield",
      "handler_exists": true,
      "known": true,
      "name": "Translate PIN (DUKPT — TDES, Format 0/3/4)",
      "category": "PIN",
      "apc_operation": "translate_pin_data",
      "apc_key_type": "TR31_P0_PIN_ENCRYPTION_KEY",
      "confidence": "high"
    },
    {
      "cmd": "KQ",
      "vendor": "thales_payshield",
      "handler_exists": true,
      "known": true,
      "name": "EMV/Mastercard ARQC Verification",
      "category": "ARQC",
      "apc_operation": "verify_auth_request_cryptogram",
      "apc_key_type": "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS_KEY",
      "confidence": "high"
    },
    {
      "cmd": "GW",
      "vendor": "thales_payshield",
      "handler_exists": false,
      "known": true,
      "name": "DUKPT MAC Generate / Verify (3DES & AES)",
      "category": "MAC",
      "apc_operation": "generate_mac",
      "apc_key_type": "TR31_M3_ISO_9797_3_MAC_KEY",
      "confidence": "high"
    }
  ],
  "next_steps": [
    "Handlers already implemented in the proxy: CA, G0, KQ. No action needed.",
    "GW (DUKPT MAC Generate / Verify (3DES & AES)) → implement src/handlers/thales/gw.rs calling APC generate_mac with key type TR31_M3_ISO_9797_3_MAC_KEY."
  ],
  "migration_notes": [
    "NOTE — DUKPT Migration:\nIf the legacy codebase uses TDES DUKPT (CI command with 10-byte KSN): The BDK and IPEK are LMK-encrypted on the source HSM. They cannot be imported into APC directly..."
  ]
}
```

---

**Agent response**

Three of four commands already have proxy handlers — no action needed for `CA`, `G0`, `KQ`.

**One handler to build: `GW`**

- **What it does:** DUKPT MAC generate/verify (TDES and AES)
- **APC operation:** `generate_mac`
- **Key type:** `TR31_M3_ISO_9797_3_MAC_KEY`
- **Where to put it:** `src/handlers/thales/gw.rs` — model it on the existing `m6.rs` handler

Want me to write `gw.rs` now? I'll need the GW parameter layout from the Thales payShield Host Commands manual (payload length 96 bytes observed). If you have the manual section handy, paste it and I'll derive the field offsets directly.
