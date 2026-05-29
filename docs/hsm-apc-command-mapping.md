# HSM ↔ APC Cross-Vendor Command Alignment

Each row is a logical payment operation anchored to the APC API. The vendor columns show which HSM command codes map to that operation, making cross-vendor equivalence and gaps immediately visible.

**How to read this:**
- Same row → functionally equivalent commands across vendors
- `—` → vendor has no command for this operation
- Multiple codes in a cell → sub-variants or alternate command names for the same function
- `[m]` → medium confidence (reference/community source; wire detail may differ)
- `[d]` → directory quality (name and category only; no wire format; Atalla/NCR)
- Commands **in bold** are the most common form seen in acquirer/processor codebases

**Vendors:** Thales payShield 10K (International/Core and Legacy command sets), Futurex Excrypt Enterprise SSP v.2, Atalla/NCR

---

## PIN Translation

*Translating a PIN block between encryption keys without exposing the clear PIN.*

| Operation | APC Call | Key Type | Thales International/Core | Thales Legacy | Futurex Excrypt | Atalla |
|-----------|----------|----------|--------------------------|---------------|-----------------|--------|
| ZPK/TPK → ZPK (symmetric) | `translate_pin_data` | `TR31_P0` | **CA**, **CC**, BQ | KC, GC [see note] | **TPIN**, XPIN, TPDD | 31, 33, 335 |
| DUKPT → ZPK (3DES DUKPT) | `translate_pin_data` | `TR31_B0` + KSN | **CI**, G0 | — | **TPIN** | 346 |
| DUKPT → ZPK (AES DUKPT) | `translate_pin_data` | `TR31_B0` + KSN | **CI** | — | **TPIN** | — |
| RSA-encrypted PIN → ZPK | `translate_pin_data` | `TR31_P0` | AQ | — | TRPN | — |
| ZPK → RSA-encrypted PIN | `translate_pin_data` | `TR31_P0` | — | — | TSPN | — |
| PIN block format conversion | `translate_pin_data` | `TR31_P0` | BQ | — | — | 33, 335 |
| LMK internal re-encryption | `translate_pin_data` | `TR31_P0` | JC, JE, JG [m] | — | — | — |
| Double-encrypted PIN translate | `translate_pin_data` | `TR31_P0` | — | — | — | 35 [d] |
| DUKPT → 3DES + verify MAC | `translate_pin_data` | `TR31_B0` | — | — | — | 346, 347 [d] |

> **Note on LMK (JC/JE/JG):** These are internal HSM re-encryption operations. In APC there is no LMK concept — keys are identified by ARN. Translate-to-LMK = import/create in APC; translate-from-LMK = use the ARN directly.

> **Note on GC (Legacy):** In the Legacy set, GC = "Translate ZPK from LMK to ZMK Encryption." In the International/Core set, GC = "Generate ZMK Component" (medium confidence). Same response code GD; check surrounding context to identify which is in use.

---

## PIN Verification

*Verifying a cardholder PIN against a stored offset, PVV, or reference PIN.*

| Operation | APC Call | Key Type | Thales International/Core | Thales Legacy | Futurex Excrypt | Atalla |
|-----------|----------|----------|--------------------------|---------------|-----------------|--------|
| IBM 3624 — terminal key | `verify_pin_data` | `TR31_V1` | DA [m], CG | — | VPIN | 32 [d] |
| IBM 3624 — interchange (ZPK) | `verify_pin_data` | `TR31_V1` | EA [m], EG | — | VPIN | 32 [d] |
| IBM 3624 — DUKPT (3DES) | `verify_pin_data` | `TR31_B0` | **CK**, GO | CO | — | — |
| IBM 3624 — DUKPT (3DES & AES) | `verify_pin_data` | `TR31_B0` | GO | — | — | — |
| Visa PVV — terminal key | `verify_pin_data` | `TR31_V2` | DC [m] | — | VPIN | 32 [d] |
| Visa PVV — interchange (ZPK) | `verify_pin_data` | `TR31_V2` | EC [m] | — | VPIN | 32 [d] |
| Visa PVV — DUKPT (3DES) | `verify_pin_data` | `TR31_B0` | **CM** | — | — | — |
| Visa PVV — DUKPT (3DES & AES) | `verify_pin_data` | `TR31_B0` | GQ | — | — | — |
| Diebold — terminal key | `verify_pin_data` | `TR31_V1` | CG | — | — | — |
| Diebold — interchange | `verify_pin_data` | `TR31_V1` | EG | — | — | — |
| Diebold — DUKPT (3DES) | `verify_pin_data` | `TR31_B0` | GS | CO | — | — |
| Diebold — DUKPT (3DES & AES) | `verify_pin_data` | `TR31_B0` | GS | — | — | — |
| Comparison — terminal key | `verify_pin_data` | `TR31_P0` | BC | — | — | — |
| Comparison — interchange | `verify_pin_data` | `TR31_P0` | BE | — | — | — |
| Encrypted PIN — DUKPT | `verify_pin_data` | `TR31_B0` | GU | CQ | — | — |
| Card + PIN combined | `verify_pin_data` | `TR31_V1` or `TR31_V2` | — | — | VMAP [see note] | 3A [d] |

> **TDES DUKPT prohibition:** CK, CM, CO, CQ, and the TDES variants of GO/GQ/GS/GU are prohibited for new deployments since January 2023 (PCI PIN Req 2-2). Migrate to AES DUKPT.

> **VMAP (Futurex):** VMAP combines MAC verification and PIN verification in one command. APC requires two separate calls. CO (Thales Legacy) also combined Diebold DUKPT verify but is superseded by GS.

---

## PIN Generation / Offset

*Generating a PIN, PIN offset, or PVV for card issuance or PIN change flows.*

| Operation | APC Call | Key Type | Thales International/Core | Thales Legacy | Futurex Excrypt | Atalla |
|-----------|----------|----------|--------------------------|---------------|-----------------|--------|
| IBM 3624 natural PIN derivation | `generate_pin_data` | `TR31_V1` | EE | — | — | — |
| IBM 3624 offset — LMK-encrypted PIN | `generate_pin_data` | `TR31_V1` | DE | — | — | 3D [d] |
| IBM 3624 offset — customer-selected | `generate_pin_data` | `TR31_V1` | BK | — | — | 30A [d], 37B [d] |
| Diebold PIN derivation | `generate_pin_data` | `TR31_V1` | GA | — | — | — |
| Diebold offset | `generate_pin_data` | `TR31_V1` | CE | — | — | — |
| Visa PVV — LMK-encrypted PIN | `generate_pin_data` | `TR31_V2` | DG | — | — | — |
| Visa PVV — customer-selected | `generate_pin_data` | `TR31_V2` | FW | — | — | — |
| Random PIN generation | `generate_pin_data` | `TR31_P0` | JA [m] | — | RPIN | — |
| Clear PIN ingest to LMK | `generate_pin_data` | `TR31_P0` | BA [m] | — | — | — |
| Verify PIN + generate IBM offset (atomic) | `verify_pin_data` + `generate_pin_data` | `TR31_V1` | DU | — | — | — |
| Verify PIN + generate Visa PVV (atomic) | `verify_pin_data` + `generate_pin_data` | `TR31_V2` | CU | — | — | — |
| EMV offline PIN change | `generate_mac_emv_pin_change` | `TR31_E2` + `TR31_E1` | — | — | EMVP | 351 [d] |
| Weak PIN check | *(none — application logic)* | — | — | — | WPIN | — |
| Clear PIN exposure (mailer/print) | *(no APC equivalent — PCI prohibited)* | — | NG [m] | — | — | — |

> **DU / CU (Thales):** APC has no atomic verify+generate. Split into sequential `verify_pin_data` → `generate_pin_data` calls.

> **BA / JA (Thales):** Clear PIN input is only permitted at PCI PTS-certified entry devices. APC's `generate_pin_data` does not accept clear PINs directly.

> **NG (Thales):** Exposing a clear PIN from an HSM violates PCI PIN Req 3-1. APC has no equivalent by design.

---

## Card Verification (CVV / CVC / dCVV / CVC3)

*Generating and verifying card verification values.*

| Operation | APC Call | Key Type | Thales International/Core | Thales Legacy | Futurex Excrypt | Atalla |
|-----------|----------|----------|--------------------------|---------------|-----------------|--------|
| Generate CVV / CVV2 / CVC | `generate_card_validation_data` | `TR31_C0` | **CW** | — | — | 5D [d] |
| Verify CVV / CVV2 / CVC | `verify_card_validation_data` | `TR31_C0` | **CY** | — | VCVV, VCVC | 5E [d] |
| Verify CVC2 / CVV2 (card-not-present) | `verify_card_validation_data` | `TR31_C0` | RY | — | VCVC | 5E [d] |
| Verify Amex CSC / CID | `verify_card_validation_data` | `TR31_C0` | — | — | VCSC | 35A [d], 35B [d] |
| Verify CAVV / AAV (3D Secure) | `verify_card_validation_data` | `TR31_C0` | — | — | VAAV | — |
| Generate dynamic CVV (dCVV) | `generate_card_validation_data` | `TR31_E4` | QY | — | — | — |
| Verify dynamic CVV / CVC | `verify_card_validation_data` | `TR31_E4` | PM | — | — | 357 [d] |
| Calculate or verify CVC2/CVV2/CID | `generate_card_validation_data` or `verify_card_validation_data` | `TR31_C0` | RY | — | — | — |
| Generate Mastercard CVC3 (contactless) | `generate_card_validation_data` | `TR31_E4` | NY | — | — | 359 [d] |
| Verify Discover dCVV | `verify_card_validation_data` | `TR31_C0` | — | — | — | 35F [d] |
| Verify Visa Token (cloud-based) | `verify_card_validation_data` | `TR31_C0` | — | — | — | 365 [d] |
| Verify Amex Expresspay | `verify_card_validation_data` | `TR31_C0` | — | — | — | 36A [d] |

> **C0 vs E4 (dynamic CVV):** Static CVV operations (CW/CY, CVV1/CVV2/iCVV) use `TR31_C0_CARD_VERIFICATION_KEY` (TDES_2KEY only). Dynamic CVV commands (QY/PM for Visa dCVV, NY for Mastercard CVC3) use `TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS` — an EMV master key that requires session-key derivation (DeriveKey mode). Using C0 for QY/PM/NY will fail at the APC layer.

---

## MAC / HMAC

*Generating and verifying Message Authentication Codes.*

| Operation | APC Call | Key Type | Thales International/Core | Thales Legacy | Futurex Excrypt | Atalla |
|-----------|----------|----------|--------------------------|---------------|-----------------|--------|
| Generate MAC — CBC-MAC / CMAC | `generate_mac` | `TR31_M1` or `TR31_M6` | **M6**, MA | MK, MQ, MU | GMAC, GPMC | 98 [d] |
| Verify MAC — CBC-MAC / CMAC | `verify_mac` | `TR31_M1` or `TR31_M6` | **M8**, MC | MM, MW | VMAC | 99 [d] |
| Verify + translate MAC (gateway re-MAC) | `verify_mac` + `generate_mac` | `TR31_M1` or `TR31_M6` | MY | **ME**, MO | — | 58 [d] |
| Generate MAC — ANSI X9.19 Retail MAC | `generate_mac` | `TR31_M3` | — | MS | — | — |
| Generate MAC — DUKPT | `generate_mac` | `TR31_B0` | **GW** | — | — | 386 [d] |
| Verify MAC — DUKPT | `verify_mac` | `TR31_B0` | GW | — | — | 348 [d] |
| Verify + generate MAC — Visa DUKPT | `verify_mac` + `generate_mac` | `TR31_B0` | — | — | — | 5C [d] |
| Verify MAC + decrypt PIN | `verify_mac` + `translate_pin_data` | `TR31_M3` + `TR31_P0` | — | — | — | 5F [d] |
| Generate MAC — AS2805 | `generate_mac` | `TR31_M0` | C2 | — | — | — |
| Verify MAC — AS2805 | `verify_mac` | `TR31_M0` | C4 | — | — | — |
| Generate MAC — EMV | `generate_mac` | `TR31_M6` | — | — | EMVM | 352 [d] |
| Generate HMAC (SHA-1/224/256/384/512) | `generate_mac` | `TR31_M7` | LQ | — | HMAC | 39B [d] |
| Verify HMAC | `verify_mac` | `TR31_M7` | LS | — | — | 39C [d] |
| Generate MAC + encrypt data | `generate_mac` + `encrypt_data` | `TR31_M6` + `TR31_D0` | — | — | — | 59 [d] |
| Generate CMAC — TDES | `generate_mac` | `TR31_M6` | — | — | — | 305 [d] |
| Verify CMAC — TDES | `verify_mac` | `TR31_M6` | — | — | — | 304 [d] |

> **MY / ME:** APC requires two calls. Prefer CMAC (`TR31_M6`) over CBC-MAC (`TR31_M1`) for new work. Retail MAC (`TR31_M3`) is a legacy construct.

> **M6 wire format:** The payShield M6 wire includes Mode Flag, Input Format, MAC Size, Algorithm, Padding Method, and Key Type fields before the key material. Proxy implementations that omit these fields are not wire-compatible with a real payShield.

---

## EMV / ARQC

*EMV cryptogram verification, ARPC generation, and issuer secure messaging.*

| Operation | APC Call | Key Type | Thales International/Core | Thales Legacy | Futurex Excrypt | Atalla |
|-----------|----------|----------|--------------------------|---------------|-----------------|--------|
| Verify ARQC / generate ARPC (Visa/MC static) | `verify_auth_request_cryptogram` | `TR31_E0` | **KQ** | — | EMVA | 350 [d] |
| Verify ARQC / generate ARPC (extended derivation) | `verify_auth_request_cryptogram` | `TR31_E0` | KW | — | EMVA | — |
| Verify ARQC / generate ARPC (UnionPay) | `verify_auth_request_cryptogram` | `TR31_E0` | — | JS | — | — |
| Mastercard CAP / UCAF verification | `verify_auth_request_cryptogram` | `TR31_E0` | K2 | — | — | — |
| DAC + Dynamic Number verification (EMV 3.1.1) | `verify_auth_request_cryptogram` | `TR31_E0` | KS | — | — | — |
| Issuer secure message MAC (EMV 3.1.1) | `generate_mac_emv_pin_change` | `TR31_E2` | KU | — | — | — |
| Issuer secure message MAC (EMV 4.x) | `generate_mac_emv_pin_change` | `TR31_E2` | KY | — | — | — |
| Decrypt EMV 4.x chip counters | `decrypt_data` | `TR31_E1` | K0 | — | — | — |

> **KQ wire format:** All multibyte fields (PAN+Seq, ATC, UN, Transaction Data, ARQC) are raw binary (not hex-encoded ASCII). Proxy implementations using hex ASCII require format adaptation.

> **KW:** Requires the Premium package license on the payShield device. Supports Visa CVN14/18/22, MC M/Chip, Amex, Discover, JCB, UnionPay, and cloud-based (token) SKD variants.

---

## Data Encryption / Decryption

*Encrypting and decrypting general data blocks (not PINs).*

| Operation | APC Call | Key Type | Thales International/Core | Thales Legacy | Futurex Excrypt | Atalla |
|-----------|----------|----------|--------------------------|---------------|-----------------|--------|
| Encrypt data (AES/3DES, various modes) | `encrypt_data` | `TR31_D0` | **M0** | — | — | 55 [d], 97 [d], 390 [d] |
| Decrypt data (AES/3DES, various modes) | `decrypt_data` | `TR31_D0` | **M2** | — | — | 55 [d], 97 [d] |
| Terminal authentication MAC generate | `generate_mac` | `TR31_M3` | — | HE [see note] | — | — |
| Terminal authentication MAC verify | `verify_mac` | `TR31_M3` | — | HG [see note] | — | — |
| Re-encrypt data (key-to-key translate) | `re_encrypt_data` | `TR31_D0` | **M4** | — | — | 55 [d] |
| Encrypt cardholder data — DUKPT | `encrypt_data` | `TR31_B0` | M0 (BDK mode) | — | ECDK | 388 [d] |
| Decrypt cardholder data — DUKPT | `decrypt_data` | `TR31_B0` | M2 (BDK mode) | — | DCDK | 388 [d] |
| Translate cardholder data — DUKPT | `re_encrypt_data` | `TR31_B0` | M4 (BDK mode) | — | TCDK | — |
| Encrypt/decrypt data — AES | `encrypt_data` or `decrypt_data` | `TR31_D0` | M0/M2 (AES mode) | — | — | 390 [d] |
| Hash a data block | *(none — application code)* | — | GM | — | — | — |
| RSA signature generation | *(none — use AWS KMS)* | — | EW | — | — | — |
| RSA signature verification | *(none — use AWS KMS)* | — | EY | — | — | — |

> **HE / HG (Thales Legacy):** HE generates a MAC and HG verifies a MAC — both use a TAK (TR31_M3, LMK pair 16-17). Despite the "Encrypt/Decrypt" naming in the payShield manual, these are MAC operations and APC maps them to `generate_mac`/`verify_mac` with `TR31_M3_ISO_9797_3_MAC_KEY`. Using `encrypt_data` (D0 key) would be rejected by APC. Superseded by M0/M2 for data encryption; use M6/M8 for MAC.

> **M0/M2/M4 modes:** ECB (00), CBC (01), CFB8/64 (02/03), OFB (05), CTR (06), FF1 FPE (11), Visa Standard Enc / Visa FPE (04/13, license required). For DUKPT keys, use the BDK key type codes (009/609/809/909). M4 restriction: only one of source or destination may be a BDK key.

---

## Key Management

*Creating, importing, exporting, and translating cryptographic keys.*

| Operation | APC Call | Key Type | Thales International/Core | Thales Legacy | Futurex Excrypt | Atalla |
|-----------|----------|----------|--------------------------|---------------|-----------------|--------|
| **Generate Keys** | | | | | | |
| Generate any symmetric key | `create_key` | *(per key type)* | A0 [m] | — | GPGS | 10 [d], 39A [d] |
| Generate PIN encryption key (ZPK/TPK) | `create_key` | `TR31_P0` | IA [m], KG [m] | HC | GPGS | — |
| Generate BDK (DUKPT) | `create_key` | `TR31_B0` | — | BI | GPGS | 1E [d] |
| Generate CVK | `create_key` | `TR31_C0` | — | AS | — | — |
| Generate PVK | `create_key` | `TR31_V1` or `TR31_V2` | — | FG | — | — |
| Generate TAK (MAC key) | `create_key` | `TR31_M3` | — | HA | — | — |
| Generate HMAC key | `create_key` | `TR31_M7` | L0 | — | — | — |
| Derive card-unique EMV key | `create_key` | `TR31_E0` | KI | — | — | — |
| **Import Keys** | | | | | | |
| Import key via TR-31 key block | `import_key` | `TR31_K1` | A6 [m] | — | GKBL | 117 [d] |
| Import key via TR-34 (asymmetric RKL) | `import_key` | `TR31_K1` | — | — | PEDK | 136 [d] |
| Form key from encrypted components | `import_key` | `TR31_K1` | A4, FK [m] | GG, GY | — | — |
| Import ZMK from ZMK encryption | `import_key` | `TR31_K1` | BY | GE | — | — |
| Import key under KTK | `import_key` | `TR31_K1` | HY | — | — | — |
| Import ZPK from ZMK | `import_key` | `TR31_P0` | — | FA | — | — |
| Import TAK from ZMK | `import_key` | `TR31_M3` | — | MI | — | — |
| Import CVK from ZMK | `import_key` | `TR31_C0` | — | AW | — | — |
| Import BDK from ZMK | `import_key` | `TR31_B0` | — | DW | — | — |
| Import AKB (Atalla Key Block) | `import_key` | — | — | — | — | 13 [d] |
| **Export Keys** | | | | | | |
| Export key via TR-31 key block | `export_key` | `TR31_K1` | A8 [m] | — | GKBL | 118 [d] |
| Export key via TR-34 (asymmetric RKL) | `export_key` | `TR31_K1` | B8 | — | PEDK | 136 [d] |
| Export key under KEK | `export_key` | `TR31_K1` | K8 | — | — | — |
| Translate key scheme (variant→TR-31) | `export_key` | `TR31_K1` | B0 | — | — | — |
| Export ZPK under ZMK | `export_key` | `TR31_P0` | — | KC, GC, FE | — | — |
| Export TAK under ZMK | `export_key` | `TR31_M3` | — | AG, MG | — | — |
| Export CVK under ZMK | `export_key` | `TR31_C0` | — | AU | — | — |
| Export BDK under ZMK | `export_key` | `TR31_B0` | — | DY | — | — |
| Export TMK/TPK/PVK | `export_key` | `TR31_P0` | — | AA, AE, FE | — | — |
| Export AKB (Atalla Key Block) | `export_key` | — | — | — | — | 11 [d], 1A [d] |
| **Key Verification** | | | | | | |
| Generate KCV | *(none — KCV in APC response)* | — | BU [m] | KA | — | — |
| Generate DUKPT initial key (Visa DUKPT) | `create_key` | `TR31_B0` | — | — | — | 1E [d] |
| Generate TR-31 from cryptogram | `import_key` | `TR31_K1` | — | — | GKBL | — |
| Modify TR-31 key block header | *(none — export, modify, re-import)* | — | CS | — | — | — |

> **GC (Thales Legacy translate):** Command GC = "Translate ZPK from LMK to ZMK" in the Legacy set. In International/Core, GC = "Generate ZMK Component" (medium confidence). Both have response code GD — check the surrounding context.

> **B0 / GKBL:** The PCI PIN 18-3 migration path. Converts variant-encrypted (LMK) keys to TR-31 key blocks. B0 is the payShield command; GKBL is the Futurex equivalent.

> **KA / BU:** APC automatically includes the KCV in all `create_key` and `import_key` responses — no separate API call is needed. AES keys must use CMAC-based KCV per PCI PIN Annex C (never ECB-zeros).

---

## Operations with No APC Equivalent

*HSM commands that perform functions APC does not expose. Each entry notes the recommended alternative.*

| Function | Thales International/Core | Thales Legacy | Futurex Excrypt | Atalla | Alternative |
|----------|--------------------------|---------------|-----------------|--------|-------------|
| Clear PIN exposure (mailer/print) | NG [m] | — | — | — | Not replaceable with APC. APC never exposes clear PINs (PCI PIN Req 3-1). |
| Weak PIN check | — | — | WPIN | — | Implement in application code (blocked PIN list lookup). |
| RSA signature generation | EW | — | — | — | AWS KMS `Sign` API (RSA key). |
| RSA signature verification | EY | — | — | — | AWS KMS `Verify` API (RSA key). |
| Cryptographic hashing | GM | — | — | — | Application code (`hashlib`, `MessageDigest`, etc.). |
| Random byte generation | N0 | — | ECHO [diag] | — | AWS KMS `GenerateRandom` or CSPRNG in the runtime. |
| HSM status / firmware version | NO | — | — | — | AWS CloudWatch (`AWS/PaymentCryptography`), AWS Console. |
| HSM diagnostics / self-test | NC [m] | — | — | — | AWS service health checks. |
| Host / connectivity test | QH [m] | — | ECHO | B2 [proxy] | AWS service health checks. |
| Key component XOR ceremony | GC [m], FK [m] | GG, GY | — | — | Ceremony performed out-of-band; result imported into APC via TR-34/TR-31. |

---

## Combined Operations (APC Requires Two Calls)

These HSM commands perform two operations atomically. APC exposes them as separate API calls.

| HSM Command | What it does | APC Equivalent |
|-------------|--------------|----------------|
| DU (Thales) | Verify PIN + generate IBM 3624 offset | `verify_pin_data` → `generate_pin_data` |
| CU (Thales) | Verify PIN + generate Visa PVV | `verify_pin_data` → `generate_pin_data` |
| MY (Thales) | Verify MAC + generate MAC (re-MAC) | `verify_mac` → `generate_mac` |
| ME (Thales Legacy) | Verify MAC + generate MAC | `verify_mac` → `generate_mac` |
| MO (Thales Legacy) | Verify binary MAC + generate binary MAC | `verify_mac` → `generate_mac` |
| VMAP (Futurex) | Verify MAC + verify PIN | `verify_mac` + `verify_pin_data` |
| 39 (Atalla) [d] | Translate PIN + generate MAC | `translate_pin_data` + `generate_mac` |
| BA (Atalla) [d] | PIN translate (ANSI→PIN/Pad) + verify MAC | `translate_pin_data` + `verify_mac` |
| 5F (Atalla) [d] | Verify MAC + decrypt PIN | `verify_mac` + `translate_pin_data` |

---

## Adding Futurex Excrypt Detail (Planned)

The Futurex Excrypt commands (TPIN, EMVA, GMAC, DCDK, GKBL, etc.) are already in the `hsm_analysis.py` registry. To add them to the tables above, fill in the **Futurex Excrypt** column cells that currently show `—`. All Excrypt commands use 4-character uppercase codes wrapped in `[AO<CCCC>;...]` brackets on the wire.

## Adding Atalla/NCR Detail (Planned)

Atalla commands use numeric codes (10, 31, 32, 304, etc.) at directory quality — function names and APC mappings are known, but wire protocol detail is not publicly documented. The `[d]` entries above represent the current coverage. To promote entries from directory to reference quality, the Atalla wire format documentation would be needed.

---

*The `hsm_lookup_command`, `hsm_list_commands`, and `hsm_analyze_code` MCP tools query the underlying registry in `src/apc_agent/hsm_analysis.py` — use them for interactive lookup and source code scanning. This document is the human-readable cross-vendor view of the same data.*
