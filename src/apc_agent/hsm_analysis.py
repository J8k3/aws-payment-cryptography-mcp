"""
HSM vendor command pattern recognition for code analysis and refactoring (R8).

Sources and confidence levels:
  Futurex Excrypt API:       AUTHORITATIVE — Futurex General Payment HSM Integration Guide (2024)
                             All Futurex commands are 4-character text codes (TPIN, ECHO, EMVA, etc.)
                             wrapped in bracket-delimited frames: [AOCCCC;field;...;]
  Futurex International API: AUTHORITATIVE — same source (Thales payShield-compatible command codes)
  Thales payShield Legacy:   AUTHORITATIVE — payShield 10K Legacy Host Commands (Thales payShield 10K Legacy Host Commands, 2019)
                             Official Thales documentation covering ~80 commands in 10 functional groups.
                             License PS10-LIC-LEGACY required on device.
  Thales payShield Core:     REFERENCE QUALITY — EFTlab knowledge base (commands CA, CC, DA, DC,
                             EA, EC, A0, A6, A8, M0, M2, KQ not in the legacy manual)
  Atalla (NCR):              DIRECTORY QUALITY — EFTlab command list (function names only, no wire detail)
                             Uses numeric command codes (31, 32, 33, 5D, 5E, 304, etc.).
                             Some of these codes were adopted by the Futurex Standard API for
                             Atalla backward-compatibility, but are not seen in Excrypt deployments.
                             Proxy support: not implemented — wire format undocumented.

Wire format (Thales payShield 10K):
  TCP socket (clear or TLS); 2-byte big-endian length prefix; m-byte message header (set at
  installation); 2-char command code; variable-length fields. Response: m-byte header; 2-char
  response code; 2-char error code ('00' = success, '68' = command disabled); fields.
  Key size encoding: 16H = single-DES/TDES; 'U' + 32H = double-length TDES key block;
  'T' + 48H = triple-length; 'S' + n A = TR-31 key block. STX/ETX control characters
  bracket the message when using asynchronous comms (not shown in field tables).

Key insight: Futurex's International command set uses the same command codes as Thales payShield
(CA, CC, CI, CW, CY, M6, M8, MA, etc.). Code that appears to target "Thales International" commands
may actually be running against a Futurex HSM in International compatibility mode.

Socket connection patterns:
  Futurex Excrypt/Standard:  TCP socket with mTLS; commands wrapped in [ ] delimiters,
                             fields separated by semicolons; e.g. [TPIN;...;]
  Futurex International:     TCP socket with mTLS; no delimiters; fixed-length fields;
                             command determined by first 2 chars + field offsets
  Thales payShield:          TCP socket (clear or TLS); 2-byte length prefix + 2-char command code
                             + variable-length fields; response = 2-char response code + fields
"""

from dataclasses import dataclass, field


@dataclass
class HsmCommand:
    """Represents a single HSM command and its APC mapping."""
    vendor: str
    api: str                        # Excrypt, Standard, International
    command_code: str               # e.g. "TPIN", "CA", "31"
    name: str
    category: str                   # PIN, MAC, CVV, KEY_MGMT, ENCRYPT, ARQC, P2PE
    description: str
    apc_operation: str | None       # Corresponding APC data/control plane operation
    apc_key_type: str | None        # Required APC key usage code
    notes: str = ""
    confidence: str = "high"        # high, medium (reference quality), directory (name+category only)


# ── Futurex Excrypt API ───────────────────────────────────────────────────────
# Source: Futurex General Payment HSM Integration Guide (2024) — AUTHORITATIVE
# Command format: [COMMAND_CODE;field1;field2;...;]
# mTLS socket connection required in production

FUTUREX_EXCRYPT_COMMANDS: list[HsmCommand] = [
    # PIN Translation and Verification
    HsmCommand("Futurex", "Excrypt", "TPIN", "Translate PIN Block", "PIN",
               "Translates a PIN block between encryption keys. Core acquirer operation.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Most common PIN routing command in Futurex Excrypt deployments. "
               "Supports DUKPT, ZPK, and PEK key types."),
    HsmCommand("Futurex", "Excrypt", "XPIN", "Extended PIN Translation", "PIN",
               "Extended PIN translation supporting additional schemes (IBM4736, PINPad, ANSI to ANSI).",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    HsmCommand("Futurex", "Excrypt", "TPDD", "Translate Encrypted ANSI PIN Block", "PIN",
               "Allows an encrypted ANSI PIN block to be translated.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    HsmCommand("Futurex", "Excrypt", "TRPN", "Translate PIN from RSA to Symmetric PIN Block", "PIN",
               "Translates a PIN block from RSA encryption to symmetric (ZPK/PEK).",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    HsmCommand("Futurex", "Excrypt", "TSPN", "Translate PIN from PIN Block to RSA Encryption", "PIN",
               "Translates a PIN block from symmetric to RSA encryption.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    HsmCommand("Futurex", "Excrypt", "VPIN", "Verify PIN", "PIN",
               "Verifies a cardholder PIN against a stored PVV or offset.",
               "verify_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY or TR31_V2_VISA_PIN_VERIFICATION_KEY"),
    HsmCommand("Futurex", "Excrypt", "VMAP", "Verify MAC and PIN", "PIN",
               "Verifies MAC and PIN in a single operation. Diebold, IBM3624, and Visa methods.",
               "verify_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Combined MAC+PIN verify. In APC these are separate operations."),
    HsmCommand("Futurex", "Excrypt", "RPIN", "PIN Change and Optional PIN Verification", "PIN",
               "PIN change with optional verification. IBM3624, IBM3624 DUKPT, Visa, Visa DUKPT.",
               "generate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    HsmCommand("Futurex", "Excrypt", "WPIN", "Weak PIN Checking", "PIN",
               "Checks a PIN against a list of weak/prohibited PINs.",
               None, None,
               "No direct APC equivalent — implement as application logic."),
    # EMV / ARQC
    HsmCommand("Futurex", "Excrypt", "EMVA", "Verify ARQC and Optionally Generate ARPC", "ARQC",
               "Validates EMV Authorization Request Cryptogram and generates ARPC. "
               "Core acquiring EMV validation operation.",
               "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS"),
    HsmCommand("Futurex", "Excrypt", "EMVP", "EMV PIN Change", "PIN",
               "EMV offline PIN change operation.",
               "generate_mac_emv_pin_change",
               "TR31_E2_EMV_MKEY_INTEGRITY + TR31_E1_EMV_MKEY_CONFIDENTIALITY"),
    # CVV Validation (Acquiring)
    HsmCommand("Futurex", "Excrypt", "VCVV", "Verify CVV/CVC Value", "CVV",
               "Verifies a CVV or CVC value for card-not-present transaction validation.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY"),
    HsmCommand("Futurex", "Excrypt", "VCVC", "Verify CVC and CVC2", "CVV",
               "Verifies CVC (magnetic stripe) and CVC2 (card-not-present) values.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY"),
    HsmCommand("Futurex", "Excrypt", "VCSC", "Verify Amex CSC Value", "CVV",
               "Verifies an American Express Card Security Code.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY"),
    HsmCommand("Futurex", "Excrypt", "VAAV", "Verify Account Holder Authentication Value", "CVV",
               "Verifies CAVV/AAV for 3D Secure transactions.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY"),
    # MAC
    HsmCommand("Futurex", "Excrypt", "GMAC", "Generate Message Authentication Code", "MAC",
               "Generates a MAC for transaction data integrity.",
               "generate_mac", "TR31_M6_ISO_9797_5_CMAC_KEY or TR31_M3_ISO_9797_3_MAC_KEY"),
    HsmCommand("Futurex", "Excrypt", "VMAC", "Verify Message Authentication Code", "MAC",
               "Verifies a MAC.",
               "verify_mac", "TR31_M6_ISO_9797_5_CMAC_KEY or TR31_M3_ISO_9797_3_MAC_KEY"),
    HsmCommand("Futurex", "Excrypt", "GPMC", "General Purpose Symmetric MAC", "MAC",
               "General-purpose symmetric MAC generation.",
               "generate_mac", "TR31_M6_ISO_9797_5_CMAC_KEY"),
    HsmCommand("Futurex", "Excrypt", "HMAC", "Generate MAC Hash", "MAC",
               "Generates an HMAC.",
               "generate_mac", "TR31_M7_HMAC_KEY"),
    HsmCommand("Futurex", "Excrypt", "EMVM", "Generate/Verify MAC (EMV)", "MAC",
               "EMV-specific MAC generation and verification.",
               "generate_mac", "TR31_M6_ISO_9797_5_CMAC_KEY"),
    # P2PE / Encryption
    HsmCommand("Futurex", "Excrypt", "DCDK", "Decrypt Cardholder Data Using DUKPT", "P2PE",
               "Decrypts cardholder PAN data encrypted under DUKPT at the terminal.",
               "decrypt_data", "TR31_B0_BASE_DERIVATION_KEY"),
    HsmCommand("Futurex", "Excrypt", "ECDK", "Encrypt Cardholder Data Using DUKPT", "P2PE",
               "Encrypts cardholder data under DUKPT.",
               "encrypt_data", "TR31_B0_BASE_DERIVATION_KEY"),
    HsmCommand("Futurex", "Excrypt", "TCDK", "Translate Cardholder Data Using DUKPT", "P2PE",
               "Translates cardholder data between DUKPT keys without exposing plaintext.",
               "re_encrypt_data", "TR31_B0_BASE_DERIVATION_KEY"),
    # Remote Key Loading
    HsmCommand("Futurex", "Excrypt", "PEDK", "Key Request (TR-34 Remote Key Loading)", "KEY_MGMT",
               "TR-34 key distribution. Supports two-pass (Mode 1), one-pass TR-34 (Mode 2), "
               "and one-pass with AES. Core remote key loading command.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Maps to APC get_parameters_for_import + import_key TR-34 flow."),
]

# ── Futurex/Thales International Commands ────────────────────────────────────
# IMPORTANT: Futurex International API is Thales payShield compatible.
# These command codes appear in BOTH Thales payShield and Futurex International mode codebases.
# Fixed-length fields, no delimiters. First 2 characters = command code.
# Thales response: 2-char response code where "00" = success.

INTERNATIONAL_COMMANDS: list[HsmCommand] = [
    # PIN Translation — most common acquirer operations
    HsmCommand("Thales/Futurex", "International", "CA",
               "Translate PIN Block from TPK to PEK Encryption", "PIN",
               "Translates a PIN block from Terminal PIN Key (TPK) to Zone PIN Key (ZPK/PEK). "
               "ATM terminal to acquirer host — the most common inter-zone PIN routing command.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Inbound key is a TPK (TR31_P0), outbound is ZPK (TR31_P0). "
               "Watch for Format 0 (TDES) — recommend Format 4 migration."),
    HsmCommand("Thales/Futurex", "International", "CC",
               "Translate PIN Block from PEK to PEK Encryption", "PIN",
               "Translates a PIN block from one Zone PIN Key to another. "
               "Host-to-host PIN routing between network participants.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Both inbound and outbound are ZPK/PEK (TR31_P0). "
               "Fixed TDES keys for this operation disallowed since Jan 2023 (PCI PIN Req 2-2)."),
    HsmCommand("Thales/Futurex", "International", "CI",
               "Translate PIN Block from BDK to PEK Encryption (DUKPT)", "PIN",
               "Translates a DUKPT-encrypted PIN block to a ZPK. "
               "Terminal DUKPT to acquirer host — modern DUKPT ingest.",
               "translate_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "Inbound is BDK (TR31_B0) with KSN. Outbound is ZPK (TR31_P0). "
               "Prefer AES DUKPT (AES BDK) over TDES DUKPT for new deployments."),
    HsmCommand("Thales/Futurex", "International", "G0",
               "Translate PIN from BDK to ZPK Encryption (3DES DUKPT)", "PIN",
               "3DES DUKPT PIN translation — Futurex-specific variant of CI.",
               "translate_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "TDES DUKPT — legacy. Migrate to AES DUKPT when possible."),
    HsmCommand("Thales/Futurex", "International", "JC",
               "Translate PIN from TPK to LMK Encryption", "PIN",
               "Translates from terminal key to Local Master Key encryption. "
               "Used internally before re-encryption under outbound key.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "LMK is the HSM's internal master key. In APC, keys are always under APC's custody. "
               "No direct LMK concept — use translate_pin_data with appropriate inbound/outbound keys."),
    HsmCommand("Thales/Futurex", "International", "JE",
               "Translate PIN from ZPK to LMK Encryption", "PIN",
               "Translates from ZPK to LMK.", "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    HsmCommand("Thales/Futurex", "International", "JG",
               "Translate PIN from LMK to ZPK Encryption", "PIN",
               "Translates from LMK to ZPK.", "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    # PIN Verification
    HsmCommand("Thales/Futurex", "International", "DA",
               "Verify Terminal PIN Block — IBM3624", "PIN",
               "Verifies a PIN using the IBM3624 method.",
               "verify_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY"),
    HsmCommand("Thales/Futurex", "International", "DC",
               "Verify Terminal PIN Block — Visa", "PIN",
               "Verifies a PIN using the Visa PVV method.",
               "verify_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY"),
    HsmCommand("Thales/Futurex", "International", "EA",
               "Verify PIN — IBM3624", "PIN",
               "IBM3624 PIN verification.", "verify_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY"),
    HsmCommand("Thales/Futurex", "International", "EC",
               "Verify PIN — Visa", "PIN",
               "Visa PVV PIN verification.", "verify_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY"),
    HsmCommand("Thales/Futurex", "International", "CK",
               "Verify PIN using IBM Method (DUKPT)", "PIN",
               "IBM3624 PIN verification with DUKPT.",
               "verify_pin_data", "TR31_B0_BASE_DERIVATION_KEY"),
    HsmCommand("Thales/Futurex", "International", "CM",
               "Verify PIN using Visa PVV Method", "PIN",
               "Visa PVV PIN verification.", "verify_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY"),
    # CVV
    HsmCommand("Thales/Futurex", "International", "CW",
               "Generate Visa Card Verification Value (CVV)", "CVV",
               "Generates CVV/CVV2 for Visa cards. Also used for iCVV with service code 999.",
               "generate_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "Thales response code: CX. Parameters: CVK (under LMK), PAN, expiry date, service code."),
    HsmCommand("Thales/Futurex", "International", "CY",
               "Verify Visa Card Verification Value (CVV)", "CVV",
               "Verifies CVV/CVV2 for acquirer/processor card validation.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "Thales response code: CZ. Parameters: CVK, PAN, expiry date, service code, CVV to verify."),
    # MAC
    HsmCommand("Thales/Futurex", "International", "M6",
               "Generate MAC using MAK (supports continuation mode)", "MAC",
               "Generates a MAC using a Message Authentication Key (MAK). "
               "Supports multi-block continuation mode for large messages.",
               "generate_mac", "TR31_M1_ISO_9797_1_MAC_KEY or TR31_M6_ISO_9797_5_CMAC_KEY",
               "CBC-MAC algorithm. Consider migrating to CMAC (M6 key type in APC)."),
    HsmCommand("Thales/Futurex", "International", "M8",
               "Verify MAC using MAK (supports continuation mode)", "MAC",
               "Verifies a MAC using a Message Authentication Key.",
               "verify_mac", "TR31_M1_ISO_9797_1_MAC_KEY or TR31_M6_ISO_9797_5_CMAC_KEY"),
    HsmCommand("Thales/Futurex", "International", "MA",
               "Generate MAC using MAK", "MAC",
               "Single-block MAC generation.", "generate_mac", "TR31_M1_ISO_9797_1_MAC_KEY"),
    HsmCommand("Thales/Futurex", "International", "MC",
               "Verify MAC using MAK", "MAC",
               "Single-block MAC verification.", "verify_mac", "TR31_M1_ISO_9797_1_MAC_KEY"),
    HsmCommand("Thales/Futurex", "International", "GW",
               "Generate or Verify MAC (3DES DUKPT)", "MAC",
               "DUKPT MAC generation and verification.", "generate_mac", "TR31_B0_BASE_DERIVATION_KEY"),
    HsmCommand("Thales/Futurex", "International", "C2",
               "Generate MAC (AS2805)", "MAC",
               "Australian payment network (Interac-style) MAC generation.",
               "generate_mac", "TR31_M0_ISO_16609_MAC_KEY"),
    HsmCommand("Thales/Futurex", "International", "C4",
               "Verify MAC (AS2805)", "MAC",
               "AS2805 MAC verification.", "verify_mac", "TR31_M0_ISO_16609_MAC_KEY"),
    # ARQC
    HsmCommand("Thales/Futurex", "International", "KQ",
               "ARQC/TC/AAC Verification and/or ARPC Generation", "ARQC",
               "EMV cryptogram verification (ARQC, TC, AAC) and ARPC generation.",
               "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS"),
    # Key Management
    HsmCommand("Thales/Futurex", "International", "A0",
               "Generate a Key", "KEY_MGMT",
               "Generates a new symmetric key under LMK. "
               "Equivalent to creating a key in APC. Response code: A1.",
               "create_key", None,
               "EFTlab source — reference quality. "
               "In APC: use create_key with appropriate KeyUsage code. "
               "APC has no LMK concept — keys are custody of APC HSM.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "A6",
               "Import a Key", "KEY_MGMT",
               "Imports a key encrypted under a KEK. Response code: A7.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "EFTlab source — reference quality. Maps to APC import_key via TR-31.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "A8",
               "Export a Key", "KEY_MGMT",
               "Exports a key encrypted under a KEK. Response code: A9.",
               "export_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "EFTlab source — reference quality. Maps to APC export_key via TR-31.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "IA",
               "Generate a ZPK", "KEY_MGMT",
               "Generates a Zone PIN Key. Response code: IB.",
               "create_key", None,
               "EFTlab source — reference quality. "
               "In APC: create_key with TR31_P0_PIN_ENCRYPTION_KEY usage.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "BU",
               "Generate a Key Check Value", "KEY_MGMT",
               "Generates a KCV for key verification. Response code: BV.",
               None, None,
               "EFTlab source — reference quality. "
               "APC includes KCV in all key creation and import responses. "
               "AES keys must use CMAC method for KCV per PCI PIN Annex C.",
               confidence="medium"),
    # Encryption
    HsmCommand("Thales/Futurex", "International", "M0",
               "Encrypt a Block of Data", "ENCRYPT",
               "Encrypts a data block. Response code: M1.",
               "encrypt_data", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
               "EFTlab source — reference quality.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "M2",
               "Decrypt a Block of Data", "ENCRYPT",
               "Decrypts a data block. Response code: M3.",
               "decrypt_data", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
               "EFTlab source — reference quality.",
               confidence="medium"),
]

# ── Thales payShield 10K Legacy Commands ─────────────────────────────────────
# Source: payShield 10K Legacy Host Commands (Thales payShield 10K Legacy Host Commands, 2019) — AUTHORITATIVE
# These are Thales-specific commands NOT shared with Futurex International mode.
# Commands shared with Futurex (CI, CK, CM, CW, CY, MA, MC, M6, M8, KQ, IA) remain
# in INTERNATIONAL_COMMANDS above. This list covers commands unique to the payShield
# Legacy command set that are relevant to acquirer/processor migration.
# Out-of-scope sections skipped: SEED (Korean algorithm), VisaCash, CEPS (issuer/purse),
# printer commands (OE, OC, TA), and LMK-rekey-only commands (AY).

THALES_LEGACY_COMMANDS: list[HsmCommand] = [
    # ── Key Generation ────────────────────────────────────────────────────────
    HsmCommand("Thales", "Legacy", "HC",
               "Generate a TMK, TPK or PVK", "KEY_MGMT",
               "Generates a random terminal key (TMK, TPK, or PVK), returns it encrypted "
               "under the current TMK/TPK/PVK (16H or U+32H or T+48H) and under LMK pair 14-15. "
               "Response code: HD. Disabled by 'Enforce key type 002 separation' HSM setting.",
               "create_key", "TR31_P0_PIN_ENCRYPTION_KEY",
               "In APC: create_key with TR31_P0_PIN_ENCRYPTION_KEY. No LMK concept — "
               "key returned as APC ARN. TMK hierarchy replaced by TR-34/TR-31 remote key loading."),
    HsmCommand("Thales", "Legacy", "HA",
               "Generate a TAK", "KEY_MGMT",
               "Generates a random Terminal Authentication Key (TAK) encrypted under a TMK "
               "and under LMK pair 16-17. Response code: HB. Takes TMK (LMK pair 14-15) as input.",
               "create_key", "TR31_M3_ISO_9797_3_MAC_KEY",
               "TAK used for CBC-MAC between host and terminal. "
               "In APC: create_key with TR31_M3_ISO_9797_3_MAC_KEY or M6 (CMAC preferred). "
               "No TMK→TAK wrapping concept — APC is the key custody boundary."),
    HsmCommand("Thales", "Legacy", "BI",
               "Generate a BDK", "KEY_MGMT",
               "Generates a Base Derivation Key for DUKPT, returned under LMK pair 28-29 "
               "and optionally under a ZMK. Response code: BJ.",
               "create_key", "TR31_B0_BASE_DERIVATION_KEY",
               "In APC: create_key with TR31_B0_BASE_DERIVATION_KEY. "
               "AES_128 strongly preferred — TDES BDK prohibited for new deployments since Jan 2023."),
    HsmCommand("Thales", "Legacy", "AS",
               "Generate a CVK Pair", "KEY_MGMT",
               "Generates a Visa CVK pair under LMK pair 14-15 variant 4. Response code: AT. "
               "Returns CVK A (16H) + CVK B (16H), or unified CVK A/B (U+32H) with KCV. "
               "Superseded by A0.",
               "create_key", "TR31_C0_CARD_VERIFICATION_KEY",
               "In APC: create_key with TR31_C0_CARD_VERIFICATION_KEY. "
               "APC stores as a single key object; CVK A/B pair maps to one APC CVK."),
    HsmCommand("Thales", "Legacy", "FG",
               "Generate a Pair of PVKs", "KEY_MGMT",
               "Generates a pair of PIN Verification Keys under LMK pair 14-15. Response code: FH. "
               "Returns PVK A and PVK B separately, each with KCV.",
               "create_key", "TR31_V2_VISA_PIN_VERIFICATION_KEY",
               "In APC: create_key with TR31_V2_VISA_PIN_VERIFICATION_KEY (Visa PVV) "
               "or TR31_V1_IBM3624_PIN_VERIFICATION_KEY (IBM offset method)."),
    HsmCommand("Thales", "Legacy", "GG",
               "Form a ZMK from Three ZMK Components", "KEY_MGMT",
               "XORs three clear ZMK components (each entered by a separate custodian) "
               "to form a Zone Master Key under LMK. Response code: GH. "
               "Core dual/triple-control key ceremony command.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "In APC: ZMK ceremony is out-of-band; resulting KEK imported via import_key "
               "using TR-34 (recommended) or TR-31. APC has no component-XOR ceremony command."),
    HsmCommand("Thales", "Legacy", "GY",
               "Form a ZMK from 2 to 9 ZMK Components", "KEY_MGMT",
               "XORs 2 to 9 ZMK components to form a ZMK. Response code: GZ. "
               "Flexible N-of-N variant of GG.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Same APC migration path as GG — TR-34/TR-31 import after out-of-band ceremony."),
    # ── Key Translation / Export ───────────────────────────────────────────────
    HsmCommand("Thales", "Legacy", "AA",
               "Translate a TMK, TPK or PVK", "KEY_MGMT",
               "Re-encrypts a TMK/TPK/PVK from encryption under one terminal key to another. "
               "Response code: AB. Used to update a terminal key under a replacement TMK.",
               "export_key", "TR31_P0_PIN_ENCRYPTION_KEY",
               "In APC: export_key with TR-31 wrapping. TMK hierarchy replaced by "
               "TR-34 remote key loading; no equivalent of this TMK-based re-wrap flow."),
    HsmCommand("Thales", "Legacy", "AE",
               "Translate a TMK, TPK or PVK from LMK to Another TMK, TPK or PVK", "KEY_MGMT",
               "Translates a stored key from LMK encryption to encryption under another terminal key. "
               "Response code: AF. Replaces a terminal key from the HSM database. "
               "Disabled by 'Enforce key type 002 separation' HSM setting.",
               "export_key", "TR31_P0_PIN_ENCRYPTION_KEY",
               "In APC: export_key. No LMK database concept — keys are APC ARNs."),
    HsmCommand("Thales", "Legacy", "AG",
               "Translate a TAK from LMK to TMK Encryption", "KEY_MGMT",
               "Translates a TAK from LMK to TMK encryption for delivery to a terminal. "
               "Response code: AH. Superseded by A8 (Export Key).",
               "export_key", "TR31_M3_ISO_9797_3_MAC_KEY",
               "In APC: export_key wrapping the MAC key under a KEK."),
    HsmCommand("Thales", "Legacy", "AU",
               "Translate a CVK Pair from LMK to ZMK Encryption", "KEY_MGMT",
               "Exports a CVK pair from LMK to ZMK encryption for delivery to a network partner. "
               "Response code: AV.",
               "export_key", "TR31_C0_CARD_VERIFICATION_KEY",
               "In APC: export_key with TR-31 block under ZMK/KEK."),
    HsmCommand("Thales", "Legacy", "AW",
               "Translate a CVK Pair from ZMK to LMK Encryption", "KEY_MGMT",
               "Imports a CVK pair from ZMK encryption into LMK. Response code: AX. "
               "Used to receive CVK from a network partner.",
               "import_key", "TR31_C0_CARD_VERIFICATION_KEY",
               "In APC: import_key with TR-31 block under ZMK/KEK."),
    HsmCommand("Thales", "Legacy", "FE",
               "Translate a TMK, TPK or PVK from LMK to ZMK Encryption", "KEY_MGMT",
               "Exports a terminal key from LMK protection to ZMK encryption. Response code: FF. "
               "Used to distribute a terminal key to a network partner.",
               "export_key", "TR31_P0_PIN_ENCRYPTION_KEY",
               "In APC: export_key with TR-31 block under ZMK/KEK."),
    HsmCommand("Thales", "Legacy", "FC",
               "Translate a TMK, TPK or PVK from ZMK to LMK Encryption", "KEY_MGMT",
               "Imports a terminal key from ZMK encryption into LMK. Response code: FD.",
               "import_key", "TR31_P0_PIN_ENCRYPTION_KEY",
               "In APC: import_key with TR-31 block."),
    HsmCommand("Thales", "Legacy", "AC",
               "Translate a TAK", "KEY_MGMT",
               "Re-encrypts a TAK between TMK encryptions. Response code: AD. "
               "Used when rotating the TMK that protects a TAK.",
               "export_key", "TR31_M3_ISO_9797_3_MAC_KEY",
               "In APC: export_key / import_key for key rotation. No TMK wrapping hierarchy."),
    HsmCommand("Thales", "Legacy", "MG",
               "Translate a TAK from LMK to ZMK Encryption", "KEY_MGMT",
               "Exports a TAK from LMK protection to ZMK encryption. Response code: MH.",
               "export_key", "TR31_M3_ISO_9797_3_MAC_KEY",
               "In APC: export_key with TR-31 block."),
    HsmCommand("Thales", "Legacy", "MI",
               "Translate a TAK from ZMK to LMK Encryption", "KEY_MGMT",
               "Imports a TAK from ZMK encryption into LMK. Response code: MJ.",
               "import_key", "TR31_M3_ISO_9797_3_MAC_KEY",
               "In APC: import_key with TR-31 block."),
    HsmCommand("Thales", "Legacy", "KC",
               "Translate a ZPK", "KEY_MGMT",
               "Re-encrypts a ZPK from one ZMK to another ZMK. Response code: KD. "
               "Used for inter-network PIN key exchange when a ZPK crosses a zone boundary.",
               "export_key", "TR31_P0_PIN_ENCRYPTION_KEY",
               "In APC: export_key under outbound ZMK/KEK. "
               "TR-31 key block carries usage code P0 to enforce PIN-only use."),
    HsmCommand("Thales", "Legacy", "GC",
               "Translate a ZPK from LMK to ZMK Encryption", "KEY_MGMT",
               "Exports a ZPK from LMK protection to ZMK encryption. Response code: GD.",
               "export_key", "TR31_P0_PIN_ENCRYPTION_KEY",
               "In APC: export_key with TR-31 block under ZMK/KEK."),
    HsmCommand("Thales", "Legacy", "FA",
               "Translate a ZPK from ZMK to LMK Encryption", "KEY_MGMT",
               "Imports a ZPK from ZMK encryption into LMK. Response code: FB. "
               "Used to receive a ZPK from a network partner.",
               "import_key", "TR31_P0_PIN_ENCRYPTION_KEY",
               "In APC: import_key with TR-31 block. APC key ARN replaces LMK storage."),
    HsmCommand("Thales", "Legacy", "GE",
               "Translate a ZMK", "KEY_MGMT",
               "Re-encrypts a ZMK using different key components. Response code: GF. "
               "ZMK (Zone Master Key) is used for inter-zone key exchange.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "In APC: ZMK maps to KEK (TR31_K1). New ZMK establishment uses "
               "get_parameters_for_import + import_key with TR-34."),
    HsmCommand("Thales", "Legacy", "DW",
               "Translate a BDK from ZMK to LMK Encryption", "KEY_MGMT",
               "Imports a BDK from ZMK encryption into LMK. Response code: DX. "
               "Used when receiving a DUKPT BDK from an acquirer partner.",
               "import_key", "TR31_B0_BASE_DERIVATION_KEY",
               "In APC: import_key with TR-31 block (usage B0)."),
    HsmCommand("Thales", "Legacy", "DY",
               "Translate a BDK from LMK to ZMK Encryption", "KEY_MGMT",
               "Exports a BDK from LMK protection to ZMK encryption. Response code: DZ. "
               "Used when distributing a DUKPT BDK to a terminal management partner.",
               "export_key", "TR31_B0_BASE_DERIVATION_KEY",
               "In APC: export_key with TR-31 block (usage B0)."),
    HsmCommand("Thales", "Legacy", "KA",
               "Generate a Key Check Value (Not Double-Length ZMK)", "KEY_MGMT",
               "Generates a KCV for a key under LMK. Response code: KB. "
               "Not usable for double-length ZMKs.",
               None, None,
               "In APC: KCV is included in all create_key and import_key responses "
               "(KeyCheckValue field). No separate APC call needed. "
               "AES keys must use CMAC-based KCV — never ECB-zeros method."),
    # ── Legacy Message Encryption ─────────────────────────────────────────────
    HsmCommand("Thales", "Legacy", "HE",
               "Encrypt Data Block", "ENCRYPT",
               "Encrypts a 64-bit (16H) data block using a TAK under LMK pair 16-17 variant 0. "
               "Response code: HF. Superseded by M0. Single 64-bit block only — not for "
               "general data encryption.",
               "encrypt_data", "TR31_M3_ISO_9797_3_MAC_KEY",
               "TAK is a MAC key (M-class), not an encryption key (D-class). "
               "In APC: if the intent is PIN pad command authentication, model as generate_mac. "
               "If general data encryption, use encrypt_data with TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY."),
    HsmCommand("Thales", "Legacy", "HG",
               "Decrypt Data Block", "ENCRYPT",
               "Decrypts a 64-bit (16H) data block using a TAK under LMK pair 16-17 variant 0. "
               "Response code: HH. Superseded by M2.",
               "decrypt_data", "TR31_M3_ISO_9797_3_MAC_KEY",
               "Mirror of HE. Same APC key-type considerations apply."),
    # ── Legacy DUKPT PIN Verification ─────────────────────────────────────────
    HsmCommand("Thales", "Legacy", "CO",
               "Verify a PIN Using the Diebold Method (DUKPT)", "PIN",
               "Verifies a PIN using the Diebold method with original single-length DUKPT "
               "key derivation from a double-length BDK. Response code: CP. "
               "Takes BDK + Diebold table index (stored in user storage) + KSN (3H descriptor + "
               "12-20H KSN) + PIN block (16H) + account number (12N) + PIN validation data (16H) "
               "+ offset (4N). Superseded by GS (3DES DUKPT Diebold verify).",
               "verify_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "Original single-length DUKPT (derives 56-bit working key from 112-bit BDK). "
               "In APC: verify_pin_data with IncomingDukptAttributes. "
               "Diebold method requires IncomingDukptAttributes.DukptKeyDerivationType=TDES_2KEY. "
               "Migrate to AES DUKPT — TDES prohibited for new deployments since Jan 2023."),
    HsmCommand("Thales", "Legacy", "CQ",
               "Verify a PIN Using the Encrypted PIN Method (DUKPT)", "PIN",
               "Verifies a PIN using the Encrypted PIN comparison method with DUKPT key derivation. "
               "Response code: CR. Takes BDK + KSN + encrypted PIN block from terminal + "
               "account number (12N) + reference PIN encrypted under LMK. Superseded by GU.",
               "verify_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "Decrypts terminal PIN block using DUKPT-derived key, then compares against "
               "host-stored PIN (encrypted under LMK). In APC: verify_pin_data; the reference "
               "PIN is stored as APC's PinVerificationKeyArn data — never log either PIN value."),
    # ── Legacy MAC ────────────────────────────────────────────────────────────
    HsmCommand("Thales", "Legacy", "ME",
               "Verify and Translate a MAC", "MAC",
               "Verifies a MAC under one MAK and generates a new MAC under a different MAK "
               "in a single command. Response code: MF. Used at network gateway boundaries.",
               "verify_mac", "TR31_M1_ISO_9797_1_MAC_KEY",
               "In APC: two separate calls — verify_mac (inbound MAK) + generate_mac (outbound MAK). "
               "Both keys should be TR31_M3 or TR31_M6; CBC-MAC algorithm is a legacy construct."),
    HsmCommand("Thales", "Legacy", "MQ",
               "Generate MAC (MAB) for Large Message", "MAC",
               "Generates a MAB (Message Authentication Block) for messages longer than 64 bytes "
               "using multi-block CBC chaining. Response code: MR. Uses MAK (LMK pair 16-17).",
               "generate_mac", "TR31_M1_ISO_9797_1_MAC_KEY",
               "CBC-MAC chaining across multiple blocks. In APC: generate_mac handles "
               "variable-length messages internally. Migrate to CMAC (M6 key type) for new work."),
    HsmCommand("Thales", "Legacy", "MS",
               "Generate MAC (MAB) using ANSI X9.19 Method for Large Message", "MAC",
               "Generates a Retail MAC (ANSI X9.19 / ISO 9797-1 Algorithm 3) for large messages: "
               "single-DES encrypt all blocks except last, TDES-encrypt last block. Response code: MT.",
               "generate_mac", "TR31_M3_ISO_9797_3_MAC_KEY",
               "ANSI X9.19 Retail MAC is a legacy construct — CBC-MAC with TDES final block. "
               "In APC: generate_mac with GenerationAttributes.Algorithm=ISO_9797_ALGORITHM_3. "
               "Migrate to CMAC where downstream system supports it."),
    HsmCommand("Thales", "Legacy", "MK",
               "Generate a Binary MAC", "MAC",
               "Generates a MAC over binary (non-ASCII) message data. Response code: ML. "
               "Functionally equivalent to MA but accepts arbitrary binary input.",
               "generate_mac", "TR31_M1_ISO_9797_1_MAC_KEY",
               "In APC: generate_mac accepts binary data natively."),
    HsmCommand("Thales", "Legacy", "MM",
               "Verify a Binary MAC", "MAC",
               "Verifies a MAC over binary message data. Response code: MN.",
               "verify_mac", "TR31_M1_ISO_9797_1_MAC_KEY",
               "In APC: verify_mac."),
    HsmCommand("Thales", "Legacy", "MO",
               "Verify and Translate a Binary MAC", "MAC",
               "Verifies a binary MAC under one MAK and generates a new binary MAC under another. "
               "Response code: MP. Gateway boundary re-MAC operation.",
               "verify_mac", "TR31_M1_ISO_9797_1_MAC_KEY",
               "In APC: verify_mac + generate_mac (two separate calls). "
               "Both keys should be TR31_M3 or TR31_M6."),
    HsmCommand("Thales", "Legacy", "MU",
               "Generate a MAC on a Binary Message", "MAC",
               "Generates a MAC over a variable-length binary message. Response code: MV.",
               "generate_mac", "TR31_M1_ISO_9797_1_MAC_KEY",
               "In APC: generate_mac."),
    HsmCommand("Thales", "Legacy", "MW",
               "Verify a MAC on a Binary Message", "MAC",
               "Verifies a MAC over a variable-length binary message. Response code: MX.",
               "verify_mac", "TR31_M1_ISO_9797_1_MAC_KEY",
               "In APC: verify_mac."),
    # ── UnionPay ──────────────────────────────────────────────────────────────
    HsmCommand("Thales", "Legacy", "JS",
               "ARQC Verification and/or ARPC Generation (UnionPay)", "ARQC",
               "Verifies a UnionPay EMV Authorization Request Cryptogram and optionally generates "
               "an ARPC. Response code: JT. Distinct from KQ (which is the core/International command).",
               "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
               "UnionPay-specific ARQC/ARPC. In APC: verify_auth_request_cryptogram with "
               "TR31_E0 master key. UnionPay uses a slightly different derivation than Visa/Mastercard."),
]

# ── Atalla (HPE/Micro Focus/NCR) Commands ────────────────────────────────────
# Source: EFTlab knowledge base — DIRECTORY QUALITY (function names only, no parameter detail)
# Wire protocol: TCP socket, binary header, fixed-length fields — format not publicly documented.
# Note: Many Atalla numeric codes (31, 32, 33, 5D, 5E, 98, 99, 304, 305, etc.) overlap with
# Futurex Standard API codes — Futurex's Standard API was designed to be Atalla-compatible.
# Codes shared with Futurex Standard are listed here for explicit Atalla attribution.
# Proxy support: NOT IMPLEMENTED — wire format undocumented.

ATALLA_COMMANDS: list[HsmCommand] = [
    # ── PIN ──────────────────────────────────────────────────────────────────
    HsmCommand("Atalla", "Standard", "30", "Encrypt PIN – ANSI Format 0", "PIN",
               "Encrypts a clear PIN under a Zone PIN Key using ANSI Format 0.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Format 0 is legacy — migrate to Format 4. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "31", "Translate PIN", "PIN",
               "Translates a PIN block between encryption keys.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "32", "Verify PIN", "PIN",
               "PIN verification. Multiple methods: Atalla 2×2, DES BiLevel, Burroughs, "
               "Clear-PIN, Diebold, IBM 3624, Identikey, NCR, PIN-Block Comparison, Visa.",
               "verify_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY",
               "Method selected by sub-parameter. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "33", "Translate PIN (Format Conversion)", "PIN",
               "Translates PIN between formats: ANSI↔IBM 4731, ANSI↔PIN/Pad, "
               "ANSI↔PLUS, IBM 3624↔IBM 3624, IBM 3624↔PIN/Pad, IBM 4731↔IBM 4731.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Covers multiple legacy format translations. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "35", "Translate PIN – Double-Encrypted", "PIN",
               "Translates a double-encrypted PIN block.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "36", "Verify Double-Encrypted PIN", "PIN",
               "Verifies a double-encrypted PIN.",
               "verify_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "37", "PIN Change", "PIN",
               "PIN change. Methods: Atalla DES Bilevel, Diebold, IBM 3624, Identikey, NCR, Visa.",
               "generate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "39", "Translate PIN And Generate MAC", "PIN",
               "Combined PIN translation and MAC generation in a single command.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "APC requires separate translate_pin_data + generate_mac calls. "
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "3A", "Verify Card and PIN", "PIN",
               "Combined card and PIN verification. Methods: IBM 3624, NCR, Visa.",
               "verify_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "3D", "Generate PVN and IBM Offset", "PIN",
               "Generates a PIN Verification Number and IBM 3624 PIN offset.",
               "generate_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "90", "Decrypt PIN", "PIN",
               "Decrypts an encrypted PIN block.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Maps to translate_pin_data with plaintext output — requires care around PCI PIN. "
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "BA", "PIN Translate (ANSI to PIN/Pad) and MAC Verification", "PIN",
               "Translates an ANSI PIN block to PIN/Pad format and verifies a MAC.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Combined operation — two APC calls required. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "BB", "Translate PIN (ANSI to PLUS) and Verify MAC", "PIN",
               "Translates ANSI PIN to PLUS network format and verifies MAC.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "BD", "Translate PIN and Generate MAC", "PIN",
               "Translates PIN block and generates a MAC.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Two APC calls required. EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "30A", "Calculate PIN Offset", "PIN",
               "Calculates a PIN offset for IBM 3624 PIN verification.",
               "generate_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "335", "PIN and PIN-Block Translate", "PIN",
               "Translates a PIN and/or PIN block between formats.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "346", "PIN Translate – DUKPT to 3DES and Verify MAC", "PIN",
               "DUKPT PIN translation to 3DES with MAC verification.",
               "translate_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "347", "PIN Translate – DUKPT to 3DES and Generate MAC", "PIN",
               "DUKPT PIN translation to 3DES with MAC generation.",
               "translate_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "37B", "Generate ePIN Offset", "PIN",
               "Generates an electronic PIN offset.",
               "generate_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    # ── MAC ──────────────────────────────────────────────────────────────────
    HsmCommand("Atalla", "Standard", "58", "MAC Translate", "MAC",
               "Translates a MAC from one key to another.",
               "generate_mac", "TR31_M3_ISO_9797_3_MAC_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "59", "Generate MAC and Encrypt or Translate Data", "MAC",
               "Combined MAC generation with data encryption or translation.",
               "generate_mac", "TR31_M6_ISO_9797_5_CMAC_KEY",
               "Two APC calls required. EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "5C", "Verify and Generate MAC for Visa DUKPT", "MAC",
               "Verifies inbound MAC and generates outbound MAC using Visa DUKPT keys.",
               "verify_mac", "TR31_B0_BASE_DERIVATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "5F", "Verify MAC and Decrypt PIN", "MAC",
               "Verifies a MAC and decrypts a PIN block in a single operation.",
               "verify_mac", "TR31_M3_ISO_9797_3_MAC_KEY",
               "Two APC calls required. EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "98", "Generate MAC", "MAC",
               "Generates a MAC for message authentication.",
               "generate_mac", "TR31_M3_ISO_9797_3_MAC_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "99", "Verify MAC", "MAC",
               "Verifies a MAC.",
               "verify_mac", "TR31_M3_ISO_9797_3_MAC_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "304", "Verify CMAC using TDES", "MAC",
               "Verifies a CMAC using a TDES key.",
               "verify_mac", "TR31_M6_ISO_9797_5_CMAC_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "305", "Generate CMAC using TDES", "MAC",
               "Generates a CMAC using a TDES key.",
               "generate_mac", "TR31_M6_ISO_9797_5_CMAC_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "348", "Verify DUKPT MAC", "MAC",
               "Verifies a MAC generated using DUKPT key derivation.",
               "verify_mac", "TR31_B0_BASE_DERIVATION_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "352", "Generate EMV MAC", "MAC",
               "Generates an EMV transaction MAC.",
               "generate_mac", "TR31_M6_ISO_9797_5_CMAC_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "386", "Generate DUKPT MAC", "MAC",
               "Generates a MAC using DUKPT key derivation.",
               "generate_mac", "TR31_B0_BASE_DERIVATION_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "39B", "Generate MAC using HMAC", "MAC",
               "Generates an HMAC.",
               "generate_mac", "TR31_M7_HMAC_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "39C", "Verify MAC using HMAC", "MAC",
               "Verifies an HMAC.",
               "verify_mac", "TR31_M7_HMAC_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    # ── CVV ──────────────────────────────────────────────────────────────────
    HsmCommand("Atalla", "Standard", "5D", "Generate CVV/CVC", "CVV",
               "Generates a Card Verification Value or Card Verification Code.",
               "generate_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "5E", "Verify CVV/CVC", "CVV",
               "Verifies a Card Verification Value or Code.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "357", "Verify dCVV", "CVV",
               "Verifies a dynamic Card Verification Value.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "359", "Verify dynamic CVC3", "CVV",
               "Verifies a contactless CVC3 value (Mastercard PayPass).",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "35A", "Verify AMEX CSC", "CVV",
               "Verifies an American Express Card Security Code.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "35B", "Generate AMEX CSC", "CVV",
               "Generates an American Express Card Security Code.",
               "generate_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "35F", "Verify Discover DCVV", "CVV",
               "Verifies a Discover dynamic CVV.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "365", "Verify Visa Cloud-Based Payments", "CVV",
               "Verifies a Visa Token Service cloud-based payment cryptogram.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "36A", "Verify AMEX Expresspay (Magstripe Mode)", "CVV",
               "Verifies an American Express Expresspay contactless magstripe value.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    # ── ARQC ─────────────────────────────────────────────────────────────────
    HsmCommand("Atalla", "Standard", "350", "Verify EMV ARQC", "ARQC",
               "Verifies an EMV Authorization Request Cryptogram.",
               "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "351", "EMV PIN Change", "PIN",
               "Performs an EMV offline PIN change.",
               "generate_mac_emv_pin_change",
               "TR31_E2_EMV_MKEY_INTEGRITY + TR31_E1_EMV_MKEY_CONFIDENTIALITY",
               "EFTlab source, directory quality.", confidence="directory"),
    # ── ENCRYPT / P2PE ───────────────────────────────────────────────────────
    HsmCommand("Atalla", "Standard", "55", "Encrypt, Decrypt or Translate Data", "ENCRYPT",
               "General-purpose data encryption, decryption, or re-encryption.",
               "encrypt_data", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "97", "Encrypt/Decrypt Data", "ENCRYPT",
               "Encrypts or decrypts a data block.",
               "encrypt_data", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "388", "DES DUKPT Encrypt/Decrypt Data", "P2PE",
               "Encrypts or decrypts cardholder data using DUKPT 3DES.",
               "encrypt_data", "TR31_B0_BASE_DERIVATION_KEY",
               "Shared code with Futurex Standard. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "390", "Encrypt/Decrypt Data using AES", "ENCRYPT",
               "Encrypts or decrypts data using an AES key.",
               "encrypt_data", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    # ── KEY MANAGEMENT ───────────────────────────────────────────────────────
    HsmCommand("Atalla", "Standard", "10", "Generate 3DES Working Key", "KEY_MGMT",
               "Generates a new 3DES working key of any type.",
               "create_key", None,
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "11", "Export Working Key in AKB Format", "KEY_MGMT",
               "Exports a working key wrapped in Atalla Key Block (AKB) format.",
               "export_key", None,
               "AKB is Atalla's proprietary key block format. APC uses TR-31. "
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "13", "Import Working Key in AKB Format", "KEY_MGMT",
               "Imports a working key from Atalla Key Block (AKB) format.",
               "import_key", None,
               "AKB → TR-31 conversion may be required. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "1A", "Export Working Key (non-AKB)", "KEY_MGMT",
               "Exports a working key in a format other than AKB.",
               "export_key", None,
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "1E", "Generate Initial DUKPT Key (Visa DUKPT)", "KEY_MGMT",
               "Generates a new initial key for a PIN pad using Visa DUKPT.",
               "create_key", "TR31_B0_BASE_DERIVATION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "117", "Import TR-31 Formatted Working Key", "KEY_MGMT",
               "Imports a working key wrapped in a TR-31 key block.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "118", "Export Working Key in TR-31 Format", "KEY_MGMT",
               "Exports a working key wrapped in a TR-31 key block.",
               "export_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "EFTlab source, directory quality.", confidence="directory"),
    HsmCommand("Atalla", "Standard", "136", "Generate TR-34 Key Block", "KEY_MGMT",
               "Generates a TR-34 key distribution block for asymmetric key transport.",
               "export_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Maps to APC TR-34 export flow. EFTlab source, directory quality.",
               confidence="directory"),
    HsmCommand("Atalla", "Standard", "39A", "Generate AES or HMAC Symmetric Key", "KEY_MGMT",
               "Generates a new AES or HMAC symmetric key.",
               "create_key", None,
               "EFTlab source, directory quality.", confidence="directory"),
]

# ── Unified command registry ──────────────────────────────────────────────────

ALL_COMMANDS: list[HsmCommand] = (
    FUTUREX_EXCRYPT_COMMANDS
    + INTERNATIONAL_COMMANDS
    + THALES_LEGACY_COMMANDS
    + ATALLA_COMMANDS
)

# Index by command code for fast lookup
_COMMAND_INDEX: dict[str, list[HsmCommand]] = {}
for _cmd in ALL_COMMANDS:
    _COMMAND_INDEX.setdefault(_cmd.command_code, []).append(_cmd)


# ── Socket pattern recognition helpers ───────────────────────────────────────

# Futurex Excrypt: commands wrapped in [ ] with ; separators
FUTUREX_EXCRYPT_PATTERNS = [
    r'\[([A-Z]{4});',                   # [TPIN; or [EMVA;
    r'send\s*\(\s*["\[](TPIN|XPIN|EMVA|GMAC|VMAC|TPDD|VPIN|DCDK|ECDK)',
]

# Numeric codes: Atalla Standard API and Futurex Standard (Atalla-compatible).
# Production Futurex deployments use Excrypt 4-char text codes — numeric codes
# are most likely Atalla. Kept for completeness so Atalla codebases are recognized.
NUMERIC_HSM_PATTERNS = [
    r'["\'](31|32|33|346|350|56|57|5A|5B|5C|304|305|5D|5E|388)["\']',
]

# International / Thales: 2-char codes, fixed-length fields.
# Covers Thales/Futurex International shared codes (CA, CC, MA, etc.) AND
# Thales payShield Legacy-only codes (HC, HA, BI, GG, ME, MQ, etc.).
INTERNATIONAL_AND_THALES_PATTERNS = [
    r'["\'](CA|CB|CC|CD|CI|CJ|CW|CX|CY|CZ|DA|DC|EA|EC|M6|M7|M8|M9|MA|MC|ME|MK|MM|MO|MQ|MS|MU|MW|A0|A6|A8|IA|BU|KQ|GW)',
    r'["\'](HC|HD|HA|HB|HE|HF|HG|HH|BI|BJ|AS|AT|FG|FH|GG|GH|GY|GZ)',  # Thales Legacy key gen
    r'["\'](AA|AB|AE|AF|AG|AH|AC|AD|AU|AV|AW|AX|FA|FB|FC|FD|FE|FF|GC|GD|GE|GF|GY|GZ|KC|KD|KA|KB)',  # Thales Legacy translate
    r'["\'](MG|MH|MI|MJ|DW|DX|DY|DZ|CO|CP|CQ|CR|JS|JT)',  # Thales Legacy additional
    r'hsm_command\s*=\s*["\']([A-Z]{2})',
    r'cmd\s*=\s*["\']([A-Z]{2})',
    r'socket\.send.*["\']([A-Z]{2})\d',
]

# Generic HSM socket connection patterns
HSM_SOCKET_PATTERNS = [
    r'socket\.connect\([^)]*(\d{4,5})[^)]*\)',   # TCP port connection
    r'ssl\.wrap_socket',                           # TLS socket
    r'context\.wrap_socket',                       # mTLS socket
    r'HSM_HOST|HSM_PORT|hsm_host|hsm_port',       # common config variable names
    r'payshield|futurex|atalla|excrypt',           # vendor name references
]

# ── APC migration guidance ────────────────────────────────────────────────────

LMK_MIGRATION_NOTE = """
NOTE — LMK Key Concept:
Physical Thales/Futurex HSMs use a Local Master Key (LMK) to protect all keys stored on the device.
Commands like JC/JE (translate to LMK) and JG (translate from LMK) are internal re-encryption
operations on the HSM.

In APC, there is no LMK concept — all keys are stored and protected by APC's own HSM boundary.
When migrating LMK-based workflows to APC:
  - Keys previously encrypted under LMK become APC keys (create_key or import_key)
  - "Translate to LMK" = importing or creating a key in APC
  - "Translate from LMK" = using the key in an APC operation directly
  - All key-under-LMK storage is replaced by APC key ARNs
"""

DUKPT_MIGRATION_NOTE = """
NOTE — DUKPT Migration:
If the legacy codebase uses TDES DUKPT (CI command with 10-byte KSN):
  - The BDK and IPEK are replaced by an APC BDK (TR31_B0_BASE_DERIVATION_KEY, AES_128 recommended)
  - The KSN format changes for AES DUKPT: 12 bytes (32-bit BDK ID + 32-bit derivation ID + 32-bit counter)
  - Fixed TDES keys are prohibited since Jan 2023 — migrate the BDK to AES
  - The translate_pin_data call with IncomingDukptAttributes replaces the CI/G0 command
"""

FIXED_KEY_MIGRATION_NOTE = """
WARNING — Fixed Key Detection:
If the legacy code uses CC (ZPK-to-ZPK PIN translation) with static/fixed keys that never rotate,
this pattern has been prohibited since 1 January 2023 for TDES keys (PCI PIN Req 2-2).
Recommend migrating to:
  1. DUKPT (AES) for terminal-to-host encryption
  2. Master/session key scheme with AES for host-to-host
"""


def lookup_command(command_code: str) -> list[HsmCommand]:
    """Look up all known HSM commands matching a given code."""
    return _COMMAND_INDEX.get(command_code.upper(), [])


def get_apc_mapping(command_code: str) -> dict:
    """
    Return the APC mapping for a given HSM command code.
    Returns a dict with apc_operation, apc_key_type, notes, and compliance warnings.
    """
    commands = lookup_command(command_code)
    if not commands:
        return {"error": f"Unknown command code: {command_code}"}

    results = []
    for cmd in commands:
        result = {
            "vendor": cmd.vendor,
            "api": cmd.api,
            "command_code": cmd.command_code,
            "name": cmd.name,
            "category": cmd.category,
            "description": cmd.description,
            "apc_operation": cmd.apc_operation,
            "apc_key_type": cmd.apc_key_type,
            "notes": cmd.notes,
            "confidence": cmd.confidence,
        }
        # Attach relevant migration notes
        if command_code.upper() in ("JC", "JE", "JG"):
            result["migration_note"] = LMK_MIGRATION_NOTE
        if command_code.upper() in ("CI", "G0", "346"):
            result["migration_note"] = DUKPT_MIGRATION_NOTE
        if command_code.upper() == "CC":
            result["migration_note"] = FIXED_KEY_MIGRATION_NOTE
        results.append(result)

    return {"matches": results}


def list_commands_by_category(category: str) -> list[dict]:
    """List all known commands in a category: PIN, MAC, CVV, KEY_MGMT, ENCRYPT, ARQC, P2PE."""
    return [
        {
            "vendor": c.vendor, "api": c.api, "code": c.command_code,
            "name": c.name, "apc_operation": c.apc_operation,
        }
        for c in ALL_COMMANDS
        if c.category.upper() == category.upper()
    ]


def list_commands_by_vendor(vendor: str) -> list[dict]:
    """List all known commands for a vendor: Futurex, Thales, Thales/Futurex, Atalla."""
    return [
        {
            "api": c.api, "code": c.command_code,
            "name": c.name, "apc_operation": c.apc_operation,
        }
        for c in ALL_COMMANDS
        if vendor.lower() in c.vendor.lower()
    ]


