"""
HSM vendor command pattern recognition for code analysis and refactoring (R8).

Sources and confidence levels:
  Futurex Excrypt API:       AUTHORITATIVE — Futurex General Payment HSM Integration Guide (2024)
  Futurex Standard API:      AUTHORITATIVE — same source
  Futurex International API: AUTHORITATIVE — same source (note: Thales-compatible command codes)
  Thales payShield:          REFERENCE QUALITY — EFTlab knowledge base (professionally validated,
                             not official Thales documentation)
  Atalla:                    NOT YET AVAILABLE — do not implement pattern matching

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

# ── Futurex Standard API ──────────────────────────────────────────────────────
# Numeric command codes. No delimiters — fields at fixed offsets.

FUTUREX_STANDARD_COMMANDS: list[HsmCommand] = [
    HsmCommand("Futurex", "Standard", "31", "Translate PIN Block", "PIN",
               "Standard PIN block translation.", "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    HsmCommand("Futurex", "Standard", "32", "Verify PIN", "PIN",
               "PIN verification. Multiple modes: ANSI, Diebold, IBM3624, Visa, and DUKPT variants.",
               "verify_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY"),
    HsmCommand("Futurex", "Standard", "33", "Extended PIN Translation", "PIN",
               "Extended PIN translation.", "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    HsmCommand("Futurex", "Standard", "335", "Translate PIN Block (variant)", "PIN",
               "PIN block translation variant.", "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY"),
    HsmCommand("Futurex", "Standard", "346", "DUKPT PIN Translate", "PIN",
               "DUKPT-specific PIN translation.", "translate_pin_data", "TR31_B0_BASE_DERIVATION_KEY"),
    HsmCommand("Futurex", "Standard", "350", "EMV ARQC Validation", "ARQC",
               "Validates an EMV ARQC.", "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS"),
    HsmCommand("Futurex", "Standard", "56", "Generate MAC (≤512 bytes)", "MAC",
               "MAC generation for messages up to 512 bytes.", "generate_mac", "TR31_M6_ISO_9797_5_CMAC_KEY"),
    HsmCommand("Futurex", "Standard", "57", "Generate MAC (>512 bytes)", "MAC",
               "MAC generation for messages over 512 bytes.", "generate_mac", "TR31_M6_ISO_9797_5_CMAC_KEY"),
    HsmCommand("Futurex", "Standard", "5A", "Verify MAC (≤512 bytes)", "MAC",
               "MAC verification for messages up to 512 bytes.", "verify_mac", "TR31_M6_ISO_9797_5_CMAC_KEY"),
    HsmCommand("Futurex", "Standard", "5B", "Verify MAC (>512 bytes)", "MAC",
               "MAC verification for messages over 512 bytes.", "verify_mac", "TR31_M6_ISO_9797_5_CMAC_KEY"),
    HsmCommand("Futurex", "Standard", "5C", "Verify and Generate MAC (DUKPT)", "MAC",
               "DUKPT MAC verify and generate.", "verify_mac", "TR31_B0_BASE_DERIVATION_KEY"),
    HsmCommand("Futurex", "Standard", "304", "Verify CMAC using TDES", "MAC",
               "CMAC verification.", "verify_mac", "TR31_M6_ISO_9797_5_CMAC_KEY"),
    HsmCommand("Futurex", "Standard", "305", "Generate CMAC using TDES", "MAC",
               "CMAC generation.", "generate_mac", "TR31_M6_ISO_9797_5_CMAC_KEY"),
    HsmCommand("Futurex", "Standard", "348", "Verify MAC (DUKPT BDK+KSN)", "MAC",
               "Verifies MAC derived from DUKPT BDK and KSN.", "verify_mac", "TR31_B0_BASE_DERIVATION_KEY"),
    HsmCommand("Futurex", "Standard", "386", "Generate MAC (DUKPT BDK+KSN)", "MAC",
               "Generates MAC derived from DUKPT BDK and KSN.", "generate_mac", "TR31_B0_BASE_DERIVATION_KEY"),
    HsmCommand("Futurex", "Standard", "5D", "Generate Card Verification Value (CVV)", "CVV",
               "CVV generation.", "generate_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY"),
    HsmCommand("Futurex", "Standard", "5E", "Verify Card Verification Value (CVV)", "CVV",
               "CVV verification.", "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY"),
    HsmCommand("Futurex", "Standard", "388", "3DES DUKPT Encrypt/Decrypt Data", "P2PE",
               "DUKPT data encryption/decryption (3DES).", "encrypt_data", "TR31_B0_BASE_DERIVATION_KEY"),
    HsmCommand("Futurex", "Standard", "52", "Data Translate", "P2PE",
               "Translates data between keys.", "re_encrypt_data", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY"),
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
    + FUTUREX_STANDARD_COMMANDS
    + INTERNATIONAL_COMMANDS
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

# Standard API: numeric codes sent over socket
FUTUREX_STANDARD_PATTERNS = [
    r'["\'](31|32|33|346|350|56|57|5A|5B|5C|304|305|5D|5E|388)["\']',
]

# International / Thales: 2-char codes, fixed-length fields
INTERNATIONAL_PATTERNS = [
    r'["\'](CA|CB|CC|CD|CI|CJ|CW|CX|CY|CZ|DA|DC|EA|EC|M6|M7|M8|M9|MA|MC|A0|A6|A8|IA|BU|KQ|GW)',
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
    """List all known commands for a vendor: Futurex, Thales, Thales/Futurex."""
    return [
        {
            "api": c.api, "code": c.command_code,
            "name": c.name, "apc_operation": c.apc_operation,
        }
        for c in ALL_COMMANDS
        if vendor.lower() in c.vendor.lower()
    ]


IMPLEMENTATION_STATUS = (
    "Futurex Excrypt/Standard/International: AUTHORITATIVE — Futurex General Payment HSM Integration Guide (2024). "
    "Thales payShield 10K: REFERENCE QUALITY — EFTlab knowledge base. "
    "Atalla (HPE/Micro Focus/NCR): DIRECTORY QUALITY — EFTlab command list (function names only, "
    "no parameter detail or wire protocol). Proxy support not implemented for Atalla."
)
