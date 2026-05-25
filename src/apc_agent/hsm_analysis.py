"""
HSM vendor command pattern recognition for code analysis and refactoring (R8).

Sources and confidence levels:
  Futurex Excrypt API:       AUTHORITATIVE — Futurex General Payment HSM Integration Guide (2024)
                             All Futurex commands are 4-character text codes (TPIN, ECHO, EMVA, etc.)
                             wrapped in bracket-delimited frames: [AOCCCC;field;...;]
  Thales/Futurex             MIXED: Core PIN/MAC/CVV commands (CA, CC, CI, CW, CY, G0, M6, M8, C2, C4,
  International shared:      KQ, GW) from Futurex Integration Guide — AUTHORITATIVE. Key management
                             and PIN verify commands (DA, DC, EA, EC, A0, A6, A8, IA, BU, M0, M2)
                             from EFTlab knowledge base — REFERENCE QUALITY (confidence="medium").
  Thales payShield Legacy:   AUTHORITATIVE — payShield 10K Legacy Host Commands (Thales payShield 10K Legacy Host Commands, 2019)
                             Official Thales documentation covering ~80 commands in 10 functional groups.
                             License PS10-LIC-LEGACY required on device.
  Atalla (NCR):              DIRECTORY QUALITY — EFTlab command list (function names only, no wire detail)
                             Uses numeric command codes (31, 32, 33, 5D, 5E, 304, etc.).
                             Some of these codes were adopted by the Futurex Standard API for
                             Atalla backward-compatibility, but are not seen in Excrypt deployments.
                             Proxy support: not implemented — wire format undocumented.

Wire format (Futurex Excrypt):
  TCP socket with mTLS; commands wrapped in [ ] delimiters, AO prefix prepended to the
  4-character command code on the wire: [AO<CCCC>;<field_id><value>;...;]
  Field identifiers are 2-char alphanumeric codes immediately followed by the value with
  no separator. Common field IDs from whitepaper examples:
    AW = wrapping mode (1 = 3DES MFK)
    AX = inbound key (cryptogram or TR-31 key block for TPIN/GKBL)
    BT = outbound key
    AL = PIN block (in) / translated PIN block (out)
    AK = PAN (TPIN) or key block header target (GKBL)
    AS = source key type (1 = cryptogram)
    BG = key data (cryptogram body)
    BB = output key block (response)
    AE = error code / KCV (response)
  Application code typically passes the 4-char code without AO prefix to the API client,
  which prepends AO before sending. Futurex HSMs automatically pad shorter key blocks to
  at least 3DES length. Key block settings (ANSI TR-31, cryptogram disable) are controlled
  in Excrypt Manager → Extended Options → Key Block Policy.

Wire format (Thales payShield 10K):
  TCP socket (clear or TLS); 2-byte big-endian length prefix; m-byte message header (set at
  installation, commonly 4 bytes '0000'); 2-char command code; variable-length fields.
  Response: m-byte header; 2-char response code (command letter + next letter, e.g. NC→ND);
  2-char error code ('00' = success, '68' = command disabled); fields.
  Key size encoding: 16H = single-DES/TDES; 'U' + 32H = double-length TDES key block;
  'T' + 48H = triple-length; 'S' + n A = TR-31 key block. STX/ETX control characters
  bracket the message when using asynchronous comms (not shown in field tables).
  Simulated firmware version: 4.8.3 (KeyLab payShield 10K simulator, v1.1.2).

  Common host command response/error codes (2-digit hex after response command code):
    00 = No error (success)
    01 = Verification failure (PIN/MAC/CVV mismatch or key parity import error)
    04 = Invalid key type
    05 = Invalid key length
    10 = Source key parity error
    11 = Destination key parity error or key all zeros
    15 = Invalid input data
    20 = PIN block error
    21 = No LMK loaded
    24 = Invalid PAN
    26 = Invalid expiry date
    30 = Invalid ARQC
    32 = Invalid transaction data
    68 = Command disabled (Function Blocking — enable in HSM settings)

  Console commands (physical keyboard on HSM, offline/maintenance mode only — not host commands):
    vt  = View Table (show LMK table and key change storage)
    GT  = Generate Test LMK (quick setup for dev/test environments)
    GK  = Generate Keys (component of production LMK setup ceremony)
    LK  = Load Keys (second step of production LMK load; GK then LK)
  Console prompt reflects mode: Offline> / Online> / Maintenance>

  Key type codes (3-digit, used in key generation/translation commands):
    000 = ZMK (Zone Master Key)    LMK pair 04-05
    001 = ZPK (Zone PIN Key)       LMK pair 06-07
    002 = PVK / TMK / TPK          LMK pair 14-15
    003 = TAK (Terminal Auth Key)  LMK pair 16-17
    006 = WWK                      LMK pair 22-23
    008 = ZAK                      LMK pair 26-27
    009 = BDK (DUKPT)              LMK pair 28-29

  Key scheme designators (key length/format prefix on encrypted key value):
    Z = single-length DES (deprecated)
    U = double-length TDES variant (most common legacy)
    T = triple-length TDES variant
    X = double-length TDES ANSI (X9.24 format)
    Y = triple-length TDES ANSI

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
               "Supports DUKPT, ZPK, and PEK key types. "
               "Wire fields: AW=wrapping mode, AX=inbound PEK (cryptogram or TR-31 block), "
               "BT=outbound PEK, AL=PIN block, AK=PAN. "
               "Example: [AOTPIN;AW1;AX<inbound_pek>;BT<outbound_pek>;AL<pin_block>;AK<pan>;]"),
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
    HsmCommand("Futurex", "Excrypt", "GPGS", "General Purpose Generate Symmetric Key", "KEY_MGMT",
               "Generates a symmetric key (TDES or AES) under the HSM master file key. "
               "Returns the key as a raw cryptogram (legacy) with no MAC or binding metadata. "
               "Used for one-time symmetric key generation outside of DUKPT or TR-31 flows.",
               "create_key", None,
               "Wire example: [AOGPGS;CT3;FS1;] → [AOGPGS;AE5AAE;BG<24-byte-hex-cryptogram>;RT1;]. "
               "The 24-byte BG field is a TDES cryptogram — length reveals the algorithm, "
               "usage/type are stored only in a separate key database (no binding). "
               "Migrate generated keys through GKBL immediately to obtain a TR-31 key block "
               "for PCI PIN 18-3 compliance. "
               "Source: Futurex TR-31 Key Block Implementation Whitepaper (2024)."),
    HsmCommand("Futurex", "Excrypt", "GKBL", "Translate Cryptogram to TR-31 Key Block", "KEY_MGMT",
               "Translates an existing cryptogram into a TR-31 key block, or generates a new key "
               "directly as a TR-31 key block. Core PCI PIN 18-3 migration command — attaches "
               "key usage, algorithm, mode-of-use, and exportability to the key value via the "
               "header, providing both confidentiality and integrity. "
               "Must be enabled via Excrypt Manager → Function Blocking tab.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Wire example (cryptogram → key block): "
               "[AOGKBL;AS1;BG<cryptogram>;AKA0088P0TE00E0000;] → [AOGKBL;BB<key_block>;AE<kcv>;]. "
               "TR-31 key block header fields (example 'A0088P0TE00E0000'): "
               "  pos 0     — version: A=Key Variant Binding (DEPRECATED, do not use for new keys), "
               "                        B=TDEA Key Derivation Binding, "
               "                        C=TDEA Key Variant Binding, "
               "                        D=AES Key Derivation Binding (REQUIRED for PCI P2PE Req 12-5); "
               "  pos 1-4   — total key block length in ASCII decimal (e.g. '0088'); "
               "  pos 5-6   — key usage (TR-31 code, e.g. P0=PIN encryption, M6=CMAC, "
               "                          C0=CVK, B0=BDK, K1=KEK, D0=data encryption); "
               "  pos 7     — algorithm: A=AES, T=Triple-DES, D=DES (prohibited); "
               "  pos 8     — mode of use: E=encrypt/wrap only, N=no restriction, "
               "                            X=derive keys, G=generate/verify MAC; "
               "  pos 9-10  — key version (00=not a component, 01-99=component index); "
               "  pos 11    — exportability: E=exportable under KEK, N=non-exportable, S=sensitive; "
               "  pos 12-13 — number of optional blocks (00=none); "
               "  pos 14-15 — reserved by TR-31 spec (00). "
               "Version D (AES) is required for PCI P2PE compliance (Req 12-5); versions B/C use TDES MFK. "
               "Futurex HSMs pad shorter key blocks to at least 3DES length automatically. "
               "After migration, only key blocks should be stored — disable cryptograms in Key Block Policy. "
               "Source: Futurex TR-31 Key Block Implementation Whitepaper (2024)."),
]

# ── Futurex/Thales International Commands ────────────────────────────────────
# IMPORTANT: Futurex International API is Thales payShield compatible.
# These command codes appear in BOTH Thales payShield and Futurex International mode codebases.
# Fixed-length fields, no delimiters. First 2 characters = command code.
# Thales response: 2-char response code where "00" = success.
#
# Wire format reference: PUGD0537-004 Rev A, August 2020 (payShield 10K Core Host Commands) — AUTHORITATIVE
# for M0/M2/M4 (p.381/388/394), M6/M8/MY (p.363/368/373), KQ/KW/KU/KY/K2 (p.468–483).
# PIN/MAC/CVV commands also confirmed in Futurex General Payment HSM Integration Guide (2024).

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
    HsmCommand("Thales/Futurex", "International", "JA",
               "Generate Random PIN", "PIN",
               "Generates a random PIN of specified length for a given PAN. "
               "Returns the PIN encrypted under LMK. Response code: JB.",
               "generate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Wire params (thales-bogr): PAN (12N), PIN length (2N). "
               "In APC: generate_pin_data returns a PIN block encrypted under the specified PEK; "
               "APC has no LMK concept — the output key is the APC PEK ARN. "
               "EFTlab + thales-bogr sources — reference quality.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "BA",
               "Encrypt Clear PIN to LMK-Encrypted PIN Block", "PIN",
               "Accepts a clear PIN and account number, returns a PIN block encrypted under LMK. "
               "Used to bring a clear PIN into HSM custody. Response code: BB.",
               "generate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Wire params (thales-bogr): PIN format (7-char, e.g. 01 = ISO Format 1), "
               "account number. Clear PIN must never appear in logs — this command is the "
               "boundary where clear PINs enter HSM custody. "
               "In APC: generate_pin_data. Clear PIN input is not supported by APC directly; "
               "use generate_pin_data with PIN entered at a PCI PTS-certified device. "
               "EFTlab + thales-bogr sources — reference quality.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "NG",
               "Decrypt PIN Block to Clear PIN (Get Clear PIN)", "PIN",
               "Decrypts an LMK-encrypted PIN block to recover the clear PIN. Response code: NH.",
               None, None,
               "COMPLIANCE HARD STOP: Exposing a clear PIN from an HSM violates PCI PIN Req 3-1. "
               "This command exists for PIN printing workflows (e.g. mailers) and must only be "
               "used with a PIN print module under dual control. Never log the clear PIN output. "
               "In APC: no equivalent. APC does not expose clear PINs under any circumstance. "
               "Wire params (thales-bogr): account number (12N last digits), PIN under LMK. "
               "EFTlab + thales-bogr sources — reference quality.",
               confidence="medium"),
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
               "IBM 3624 offset PIN verification with original single-length DUKPT. "
               "Response code: CL. BDK (LMK pair 28-29) derives a 56-bit working key "
               "from the KSN. Field layout: BDK (32H|U+32H) + PVK (16H|U+32H|T+48H, LMK 14-15 v0) "
               "+ KSN descriptor (3H) + KSN (20H standard) + PIN block (16H ISO-0) "
               "+ check length (2N) + account number (12N) + decimalization table (16N) "
               "+ PIN validation data (12A) + IBM offset (12H, F-padded).",
               "verify_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "APC Rust SDK v1: use PinVerificationAttributes::Ibm3624Pin(Ibm3624PinVerification). "
               "Ibm3624PinVerification fields: decimalization_table, pin_validation_data_pad_character, "
               "pin_validation_data, pin_offset. BDK ARN goes in encryption_key_identifier on the outer "
               "verify_pin_data call — NOT inside DukptAttributes. DukptAttributes only holds "
               "key_serial_number + dukpt_derivation_type (DukptDerivationType::Tdes2Key). "
               "PVK ARN goes in verification_key_identifier. PIN block goes in encrypted_pin_block at "
               "the outer call level. Note: Ibm3624PinOffset is for generate_pin_data, not verify. "
               "CO (Diebold) and CQ (Encrypted PIN) have no APC equivalent — return error 68."),
    HsmCommand("Thales/Futurex", "International", "CM",
               "Verify PIN using Visa PVV Method (DUKPT)", "PIN",
               "Visa PVV PIN verification with original single-length DUKPT. "
               "Response code: CN. BDK (LMK pair 28-29) derives the working key from the KSN. "
               "Field layout: BDK (32H|U+32H) + PVK (32H|U+32H|T+48H, LMK 14-15 v0) "
               "+ KSN descriptor (3H) + KSN (20H) + PIN block (16H ISO-0) + PAN (12N) "
               "+ PVKI (1N) + PVV (4N). Token mode (';' delimiter before PVKI) not mappable to APC.",
               "verify_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY",
               "APC Rust SDK v1: use PinVerificationAttributes::VisaPin(VisaPinVerification). "
               "VisaPinVerification fields: pin_verification_key_index (PVKI as i32), verification_value (PVV). "
               "BDK ARN goes in encryption_key_identifier on the outer verify_pin_data call. "
               "DukptAttributes only holds key_serial_number + dukpt_derivation_type. "
               "PVK ARN goes in verification_key_identifier. PIN block goes in encrypted_pin_block "
               "at the outer call level. Note: VisaPinVerificationValue is for generate_pin_data, not verify."),
    HsmCommand("Thales/Futurex", "International", "DE",
               "Generate an IBM PIN Offset (of an LMK-encrypted PIN)", "PIN",
               "Generates an IBM 3624 PIN offset from a customer-selected PIN already encrypted "
               "under LMK and a PVK. The offset encodes the delta between the natural PIN and the "
               "customer's chosen PIN, and is stored on the card/database for later verification. "
               "Response code: DF.",
               "generate_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.217 — AUTHORITATIVE. "
               "Used in card issuance flows where the customer selected their own PIN. "
               "See also BK (offset from customer-selected PIN without LMK step). "
               "In APC: generate_pin_data with TR31_V1_IBM3624_PIN_VERIFICATION_KEY."),
    HsmCommand("Thales/Futurex", "International", "EE",
               "Derive a PIN Using the IBM Offset Method", "PIN",
               "Derives the natural PIN for an account from the PAN using IBM 3624 DES derivation "
               "(encrypt transformed PAN with PVK, apply decimalization table). "
               "Response code: EF. Used in card issuance to compute the initial system-assigned PIN.",
               "generate_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.210 — AUTHORITATIVE. "
               "IBM 3624 natural PIN derivation: PAN → transform → DES encrypt with PVK → decimalize → PIN. "
               "The result is the 'natural PIN' that may then be printed on a mailer (NG command) "
               "or combined with an offset via DE. "
               "In APC: generate_pin_data with TR31_V1_IBM3624_PIN_VERIFICATION_KEY."),
    HsmCommand("Thales/Futurex", "International", "GA",
               "Derive a PIN Using the Diebold Method", "PIN",
               "Derives a PIN for an account using the Diebold derivation algorithm. "
               "Response code: GB. Used in card issuance to compute the initial system-assigned PIN.",
               "generate_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.213 — AUTHORITATIVE. "
               "Diebold PIN derivation variant; same APC mapping as EE (IBM 3624). "
               "In APC: generate_pin_data with TR31_V1_IBM3624_PIN_VERIFICATION_KEY."),
    HsmCommand("Thales/Futurex", "International", "BK",
               "Generate an IBM PIN Offset (of a Customer-Selected PIN)", "PIN",
               "Generates an IBM 3624 PIN offset where the customer enters their desired PIN "
               "directly (not pre-encrypted under LMK). Response code: BL.",
               "generate_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.220 — AUTHORITATIVE. "
               "Customer-facing variant of DE. The clear PIN is accepted only at PCI PTS-certified "
               "entry devices and must never be logged. In APC: generate_pin_data."),
    HsmCommand("Thales/Futurex", "International", "CE",
               "Generate a Diebold PIN Offset", "PIN",
               "Generates a Diebold PIN offset for a given account. Response code: CF.",
               "generate_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.224 — AUTHORITATIVE. "
               "Diebold offset variant. In APC: generate_pin_data."),
    HsmCommand("Thales/Futurex", "International", "DG",
               "Generate an ABA PVV (of an LMK-encrypted PIN)", "PIN",
               "Generates an ABA PVV (Visa PIN Verification Value) from a customer-selected PIN "
               "encrypted under LMK. Response code: DH.",
               "generate_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.225 — AUTHORITATIVE. "
               "LMK-encrypted PIN input variant of FW. "
               "In APC: generate_pin_data with TR31_V2_VISA_PIN_VERIFICATION_KEY."),
    HsmCommand("Thales/Futurex", "International", "FW",
               "Generate an ABA PVV (of a Customer-Selected PIN)", "PIN",
               "Generates an ABA PVV where the customer enters their desired PIN directly. "
               "Response code: FX.",
               "generate_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.227 — AUTHORITATIVE. "
               "Customer-facing variant of DG. Clear PIN accepted only at PCI PTS-certified devices. "
               "In APC: generate_pin_data with TR31_V2_VISA_PIN_VERIFICATION_KEY."),
    HsmCommand("Thales/Futurex", "International", "DU",
               "Verify a PIN and Generate an IBM PIN Offset (of Customer-Selected New PIN)", "PIN",
               "Verifies the cardholder's current PIN and, if correct, generates an IBM 3624 offset "
               "for their new customer-selected PIN. Atomic PIN change. Response code: DV.",
               "generate_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.255 — AUTHORITATIVE. "
               "Combined verify-then-generate in a single command. "
               "In APC: verify_pin_data followed by generate_pin_data (two calls)."),
    HsmCommand("Thales/Futurex", "International", "CU",
               "Verify a PIN and Generate an ABA PVV (of Customer-Selected New PIN)", "PIN",
               "Verifies the cardholder's current PIN and, if correct, generates a new ABA PVV "
               "for their customer-selected new PIN. Atomic PIN change. Response code: CV.",
               "generate_pin_data", "TR31_V2_VISA_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.259 — AUTHORITATIVE. "
               "Combined verify-then-generate in a single command. "
               "In APC: verify_pin_data followed by generate_pin_data (two calls)."),
    # PIN Verification — non-DUKPT variants
    HsmCommand("Thales/Futurex", "International", "BC",
               "Verify a Terminal PIN Using the Comparison Method", "PIN",
               "Verifies a terminal PIN by decrypting it and comparing against a stored PIN "
               "encrypted under LMK. Response code: BD.",
               "verify_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0537-004 Rev A, p.277 — AUTHORITATIVE. "
               "Comparison method: decrypts both PIN blocks and compares clear values. "
               "In APC: verify_pin_data with PinVerificationAttributes for comparison method."),
    HsmCommand("Thales/Futurex", "International", "BE",
               "Verify an Interchange PIN Using the Comparison Method", "PIN",
               "Verifies an interchange (ZPK-encrypted) PIN by decrypting and comparing "
               "against an LMK-stored reference PIN. Response code: BF.",
               "verify_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0537-004 Rev A, p.279 — AUTHORITATIVE. "
               "Interchange variant of BC. In APC: verify_pin_data."),
    HsmCommand("Thales/Futurex", "International", "CG",
               "Verify a Terminal PIN Using the Diebold Method", "PIN",
               "Verifies a terminal PIN using the Diebold PIN verification algorithm. "
               "Response code: CH.",
               "verify_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.269 — AUTHORITATIVE. "
               "Terminal key (TPK) inbound. In APC: verify_pin_data."),
    HsmCommand("Thales/Futurex", "International", "EG",
               "Verify an Interchange PIN Using the Diebold Method", "PIN",
               "Verifies an interchange (ZPK-encrypted) PIN using the Diebold algorithm. "
               "Response code: EH.",
               "verify_pin_data", "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.271 — AUTHORITATIVE. "
               "ZPK inbound. In APC: verify_pin_data."),
    # DUKPT PIN Verification — 3DES and AES (X9.24-1 and X9.24-3)
    HsmCommand("Thales/Futurex", "International", "GO",
               "Verify a PIN Using the IBM Offset Method (3DES & AES DUKPT)", "PIN",
               "Verifies a DUKPT-encrypted PIN using the IBM 3624 offset method. Supports both "
               "3DES (X9.24-1) and AES (X9.24-3) DUKPT. Response code: GP.",
               "verify_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "Source: PUGD0537-004 Rev A, p.349 — AUTHORITATIVE. "
               "BDK (LMK pair 28-29) + KSN derive the working key. "
               "In APC: verify_pin_data with IncomingDukptAttributes (BDK ARN + KSN + dukpt_derivation_type). "
               "For AES DUKPT: dukpt_derivation_type=AES_128 and 12-byte KSN."),
    HsmCommand("Thales/Futurex", "International", "GQ",
               "Verify a PIN Using the ABA PVV Method (3DES & AES DUKPT)", "PIN",
               "Verifies a DUKPT-encrypted PIN using the ABA PVV (Visa PIN Verification Value) "
               "method. Supports both 3DES and AES DUKPT. Response code: GR.",
               "verify_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "Source: PUGD0537-004 Rev A, p.352 — AUTHORITATIVE. "
               "In APC: verify_pin_data with IncomingDukptAttributes + "
               "PinVerificationAttributes::VisaPin(VisaPinVerification). "
               "PVK ARN in verification_key_identifier; BDK ARN in encryption_key_identifier."),
    HsmCommand("Thales/Futurex", "International", "GS",
               "Verify a PIN Using the Diebold Method (3DES & AES DUKPT)", "PIN",
               "Verifies a DUKPT-encrypted PIN using the Diebold method. "
               "Supports both 3DES and AES DUKPT. Response code: GT.",
               "verify_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "Source: PUGD0537-004 Rev A, p.355 — AUTHORITATIVE. "
               "In APC: verify_pin_data with IncomingDukptAttributes."),
    HsmCommand("Thales/Futurex", "International", "GU",
               "Verify a PIN Using the Encrypted PIN Method (3DES & AES DUKPT)", "PIN",
               "Verifies a DUKPT-encrypted PIN by decrypting and comparing against a stored "
               "reference PIN (Encrypted PIN comparison method). Supports 3DES and AES DUKPT. "
               "Response code: GV.",
               "verify_pin_data", "TR31_B0_BASE_DERIVATION_KEY",
               "Source: PUGD0537-004 Rev A, p.358 — AUTHORITATIVE. "
               "In APC: verify_pin_data with IncomingDukptAttributes. "
               "TDES prohibited for new deployments since Jan 2023 — migrate to AES DUKPT."),
    # PIN Translation — additional
    HsmCommand("Thales/Futurex", "International", "BQ",
               "Translate PIN Algorithm (PIN Block Format Conversion)", "PIN",
               "Translates a PIN block from one PIN block format to another without decrypting "
               "the PIN to clear text. Response code: BR.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0537-004 Rev A, p.294 — AUTHORITATIVE. "
               "Used to convert between ISO Format 0, Format 1, Format 3, Format 4, etc. "
               "In APC: translate_pin_data with explicit source and target format specifiers."),
    HsmCommand("Thales/Futurex", "International", "AQ",
               "Translate an RSA-encrypted PIN to a ZPK or TPK-encrypted PIN", "PIN",
               "Translates a PIN block encrypted under an RSA public key into a symmetric "
               "(ZPK or TPK) encrypted PIN block. Response code: AR.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0537-004 Rev A, p.296 — AUTHORITATIVE. "
               "Used in RSA-based remote PIN entry (OPINPad) flows. "
               "In APC: no direct RSA PIN translate — decrypt RSA-encrypted PIN then "
               "translate_pin_data; or use a dedicated PIN translation HSM for the RSA step."),
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
    HsmCommand("Thales/Futurex", "International", "QY",
               "Generate a Dynamic CVV", "CVV",
               "Generates a Dynamic Card Verification Value (dCVV) for a contactless or EMV "
               "transaction. Response code: QZ.",
               "generate_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.306 — AUTHORITATIVE. "
               "dCVV is time-limited or transaction-specific; requires a DCVV-enabled CVK. "
               "In APC: generate_card_validation_data with TR31_C0_CARD_VERIFICATION_KEY."),
    HsmCommand("Thales/Futurex", "International", "PM",
               "Verify a Dynamic CVV/CVC", "CVV",
               "Verifies a Dynamic CVV or CVC value for contactless or EMV transactions. "
               "Response code: PN.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.308 — AUTHORITATIVE. "
               "Validates the dCVV against the expected value derived from the card's dynamic key. "
               "In APC: verify_card_validation_data with TR31_C0_CARD_VERIFICATION_KEY."),
    HsmCommand("Thales/Futurex", "International", "RY",
               "Calculate/Verify Card Security Codes", "CVV",
               "Calculates or verifies card security codes (Mastercard CVC2, Visa CVV2, Amex CID). "
               "Response code: RZ.",
               "verify_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.315-316 — AUTHORITATIVE. "
               "Dual-function: generate or verify depending on parameters. "
               "In APC: generate_card_validation_data or verify_card_validation_data with TR31_C0."),
    HsmCommand("Thales/Futurex", "International", "NY",
               "Generate IVCVC3 and Static CVC3", "CVV",
               "Generates an Initial Vector CVC3 (IVCVC3) and/or Static CVC3 for Mastercard "
               "contactless (PayPass/Tap & Go) transactions. Response code: NZ.",
               "generate_card_validation_data", "TR31_C0_CARD_VERIFICATION_KEY",
               "Source: PUGD0537-004 Rev A, p.493 — AUTHORITATIVE. "
               "CVC3 is Mastercard's contactless card verification value. "
               "IVCVC3 is a one-time initialization vector; Static CVC3 is precomputed at issuance. "
               "In APC: generate_card_validation_data with TR31_C0_CARD_VERIFICATION_KEY."),
    # MAC
    HsmCommand("Thales/Futurex", "International", "M6",
               "Generate MAC using MAK (supports continuation mode)", "MAC",
               "Generates a MAC using a Message Authentication Key (MAK). "
               "Supports multi-block continuation mode for large messages. Response code: M7.",
               "generate_mac", "TR31_M1_ISO_9797_1_MAC_KEY or TR31_M6_ISO_9797_5_CMAC_KEY",
               "Source: PUGD0537-004 Rev A, p.363 — AUTHORITATIVE. "
               "Wire: Mode Flag 1N + Input Format Flag 1N + MAC Size 1N + MAC Algorithm 1N "
               "+ Padding Method 1N + Key Type 3H (003=TAK/008=ZAK variant, FFF=KB-LMK) "
               "+ Key (16H/U+32H/T+48H or S+nA) + [Message Length 4H] + Message. "
               "Response M7: Error 2A + MAC (8H or 16H). "
               "Use MY for Key Block LMK keys. CBC-MAC — consider migrating to CMAC for new work. "
               "WARNING: proxy mac.rs uses simplified format (mode 1N + key 32H fixed + msg_len 4H) "
               "without the Input Format, MAC Size, Algorithm, Padding, or Key Type fields — "
               "not wire-compatible with a real payShield M6."),
    HsmCommand("Thales/Futurex", "International", "M8",
               "Verify MAC using MAK (supports continuation mode)", "MAC",
               "Verifies a MAC using a Message Authentication Key. Response code: M9. "
               "Error 01 = MAC mismatch.",
               "verify_mac", "TR31_M1_ISO_9797_1_MAC_KEY or TR31_M6_ISO_9797_5_CMAC_KEY",
               "Source: PUGD0537-004 Rev A, p.368 — AUTHORITATIVE. "
               "Same wire layout as M6 with MAC value appended at end of command payload."),
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
               "AS2805 MAC generation (Australian payment network standard).",
               "generate_mac", "TR31_M0_ISO_16609_MAC_KEY"),
    HsmCommand("Thales/Futurex", "International", "C4",
               "Verify MAC (AS2805)", "MAC",
               "AS2805 MAC verification.", "verify_mac", "TR31_M0_ISO_16609_MAC_KEY"),
    HsmCommand("Thales/Futurex", "International", "MY",
               "Verify and Translate MAC", "MAC",
               "Verifies a MAC under one key and generates a new MAC under a different key in a "
               "single atomic operation. Response code: MZ. Used at network gateway boundaries "
               "to re-MAC a message as it crosses zone boundaries.",
               "verify_mac", "TR31_M1_ISO_9797_1_MAC_KEY or TR31_M6_ISO_9797_5_CMAC_KEY",
               "Source: PUGD0537-004 Rev A, p.371 — AUTHORITATIVE. "
               "Core equivalent of Legacy ME command. "
               "In APC: two separate calls — verify_mac (inbound MAK ARN) then generate_mac (outbound MAK ARN). "
               "Both keys should be TR31_M3 or TR31_M6; prefer CMAC over CBC-MAC for new deployments."),
    # ARQC
    HsmCommand("Thales/Futurex", "International", "KQ",
               "Verify ARQC / Generate ARPC (Static & MC Proprietary SKD)", "ARQC",
               "EMV cryptogram verification (ARQC, TC, AAC) and ARPC generation. "
               "Supports Visa Static Data Auth and Mastercard Proprietary SKD. Response code: KR.",
               "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
               "Source: PUGD0537-004 Rev A, p.468 — AUTHORITATIVE. "
               "Wire (all multibyte fields are RAW BINARY, not hex-encoded): "
               "Mode Flag 1N (0=verify only, 1=verify+ARPC M1, 2=verify+ARPC M2, "
               "3=skip verify+ARPC M1, 4=skip verify+ARPC M2) + Scheme ID 1N (0=Visa/Amex, 1=MC) "
               "+ Key Type 3H (00E=IMK-AC, FFF=KB-LMK) + Key (16H/U+32H/T+48H or S+nA) "
               "+ PAN+PAN_Seq 8 B (BCD packed, left-justified, right-padded with 0xF; includes 2-digit seq) "
               "+ ATC 2 B + UN 4 B (Unpredictable Number) "
               "+ Transaction Data Length 2 B + Transaction Data n B "
               "+ ';' delimiter 0x3B + ARQC 8 B. "
               "Mode 1/3 appends: ARC 2 B (ARPC Method 1). "
               "Mode 2/4 appends: CSU 4 B + PAD length 1 B + PAD n B (ARPC Method 2). "
               "Response KR: error 2A + ARPC 8 B (if mode ≠ 0). "
               "For Visa CVN14/18/22, MC M/Chip, Amex, Discover, JCB, UnionPay, or cloud SKD use KW. "
               "WARNING: proxy kq_arqc.rs uses hex-encoded ASCII (non-standard) — not wire-compatible "
               "with a real payShield without format adaptation. See payshield-core-commands-ref.md."),
    HsmCommand("Thales/Futurex", "International", "KW",
               "Verify ARQC / Generate ARPC (EMV & Cloud-Based SKD)", "ARQC",
               "EMV cryptogram verification and ARPC generation with extended derivation method support. "
               "Covers Visa CVN14/18/22, Mastercard M/Chip, Amex, Discover, JCB, UnionPay, and "
               "cloud-based (token) SKD variants. Response code: KX.",
               "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
               "Source: PUGD0537-004 Rev A, p.471 — AUTHORITATIVE. Requires Premium package license. "
               "Wire: same binary-encoded structure as KQ plus Derivation Method 1A field "
               "(scheme-specific code identifying the CVN/SKD variant) after Scheme ID. "
               "APC verify_auth_request_cryptogram supports the major EMV derivation methods natively; "
               "map the Derivation Method byte to the appropriate MajorKeyDerivationMode "
               "and SessionKeyDerivationMode in EmvCommon/VisaAmex/Mastercard attributes."),
    HsmCommand("Thales/Futurex", "International", "KU",
               "Generate Secure Message (EMV 3.1.1)", "ARQC",
               "Generates an EMV 3.1.1 issuer secure message for delivery to the chip card. "
               "Computes a MAC over the script command using the SMI (Secure Messaging Integrity) "
               "issuer master key, and optionally encrypts sensitive data with the SMC key. "
               "Response code: KV.",
               "generate_mac_emv_pin_change", "TR31_E2_EMV_MKEY_INTEGRITY",
               "Source: PUGD0537-004 Rev A, p.475 — AUTHORITATIVE. "
               "Covers issuer script MAC generation for all EMV 3.1.1 secure messaging commands "
               "(e.g. PUT DATA, EXTERNAL AUTHENTICATE, PIN UNBLOCK). "
               "In APC: generate_mac_emv_pin_change for PIN-change scripts (MAC+cipher combined); "
               "generate_mac with TR31_E2_EMV_MKEY_INTEGRITY for MAC-only scripts. "
               "Key: SMI master key (TR31_E2). Optional SMC key (TR31_E1) for confidentiality."),
    HsmCommand("Thales/Futurex", "International", "KY",
               "Generate Secure Message (EMV 4.x)", "ARQC",
               "Generates an EMV 4.x issuer secure message. Extends KU to support the EMV 4.x "
               "secure messaging format (longer MAC, updated derivation). Response code: KZ.",
               "generate_mac_emv_pin_change", "TR31_E2_EMV_MKEY_INTEGRITY",
               "Source: PUGD0537-004 Rev A, p.480 — AUTHORITATIVE. "
               "Same conceptual operation as KU but for EMV 4.x (EMV 2004+) card profiles. "
               "In APC: same mapping as KU — generate_mac_emv_pin_change or generate_mac with TR31_E2."),
    HsmCommand("Thales/Futurex", "International", "K2",
               "Mastercard CAP (Chip Authentication Program) Verification", "ARQC",
               "Verifies a Mastercard CAP one-time password or transaction authentication code. "
               "Response code: K3.",
               "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
               "Source: PUGD0537-004 Rev A, p.485 — AUTHORITATIVE. "
               "Mastercard CAP (also known as MasterCard Secure Code / UCAF): "
               "card-generates a 6–8 digit OTP from the AC key and transaction parameters. "
               "In APC: verify_auth_request_cryptogram with TR31_E0 master key."),
    HsmCommand("Thales/Futurex", "International", "KS",
               "Data Authentication Code and Dynamic Number Verification (EMV 3.1.1)", "ARQC",
               "Verifies an EMV 3.1.1 Data Authentication Code (DAC) and Dynamic Number "
               "(dynamic CVV equivalent) using the issuer application cryptogram key. "
               "Response code: KT.",
               "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
               "Source: PUGD0537-004 Rev A, p.488 — AUTHORITATIVE. "
               "Used for EMV 3.1.1 contactless/chip card SDA and DDA verification. "
               "In APC: verify_auth_request_cryptogram with TR31_E0 master key."),
    HsmCommand("Thales/Futurex", "International", "K0",
               "Decrypt Encrypted Counters (EMV 4.x)", "ARQC",
               "Decrypts the encrypted counters in an EMV 4.x chip card response using the "
               "appropriate issuer master key. Response code: K1.",
               "decrypt_data", "TR31_E1_EMV_MKEY_CONFIDENTIALITY",
               "Source: PUGD0537-004 Rev A, p.490 — AUTHORITATIVE. "
               "Used to recover plain-text ATC and other counters from an EMV 4.x card response "
               "for risk management and velocity checking. "
               "In APC: decrypt_data with TR31_E1_EMV_MKEY_CONFIDENTIALITY issuer master key."),
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
               "Encrypts a data block. Response code: M1. Supports ECB, CBC, CFB8/64, OFB, CTR, "
               "FF1 FPE (NIST SP 800-38G), Visa Standard Encryption (mode 04), and Visa FPE (mode 13).",
               "encrypt_data", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
               "Source: PUGD0537-004 Rev A, p.381 — AUTHORITATIVE. "
               "Mode Flag 2N: 00=ECB, 01=CBC(+IV), 02=CFB8(+IV), 03=CFB64(+IV), "
               "04=Visa Std Enc (license), 05=OFB(+IV), 06=CTR(+IV), 11=FF1 FPE, 13=Visa FPE (license). "
               "Input Format Flag 1N (0=binary, 1=hex, 2=text) — omitted for modes 04/13. "
               "Output Format Flag 1N (0=binary, 1=hex) — omitted for mode 13. "
               "Key Type 3H: 009/609/809/909=BDK-1/2/3/4, 00A=ZEK, 00B=DEK, 30B=TEK, FFF=KB-LMK. "
               "For BDK: KSN Descriptor 3H + KSN 12-20H (24H for AES BDK). "
               "IV 16H (DES) or 32H (AES) for modes 01-03/05-06 — use all-zeros for first block. "
               "Modes 00-10: Message Length 4H (max 0x7D00) + Message. "
               "Modes 04/13: Block Count 2N + [Block Type 1A (A=PAN/B=Name/C=Track1/D=Track2) + Len 4H + Data] per block. "
               "No HSM padding — input must be a multiple of block size (8B DES/3DES, 16B AES). "
               "Response M1 adds output IV + Message Length + Encrypted Message. "
               "In APC: encrypt_data with TR31_D0 key."),
    HsmCommand("Thales/Futurex", "International", "M2",
               "Decrypt a Block of Data", "ENCRYPT",
               "Decrypts a data block. Response code: M3. Identical structure to M0 with additional "
               "mode 10=BPS (Ingenico FPE, requires PS10-LIC-VDSP).",
               "decrypt_data", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
               "Source: PUGD0537-004 Rev A, p.388 — AUTHORITATIVE. "
               "Same field layout as M0; mode 10 (BPS/Ingenico FPE) is decrypt-only. "
               "BDK key restrictions: BDK-1/3=bidirectional, BDK-2=request data, BDK-4=response data. "
               "In APC: decrypt_data with TR31_D0 key."),
    HsmCommand("Thales/Futurex", "International", "M4",
               "Translate (Re-encrypt) a Data Block", "ENCRYPT",
               "Re-encrypts a data block from one key to another without exposing plaintext. "
               "Response code: M5. Used at zone boundaries to change the protecting key.",
               "re_encrypt_data", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
               "Source: PUGD0537-004 Rev A, p.394 — AUTHORITATIVE. "
               "Fields: Source Mode Flag 2N + Dest Mode Flag 2N (no BPS for dest) "
               "+ [FPE Radix Flag/Value/Tweak if Source or Dest mode=11] "
               "+ Input Format Flag 1N + Output Format Flag 1N "
               "+ Source Key Type 3H + Source Key + [Source KSN Descriptor+KSN if BDK] "
               "+ Dest Key Type 3H + Dest Key + [Dest KSN Descriptor+KSN if BDK] "
               "+ Source IV (if mode CBC/CFB/OFB) + Dest IV (if mode CBC/CFB/OFB) "
               "+ Message Length 4H + Encrypted Message (or Block Count+Blocks for modes 04/13). "
               "Only Source OR Destination may be a BDK — not both. "
               "Source BDK-1/3=bidirectional, BDK-2=request. Dest BDK-1/3=bidirectional, BDK-4=response. "
               "In APC: re_encrypt_data; both keys must be TR31_D0."),
    # Key Management — ceremony and generation
    HsmCommand("Thales/Futurex", "International", "GC",
               "Generate ZMK Component", "KEY_MGMT",
               "Generates a clear ZMK component for use in a split-knowledge key ceremony. "
               "Returns the clear component and its encrypted form under LMK. Response code: GD. "
               "Parameters: key length [1=single, 2=double, 3=triple], key type (3-digit), key scheme.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "In APC: the ceremony is performed out-of-band by custodians; the resulting "
               "ZMK/KEK is imported via import_key using TR-34 (recommended) or TR-31. "
               "APC has no component generation command. "
               "snowch/hsm-guide source — reference quality.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "FK",
               "Form Key from Components", "KEY_MGMT",
               "XORs 2–9 key components (entered by separate custodians) into a working key. "
               "Component types: X=clear XOR, H=half/third, E=LMK-encrypted, S=smartcard. "
               "Response code: FL.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "In APC: no equivalent — component XOR ceremony is out-of-band; result is "
               "imported via TR-34/TR-31. "
               "snowch/hsm-guide source — reference quality.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "KG",
               "Generate Zone PIN Key (ZPK)", "KEY_MGMT",
               "Generates a new ZPK encrypted under both LMK and an optional ZMK. "
               "Response code: KH. Parameters: key length, key type (001=ZPK), key scheme (LMK), "
               "key scheme (ZMK), encrypted ZMK.",
               "create_key", "TR31_P0_PIN_ENCRYPTION_KEY",
               "In APC: create_key with TR31_P0_PIN_ENCRYPTION_KEY usage. "
               "APC replaces LMK storage — the key ARN is the reference. "
               "snowch/hsm-guide source — reference quality.",
               confidence="medium"),
    # Key Management — Core additions (authoritative sources)
    HsmCommand("Thales/Futurex", "International", "A4",
               "Form a Key from Encrypted Components", "KEY_MGMT",
               "XORs 2 or 3 LMK-encrypted key components to form a working key under LMK. "
               "Response code: A5. Variant of FK where components arrive pre-encrypted under LMK.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Source: PUGD0537-004 Rev A, p.50 — AUTHORITATIVE. "
               "Components are provided as LMK-encrypted values rather than clear text. "
               "In APC: ceremony is out-of-band; resulting key imported via import_key TR-31/TR-34."),
    HsmCommand("Thales/Futurex", "International", "B0",
               "Translate Key Scheme", "KEY_MGMT",
               "Translates a key from one key block scheme to another (e.g. variant-LMK → TR-31, "
               "or TDES → AES key block). Response code: B1.",
               "export_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Source: PUGD0537-004 Rev A, p.64 — AUTHORITATIVE. "
               "Core PCI PIN 18-3 migration tool: converts variant-encrypted keys to TR-31 key blocks. "
               "In APC: import_key (TR-31) then export_key under KEK for redistribution."),
    HsmCommand("Thales/Futurex", "International", "B8",
               "Export a Key under a TR-34 Public Key", "KEY_MGMT",
               "Exports a key wrapped under an RSA public key using the TR-34 protocol for "
               "asymmetric remote key distribution. Response code: B9.",
               "export_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Source: PUGD0537-004 Rev A, p.195 — AUTHORITATIVE. "
               "TR-34 asymmetric key distribution: used for remote key loading (RKL) to terminals. "
               "In APC: get_parameters_for_export + export_key with TR-34 wrapping. "
               "TR-34 is the recommended replacement for manual TMK/ZMK key injection ceremonies."),
    HsmCommand("Thales/Futurex", "International", "BY",
               "Translate a ZMK from ZMK to LMK Encryption", "KEY_MGMT",
               "Imports a ZMK from encryption under another ZMK into LMK protection. "
               "Response code: BZ.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Source: PUGD0537-004 Rev A, p.65 — AUTHORITATIVE. "
               "Used to receive a ZMK from a network partner encrypted under a pre-established ZMK. "
               "In APC: import_key with TR-31 key block; APC ARN replaces LMK storage."),
    HsmCommand("Thales/Futurex", "International", "HY",
               "Import a Key Encrypted under a KTK", "KEY_MGMT",
               "Imports a key encrypted under a Key Transfer Key (KTK) into LMK protection. "
               "Response code: HZ.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Source: PUGD0537-004 Rev A, p.56 — AUTHORITATIVE. "
               "KTK (Key Transfer Key) is a KEK used specifically for injection into secure equipment. "
               "In APC: import_key with the KTK as the wrapping KEK (TR31_K1 usage)."),
    HsmCommand("Thales/Futurex", "International", "K8",
               "Export a Key under a KEK", "KEY_MGMT",
               "Exports a key from LMK protection encrypted under a Key Encryption Key for "
               "delivery to a network partner. Response code: K9.",
               "export_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Source: PUGD0537-004 Rev A, p.82 — AUTHORITATIVE. "
               "General-purpose key export under KEK. In APC: export_key with TR-31 wrapping "
               "and TR31_K1 KEK. Prefer TR-34 for initial KEK establishment."),
    HsmCommand("Thales/Futurex", "International", "KI",
               "Derive Card Unique DES Keys", "KEY_MGMT",
               "Derives a card-unique DES key for EMV card personalization using an issuer "
               "derivation key and card-specific data (PAN, PAN sequence number). Response code: KJ.",
               "create_key", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
               "Source: PUGD0537-004 Rev A, p.76 — AUTHORITATIVE. "
               "Used in EMV card issuance to derive per-card keys from an issuer master key. "
               "In APC: no direct equivalent for card-personalization key derivation — "
               "use create_key to generate a unique key per card or derive externally using "
               "EMV Key Derivation tools."),
    # HMAC
    HsmCommand("Thales/Futurex", "International", "L0",
               "Generate an HMAC Secret Key", "MAC",
               "Generates a new HMAC secret key under LMK. Response code: L1.",
               "create_key", "TR31_M7_HMAC_KEY",
               "Source: PUGD0537-004 Rev A, p.402 — AUTHORITATIVE. "
               "Supports SHA-1, SHA-256, SHA-384, and SHA-512 based HMAC keys. "
               "In APC: create_key with TR31_M7_HMAC_KEY."),
    HsmCommand("Thales/Futurex", "International", "LQ",
               "Generate an HMAC on a Block of Data", "MAC",
               "Generates an HMAC over a data block using an HMAC secret key. Response code: LR.",
               "generate_mac", "TR31_M7_HMAC_KEY",
               "Source: PUGD0537-004 Rev A, p.405 — AUTHORITATIVE. "
               "Supports HMAC-SHA-1 (20 B), HMAC-SHA-256 (32 B), HMAC-SHA-384 (48 B), "
               "HMAC-SHA-512 (64 B). Output length determined by algorithm, not truncated. "
               "In APC: generate_mac with TR31_M7_HMAC_KEY."),
    HsmCommand("Thales/Futurex", "International", "LS",
               "Verify an HMAC on a Block of Data", "MAC",
               "Verifies an HMAC over a data block. Response code: LT. Error 01 = HMAC mismatch.",
               "verify_mac", "TR31_M7_HMAC_KEY",
               "Source: PUGD0537-004 Rev A, p.407 — AUTHORITATIVE. "
               "In APC: verify_mac with TR31_M7_HMAC_KEY."),
    HsmCommand("Thales/Futurex", "International", "LU",
               "Import an HMAC Key under a ZMK", "MAC",
               "Imports an HMAC key from ZMK encryption into LMK protection. Response code: LV.",
               "import_key", "TR31_M7_HMAC_KEY",
               "Source: PUGD0537-004 Rev A, p.409 — AUTHORITATIVE. "
               "In APC: import_key with TR31_M7_HMAC_KEY; wrapping key is TR31_K1 KEK."),
    HsmCommand("Thales/Futurex", "International", "LW",
               "Export an HMAC Key under a ZMK", "MAC",
               "Exports an HMAC key from LMK protection to ZMK encryption for delivery to a "
               "network partner. Response code: LX.",
               "export_key", "TR31_M7_HMAC_KEY",
               "Source: PUGD0537-004 Rev A, p.411 — AUTHORITATIVE. "
               "In APC: export_key with TR31_M7_HMAC_KEY; wrapping key is TR31_K1 KEK."),
    # RSA and Data Protection
    HsmCommand("Thales/Futurex", "International", "EW",
               "Generate an RSA Signature", "ENCRYPT",
               "Generates an RSA digital signature over a data block or pre-computed hash. "
               "Response code: EX.",
               None, None,
               "Source: PUGD0537-004 Rev A, p.375 — AUTHORITATIVE. "
               "RSA signing for message authentication or non-repudiation. "
               "APC does not support RSA signature generation — "
               "use AWS KMS for RSA signing operations in migration architectures."),
    HsmCommand("Thales/Futurex", "International", "EY",
               "Validate an RSA Signature", "ENCRYPT",
               "Validates an RSA digital signature. Response code: EZ.",
               None, None,
               "Source: PUGD0537-004 Rev A, p.377 — AUTHORITATIVE. "
               "RSA signature verification. APC does not support RSA signature verification — "
               "use AWS KMS for RSA verification in migration architectures."),
    HsmCommand("Thales/Futurex", "International", "GM",
               "Hash a Block of Data", "ENCRYPT",
               "Computes a cryptographic hash (SHA-1, SHA-256, SHA-384, or SHA-512) over a "
               "data block. Response code: GN.",
               None, None,
               "Source: PUGD0537-004 Rev A, p.379 — AUTHORITATIVE. "
               "Hashing utility with no APC equivalent — implement in application code using "
               "standard libraries (Python hashlib, Java MessageDigest, Go crypto/sha256, etc.)."),
    # HSM Management / Utility
    HsmCommand("Thales/Futurex", "International", "N0",
               "Generate a Random Value", "KEY_MGMT",
               "Generates a cryptographically random value of specified byte length. "
               "Response code: N1.",
               None, None,
               "Source: PUGD0537-004 Rev A, p.445 — AUTHORITATIVE. "
               "No direct APC equivalent for standalone random number generation. "
               "APC uses randomness internally for all key generation. "
               "For application-level randomness: use AWS KMS GenerateRandom or language runtime CSPRNG."),
    HsmCommand("Thales/Futurex", "International", "NO",
               "HSM Status", "KEY_MGMT",
               "Returns HSM operational status, firmware version, and LMK check value. "
               "Response code: NP.",
               None, None,
               "Source: PUGD0537-004 Rev A, p.448 — AUTHORITATIVE. "
               "No APC equivalent — monitor APC health via AWS CloudWatch metrics and the "
               "AWS Management Console (namespace: AWS/PaymentCryptography)."),
    HsmCommand("Thales/Futurex", "International", "CS",
               "Modify Key Block Header", "KEY_MGMT",
               "Modifies header fields of a TR-31 key block (exportability, mode of use, "
               "key version) without changing the encrypted key value. Response code: CT.",
               "import_key", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
               "Source: PUGD0537-004 Rev A, p.443 — AUTHORITATIVE. "
               "Used during PCI PIN 18-3 key block migration to update key metadata. "
               "In APC: no direct equivalent — key attributes are set at creation/import and "
               "cannot be modified after the fact. "
               "Workaround: export the key, modify the TR-31 header fields, re-import."),
    # Diagnostic / utility (no APC equivalent)
    HsmCommand("Thales/Futurex", "International", "NC",
               "Perform HSM Diagnostics / Self-Test", "KEY_MGMT",
               "Runs HSM self-test and returns firmware version and LMK check value. "
               "Response code: ND. No input parameters required. "
               "Wire hex example: command code 'NC' = 0x4E43.",
               None, None,
               "No APC equivalent — APC health is monitored via CloudWatch and the AWS console. "
               "snowch/hsm-guide + thales-bogr sources — reference quality.",
               confidence="medium"),
    HsmCommand("Thales/Futurex", "International", "QH",
               "Query Host / Connectivity Test", "KEY_MGMT",
               "Tests HSM connectivity and returns firmware version and LMK check value. "
               "Response code: QI.",
               None, None,
               "No APC equivalent — use AWS service health checks. "
               "snowch/hsm-guide source — reference quality.",
               confidence="medium"),
    # ── RTKS / Australian AS2805 TKS Commands ────────────────────────────────
    # Source: payShield 10K Host Programmer's Manual PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE
    # CRITICAL: R* command codes are DUAL-PURPOSE. The same code has COMPLETELY DIFFERENT
    # semantics depending on which TKS is configured as the HSM security setting:
    # Variant A = Racal TKS (RTKS), Variant B = Australian AS2805 TKS.
    # H* commands (HI, HK, etc.) access whichever TKS is NOT the configured default.
    HsmCommand("Thales", "International", "RI",
               "RTKS TX Request with PIN / AS2805 Verify TX Request (no CD field)", "PIN",
               "DUAL-PURPOSE: "
               "If RTKS configured: Processes terminal PIN request using T/AQ Key (acquirer key). "
               "If Australian TKS configured: Verifies TX request with PIN when CD Field is not available. "
               "H* equivalent (non-configured TKS): HI. Response code: RJ.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "The exact APC mapping depends on which TKS function is in use. "
               "RTKS variant: translate_pin_data (TPK→ZPK or TPK→PEK). "
               "AS2805 variant: verify_pin_data or translate_pin_data. "
               "Identify active TKS before migrating. No bundled TKS abstraction in APC — "
               "each cryptographic step becomes a separate API call."),
    HsmCommand("Thales", "International", "RK",
               "RTKS TX Request Without PIN / AS2805 Generate TX Response with Auth Para (Acquirer)", "MAC",
               "DUAL-PURPOSE: "
               "If RTKS configured: Authenticates a non-PIN transaction request (MAC-based). "
               "If Australian TKS configured: Generates transaction response with authentication parameters, acquirer side. "
               "H* equivalent: HK. Response code: RL.",
               "generate_mac", "TR31_M0_ISO_16609_MAC_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "RTKS variant: MAC authentication → generate_mac with TAK (TR31_M3 or TR31_M6). "
               "AS2805 variant: MAC generation per AS2805 → generate_mac with TR31_M0_ISO_16609_MAC_KEY. "
               "AS2805 MAC key is M0 (ISO 16609), not M3 (retail MAC) or M6 (CMAC)."),
    HsmCommand("Thales", "International", "RM",
               "RTKS Administration Request / AS2805 Generate TX Response with Auth Para (Issuer)", "MAC",
               "DUAL-PURPOSE: "
               "If RTKS configured: Processes HSM administrative/maintenance transaction request. "
               "If Australian TKS configured: Generates transaction response with authentication parameters, card-issuer side. "
               "H* equivalent: HM. Response code: RN.",
               "generate_mac", "TR31_M0_ISO_16609_MAC_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "AS2805 variant: issuer-side MAC generation, AS2805 protocol. "
               "RTKS admin variant: administrative session management — no APC equivalent."),
    HsmCommand("Thales", "International", "RO",
               "RTKS TX Response with Auth Para (Issuer) / AS2805 Translate PIN from PEK to ZPK", "PIN",
               "DUAL-PURPOSE: "
               "If RTKS configured: Processes card issuer authentication response with auth parameters. "
               "If Australian TKS configured: Translates a PIN block from PEK encryption to ZPK encryption. "
               "H* equivalent: HO. Response code: RP.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "AS2805 variant is a direct PIN translation: translate_pin_data with IncomingEncryptionKey (PEK) "
               "and OutgoingEncryptionKey (ZPK). "
               "RTKS variant: issuer response verification — verify_mac or verify_auth_request_cryptogram depending on scheme."),
    HsmCommand("Thales", "International", "RQ",
               "RTKS Generate Auth Para and TX Response / AS2805 Verify TX Completion Confirmation", "MAC",
               "DUAL-PURPOSE: "
               "If RTKS configured: Generates authentication parameters and transaction response. "
               "If Australian TKS configured: Verifies transaction completion confirmation (MAC verification). "
               "H* equivalent: HQ. Response code: RR.",
               "verify_mac", "TR31_M0_ISO_16609_MAC_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "AS2805 variant: verify_mac with TR31_M0_ISO_16609_MAC_KEY. "
               "RTKS variant: generate_mac with TAK."),
    HsmCommand("Thales", "International", "RS",
               "RTKS Confirmation / AS2805 Generate TX Completion Response", "MAC",
               "DUAL-PURPOSE: "
               "If RTKS configured: Confirms transaction completion (final step of RTKS sequence). "
               "If Australian TKS configured: Generates MAC for transaction completion response. "
               "H* equivalent: HS. Response code: RT.",
               "generate_mac", "TR31_M0_ISO_16609_MAC_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "AS2805 variant: generate_mac. RTKS variant: MAC verification or confirmation step."),
    HsmCommand("Thales", "International", "RU",
               "RTKS TX Request with PIN (T/CI Key) / AS2805 Generate Auth Para at Card Issuer", "PIN",
               "DUAL-PURPOSE: "
               "If RTKS configured: Processes terminal PIN request using T/CI Key (card issuer key). "
               "If Australian TKS configured: Generates authentication parameters at the card issuer. "
               "H* equivalent: HU. Response code: RV.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "RTKS variant: PIN translation with issuer-side key (CI key) → translate_pin_data. "
               "AS2805 variant: issuer auth parameter generation → generate_mac with M0 key."),
    HsmCommand("Thales", "International", "RW",
               "RTKS Translate KEYVAL / AS2805 Generate Initial Terminal Key", "KEY_MGMT",
               "DUAL-PURPOSE: "
               "If RTKS configured: Translates a KEYVAL value between format representations. "
               "If Australian TKS configured: Generates and distributes an initial terminal key under ZMK. "
               "H* equivalent: HW. Response code: RX.",
               "import_key", "TR31_K0_KEY_ENCRYPTION_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "AS2805 'Generate Initial Terminal Key' maps to APC key distribution: "
               "create_key (TR31_P0 or TR31_M0) + export_key (wrapped under ZMK/TMK). "
               "RTKS KEYVAL translation: no direct APC equivalent."),
    # H* cross-TKS variants — same parameters as R*, opposite TKS
    HsmCommand("Thales", "International", "HI",
               "Cross-TKS variant of RI (non-configured TKS)", "PIN",
               "Provides access to the non-configured TKS function for RI. "
               "If HSM is configured for RTKS, HI performs Australian TKS function. "
               "If HSM is configured for Australian TKS, HI performs RTKS function. "
               "Response code: HJ.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "APC mapping identical to RI — see RI notes. Rarely used; indicates dual-TKS deployment."),
    HsmCommand("Thales", "International", "HK",
               "Cross-TKS variant of RK (non-configured TKS)", "MAC",
               "Provides access to the non-configured TKS function for RK. Response code: HL.",
               "generate_mac", "TR31_M0_ISO_16609_MAC_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. See RK notes."),
    HsmCommand("Thales", "International", "HM",
               "Cross-TKS variant of RM (non-configured TKS)", "MAC",
               "Provides access to the non-configured TKS function for RM. Response code: HN.",
               "generate_mac", "TR31_M0_ISO_16609_MAC_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. See RM notes."),
    HsmCommand("Thales", "International", "HO",
               "Cross-TKS variant of RO (non-configured TKS)", "PIN",
               "Provides access to the non-configured TKS function for RO. Response code: HP.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. See RO notes."),
    HsmCommand("Thales", "International", "HQ",
               "Cross-TKS variant of RQ (non-configured TKS)", "MAC",
               "Provides access to the non-configured TKS function for RQ. Response code: HR.",
               "verify_mac", "TR31_M0_ISO_16609_MAC_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. See RQ notes."),
    HsmCommand("Thales", "International", "HS",
               "Cross-TKS variant of RS (non-configured TKS)", "MAC",
               "Provides access to the non-configured TKS function for RS. Response code: HT.",
               "generate_mac", "TR31_M0_ISO_16609_MAC_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. See RS notes."),
    HsmCommand("Thales", "International", "HU",
               "Cross-TKS variant of RU (non-configured TKS)", "PIN",
               "Provides access to the non-configured TKS function for RU. Response code: HV.",
               "translate_pin_data", "TR31_P0_PIN_ENCRYPTION_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. See RU notes."),
    HsmCommand("Thales", "International", "HW",
               "Cross-TKS variant of RW (non-configured TKS)", "KEY_MGMT",
               "Provides access to the non-configured TKS function for RW. Response code: HX.",
               "import_key", "TR31_K0_KEY_ENCRYPTION_KEY",
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. See RW notes."),
    # ── LMK Migration / BDK Management ────────────────────────────────────────
    HsmCommand("Thales", "International", "BW",
               "Translate BDK or IKEY from Old LMK to New LMK", "KEY_MGMT",
               "Re-encrypts a BDK or IKEY from one LMK to another after an LMK re-key operation. "
               "Takes BDK/IKEY encrypted under old LMK, returns it encrypted under new LMK. "
               "Response code: BX.",
               None, None,
               "Source: PUGD0541-003 Rev A, Ch.4 — AUTHORITATIVE. "
               "No APC equivalent. APC manages its own key protection internally — "
               "there is no host-visible LMK re-key operation. When migrating from payShield to APC, "
               "export the BDK as TR-31 under a transport KEK before the LMK re-key, then import into APC. "
               "The BW command itself has no APC counterpart."),
    HsmCommand("Thales", "International", "GK",
               "Export BDK or IKEY Encrypted Under RSA Public Key", "KEY_MGMT",
               "Exports a BDK or IKEY encrypted under an RSA public key for secure transport. "
               "The RSA public key is validated by a MAC before use. Response code: GL.",
               "export_key", "TR31_B0_BASE_DERIVATION_KEY",
               "Source: PUGD0541-003 Rev A, Ch.5 RSA command set — AUTHORITATIVE. "
               "APC equivalent: export_key with WrappingKeySpec RSA_OAEP_SHA_256 or similar. "
               "Prefer TR-34 (get_parameters_for_export → export_key with TR-34 token) for "
               "standards-compliant authenticated BDK distribution."),
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
               "ARQC Verification and/or ARPC Generation (UnionPay / CUP)", "ARQC",
               "Source: PUGD0538-003 §7 pp.122-123 — AUTHORITATIVE. "
               "Verifies a UnionPay (CUP / PBOC 2.0/3.0) ARQC and optionally generates an ARPC. "
               "Response code: JT. License: PS10-LIC-LEGACY. "
               "Mode Flag (1H): '0'=verify only, '1'=verify+ARPC(ARC required), '2'=ARPC-only(no TxnData in wire). "
               "Scheme ID (1N): always '1' (CUP Card Key Derivation CUP ver4.2). "
               "KEY STRUCTURAL DIFFERENCE FROM KQ: "
               "(1) JS has NO 3H Key Type field before the key — key starts immediately after Scheme ID. "
               "(2) MK-AC is base-32H (always double-length minimum) — use parse_key_32 NOT parse_legacy_key. "
               "(3) PAN/Seq is 8B binary BCD (same decode as KQ: nibbles 0-11=right-12 PAN, 12-13=seq, 14-15=0xFF). "
               "(4) ATC is 2B binary (not 4H ASCII). "
               "(5) Padding Flag (1N, '0'/'1') is a SEPARATE FIELD between ATC and TxnLen — present for Modes 0,1 only. "
               "(6) TxnLen is 2H ASCII (2 hex chars, max 'FF'=255 bytes) NOT 4H. "
               "(7) TxnData is nB binary (not ASCII hex). "
               "(8) 0x3B delimiter required after TxnData (Modes 0,1). "
               "(9) ARQC is 8B binary (not 16H ASCII). "
               "(10) ARC is 2B binary (not 4H ASCII). "
               "Mode 2 limitation: APC verify_auth_request_cryptogram requires TransactionData; "
               "JS Mode 2 omits it — Mode 2 cannot be translated to APC. Reject with clear error. "
               "CUP padding: 0x80 + 0x00 bytes to 8-byte boundary (per JR/T 0025.5-2010 Appendix D.2). "
               "No ARPC Method 2 (CSU) — JS has no CSU field; ARPC Method 1 (XOR+ARC) only. "
               "KB entry: payment://knowledge-base concept.thales-js-command has full field table.",
               "verify_auth_request_cryptogram", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
               "In APC: verify_auth_request_cryptogram with TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS. "
               "Session key derivation: SessionKeyDerivation::Emv2000 (CUP/PBOC is EMV-2000 based). "
               "MajorKeyDerivationMode: EmvOptionA (CUP uses Option A-style IMK diversification). "
               "ARPC: CryptogramVerificationArpcMethod1 with auth_response_code from 2B binary ARC field."),
    HsmCommand("Thales", "Legacy", "JU",
               "Generate Secure Message with Integrity and optional Confidentiality (UnionPay)", "ARQC",
               "Source: PUGD0538-003 §7 pp.124-126 — AUTHORITATIVE. "
               "Generates a UnionPay issuer-to-card Secure Message: MAC (integrity) and optionally "
               "encrypted data or encrypted PIN block (confidentiality). Response code: JV. "
               "License: PS10-LIC-LEGACY. "
               "Mode Flag (1N): 0=integrity only, 1=integrity+confidentiality(same IMK), "
               "2=integrity+confidentiality(different keys), 3=integrity+confidentiality+PIN(same IMK), "
               "4=integrity+confidentiality+PIN(different keys). "
               "Uses MK-SMI (Variant 2 of LMK pair 28-29) for MAC; "
               "MK-SMC (Variant 3 of LMK pair 28-29) for encryption (Modes 2 and 4 only). "
               "PIN change modes (3,4): accepts Source PIN Block (ZPK or TPK encrypted), "
               "translates to session key encryption for card delivery. "
               "Response: MAC (4B = 8H), optionally Encrypted Destination PIN Block (32H for Modes 3,4), "
               "optionally Ciphertext Message Data (nB for Modes 1,2).",
               "generate_mac_emv_pin_change", "TR31_E2_EMV_MKEY_INTEGRITY",
               "In APC: generate_mac_emv_pin_change for MAC (uses TR31_E2_EMV_MKEY_INTEGRITY). "
               "For confidentiality (Modes 1-4): also requires TR31_E1_EMV_MKEY_CONFIDENTIALITY. "
               "APC GenerateMacEmvPinChange covers integrity MAC + PIN block encryption in one call. "
               "No direct APC equivalent for data confidentiality (non-PIN data encryption, Modes 1-2) — "
               "that requires a separate encrypt_data call with the session key."),
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
    r'\[AO([A-Z]{4});',                 # [AOTPIN; [AOGKBL; — actual Excrypt wire format
    r'\[([A-Z]{4});',                   # [TPIN; [EMVA; — application-level / abbreviated
    r'send\s*\(\s*["\[](TPIN|XPIN|EMVA|GMAC|VMAC|TPDD|VPIN|DCDK|ECDK|GKBL|GPGS)',
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
    r'["\'](CA|CB|CC|CD|CI|CJ|CW|CX|CY|CZ|DA|DC|EA|EC|M0|M2|M4|M6|M7|M8|M9|MA|MC|ME|MK|MM|MO|MQ|MS|MU|MW|MY|MZ|A0|A6|A8|IA|BU|KQ|KR|KS|KW|KX|KU|KV|KY|KZ|K0|K2|K3|GW)',
    r'["\'](DE|EE|GA|BK|CE|DG|FW|DU|CU|BC|BE|CG|EG|GO|GQ|GS|GU|BQ|AQ|CK|CM|JA|BA|NG|JC|JE|JG|FK|KG|NC|QH)',  # PIN/Key INTERNATIONAL (Core additions)
    r'["\'](QY|PM|RY|NY|A4|B0|B8|BY|HY|K8|KI|L0|LQ|LS|LU|LW|EW|EY|GM|NO|N0|CS)',  # CVV/HMAC/RSA/Mgmt INTERNATIONAL (Core)
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


