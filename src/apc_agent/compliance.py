"""
PCI PIN v3.1 compliance guard-rails and legacy construct detection.
All requirement citations reference PCI PIN Security Requirements and Testing Procedures v3.1, March 2021.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    HARD_STOP = "hard_stop"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ComplianceResult:
    severity: Severity
    message: str
    modern_alternative: str | None = None
    requires_qsa_exception: bool = False
    pci_requirement: str | None = None


# TR-31 key usage codes mapped to human-readable names and allowed operations.
# Source: APC User Guide + PCI PIN v3.1 Req 19
KEY_USAGE_REGISTRY = {
    "TR31_B0_BASE_DERIVATION_KEY": {
        "name": "Base Derivation Key (BDK)",
        "allowed_operations": ["encrypt_data", "decrypt_data", "translate_pin_data"],
        "description": "DUKPT base key — never used directly for transactions",
    },
    "TR31_C0_CARD_VERIFICATION_KEY": {
        "name": "Card Verification Key (CVK)",
        "allowed_operations": ["generate_card_validation_data", "verify_card_validation_data"],
        "description": "Used for CVV, CVV2, iCVV generation and verification",
    },
    "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY": {
        "name": "Symmetric Data Encryption Key (DEK)",
        "allowed_operations": ["encrypt_data", "decrypt_data", "re_encrypt_data"],
        "description": "General-purpose symmetric data encryption",
    },
    "TR31_D1_ASYMMETRIC_KEY_FOR_DATA_ENCRYPTION": {
        "name": "Asymmetric Data Encryption Key",
        "allowed_operations": ["encrypt_data", "decrypt_data"],
        "description": "RSA public key for data encryption",
    },
    "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS": {
        "name": "EMV Application Cryptogram Master Key",
        "allowed_operations": ["verify_auth_request_cryptogram", "generate_mac_emv_pin_change"],
        "description": "Used for ARQC/ARPC verification",
    },
    "TR31_E1_EMV_MKEY_CONFIDENTIALITY": {
        "name": "EMV Secure Messaging Confidentiality Key",
        "allowed_operations": ["encrypt_data", "decrypt_data", "generate_mac_emv_pin_change"],
        "description": "EMV script confidentiality",
    },
    "TR31_E2_EMV_MKEY_INTEGRITY": {
        "name": "EMV Secure Messaging Integrity Key",
        "allowed_operations": ["generate_mac_emv_pin_change"],
        "description": "EMV script integrity (MAC)",
    },
    "TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS": {
        "name": "EMV Dynamic Number Key",
        "allowed_operations": ["generate_card_validation_data", "verify_card_validation_data"],
        "description": "Used for dynamic card verification values",
    },
    "TR31_E6_EMV_MKEY_OTHER": {
        "name": "EMV Other Master Key",
        "allowed_operations": [
            "encrypt_data", "decrypt_data",
            "generate_card_validation_data", "verify_card_validation_data",
        ],
        "description": "General-purpose EMV master key",
    },
    "TR31_K0_KEY_ENCRYPTION_KEY": {
        "name": "Key Encryption Key (KEK)",
        "allowed_operations": ["import_key", "export_key"],
        "description": "Wraps other keys for transport",
    },
    "TR31_K1_KEY_BLOCK_PROTECTION_KEY": {
        "name": "Key Block Protection Key (KBPK)",
        "allowed_operations": ["import_key", "export_key"],
        "description": "TR-31 key block wrapping key — preferred over K0 for new deployments",
    },
    "TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT": {
        "name": "Asymmetric Key Agreement Key",
        "allowed_operations": ["import_key", "export_key"],
        "description": "ECDH key agreement",
    },
    "TR31_M0_ISO_16609_MAC_KEY": {
        "name": "MAC Key (AS2805 / ISO 16609)",
        "allowed_operations": ["generate_mac", "verify_mac"],
        "description": "AS2805 MAC key",
    },
    "TR31_M1_ISO_9797_1_MAC_KEY": {
        "name": "MAC Key (ISO 9797-1 Algorithm 1)",
        "allowed_operations": ["generate_mac", "verify_mac"],
        "description": "CBC-MAC — consider upgrading to CMAC (M6)",
    },
    "TR31_M3_ISO_9797_3_MAC_KEY": {
        "name": "MAC Key (ISO 9797-1 Algorithm 3 / Retail MAC)",
        "allowed_operations": ["generate_mac", "verify_mac"],
        "description": "Retail MAC (ANSI X9.19) — legacy, consider CMAC",
    },
    "TR31_M6_ISO_9797_5_CMAC_KEY": {
        "name": "CMAC Key (ISO 9797-1 Algorithm 5)",
        "allowed_operations": ["generate_mac", "verify_mac"],
        "description": "Preferred MAC algorithm for new deployments",
    },
    "TR31_M7_HMAC_KEY": {
        "name": "HMAC Key",
        "allowed_operations": ["generate_mac", "verify_mac"],
        "description": "HMAC with approved hash function",
    },
    "TR31_P0_PIN_ENCRYPTION_KEY": {
        "name": "PIN Encryption Key (PEK / ZPK / AWK / IWK)",
        "allowed_operations": ["generate_pin_data", "verify_pin_data", "translate_pin_data"],
        "description": "Encrypts PIN blocks for storage or transmission",
    },
    "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE": {
        "name": "Asymmetric Signature Key (CA / Trust Anchor)",
        "allowed_operations": ["import_key"],
        "description": "Trusted CA public key for TR-34 key exchange",
    },
    "TR31_V1_IBM3624_PIN_VERIFICATION_KEY": {
        "name": "IBM3624 PIN Verification Key (PVK)",
        "allowed_operations": ["generate_pin_data", "verify_pin_data"],
        "description": "IBM3624 PIN offset generation and verification",
    },
    "TR31_V2_VISA_PIN_VERIFICATION_KEY": {
        "name": "Visa PIN Verification Key (PVK)",
        "allowed_operations": ["generate_pin_data", "verify_pin_data"],
        "description": "Visa/ABA PVV generation and verification",
    },
}

# Algorithms that are hard-prohibited under PCI PIN v3.1 Annex C
PROHIBITED_ALGORITHMS = {
    "TDES_2KEY": ComplianceResult(
        severity=Severity.HARD_STOP,
        message="Single-length or two-key TDES provides less than 112 bits of security and is prohibited by PCI PIN v3.1 Annex C.",
        modern_alternative="Use AES-128 or TDES_3KEY (triple-length, 168-bit) at minimum.",
        pci_requirement="Annex C",
    ),
    "DES": ComplianceResult(
        severity=Severity.HARD_STOP,
        message="Single DES (56-bit) is prohibited. Minimum is TDEA with double-length keys (112 bits) per PCI PIN v3.1 Annex C.",
        modern_alternative="Use AES-128.",
        pci_requirement="Annex C",
    ),
    "RSA_1024": ComplianceResult(
        severity=Severity.HARD_STOP,
        message="RSA-1024 is below the 2048-bit minimum required by PCI PIN v3.1 Annex C.",
        modern_alternative="Use RSA-2048 minimum. RSA-4096 recommended for long-term keys.",
        pci_requirement="Annex C",
    ),
}

# Legacy constructs with warnings — not hard stops unless noted
LEGACY_CONSTRUCTS = {
    "TDES_FIXED_KEY_PIN": ComplianceResult(
        severity=Severity.HARD_STOP,
        message=(
            "Fixed TDEA keys for PIN encryption in POI devices and host-to-host connections "
            "have been prohibited since 1 January 2023 (PCI PIN v3.1 Req 2-2)."
        ),
        modern_alternative="Use AES DUKPT (X9.24-3-2017) or master/session key with AES.",
        requires_qsa_exception=False,
        pci_requirement="Req 2-2",
    ),
    "TDES_NEW_DEPLOYMENT": ComplianceResult(
        severity=Severity.WARNING,
        message=(
            "TDES/3DES is a legacy algorithm. PCI PIN v3.1 references TDEA as still permitted "
            "at double-length (112-bit) minimum, but AES migration is strongly encouraged across "
            "the industry. New deployments should use AES."
        ),
        modern_alternative="AES-128 minimum for all new deployments.",
        pci_requirement="Annex C",
    ),
    "PIN_FORMAT_0": ComplianceResult(
        severity=Severity.WARNING,
        message=(
            "ISO Format 0 PIN blocks are XOR-based and TDES-only. PCI SSC has suspended the "
            "Format 4 mandate (v3.1 update) but strongly encourages migration. Use Format 4 "
            "for all new deployments unless the downstream system does not support it."
        ),
        modern_alternative="ISO Format 4 (AES-based, includes PAN in encryption).",
        requires_qsa_exception=True,
        pci_requirement="Req 2-3 / Req 3",
    ),
    "PIN_FORMAT_1": ComplianceResult(
        severity=Severity.WARNING,
        message=(
            "ISO Format 1 PIN blocks may not be translated back to Format 1 once converted "
            "(PCI PIN v3.1 Req 3-3). This is a one-way migration path."
        ),
        modern_alternative="ISO Format 4.",
        pci_requirement="Req 3-3",
    ),
    "PIN_FORMAT_3": ComplianceResult(
        severity=Severity.WARNING,
        message="ISO Format 3 offers no advantage over Format 4 for new deployments.",
        modern_alternative="ISO Format 4.",
        pci_requirement="Req 3",
    ),
    "CBC_MAC": ComplianceResult(
        severity=Severity.WARNING,
        message="CBC-MAC (ISO 9797-1 Algorithm 1) is a legacy MAC algorithm susceptible to length-extension attacks.",
        modern_alternative="CMAC (ISO 9797-1 Algorithm 5) — use TR31_M6_ISO_9797_5_CMAC_KEY.",
    ),
    "RETAIL_MAC": ComplianceResult(
        severity=Severity.WARNING,
        message="Retail MAC (ANSI X9.19 / ISO 9797-1 Algorithm 3) is a legacy algorithm still common in older acquirer networks.",
        modern_alternative="CMAC (ISO 9797-1 Algorithm 5) when counterparty supports it.",
    ),
    "TDES_DUKPT": ComplianceResult(
        severity=Severity.WARNING,
        message=(
            "TDES DUKPT (X9.24-1:2009, IPEK-based) is the legacy DUKPT standard. "
            "AES DUKPT (X9.24-3-2017, IK-based) is the modern replacement."
        ),
        modern_alternative="AES DUKPT with AES BDK. Note: IPEK terminology replaced by IK in AES DUKPT.",
    ),
    "RSA_WRAP": ComplianceResult(
        severity=Severity.WARNING,
        message=(
            "Raw RSA key wrapping does not include payload signing or key attribute binding. "
            "TR-34 uses RSA internally but provides authentication and attribute integrity."
        ),
        modern_alternative="TR-34 for all asymmetric key distribution.",
    ),
}

# PAN change during PIN translation — hard stop per PCI PIN Req 3-3
PAN_CHANGE_VIOLATION = ComplianceResult(
    severity=Severity.HARD_STOP,
    message=(
        "Translating a PIN from one PAN to another is explicitly prohibited by PCI PIN v3.1 Req 3-3. "
        "The incoming and outgoing PrimaryAccountNumber values must match. "
        "AWS Payment Cryptography enforces this at the API level."
    ),
    pci_requirement="Req 3-3",
)

# PIN block retention — hard stop per PCI PIN Req 4
PIN_BLOCK_RETENTION_VIOLATION = ComplianceResult(
    severity=Severity.HARD_STOP,
    message=(
        "Encrypted PIN blocks must not be stored in transaction journals or logs (PCI PIN v3.1 Req 4). "
        "Mask or delete the PIN block (ISO 8583 field 52) before any logging occurs."
    ),
    pci_requirement="Req 4",
)

# Legal PIN block format translation matrix per PCI PIN Req 3-3
# True = translation permitted, False = prohibited
PIN_FORMAT_TRANSLATION_MATRIX = {
    ("IsoFormat0", "IsoFormat0"): True,
    ("IsoFormat0", "IsoFormat3"): True,
    ("IsoFormat0", "IsoFormat4"): True,
    ("IsoFormat0", "IsoFormat1"): False,
    ("IsoFormat0", "IsoFormat2"): False,
    ("IsoFormat1", "IsoFormat0"): True,
    ("IsoFormat1", "IsoFormat3"): True,
    ("IsoFormat1", "IsoFormat4"): True,
    ("IsoFormat1", "IsoFormat1"): False,
    ("IsoFormat1", "IsoFormat2"): True,   # IC card only
    ("IsoFormat3", "IsoFormat0"): True,
    ("IsoFormat3", "IsoFormat3"): True,
    ("IsoFormat3", "IsoFormat4"): True,
    ("IsoFormat3", "IsoFormat1"): False,
    ("IsoFormat3", "IsoFormat2"): False,
    ("IsoFormat4", "IsoFormat0"): True,
    ("IsoFormat4", "IsoFormat3"): True,
    ("IsoFormat4", "IsoFormat4"): True,
    ("IsoFormat4", "IsoFormat1"): False,
    ("IsoFormat4", "IsoFormat2"): False,
}

LEGACY_CONSTRAINT_PROTOCOL = """
LEGACY CONSTRAINT PROTOCOL — ACTION REQUIRED

The operation you are requesting uses a deprecated or non-preferred cryptographic construct.
Before proceeding, please confirm the following:

1. Have you verified with the downstream party that the modern alternative ({modern_alternative}) is NOT supported?
2. Do you understand that implementing this construct may require a formal PCI exception or compensating
   control documented with your QSA (Qualified Security Assessor) and relevant payment brand?

If the downstream system genuinely does not support the modern approach, this tool will help you
implement the legacy path correctly and safely. However, you must acknowledge:
  - The compliance documentation obligation with your QSA
  - That this configuration should be revisited when the downstream party upgrades

Please confirm by responding: "I have verified that {modern_alternative} is not supported by the
downstream system and I understand the QSA documentation requirement."
"""


def check_key_operation_compatibility(key_usage: str, operation: str) -> ComplianceResult | None:
    registry_entry = KEY_USAGE_REGISTRY.get(key_usage)
    if registry_entry is None:
        return None
    if operation not in registry_entry["allowed_operations"]:
        allowed = ", ".join(registry_entry["allowed_operations"])
        return ComplianceResult(
            severity=Severity.HARD_STOP,
            message=(
                f"Key usage {key_usage} ({registry_entry['name']}) cannot be used for '{operation}'. "
                f"Allowed operations: {allowed}. "
                "Key usage separation is enforced by APC and required by PCI PIN v3.1 Req 19."
            ),
            pci_requirement="Req 19",
        )
    return None


def check_pin_format_translation(incoming_format: str, outgoing_format: str) -> ComplianceResult | None:
    permitted = PIN_FORMAT_TRANSLATION_MATRIX.get((incoming_format, outgoing_format))
    if permitted is False:
        return ComplianceResult(
            severity=Severity.HARD_STOP,
            message=(
                f"Translating from {incoming_format} to {outgoing_format} is prohibited by PCI PIN v3.1 Req 3-3. "
                "Standard PIN-block formats must not be translated into non-permitted formats."
            ),
            pci_requirement="Req 3-3",
        )
    return None


def check_algorithm(algorithm: str) -> ComplianceResult | None:
    return PROHIBITED_ALGORITHMS.get(algorithm)


def check_legacy_construct(construct: str) -> ComplianceResult | None:
    return LEGACY_CONSTRUCTS.get(construct)


def format_legacy_constraint_prompt(modern_alternative: str) -> str:
    return LEGACY_CONSTRAINT_PROTOCOL.format(modern_alternative=modern_alternative)


def get_key_usage_info(key_usage: str) -> dict | None:
    return KEY_USAGE_REGISTRY.get(key_usage)


def list_key_usages() -> list[dict]:
    return [
        {"code": code, **info}
        for code, info in KEY_USAGE_REGISTRY.items()
    ]
