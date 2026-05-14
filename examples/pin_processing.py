"""
Example: AES DUKPT PIN block translation (acquirer happy path).

Flow:
  1. Create a BDK (AES-128, B0) for DUKPT terminal key derivation
  2. Create a ZPK (AES-128, P0) for host-to-host PIN routing
  3. Translate an inbound ISO Format 4 PIN block (DUKPT) to Format 4 under ZPK

This follows the reference architecture from REQUIREMENTS.md:
  Terminal → AES DUKPT (Format 4) → translate_pin_data → ZPK AES (Format 4) → network

Prerequisites:
  - AWS credentials configured (IAM role, profile, or environment variables)
  - APC endpoints available in your region
  - A real KSN from a DUKPT-enabled terminal for production use
"""

import boto3

control = boto3.client("payment-cryptography")
data = boto3.client("payment-cryptography-data")

PAN = "4111111111111111"
# In production: KSN comes from the terminal with each transaction
KSN = "FFFF9876543210E00001"
# In production: encrypted PIN block comes from the terminal
ENCRYPTED_PIN_BLOCK = "AC17DC148BDA645E"


def create_bdk() -> str:
    response = control.create_key(
        KeyAttributes={
            "KeyAlgorithm": "AES_128",
            "KeyUsage": "TR31_B0_BASE_DERIVATION_KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyModesOfUse": {
                "DeriveKey": True,
                "Encrypt": False,
                "Decrypt": False,
                "Wrap": False,
                "Unwrap": False,
                "Generate": False,
                "Sign": False,
                "Verify": False,
            },
        },
        Exportable=False,
        Enabled=True,
        KeyCheckValueAlgorithm="CMAC",
    )
    arn = response["Key"]["KeyArn"]
    print(f"BDK created: {arn}")
    return arn


def create_zpk() -> str:
    response = control.create_key(
        KeyAttributes={
            "KeyAlgorithm": "AES_128",
            "KeyUsage": "TR31_P0_PIN_ENCRYPTION_KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyModesOfUse": {
                # APC enforces TR-31: Encrypt+Decrypt together is not a valid
                # combination. Use NoRestrictions for a bidirectional ZPK.
                "NoRestrictions": True,
            },
        },
        Exportable=True,
        Enabled=True,
        KeyCheckValueAlgorithm="CMAC",
    )
    arn = response["Key"]["KeyArn"]
    print(f"ZPK created: {arn}")
    return arn


def translate_pin(bdk_arn: str, zpk_arn: str) -> dict:
    response = data.translate_pin_data(
        IncomingKeyIdentifier=bdk_arn,
        OutgoingKeyIdentifier=zpk_arn,
        # ISO Format 4 inbound from DUKPT terminal
        IncomingTranslationAttributes={"IsoFormat4": {"PrimaryAccountNumber": PAN}},
        # ISO Format 4 outbound under ZPK for network routing
        OutgoingTranslationAttributes={"IsoFormat4": {"PrimaryAccountNumber": PAN}},
        EncryptedPinBlock=ENCRYPTED_PIN_BLOCK,
        IncomingDukptAttributes={"KeySerialNumber": KSN},
    )
    print(f"Translated PIN block: {response['PinBlock']}")
    print(f"Under key: {response['KeyArn']}")
    return response


if __name__ == "__main__":
    bdk_arn = create_bdk()
    zpk_arn = create_zpk()
    result = translate_pin(bdk_arn, zpk_arn)
