"""
Example: CVV and CVV2 generation and verification.

Flow:
  1. Create a CVK (AES-128, C0)
  2. Generate a CVV1 (magnetic stripe) and CVV2 (card-not-present) for a test PAN
  3. Verify both values

Note: CVV generation is typically an issuer function but CVV verification
is performed by acquirers and processors for card-present and CNP transactions.
APC supports both for acquirer/processor use cases.
"""

import boto3

control = boto3.client("payment-cryptography")
data = boto3.client("payment-cryptography-data")

PAN = "4111111111111111"
EXPIRY = "2812"         # MMYY format
SERVICE_CODE_CVV1 = "101"
SERVICE_CODE_CVV2 = "000"
SERVICE_CODE_ICVV = "999"


def create_cvk() -> str:
    response = control.create_key(
        KeyAttributes={
            "KeyAlgorithm": "AES_128",
            "KeyUsage": "TR31_C0_CARD_VERIFICATION_KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyModesOfUse": {
                "Generate": True,
                "Verify": True,
                "Encrypt": False,
                "Decrypt": False,
                "Wrap": False,
                "Unwrap": False,
                "Sign": False,
                "DeriveKey": False,
            },
        },
        Exportable=False,
        Enabled=True,
        KeyCheckValueAlgorithm="CMAC",
    )
    arn = response["Key"]["KeyArn"]
    print(f"CVK created: {arn}")
    return arn


def generate_cvv1(cvk_arn: str) -> str:
    response = data.generate_card_validation_data(
        KeyIdentifier=cvk_arn,
        PrimaryAccountNumber=PAN,
        GenerationAttributes={
            "CardVerificationValue1": {
                "CardExpiryDate": EXPIRY,
                "ServiceCode": SERVICE_CODE_CVV1,
            }
        },
    )
    cvv = response["ValidationData"]
    print(f"CVV1: {cvv}")
    return cvv


def generate_cvv2(cvk_arn: str) -> str:
    response = data.generate_card_validation_data(
        KeyIdentifier=cvk_arn,
        PrimaryAccountNumber=PAN,
        GenerationAttributes={
            "CardVerificationValue2": {
                "CardExpiryDate": EXPIRY,
            }
        },
    )
    cvv2 = response["ValidationData"]
    print(f"CVV2: {cvv2}")
    return cvv2


def verify_cvv(cvk_arn: str, cvv: str) -> bool:
    response = data.verify_card_validation_data(
        KeyIdentifier=cvk_arn,
        PrimaryAccountNumber=PAN,
        VerificationAttributes={
            "CardVerificationValue1": {
                "CardExpiryDate": EXPIRY,
                "ServiceCode": SERVICE_CODE_CVV1,
            }
        },
        ValidationData=cvv,
    )
    valid = response.get("KeyArn") is not None
    print(f"CVV1 verification: {'PASS' if valid else 'FAIL'}")
    return valid


if __name__ == "__main__":
    cvk_arn = create_cvk()
    cvv1 = generate_cvv1(cvk_arn)
    cvv2 = generate_cvv2(cvk_arn)
    verify_cvv(cvk_arn, cvv1)
