"""
Example: Import a Zone PIN Key (ZPK) from an external system via TR-31 key block.

This is the standard pattern for receiving a working key from an acquiring network,
processor, or partner HSM that supports TR-31 / X9.143 key blocks.

Flow:
  1. Create a Key Block Protection Key (KBPK) in APC — this is the wrapping key
     your partner will use to wrap the ZPK they send you
  2. Export the KBPK public parameters so your partner can wrap against it
     (in practice: share your KBPK via TR-34 or a key ceremony first)
  3. Import the TR-31-wrapped ZPK your partner sends you

For initial KEK establishment with a new partner, use TR-34 (get_parameters_for_import
with Tr34KeyBlock type) rather than TR-31 — TR-31 requires you already share a KBPK.

Prerequisites:
  - An existing KBPK in APC (K1 key type) or create one in step 1
  - A TR-31 key block from your partner wrapping a ZPK under your KBPK
"""

import boto3

control = boto3.client("payment-cryptography")

# Replace with a real TR-31 key block from your partner's HSM
# Format: header (16 chars) + encrypted key + MAC
# Example header: A0088P0TE00N0000 (length=A0088, version=P0, usage=TE, algorithm=0, mode=N)
PARTNER_TR31_KEY_BLOCK = "REPLACE_WITH_REAL_TR31_KEY_BLOCK_FROM_PARTNER"


def create_kbpk() -> str:
    """Create a Key Block Protection Key that your partner will use to wrap keys for you."""
    response = control.create_key(
        KeyAttributes={
            "KeyAlgorithm": "AES_256",
            "KeyUsage": "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyModesOfUse": {
                "Wrap": True,
                "Unwrap": True,
                "Encrypt": False,
                "Decrypt": False,
                "Generate": False,
                "Sign": False,
                "Verify": False,
                "DeriveKey": False,
            },
        },
        Exportable=True,
        Enabled=True,
        KeyCheckValueAlgorithm="CMAC",
    )
    arn = response["Key"]["KeyArn"]
    kcv = response["Key"]["KeyCheckValue"]
    print(f"KBPK created: {arn}")
    print(f"KCV (share with partner for verification): {kcv}")
    return arn


def import_zpk_via_tr31(kbpk_arn: str) -> str:
    """Import a ZPK wrapped in a TR-31 key block by your partner."""
    response = control.import_key(
        KeyMaterial={
            "Tr31KeyBlock": {
                "WrappingKeyIdentifier": kbpk_arn,
                "WrappedKeyBlock": PARTNER_TR31_KEY_BLOCK,
            }
        },
        Enabled=True,
        KeyCheckValueAlgorithm="CMAC",
    )
    arn = response["Key"]["KeyArn"]
    kcv = response["Key"]["KeyCheckValue"]
    print(f"ZPK imported: {arn}")
    print(f"ZPK KCV (verify with partner): {kcv}")
    return arn


if __name__ == "__main__":
    print("Step 1: Create KBPK (share this with your partner via TR-34 or key ceremony)")
    kbpk_arn = create_kbpk()

    print("\nStep 2: Once partner has wrapped a ZPK under your KBPK, import it:")
    if PARTNER_TR31_KEY_BLOCK != "REPLACE_WITH_REAL_TR31_KEY_BLOCK_FROM_PARTNER":
        zpk_arn = import_zpk_via_tr31(kbpk_arn)
    else:
        print("  Skipping import — replace PARTNER_TR31_KEY_BLOCK with a real key block first.")
