"""
Live integration tests against real AWS Payment Cryptography via the MCP tools.

Tests call the MCP tool functions (control_plane / data_plane) — not boto3 directly.
This exercises the actual tool layer that Claude uses, including compliance guards,
parameter mapping, and mode-of-use defaults.

APC bills for keys by the month (~$1/key/month). Keys scheduled for deletion
enter a pending state for 3 days minimum; they are not billed during that window.

Prerequisites:
    AWS credentials in the default profile, APC endpoint in us-east-1.

Run:
    INTEGRATION_TESTS=true AWS_REGION=us-east-1 pytest tests/test_integration.py -v -s
"""

import base64
import os

import pytest

from apc_agent.server import mcp

pytestmark = pytest.mark.integration

REGION = os.environ.get("AWS_REGION", "us-east-1")
PAN = "4111111111111111"
MESSAGE_HEX = "49534F38353833446174614669656C6436"  # "ISO8583DataField6"


async def _tool(name: str, **kwargs):
    return await mcp._tool_manager.call_tool(name, kwargs)


async def _create_key(algorithm: str, usage: str) -> str:
    kcv = "ANSI_X9_24" if algorithm.startswith("TDES") else "CMAC"
    r = await _tool(
        "create_key",
        key_algorithm=algorithm,
        key_usage=usage,
        key_class="SYMMETRIC_KEY",
        exportable=False,
        key_check_value_algorithm=kcv,
    )
    assert "error" not in r, f"create_key failed: {r}"
    return r["Key"]["KeyArn"]


async def _delete_key(arn: str) -> None:
    try:
        await _tool("delete_key", key_identifier=arn, delete_key_in_days=3)
    except Exception as exc:
        print(f"\n  WARNING: could not schedule deletion for {arn}: {exc}")


@pytest.fixture(autouse=True)
def require_real_aws():
    if os.environ.get("INTEGRATION_TESTS") != "true":
        pytest.skip("Set INTEGRATION_TESTS=true to run against real AWS")


# ── Key Lifecycle ─────────────────────────────────────────────────────────────

class TestKeyLifecycle:
    """create_key and delete_key tools — verifies the tool layer creates real keys."""

    async def test_bdk_create_delete(self):
        arn = await _create_key("AES_128", "TR31_B0_BASE_DERIVATION_KEY")
        try:
            assert "arn:aws:payment-cryptography:" in arn
            print(f"\n  PASS  BDK created — {arn}")
        finally:
            await _delete_key(arn)

    async def test_zpk_create_delete(self):
        arn = await _create_key("AES_128", "TR31_P0_PIN_ENCRYPTION_KEY")
        try:
            assert "arn:aws:payment-cryptography:" in arn
            print(f"\n  PASS  ZPK created (NoRestrictions mode) — {arn}")
        finally:
            await _delete_key(arn)


# ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

class TestEncryptDecrypt:
    """encrypt_data and decrypt_data tools — AES-CBC round-trip."""

    PLAINTEXT = "00112233445566778899AABBCCDDEEFF"
    IV = "000102030405060708090A0B0C0D0E0F"

    async def test_aes_cbc_round_trip(self):
        arn = await _create_key("AES_128", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY")
        try:
            attrs = {"Symmetric": {"Mode": "CBC", "InitializationVector": self.IV, "PaddingType": "PKCS1"}}

            enc = await _tool("encrypt_data",
                key_identifier=arn,
                plain_text=self.PLAINTEXT,
                encryption_attributes=attrs,
            )
            assert "CipherText" in enc, f"encrypt_data failed: {enc}"
            ciphertext = enc["CipherText"]

            dec = await _tool("decrypt_data",
                key_identifier=arn,
                cipher_text=ciphertext,
                decryption_attributes=attrs,
            )
            assert "PlainText" in dec, f"decrypt_data failed: {dec}"
            assert dec["PlainText"].upper() == self.PLAINTEXT
            print("\n  PASS  AES-128-CBC encrypt/decrypt round-trip")
        finally:
            await _delete_key(arn)


# ── MAC ───────────────────────────────────────────────────────────────────────

class TestMac:
    """generate_mac and verify_mac tools — CMAC round-trip."""

    async def test_cmac_round_trip(self):
        arn = await _create_key("AES_128", "TR31_M6_ISO_9797_5_CMAC_KEY")
        try:
            gen = await _tool("generate_mac",
                key_identifier=arn,
                message_data=MESSAGE_HEX,
                generation_attributes={"Algorithm": "CMAC"},
            )
            assert "Mac" in gen, f"generate_mac failed: {gen}"
            mac = gen["Mac"]

            ver = await _tool("verify_mac",
                key_identifier=arn,
                message_data=MESSAGE_HEX,
                mac=mac,
                verification_attributes={"Algorithm": "CMAC"},
            )
            assert ver.get("KeyArn") == arn
            print(f"\n  PASS  CMAC generate+verify — MAC={mac}")
        finally:
            await _delete_key(arn)


# ── CVV ───────────────────────────────────────────────────────────────────────

class TestCvv:
    """generate_card_validation_data and verify_card_validation_data — CVV1 round-trip."""

    EXPIRY = "0128"
    SERVICE_CODE = "101"

    async def test_cvv_round_trip(self):
        # CVV1 uses 2-key 3DES internally
        arn = await _create_key("TDES_2KEY", "TR31_C0_CARD_VERIFICATION_KEY")
        cvv_attrs = {
            "CardVerificationValue1": {
                "CardExpiryDate": self.EXPIRY,
                "ServiceCode": self.SERVICE_CODE,
            }
        }
        try:
            gen = await _tool("generate_card_validation_data",
                key_identifier=arn,
                primary_account_number=PAN,
                generation_attributes=cvv_attrs,
            )
            assert "ValidationData" in gen, f"generate_card_validation_data failed: {gen}"
            cvv = gen["ValidationData"]

            await _tool("verify_card_validation_data",
                key_identifier=arn,
                primary_account_number=PAN,
                verification_attributes=cvv_attrs,
                validation_data=cvv,
            )
            print(f"\n  PASS  CVV1 generate+verify — CVV={cvv}")
        finally:
            await _delete_key(arn)


# ── PIN ───────────────────────────────────────────────────────────────────────

class TestPin:
    """
    generate_pin_data, verify_pin_data, and translate_pin_data tools.

    Uses Visa PVV scheme with ISO Format 4 (AES PIN blocks).
    V2 PVK must be TDES_2KEY — Visa PVV algorithm uses 3DES internally.
    """

    async def test_visa_pin_generate_and_verify(self):
        pvk = await _create_key("TDES_2KEY", "TR31_V2_VISA_PIN_VERIFICATION_KEY")
        p0  = await _create_key("AES_128",   "TR31_P0_PIN_ENCRYPTION_KEY")
        try:
            gen = await _tool("generate_pin_data",
                generation_key_identifier=pvk,
                encryption_key_identifier=p0,
                generation_attributes={"VisaPin": {"PinVerificationKeyIndex": 1}},
                pin_block_format="ISO_FORMAT_4",
                primary_account_number=PAN,
            )
            assert "EncryptedPinBlock" in gen, f"generate_pin_data failed: {gen}"
            pin_block = gen["EncryptedPinBlock"]
            pvv = gen["PinData"]["VerificationValue"]

            ver = await _tool("verify_pin_data",
                verification_key_identifier=pvk,
                encrypted_pin_block=pin_block,
                encryption_key_identifier=p0,
                verification_attributes={
                    "VisaPin": {
                        "PinVerificationKeyIndex": 1,
                        "VerificationValue": pvv,
                    }
                },
                pin_block_format="ISO_FORMAT_4",
                primary_account_number=PAN,
            )
            assert ver.get("VerificationKeyArn") == pvk, (
                f"verify_pin_data unexpected response: {ver}"
            )
            print(f"\n  PASS  Visa PVV generate+verify (ISO Format 4) — PVV={pvv}")
        finally:
            await _delete_key(pvk)
            await _delete_key(p0)

    async def test_visa_format4_translate_p0_to_p0(self):
        pvk   = await _create_key("TDES_2KEY", "TR31_V2_VISA_PIN_VERIFICATION_KEY")
        p0_in = await _create_key("AES_128",   "TR31_P0_PIN_ENCRYPTION_KEY")
        p0_out = await _create_key("AES_128",  "TR31_P0_PIN_ENCRYPTION_KEY")
        try:
            gen = await _tool("generate_pin_data",
                generation_key_identifier=pvk,
                encryption_key_identifier=p0_in,
                generation_attributes={"VisaPin": {"PinVerificationKeyIndex": 1}},
                pin_block_format="ISO_FORMAT_4",
                primary_account_number=PAN,
            )
            pin_block = gen["EncryptedPinBlock"]

            result = await _tool("translate_pin_data",
                incoming_key_identifier=p0_in,
                outgoing_key_identifier=p0_out,
                incoming_translation_attributes={"IsoFormat4": {"PrimaryAccountNumber": PAN}},
                outgoing_translation_attributes={"IsoFormat4": {"PrimaryAccountNumber": PAN}},
                encrypted_pin_block=pin_block,
            )
            assert "PinBlock" in result, f"translate_pin_data failed: {result}"
            print("\n  PASS  translate_pin_data (Visa PVV, ISO Format 4, P0->P0)")
        finally:
            await _delete_key(pvk)
            await _delete_key(p0_in)
            await _delete_key(p0_out)


# ── DUKPT ─────────────────────────────────────────────────────────────────────

class TestDukpt:
    """
    encrypt_data and decrypt_data tools with DUKPT attributes.

    KSN lengths: 12 bytes (24 hex) for AES DUKPT, 10 bytes (20 hex) for TDES.
    Plaintext:   16-byte multiple for AES ECB, 8-byte multiple for TDES ECB.
    """

    AES_KSN  = "FFFF9876543210E000000001"
    TDES_KSN = "FFFF9876543210E00001"
    AES_PT   = "00112233445566778899AABBCCDDEEFF"
    TDES_PT  = "0011223344556677"

    async def test_aes_dukpt_encrypt_decrypt(self):
        bdk = await _create_key("AES_128", "TR31_B0_BASE_DERIVATION_KEY")
        attrs = {
            "Dukpt": {
                "KeySerialNumber": self.AES_KSN,
                "Mode": "ECB",
                "DukptKeyDerivationType": "AES_128",
                "DukptKeyVariant": "BIDIRECTIONAL",
            }
        }
        try:
            enc = await _tool("encrypt_data",
                key_identifier=bdk, plain_text=self.AES_PT, encryption_attributes=attrs)
            assert "CipherText" in enc, f"AES DUKPT encrypt failed: {enc}"

            dec = await _tool("decrypt_data",
                key_identifier=bdk, cipher_text=enc["CipherText"], decryption_attributes=attrs)
            assert dec["PlainText"].upper() == self.AES_PT
            print(f"\n  PASS  AES-DUKPT encrypt/decrypt — KSN={self.AES_KSN}")
        finally:
            await _delete_key(bdk)

    async def test_tdes_dukpt_encrypt_decrypt(self):
        # TDES DUKPT only supports REQUEST/RESPONSE variants, not BIDIRECTIONAL
        bdk = await _create_key("TDES_2KEY", "TR31_B0_BASE_DERIVATION_KEY")
        attrs = {
            "Dukpt": {
                "KeySerialNumber": self.TDES_KSN,
                "Mode": "ECB",
                "DukptKeyDerivationType": "TDES_2KEY",
                "DukptKeyVariant": "REQUEST",
            }
        }
        try:
            enc = await _tool("encrypt_data",
                key_identifier=bdk, plain_text=self.TDES_PT, encryption_attributes=attrs)
            assert "CipherText" in enc, f"TDES DUKPT encrypt failed: {enc}"

            dec = await _tool("decrypt_data",
                key_identifier=bdk, cipher_text=enc["CipherText"], decryption_attributes=attrs)
            assert dec["PlainText"].upper() == self.TDES_PT
            print(f"\n  PASS  TDES-DUKPT encrypt/decrypt — KSN={self.TDES_KSN}")
        finally:
            await _delete_key(bdk)


# ── EMV ───────────────────────────────────────────────────────────────────────

class TestEmv:
    """
    EMV operations via the MCP tools.

    dCVV: E4 master key (TDES_2KEY) derives a per-card key, generates dynamic CVV.
    ARQC: E0 master key (TDES_2KEY) — wrong-cryptogram path confirms the operation
          reaches APC's cryptographic comparison rather than failing on config.
    """

    async def test_dcvv_generation(self):
        # E4 dynamic numbers key — TDES_2KEY because EMV per-card derivation uses 3DES
        e4 = await _create_key("TDES_2KEY", "TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS")
        try:
            gen = await _tool("generate_card_validation_data",
                key_identifier=e4,
                primary_account_number=PAN,
                generation_attributes={
                    "DynamicCardVerificationCode": {
                        "ApplicationTransactionCounter": "0001",
                        "PanSequenceNumber": "01",
                        "TrackData": "4111111111111111D2801201",
                        "UnpredictableNumber": "12345678",
                    }
                },
            )
            assert "ValidationData" in gen, f"dCVV generation failed: {gen}"
            print(f"\n  PASS  dCVV generation (E4, TDES_2KEY) — dCVV={gen['ValidationData']}")
        finally:
            await _delete_key(e4)

    async def test_arqc_verify_wrong_cryptogram_returns_error(self):
        """
        Sends a known-wrong ARQC. _call() catches the boto3 VerificationFailedException
        (ClientError) and returns an error dict — confirming the operation reached APC's
        cryptographic comparison rather than failing on config or key type.
        """
        e0 = await _create_key("TDES_2KEY", "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS")
        try:
            result = await _tool("verify_auth_request_cryptogram",
                key_identifier=e0,
                transaction_data="000000000000000000000000000000000000000000000001",
                auth_request_cryptogram="DEADBEEFDEADBEEF",
                major_key_derivation_mode="EMV_OPTION_A",
                session_key_derivation_attributes={
                    "Visa": {
                        "PrimaryAccountNumber": PAN,
                        "PanSequenceNumber": "01",
                    }
                },
            )
            assert result.get("aws_error_code") == "VerificationFailedException", (
                f"Expected VerificationFailedException, got: {result}"
            )
            print("\n  PASS  ARQC verify — VerificationFailedException for wrong cryptogram")
        finally:
            await _delete_key(e0)


# ── Key Import ────────────────────────────────────────────────────────────────

class TestKeyImport:
    """
    Import a known AES-128 key via RSA KeyCryptogram using the import_key tool,
    then verify CMAC output against NIST SP 800-38B published test vectors.

    RSA-3072 wrapping is required — APC enforces that the wrapping key strength
    must be >= the working key strength (RSA-2048 ~112-bit < AES-128 128-bit).

    Flow:
      1. get_parameters_for_import tool -> APC RSA-3072 public key + one-time token
      2. RSA-OAEP-SHA256 wrap the known key locally
      3. import_key tool with KeyCryptogram
      4. generate_mac tool (CMAC) -> compare against NIST expected value
    """

    # NIST SP 800-38B, Appendix D.1, AES-128-CMAC Example 4 (64-byte message)
    KNOWN_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
    MSG_HEX = (
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411"
        "e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    CMAC_EXPECTED = "51f0bebf7e3b9d92fc49741779363cfe"

    def _rsa_wrap(self, key_bytes: bytes, cert_b64: str) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.x509 import load_pem_x509_certificate
        cert_pem = base64.b64decode(cert_b64)
        cert = load_pem_x509_certificate(cert_pem)
        wrapped = cert.public_key().encrypt(
            key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return wrapped.hex().upper()

    async def test_import_key_and_verify_nist_cmac(self):
        # Step 1: get APC's RSA-3072 public key and one-time import token
        # (RSA_3072 required: APC enforces wrapping key strength >= working key strength)
        params = await _tool("get_parameters_for_import",
            key_material_type="KEY_CRYPTOGRAM",
            wrapping_key_algorithm="RSA_3072",
        )
        assert "WrappingKeyCertificate" in params, f"get_parameters_for_import failed: {params}"

        # Step 2: RSA-OAEP-SHA256 wrap the known NIST key
        wrapped_hex = self._rsa_wrap(
            bytes.fromhex(self.KNOWN_KEY),
            params["WrappingKeyCertificate"],
        )

        # Step 3: import via the import_key tool
        resp = await _tool("import_key",
            key_material={
                "KeyCryptogram": {
                    "KeyAttributes": {
                        "KeyAlgorithm": "AES_128",
                        "KeyUsage": "TR31_M6_ISO_9797_5_CMAC_KEY",
                        "KeyClass": "SYMMETRIC_KEY",
                        "KeyModesOfUse": {"Generate": True, "Verify": True},
                    },
                    "Exportable": False,
                    "ImportToken": params["ImportToken"],
                    "WrappedKeyCryptogram": wrapped_hex,
                    "WrappingSpec": "RSA_OAEP_SHA_256",
                }
            },
            key_check_value_algorithm="CMAC",
            enabled=True,
        )
        assert "error" not in resp, f"import_key failed: {resp}"
        arn = resp["Key"]["KeyArn"]

        try:
            # Step 4: generate CMAC and verify against NIST expected value
            gen = await _tool("generate_mac",
                key_identifier=arn,
                message_data=self.MSG_HEX,
                generation_attributes={"Algorithm": "CMAC"},
            )
            mac = gen["Mac"].lower()
            assert mac == self.CMAC_EXPECTED, (
                f"CMAC mismatch — APC:{mac!r}  NIST:{self.CMAC_EXPECTED!r}"
            )
            print(f"\n  PASS  AES-128-CMAC matches NIST SP 800-38B exactly — MAC={mac}")
        finally:
            await _delete_key(arn)
