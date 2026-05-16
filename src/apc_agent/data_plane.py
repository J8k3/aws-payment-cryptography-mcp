"""APC data plane MCP tools — cryptographic operations."""

import boto3
from mcp.server.fastmcp import FastMCP

from .compliance import (
    Severity,
    check_legacy_construct,
    check_pin_format_translation,
    format_legacy_constraint_prompt,
    PAN_CHANGE_VIOLATION,
    PIN_BLOCK_RETENTION_VIOLATION,
)


def register_data_plane_tools(mcp: FastMCP) -> None:

    def client():
        return boto3.client("payment-cryptography-data")

    # ── Encrypt / Decrypt / Re-Encrypt ────────────────────────────────────────

    @mcp.tool()
    def encrypt_data(
        key_identifier: str,
        plain_text: str,
        encryption_attributes: dict,
        wrapped_key: dict | None = None,
    ) -> dict:
        """
        Encrypt payment data using an APC key.

        Supported key types: D0 (symmetric), D1 (asymmetric RSA), B0 (DUKPT), E1/E6 (EMV).
        All inputs and outputs are hexBinary encoded.

        encryption_attributes examples:
          Symmetric AES-CBC:
            {"Symmetric": {"Mode": "CBC", "InitializationVector": "<16-byte hex>"}}
          DUKPT AES:
            {"Dukpt": {"KeySerialNumber": "<KSN hex>", "Mode": "CBC", "DukptKeyDerivationType": "AES_128"}}
          EMV:
            {"Emv": {"MajorKeyDerivationMode": "EMV_OPTION_A", "PrimaryAccountNumber": "...",
                     "PanSequenceNumber": "01", "SessionDerivationData": "...", "Mode": "CBC"}}

        wrapped_key (dynamic key — TR-31 key block passed directly):
          {"WrappedKeyMaterial": {"Tr31KeyBlock": "<TR-31 block>"}, "KeyCheckValueAlgorithm": "CMAC"}

        Args:
            key_identifier: Key ARN or alias of the KEK (when using wrapped_key) or the working key
            plain_text: Hex-encoded plaintext to encrypt
            encryption_attributes: Algorithm-specific parameters dict
            wrapped_key: Optional TR-31 wrapped working key (key_identifier becomes the KEK)
        """
        params: dict = {
            "KeyIdentifier": key_identifier,
            "PlainText": plain_text,
            "EncryptionAttributes": encryption_attributes,
        }
        if wrapped_key:
            params["WrappedKey"] = wrapped_key
        return client().encrypt_data(**params)

    @mcp.tool()
    def decrypt_data(
        key_identifier: str,
        cipher_text: str,
        decryption_attributes: dict,
        wrapped_key: dict | None = None,
    ) -> dict:
        """
        Decrypt payment data using an APC key.

        Supported key types: D0, D1, B0 (DUKPT), E1/E6 (EMV).
        All inputs and outputs are hexBinary encoded.

        Args:
            key_identifier: Key ARN or alias of the KEK (when using wrapped_key) or the working key
            cipher_text: Hex-encoded ciphertext
            decryption_attributes: Algorithm-specific parameters (mirrors encrypt_data)
            wrapped_key: Optional TR-31 wrapped working key (key_identifier becomes the KEK)
        """
        params: dict = {
            "KeyIdentifier": key_identifier,
            "CipherText": cipher_text,
            "DecryptionAttributes": decryption_attributes,
        }
        if wrapped_key:
            params["WrappedKey"] = wrapped_key
        return client().decrypt_data(**params)

    @mcp.tool()
    def re_encrypt_data(
        incoming_key_identifier: str,
        outgoing_key_identifier: str,
        cipher_text: str,
        incoming_encryption_attributes: dict,
        outgoing_encryption_attributes: dict,
        incoming_wrapped_key: dict | None = None,
        outgoing_wrapped_key: dict | None = None,
    ) -> dict:
        """
        Re-encrypt data from one key to another without exposing plaintext.
        The decryption and re-encryption occur entirely within the APC HSM boundary.

        Args:
            incoming_key_identifier: ARN or alias of the current encryption key (or KEK)
            outgoing_key_identifier: ARN or alias of the target encryption key (or KEK)
            cipher_text: Hex-encoded ciphertext under the incoming key
            incoming_encryption_attributes: Algorithm params for decryption
            outgoing_encryption_attributes: Algorithm params for re-encryption
            incoming_wrapped_key: Optional TR-31 wrapped incoming working key
            outgoing_wrapped_key: Optional TR-31 wrapped outgoing working key
        """
        params: dict = {
            "IncomingKeyIdentifier": incoming_key_identifier,
            "OutgoingKeyIdentifier": outgoing_key_identifier,
            "CipherText": cipher_text,
            "IncomingEncryptionAttributes": incoming_encryption_attributes,
            "OutgoingEncryptionAttributes": outgoing_encryption_attributes,
        }
        if incoming_wrapped_key:
            params["IncomingWrappedKey"] = incoming_wrapped_key
        if outgoing_wrapped_key:
            params["OutgoingWrappedKey"] = outgoing_wrapped_key
        return client().re_encrypt_data(**params)

    # ── PIN Operations ────────────────────────────────────────────────────────

    @mcp.tool()
    def translate_pin_data(
        incoming_key_identifier: str,
        outgoing_key_identifier: str,
        incoming_translation_attributes: dict,
        outgoing_translation_attributes: dict,
        encrypted_pin_block: str,
        incoming_dukpt_attributes: dict | None = None,
        outgoing_dukpt_attributes: dict | None = None,
        incoming_as2805_attributes: dict | None = None,
        incoming_wrapped_key: dict | None = None,
        outgoing_wrapped_key: dict | None = None,
    ) -> dict:
        """
        Translate a PIN block between encryption zones without exposing the PIN in clear text.
        This is the primary acquirer PIN routing operation (PCI PIN Req 1, 2-2).

        COMPLIANCE ENFORCED:
        - The PAN must not change between incoming and outgoing formats (PCI PIN Req 3-3)
        - Only legal format translations are permitted (Req 3-3)
        - Fixed TDES keys are prohibited since 1 January 2023 (Req 2-2)

        Preferred flow: AES DUKPT (Format 4) inbound → ZPK AES (Format 4 or 0) outbound

        incoming_translation_attributes examples:
          ISO Format 4 (AES): {"IsoFormat4": {"PrimaryAccountNumber": "1712345678901234"}}
          ISO Format 0 (TDES): {"IsoFormat0": {"PrimaryAccountNumber": "1712345678901234"}}
          AS2805 Format 0:     {"As2805Format0": {"PrimaryAccountNumber": "1712345678901234"}}

        incoming_dukpt_attributes (when incoming key is a BDK):
          {"KeySerialNumber": "<10 or 12 byte KSN hex>"}

        incoming_as2805_attributes (when incoming block uses AS2805 format):
          {"SessionKeyDerivationAttributes": {...}}

        incoming_wrapped_key / outgoing_wrapped_key (dynamic key — TR-31 block passed directly):
          {"WrappedKeyMaterial": {"Tr31KeyBlock": "<TR-31 block>"}, "KeyCheckValueAlgorithm": "CMAC"}

        Args:
            incoming_key_identifier: ARN or alias of inbound PEK or BDK (or KEK for wrapped key)
            outgoing_key_identifier: ARN or alias of outbound PEK or BDK (or KEK for wrapped key)
            incoming_translation_attributes: PIN block format and PAN for inbound
            outgoing_translation_attributes: PIN block format and PAN for outbound
            encrypted_pin_block: Hex-encoded encrypted PIN block
            incoming_dukpt_attributes: Required when incoming key is a BDK (DUKPT)
            outgoing_dukpt_attributes: Required when outgoing key is a BDK (DUKPT)
            incoming_as2805_attributes: Required when incoming block uses AS2805 format
            incoming_wrapped_key: Optional TR-31 wrapped incoming PEK
            outgoing_wrapped_key: Optional TR-31 wrapped outgoing PEK
        """
        incoming_format = _extract_pin_format(incoming_translation_attributes)
        outgoing_format = _extract_pin_format(outgoing_translation_attributes)

        if incoming_format and outgoing_format:
            violation = check_pin_format_translation(incoming_format, outgoing_format)
            if violation:
                return {"error": violation.message, "pci_requirement": violation.pci_requirement}

        if outgoing_format == "IsoFormat0":
            result = check_legacy_construct("PIN_FORMAT_0")
            if result:
                return {
                    "compliance_warning": result.message,
                    "modern_alternative": result.modern_alternative,
                    "requires_qsa_exception": result.requires_qsa_exception,
                    "confirmation_required": format_legacy_constraint_prompt(result.modern_alternative),
                }

        params: dict = {
            "IncomingKeyIdentifier": incoming_key_identifier,
            "OutgoingKeyIdentifier": outgoing_key_identifier,
            "IncomingTranslationAttributes": incoming_translation_attributes,
            "OutgoingTranslationAttributes": outgoing_translation_attributes,
            "EncryptedPinBlock": encrypted_pin_block,
        }
        if incoming_dukpt_attributes:
            params["IncomingDukptAttributes"] = incoming_dukpt_attributes
        if outgoing_dukpt_attributes:
            params["OutgoingDukptAttributes"] = outgoing_dukpt_attributes
        if incoming_as2805_attributes:
            params["IncomingAs2805Attributes"] = incoming_as2805_attributes
        if incoming_wrapped_key:
            params["IncomingWrappedKey"] = incoming_wrapped_key
        if outgoing_wrapped_key:
            params["OutgoingWrappedKey"] = outgoing_wrapped_key

        return client().translate_pin_data(**params)

    @mcp.tool()
    def generate_pin_data(
        generation_key_identifier: str,
        encryption_key_identifier: str,
        generation_attributes: dict,
        pin_block_format: str,
        primary_account_number: str | None = None,
        pin_data_length: int | None = None,
        encryption_wrapped_key: dict | None = None,
    ) -> dict:
        """
        Generate a PIN and/or PIN verification value (PVV / offset).
        Issuer function — use with care in acquirer contexts.

        Supported schemes via generation_attributes:
          Visa PVV:          {"VisaPin": {"PinVerificationKeyIndex": 1}}
          Visa PVV value:    {"VisaPinVerificationValue": {"EncryptedPinBlock": "...", "PinVerificationKeyIndex": 1}}
          IBM3624 offset:    {"Ibm3624PinOffset": {"DecimalizationTable": "...", "PinValidationData": "..."}}
          IBM3624 random:    {"Ibm3624RandomPin": {"DecimalizationTable": "..."}}
          IBM3624 natural:   {"Ibm3624NaturalPin": {"DecimalizationTable": "..."}}
          IBM3624 from offset: {"Ibm3624PinFromOffset": {"DecimalizationTable": "...", "PinOffset": "...", "PinValidationData": "..."}}

        Supported key types:
          generation_key_identifier: V1 (IBM3624) or V2 (Visa) PVK
          encryption_key_identifier: P0 PIN Encryption Key (or KEK when using encryption_wrapped_key)

        primary_account_number is optional for ISO_FORMAT_1 (which does not include PAN).

        Args:
            generation_key_identifier: ARN or alias of PVK (V1 or V2 key)
            encryption_key_identifier: ARN or alias of PEK (P0 key) to encrypt output PIN block
            generation_attributes: Scheme-specific generation parameters
            pin_block_format: ISO_FORMAT_0, ISO_FORMAT_1, ISO_FORMAT_3, or ISO_FORMAT_4
            primary_account_number: 12-19 digit PAN (required for all formats except ISO_FORMAT_1)
            pin_data_length: PIN length (4-12); omit to use scheme default
            encryption_wrapped_key: Optional TR-31 wrapped PEK (encryption_key_identifier becomes the KEK)
        """
        if pin_block_format == "ISO_FORMAT_0":
            result = check_legacy_construct("PIN_FORMAT_0")
            if result:
                return {
                    "compliance_warning": result.message,
                    "modern_alternative": result.modern_alternative,
                    "confirmation_required": format_legacy_constraint_prompt(result.modern_alternative),
                }

        params: dict = {
            "GenerationKeyIdentifier": generation_key_identifier,
            "EncryptionKeyIdentifier": encryption_key_identifier,
            "GenerationAttributes": generation_attributes,
            "PinBlockFormat": pin_block_format,
        }
        if primary_account_number:
            params["PrimaryAccountNumber"] = primary_account_number
        if pin_data_length is not None:
            params["PinDataLength"] = pin_data_length
        if encryption_wrapped_key:
            params["EncryptionWrappedKey"] = encryption_wrapped_key
        return client().generate_pin_data(**params)

    @mcp.tool()
    def verify_pin_data(
        verification_key_identifier: str,
        encrypted_pin_block: str,
        encryption_key_identifier: str,
        verification_attributes: dict,
        pin_block_format: str,
        primary_account_number: str | None = None,
        pin_data_length: int | None = None,
        dukpt_attributes: dict | None = None,
        encryption_wrapped_key: dict | None = None,
    ) -> dict:
        """
        Verify a cardholder PIN against a stored PIN verification value.

        Supported key types:
          verification_key_identifier: V1 (IBM3624) or V2 (Visa) PVK
          encryption_key_identifier: P0 PIN Encryption Key or B0 BDK (DUKPT)

        primary_account_number is optional for ISO_FORMAT_1 (which does not include PAN).

        dukpt_attributes (when encryption_key_identifier is a BDK):
          {"KeySerialNumber": "<KSN hex>", "DukptKeyDerivationType": "AES_128"}

        Args:
            verification_key_identifier: ARN or alias of PVK
            encrypted_pin_block: Hex-encoded encrypted PIN block
            encryption_key_identifier: ARN or alias of PEK or BDK (or KEK for wrapped key)
            verification_attributes: Scheme-specific verification params (mirrors generate_pin_data)
            pin_block_format: ISO_FORMAT_0, ISO_FORMAT_1, ISO_FORMAT_3, or ISO_FORMAT_4
            primary_account_number: 12-19 digit PAN (required for all formats except ISO_FORMAT_1)
            pin_data_length: Optional PIN length override
            dukpt_attributes: Required when encryption_key_identifier is a BDK
            encryption_wrapped_key: Optional TR-31 wrapped PEK (encryption_key_identifier becomes the KEK)
        """
        params: dict = {
            "VerificationKeyIdentifier": verification_key_identifier,
            "EncryptedPinBlock": encrypted_pin_block,
            "EncryptionKeyIdentifier": encryption_key_identifier,
            "VerificationAttributes": verification_attributes,
            "PinBlockFormat": pin_block_format,
        }
        if primary_account_number:
            params["PrimaryAccountNumber"] = primary_account_number
        if pin_data_length is not None:
            params["PinDataLength"] = pin_data_length
        if dukpt_attributes:
            params["DukptAttributes"] = dukpt_attributes
        if encryption_wrapped_key:
            params["EncryptionWrappedKey"] = encryption_wrapped_key
        return client().verify_pin_data(**params)

    # ── Card Validation ───────────────────────────────────────────────────────

    @mcp.tool()
    def generate_card_validation_data(
        key_identifier: str,
        primary_account_number: str,
        generation_attributes: dict,
        validation_data_length: int | None = None,
    ) -> dict:
        """
        Generate card validation data: CVV, CVV2, iCVV, ARQC, or dynamic values.

        Supported key types: C0 (CVK), E4/E6 (EMV).

        generation_attributes examples:
          CVV:  {"CardVerificationValue1": {"CardExpiryDate": "0128", "ServiceCode": "101"}}
          CVV2: {"CardVerificationValue2": {"CardExpiryDate": "0128"}}
          iCVV: {"CardVerificationValue1": {"CardExpiryDate": "0128", "ServiceCode": "999"}}
          ARQC: {"DynamicCardVerificationCode": {"ApplicationTransactionCounter": "0001",
                                                  "PanSequenceNumber": "01",
                                                  "TrackData": "..."}}

        Args:
            key_identifier: ARN or alias of CVK (C0) or EMV key
            primary_account_number: 12-19 digit PAN
            generation_attributes: Algorithm and card data parameters
            validation_data_length: Optional output length override
        """
        params: dict = {
            "KeyIdentifier": key_identifier,
            "PrimaryAccountNumber": primary_account_number,
            "GenerationAttributes": generation_attributes,
        }
        if validation_data_length is not None:
            params["ValidationDataLength"] = validation_data_length
        return client().generate_card_validation_data(**params)

    @mcp.tool()
    def verify_card_validation_data(
        key_identifier: str,
        primary_account_number: str,
        verification_attributes: dict,
        validation_data: str,
    ) -> dict:
        """
        Verify card validation data (CVV, CVV2, iCVV, dynamic values).

        Supported key types: C0 (CVK), E4/E6 (EMV).

        Args:
            key_identifier: ARN or alias of CVK or EMV key
            primary_account_number: 12-19 digit PAN
            verification_attributes: Algorithm and card data (mirrors generate_card_validation_data)
            validation_data: The CVV/CVV2/iCVV value to verify
        """
        return client().verify_card_validation_data(
            KeyIdentifier=key_identifier,
            PrimaryAccountNumber=primary_account_number,
            VerificationAttributes=verification_attributes,
            ValidationData=validation_data,
        )

    # ── MAC Operations ────────────────────────────────────────────────────────

    @mcp.tool()
    def generate_mac(
        key_identifier: str,
        message_data: str,
        generation_attributes: dict,
        mac_length: int | None = None,
    ) -> dict:
        """
        Generate a Message Authentication Code to protect transaction data integrity.

        Preferred key type: M6 (CMAC). Legacy: M1 (CBC-MAC), M3 (Retail MAC), M0 (AS2805).
        ISO 8583 field 64 (primary MAC) or field 128 (secondary MAC).

        generation_attributes examples:
          CMAC:                        {"Algorithm": "CMAC"}
          ISO 9797-1 Alg 1 (CBC-MAC): {"Algorithm": "ISO9797_ALGORITHM1"}
          ISO 9797-1 Alg 3 (Retail):  {"Algorithm": "ISO9797_ALGORITHM3"}
          HMAC-SHA256:                 {"Algorithm": "HMAC_SHA256"}
          DUKPT CMAC:                  {"DukptCmac": {"KeySerialNumber": "...", "DukptKeyVariant": "BIDIRECTIONAL", "DukptDerivationType": "AES_128"}}
          DUKPT Alg 1:                 {"DukptIso9797Algorithm1": {"KeySerialNumber": "...", "DukptKeyVariant": "BIDIRECTIONAL", "DukptDerivationType": "TDES_2KEY"}}
          DUKPT Alg 3:                 {"DukptIso9797Algorithm3": {"KeySerialNumber": "...", "DukptKeyVariant": "BIDIRECTIONAL", "DukptDerivationType": "TDES_2KEY"}}

        Args:
            key_identifier: ARN or alias of MAC key (M0, M1, M3, M6, or M7)
            message_data: Hex-encoded message to authenticate
            generation_attributes: MAC algorithm parameters
            mac_length: Output MAC length in bytes (default per algorithm)
        """
        algo = generation_attributes.get("Algorithm", "")
        if "ALGO_1" in algo:
            result = check_legacy_construct("CBC_MAC")
            if result:
                return {
                    "compliance_warning": result.message,
                    "modern_alternative": result.modern_alternative,
                    "confirmation_required": format_legacy_constraint_prompt(result.modern_alternative),
                }
        if "ALGO_3" in algo:
            result = check_legacy_construct("RETAIL_MAC")
            if result:
                return {
                    "compliance_warning": result.message,
                    "modern_alternative": result.modern_alternative,
                    "confirmation_required": format_legacy_constraint_prompt(result.modern_alternative),
                }

        params: dict = {
            "KeyIdentifier": key_identifier,
            "MessageData": message_data,
            "GenerationAttributes": generation_attributes,
        }
        if mac_length is not None:
            params["MacLength"] = mac_length
        return client().generate_mac(**params)

    @mcp.tool()
    def verify_mac(
        key_identifier: str,
        message_data: str,
        mac: str,
        verification_attributes: dict,
        mac_length: int | None = None,
    ) -> dict:
        """
        Verify a Message Authentication Code.

        Args:
            key_identifier: ARN or alias of MAC key
            message_data: Hex-encoded message that was authenticated
            mac: Hex-encoded MAC value to verify
            verification_attributes: MAC algorithm parameters (mirrors generate_mac)
            mac_length: MAC length in bytes if non-default
        """
        params: dict = {
            "KeyIdentifier": key_identifier,
            "MessageData": message_data,
            "Mac": mac,
            "VerificationAttributes": verification_attributes,
        }
        if mac_length is not None:
            params["MacLength"] = mac_length
        return client().verify_mac(**params)

    @mcp.tool()
    def generate_mac_emv_pin_change(
        new_pin_pek_identifier: str,
        secure_messaging_integrity_key_identifier: str,
        secure_messaging_confidentiality_key_identifier: str,
        message_data: str,
        new_encrypted_pin_block: str,
        pin_block_format: str,
        derivation_method_attributes: dict,
    ) -> dict:
        """
        Generate a MAC for EMV offline PIN change operations.
        Combines MAC generation (E2 key) and PIN encryption (E1 key) in a single HSM operation.

        Required key types:
          new_pin_pek_identifier: P0 (PIN Encryption Key for new PIN)
          secure_messaging_integrity_key_identifier: E2 (EMV integrity)
          secure_messaging_confidentiality_key_identifier: E1 (EMV confidentiality)

        Args:
            new_pin_pek_identifier: ARN or alias of P0 key for new PIN
            secure_messaging_integrity_key_identifier: ARN or alias of E2 key
            secure_messaging_confidentiality_key_identifier: ARN or alias of E1 key
            message_data: Hex-encoded script command data
            new_encrypted_pin_block: Hex-encoded new PIN block encrypted under PEK
            pin_block_format: ISO_FORMAT_0 or ISO_FORMAT_4
            derivation_method_attributes: EMV derivation method (Visa, Mastercard, etc.)
        """
        return client().generate_mac_emv_pin_change(
            NewPinPekIdentifier=new_pin_pek_identifier,
            SecureMessagingIntegrityKeyIdentifier=secure_messaging_integrity_key_identifier,
            SecureMessagingConfidentialityKeyIdentifier=secure_messaging_confidentiality_key_identifier,
            MessageData=message_data,
            NewEncryptedPinBlock=new_encrypted_pin_block,
            PinBlockFormat=pin_block_format,
            DerivationMethodAttributes=derivation_method_attributes,
        )

    # ── EMV / ARQC ───────────────────────────────────────────────────────────

    @mcp.tool()
    def verify_auth_request_cryptogram(
        key_identifier: str,
        transaction_data: str,
        auth_request_cryptogram: str,
        major_key_derivation_mode: str,
        session_key_derivation_attributes: dict,
        auth_response_attributes: dict | None = None,
    ) -> dict:
        """
        Verify an EMV Authorization Request Cryptogram (ARQC) and optionally generate
        an Authorization Response Cryptogram (ARPC).

        Required key type: E0 (EMV Application Cryptogram Master Key).

        major_key_derivation_mode options:
          EMV_OPTION_A — Visa/Amex ARQC derivation
          EMV_OPTION_B — Mastercard ARQC derivation

        session_key_derivation_attributes:
          {"EmvCommon": {"ApplicationTransactionCounter": "0001",
                          "PanSequenceNumber": "01",
                          "ApplicationCryptogram": "<ARQC hex>"}}

        auth_response_attributes (to generate ARPC in same call):
          {"GenerateArpc": {"ArpcMethod1": {"AuthResponseCode": "0010"}}}
          or
          {"GenerateArpc": {"ArpcMethod2": {"CardStatusUpdate": "00000000", "ProprietaryAuthenticationData": ""}}}

        ISO 8583 field 55 contains the EMV data including ARQC and ATC (tag 0x9F36).

        Args:
            key_identifier: ARN or alias of E0 key
            transaction_data: Hex-encoded EMV transaction data for ARQC verification
            auth_request_cryptogram: Hex-encoded ARQC from the chip card
            major_key_derivation_mode: EMV_OPTION_A or EMV_OPTION_B
            session_key_derivation_attributes: ATC and session key derivation params
            auth_response_attributes: Optional ARPC generation parameters
        """
        params: dict = {
            "KeyIdentifier": key_identifier,
            "TransactionData": transaction_data,
            "AuthRequestCryptogram": auth_request_cryptogram,
            "MajorKeyDerivationMode": major_key_derivation_mode,
            "SessionKeyDerivationAttributes": session_key_derivation_attributes,
        }
        if auth_response_attributes:
            params["AuthResponseAttributes"] = auth_response_attributes
        return client().verify_auth_request_cryptogram(**params)

    # ── Key Translation ───────────────────────────────────────────────────────

    @mcp.tool()
    def translate_key_material(
        incoming_key_material: dict,
        outgoing_key_material: dict,
        key_check_value_algorithm: str | None = None,
    ) -> dict:
        """
        Translate an ECDH-wrapped TR-31 key block into a KEK-wrapped TR-31 key block
        without ever importing the working key into APC storage.

        The only documented use case is ECDH → TR-31 (KEK):
          incoming_key_material = {
            "DiffieHellmanTr31KeyBlock": {
              "CertificateAuthorityPublicKeyIdentifier": "<CA key ARN>",
              "KeyBlockHeaders": {...},
              "PrivateKeyIdentifier": "<ECC private key ARN>",
              "PublicKeyCertificate": "<base64 PEM cert of counterparty>",
              "DerivationData": "<hex>",
              "KeyAlgorithm": "AES_128",
              "KeyDerivationFunction": "NIST_SP800",
              "KeyDerivationHashAlgorithm": "SHA_256"
            }
          }
          outgoing_key_material = {
            "Tr31KeyBlock": {
              "WrappingKeyIdentifier": "<KEK ARN or alias>"
            }
          }

        key_check_value_algorithm: CMAC, ANSI_X9_24, HMAC, or SHA_1

        Args:
            incoming_key_material: ECDH-wrapped TR-31 key block (DiffieHellmanTr31KeyBlock)
            outgoing_key_material: Target KEK-wrapped TR-31 output (Tr31KeyBlock)
            key_check_value_algorithm: Optional KCV algorithm for the output key block
        """
        params: dict = {
            "IncomingKeyMaterial": incoming_key_material,
            "OutgoingKeyMaterial": outgoing_key_material,
        }
        if key_check_value_algorithm:
            params["KeyCheckValueAlgorithm"] = key_check_value_algorithm
        return client().translate_key_material(**params)

    # ── AS2805 ───────────────────────────────────────────────────────────────

    @mcp.tool()
    def generate_as2805_kek_validation(
        key_identifier: str,
        kek_validation_type: str,
        random_key_send_variant_mask: str,
    ) -> dict:
        """
        Generate an AS2805 Key Encryption Key validation value.
        Used in Australian payment network node-to-node key exchange.

        kek_validation_type:
          KekValidationRequest  — initiating node generates a validation request
          KekValidationResponse — responding node generates the validation response

        random_key_send_variant_mask:
          VARIANT_MASK_82C0 — standard AS2805 variant mask
          VARIANT_MASK_82   — alternate AS2805 variant mask

        Args:
            key_identifier: ARN or alias of the AS2805 KEK
            kek_validation_type: KekValidationRequest or KekValidationResponse
            random_key_send_variant_mask: VARIANT_MASK_82C0 or VARIANT_MASK_82
        """
        return client().generate_as2805_kek_validation(
            KeyIdentifier=key_identifier,
            KekValidationType=kek_validation_type,
            RandomKeySendVariantMask=random_key_send_variant_mask,
        )

    # ── Compliance Advisories ─────────────────────────────────────────────────

    @mcp.tool()
    def pin_block_retention_advisory() -> dict:
        """
        Return the PCI PIN requirement for PIN block handling in logs.
        Call this when designing any transaction logging or audit trail system.
        """
        return {
            "requirement": PIN_BLOCK_RETENTION_VIOLATION.pci_requirement,
            "rule": PIN_BLOCK_RETENTION_VIOLATION.message,
            "iso_8583_field": "Field 52",
            "guidance": (
                "Before writing any transaction record to a log, journal, or database, "
                "mask or delete field 52 (PIN block). Even encrypted PIN blocks must not be retained "
                "after the authorization response is received."
            ),
        }

    @mcp.tool()
    def pan_change_advisory() -> dict:
        """
        Return the PCI PIN requirement prohibiting PAN changes during PIN translation.
        """
        return {
            "requirement": PAN_CHANGE_VIOLATION.pci_requirement,
            "rule": PAN_CHANGE_VIOLATION.message,
        }


def _extract_pin_format(translation_attributes: dict) -> str | None:
    format_keys = ["IsoFormat0", "IsoFormat1", "IsoFormat2", "IsoFormat3", "IsoFormat4"]
    for key in format_keys:
        if key in translation_attributes:
            return key
    return None
