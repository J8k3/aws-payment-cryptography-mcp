"""
Unit tests for data_plane.py tool layer.

Uses unittest.mock to verify that tools construct correct boto3 call parameters
and that compliance gates fire before any boto3 call is made.

moto is applied automatically by conftest but our explicit patches take precedence,
so these tests run without real AWS credentials and without the moto backend.
"""

from unittest.mock import MagicMock, patch

import pytest

from apc_agent.data_plane import register_data_plane_tools


class _CaptureMCP:
    def __init__(self):
        self._tools = {}

    def tool(self, **kwargs):
        def decorator(fn):
            self._tools[fn.__name__] = fn
            return fn
        return decorator


@pytest.fixture(scope="module")
def tools():
    mcp = _CaptureMCP()
    register_data_plane_tools(mcp)
    return mcp._tools


# ── encrypt_data ──────────────────────────────────────────────────────────────

class TestEncryptData:
    def test_passes_correct_params_to_boto3(self, tools):
        mock_client = MagicMock()
        mock_client.encrypt_data.return_value = {"CipherText": "DEADBEEF00112233"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = tools["encrypt_data"](
                key_identifier="alias/data-enc-key",
                plain_text="AABBCCDDEEFF0011",
                encryption_attributes={"Symmetric": {"Mode": "CBC", "InitializationVector": "00" * 16}},
            )
        mock_client.encrypt_data.assert_called_once_with(
            KeyIdentifier="alias/data-enc-key",
            PlainText="AABBCCDDEEFF0011",
            EncryptionAttributes={"Symmetric": {"Mode": "CBC", "InitializationVector": "00" * 16}},
        )
        assert result["CipherText"] == "DEADBEEF00112233"

    def test_wrapped_key_included_when_provided(self, tools):
        mock_client = MagicMock()
        mock_client.encrypt_data.return_value = {"CipherText": "AABB"}
        wrapped = {"WrappedKeyMaterial": {"Tr31KeyBlock": "B0128P0TN00N00..."}, "KeyCheckValueAlgorithm": "CMAC"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["encrypt_data"](
                key_identifier="alias/kek",
                plain_text="AABB",
                encryption_attributes={"Symmetric": {"Mode": "CBC"}},
                wrapped_key=wrapped,
            )
        call_kwargs = mock_client.encrypt_data.call_args.kwargs
        assert call_kwargs["WrappedKey"] == wrapped

    def test_wrapped_key_omitted_when_none(self, tools):
        mock_client = MagicMock()
        mock_client.encrypt_data.return_value = {"CipherText": "AABB"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["encrypt_data"](
                key_identifier="alias/key",
                plain_text="AABB",
                encryption_attributes={"Symmetric": {"Mode": "ECB"}},
            )
        call_kwargs = mock_client.encrypt_data.call_args.kwargs
        assert "WrappedKey" not in call_kwargs


# ── translate_pin_data ────────────────────────────────────────────────────────

class TestTranslatePinData:
    ISO4_ATTRS = {"IsoFormat4": {"PrimaryAccountNumber": "1712345678901234"}}

    def test_illegal_format_translation_blocked_before_boto3(self, tools):
        """IsoFormat0 → IsoFormat1 is prohibited (PCI PIN Req 3-3). Must not call boto3."""
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            result = tools["translate_pin_data"](
                incoming_key_identifier="alias/zpk-in",
                outgoing_key_identifier="alias/zpk-out",
                incoming_translation_attributes={"IsoFormat0": {"PrimaryAccountNumber": "561237487695"}},
                outgoing_translation_attributes={"IsoFormat1": {}},
                encrypted_pin_block="0123456789ABCDEF",
            )
        mock_boto3.client.assert_not_called()
        assert "error" in result
        assert "pci_requirement" in result

    def test_format4_to_format4_passes_correct_params(self, tools):
        mock_client = MagicMock()
        mock_client.translate_pin_data.return_value = {"PinBlock": "FEDCBA9876543210"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = tools["translate_pin_data"](
                incoming_key_identifier="alias/zpk-in",
                outgoing_key_identifier="alias/zpk-out",
                incoming_translation_attributes=self.ISO4_ATTRS,
                outgoing_translation_attributes=self.ISO4_ATTRS,
                encrypted_pin_block="0123456789ABCDEF",
            )
        call_kwargs = mock_client.translate_pin_data.call_args.kwargs
        assert call_kwargs["IncomingKeyIdentifier"] == "alias/zpk-in"
        assert call_kwargs["OutgoingKeyIdentifier"] == "alias/zpk-out"
        assert call_kwargs["EncryptedPinBlock"] == "0123456789ABCDEF"
        assert call_kwargs["IncomingTranslationAttributes"] == self.ISO4_ATTRS
        assert result["PinBlock"] == "FEDCBA9876543210"

    def test_format0_outbound_triggers_legacy_warning_without_boto3_call(self, tools):
        """IsoFormat0 outbound is a deprecated format — tool must return confirmation_required."""
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            result = tools["translate_pin_data"](
                incoming_key_identifier="alias/zpk-in",
                outgoing_key_identifier="alias/zpk-out",
                incoming_translation_attributes={"IsoFormat4": {"PrimaryAccountNumber": "561237487695"}},
                outgoing_translation_attributes={"IsoFormat0": {"PrimaryAccountNumber": "561237487695"}},
                encrypted_pin_block="0123456789ABCDEF",
            )
        mock_boto3.client.assert_not_called()
        assert "confirmation_required" in result or "compliance_warning" in result

    def test_dukpt_attributes_included_when_provided(self, tools):
        mock_client = MagicMock()
        mock_client.translate_pin_data.return_value = {"PinBlock": "AABB"}
        dukpt = {"KeySerialNumber": "FFFF9876543210E00001"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["translate_pin_data"](
                incoming_key_identifier="alias/bdk",
                outgoing_key_identifier="alias/zpk-out",
                incoming_translation_attributes=self.ISO4_ATTRS,
                outgoing_translation_attributes=self.ISO4_ATTRS,
                encrypted_pin_block="AABB",
                incoming_dukpt_attributes=dukpt,
            )
        call_kwargs = mock_client.translate_pin_data.call_args.kwargs
        assert call_kwargs["IncomingDukptAttributes"] == dukpt
        assert "OutgoingDukptAttributes" not in call_kwargs


# ── generate_pin_data / verify_pin_data ──────────────────────────────────────

class TestPinDataComplianceGuards:
    GEN_ATTRS = {"Ibm3624RandomPin": {"DecimalizationTable": "0123456789012345"}}
    VER_ATTRS = {"Ibm3624PinOffset": {"DecimalizationTable": "0123456789012345", "PinValidationData": "1234567890123456", "PinOffset": "0000"}}

    def test_generate_format0_triggers_legacy_warning_without_boto3(self, tools):
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            result = tools["generate_pin_data"](
                generation_key_identifier="alias/pvk",
                encryption_key_identifier="alias/pek",
                generation_attributes=self.GEN_ATTRS,
                pin_block_format="ISO_FORMAT_0",
                primary_account_number="1234567890123456",
            )
        mock_boto3.client.assert_not_called()
        assert "confirmation_required" in result

    def test_generate_format3_triggers_legacy_warning_without_boto3(self, tools):
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            result = tools["generate_pin_data"](
                generation_key_identifier="alias/pvk",
                encryption_key_identifier="alias/pek",
                generation_attributes=self.GEN_ATTRS,
                pin_block_format="ISO_FORMAT_3",
                primary_account_number="1234567890123456",
            )
        mock_boto3.client.assert_not_called()
        assert "confirmation_required" in result

    def test_verify_format0_triggers_legacy_warning_without_boto3(self, tools):
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            result = tools["verify_pin_data"](
                verification_key_identifier="alias/pvk",
                encrypted_pin_block="0123456789ABCDEF",
                encryption_key_identifier="alias/pek",
                verification_attributes=self.VER_ATTRS,
                pin_block_format="ISO_FORMAT_0",
                primary_account_number="1234567890123456",
            )
        mock_boto3.client.assert_not_called()
        assert "confirmation_required" in result

    def test_verify_format3_triggers_legacy_warning_without_boto3(self, tools):
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            result = tools["verify_pin_data"](
                verification_key_identifier="alias/pvk",
                encrypted_pin_block="0123456789ABCDEF",
                encryption_key_identifier="alias/pek",
                verification_attributes=self.VER_ATTRS,
                pin_block_format="ISO_FORMAT_3",
                primary_account_number="1234567890123456",
            )
        mock_boto3.client.assert_not_called()
        assert "confirmation_required" in result

    def test_generate_format4_reaches_boto3(self, tools):
        mock_client = MagicMock()
        mock_client.generate_pin_data.return_value = {"EncryptedPinBlock": "AABBCCDDEEFF0011"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["generate_pin_data"](
                generation_key_identifier="alias/pvk",
                encryption_key_identifier="alias/pek",
                generation_attributes=self.GEN_ATTRS,
                pin_block_format="ISO_FORMAT_4",
                primary_account_number="1234567890123456",
            )
        mock_client.generate_pin_data.assert_called_once()

    def test_verify_format4_reaches_boto3(self, tools):
        mock_client = MagicMock()
        mock_client.verify_pin_data.return_value = {"VerificationStatus": "SUCESS"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["verify_pin_data"](
                verification_key_identifier="alias/pvk",
                encrypted_pin_block="0123456789ABCDEF",
                encryption_key_identifier="alias/pek",
                verification_attributes=self.VER_ATTRS,
                pin_block_format="ISO_FORMAT_4",
                primary_account_number="1234567890123456",
            )
        mock_client.verify_pin_data.assert_called_once()


# ── generate_mac ──────────────────────────────────────────────────────────────

class TestGenerateMac:
    def test_passes_correct_params_to_boto3(self, tools):
        mock_client = MagicMock()
        mock_client.generate_mac.return_value = {"Mac": "AABBCCDD"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = tools["generate_mac"](
                key_identifier="alias/mac-key",
                message_data="DEADBEEF",
                generation_attributes={"Algorithm": "CMAC"},
            )
        mock_client.generate_mac.assert_called_once_with(
            KeyIdentifier="alias/mac-key",
            MessageData="DEADBEEF",
            GenerationAttributes={"Algorithm": "CMAC"},
        )
        assert result["Mac"] == "AABBCCDD"

    def test_mac_length_included_when_provided(self, tools):
        mock_client = MagicMock()
        mock_client.generate_mac.return_value = {"Mac": "AABB"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["generate_mac"](
                key_identifier="alias/mac-key",
                message_data="DEADBEEF",
                generation_attributes={"Algorithm": "CMAC"},
                mac_length=8,
            )
        call_kwargs = mock_client.generate_mac.call_args.kwargs
        assert call_kwargs["MacLength"] == 8

    def test_mac_length_omitted_when_none(self, tools):
        mock_client = MagicMock()
        mock_client.generate_mac.return_value = {"Mac": "AABB"}
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["generate_mac"](
                key_identifier="alias/mac-key",
                message_data="DEADBEEF",
                generation_attributes={"Algorithm": "CMAC"},
            )
        call_kwargs = mock_client.generate_mac.call_args.kwargs
        assert "MacLength" not in call_kwargs
