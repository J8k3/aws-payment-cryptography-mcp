"""
Tests for compliance guards in data_plane.py.

Guards short-circuit before any AWS call, so the negative-path tests (guard fires)
need no credentials. Positive-path tests (guard does not fire) mock boto3 so the
tool reaches — and we can confirm — the AWS layer without a real account.

This test class covers the exact failure mode seen in generate_mac(): a logic error
in the guard path that silently let prohibited constructs through.
"""
from unittest.mock import MagicMock, patch

import pytest

from apc_agent.data_plane import register_data_plane_tools


class _CaptureMCP:
    def __init__(self):
        self._tools: dict = {}

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


# ── generate_mac compliance guards ───────────────────────────────────────────

class TestGenerateMacComplianceGuards:
    def test_iso9797_algorithm1_triggers_compliance_warning(self, tools):
        result = tools["generate_mac"](
            key_identifier="alias/test-mac",
            message_data="DEADBEEF",
            generation_attributes={"Algorithm": "ISO9797_ALGORITHM1"},
        )
        assert "compliance_warning" in result, (
            "CBC-MAC (ISO9797_ALGORITHM1) must trigger a compliance warning"
        )
        assert "confirmation_required" in result

    def test_iso9797_algorithm3_triggers_compliance_warning(self, tools):
        result = tools["generate_mac"](
            key_identifier="alias/test-mac",
            message_data="DEADBEEF",
            generation_attributes={"Algorithm": "ISO9797_ALGORITHM3"},
        )
        assert "compliance_warning" in result, (
            "Retail MAC (ISO9797_ALGORITHM3) must trigger a compliance warning"
        )
        assert "confirmation_required" in result

    def test_cmac_reaches_aws_layer(self, tools):
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.client.return_value = mock_client
            mock_client.generate_mac.return_value = {"Mac": "AABBCCDD"}
            result = tools["generate_mac"](
                key_identifier="alias/test-mac",
                message_data="DEADBEEF",
                generation_attributes={"Algorithm": "CMAC"},
            )
        assert "compliance_warning" not in result
        mock_client.generate_mac.assert_called_once()

    def test_hmac_sha256_reaches_aws_layer(self, tools):
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.client.return_value = mock_client
            mock_client.generate_mac.return_value = {"Mac": "AABBCCDD"}
            result = tools["generate_mac"](
                key_identifier="alias/test-mac",
                message_data="DEADBEEF",
                generation_attributes={"Algorithm": "HMAC_SHA256"},
            )
        assert "compliance_warning" not in result
        mock_client.generate_mac.assert_called_once()


# ── verify_mac compliance guards ─────────────────────────────────────────────

class TestVerifyMacComplianceGuards:
    def test_iso9797_algorithm1_triggers_compliance_warning(self, tools):
        result = tools["verify_mac"](
            key_identifier="alias/test-mac",
            message_data="DEADBEEF",
            mac="AABBCCDD",
            verification_attributes={"Algorithm": "ISO9797_ALGORITHM1"},
        )
        assert "compliance_warning" in result, (
            "CBC-MAC (ISO9797_ALGORITHM1) must trigger a compliance warning on verify_mac"
        )
        assert "confirmation_required" in result

    def test_iso9797_algorithm3_triggers_compliance_warning(self, tools):
        result = tools["verify_mac"](
            key_identifier="alias/test-mac",
            message_data="DEADBEEF",
            mac="AABBCCDD",
            verification_attributes={"Algorithm": "ISO9797_ALGORITHM3"},
        )
        assert "compliance_warning" in result, (
            "Retail MAC (ISO9797_ALGORITHM3) must trigger a compliance warning on verify_mac"
        )
        assert "confirmation_required" in result

    def test_cmac_reaches_aws_layer(self, tools):
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.client.return_value = mock_client
            mock_client.verify_mac.return_value = {"VerificationStatus": "SUCCESS"}
            result = tools["verify_mac"](
                key_identifier="alias/test-mac",
                message_data="DEADBEEF",
                mac="AABBCCDD",
                verification_attributes={"Algorithm": "CMAC"},
            )
        assert "compliance_warning" not in result
        mock_client.verify_mac.assert_called_once()


# ── translate_pin_data compliance guards ─────────────────────────────────────

class TestTranslatePinDataComplianceGuards:
    def test_prohibited_format_translation_blocked(self, tools):
        # Format 0 → Format 1 is explicitly prohibited by PCI PIN Req 3-3
        result = tools["translate_pin_data"](
            incoming_key_identifier="alias/test-pek-in",
            outgoing_key_identifier="alias/test-pek-out",
            incoming_translation_attributes={"IsoFormat0": {"PrimaryAccountNumber": "123456789012"}},
            outgoing_translation_attributes={"IsoFormat1": {"PrimaryAccountNumber": "123456789012"}},
            encrypted_pin_block="AABBCCDDEEFF0011",
        )
        assert "error" in result
        assert "pci_requirement" in result

    def test_outgoing_format0_triggers_compliance_warning(self, tools):
        result = tools["translate_pin_data"](
            incoming_key_identifier="alias/test-pek-in",
            outgoing_key_identifier="alias/test-pek-out",
            incoming_translation_attributes={"IsoFormat4": {"PrimaryAccountNumber": "123456789012"}},
            outgoing_translation_attributes={"IsoFormat0": {"PrimaryAccountNumber": "123456789012"}},
            encrypted_pin_block="AABBCCDDEEFF0011",
        )
        assert "compliance_warning" in result

    def test_format4_to_format4_reaches_aws_layer(self, tools):
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.client.return_value = mock_client
            mock_client.translate_pin_data.return_value = {"PinBlock": "AABBCCDDEEFF0011"}
            result = tools["translate_pin_data"](
                incoming_key_identifier="alias/test-pek-in",
                outgoing_key_identifier="alias/test-pek-out",
                incoming_translation_attributes={"IsoFormat4": {"PrimaryAccountNumber": "123456789012"}},
                outgoing_translation_attributes={"IsoFormat4": {"PrimaryAccountNumber": "123456789012"}},
                encrypted_pin_block="AABBCCDDEEFF0011",
            )
        assert "compliance_warning" not in result
        assert "error" not in result
        mock_client.translate_pin_data.assert_called_once()


# ── generate_pin_data compliance guards ──────────────────────────────────────

class TestGeneratePinDataComplianceGuards:
    def test_iso_format_0_triggers_compliance_warning(self, tools):
        result = tools["generate_pin_data"](
            generation_key_identifier="alias/test-pvk",
            encryption_key_identifier="alias/test-pek",
            generation_attributes={"Ibm3624RandomPin": {"DecimalizationTable": "0123456789012345"}},
            pin_block_format="ISO_FORMAT_0",
            primary_account_number="123456789012",
        )
        assert "compliance_warning" in result

    def test_iso_format_4_reaches_aws_layer(self, tools):
        with patch("apc_agent.data_plane.boto3") as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.client.return_value = mock_client
            mock_client.generate_pin_data.return_value = {"PinBlock": "AABB", "PinOffset": "1234"}
            result = tools["generate_pin_data"](
                generation_key_identifier="alias/test-pvk",
                encryption_key_identifier="alias/test-pek",
                generation_attributes={"VisaPin": {"PinVerificationKeyIndex": 1}},
                pin_block_format="ISO_FORMAT_4",
                primary_account_number="123456789012",
            )
        assert "compliance_warning" not in result
        mock_client.generate_pin_data.assert_called_once()
