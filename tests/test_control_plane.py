"""
Unit tests for control_plane.py tool layer.

Uses unittest.mock to assert that tools construct correct boto3 call parameters.
moto is applied automatically by conftest but our explicit patches take precedence,
so these tests run without real AWS credentials.
"""

from unittest.mock import MagicMock, patch

import pytest

from apc_agent.control_plane import register_control_plane_tools


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
    register_control_plane_tools(mcp)
    return mcp._tools


# ── create_key ────────────────────────────────────────────────────────────────

class TestCreateKey:
    def test_aes_ansi_kcv_blocked_before_boto3_call(self, tools):
        """AES + ANSI_X9_24 KCV must be rejected without calling boto3."""
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            result = tools["create_key"](
                key_algorithm="AES_128",
                key_usage="TR31_P0_PIN_ENCRYPTION_KEY",
                key_class="SYMMETRIC_KEY",
                exportable=False,
                key_check_value_algorithm="ANSI_X9_24",
            )
        mock_boto3.client.assert_not_called()
        assert "error" in result
        assert "CMAC" in result["error"]

    def test_unknown_key_usage_blocked_before_boto3_call(self, tools):
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            result = tools["create_key"](
                key_algorithm="AES_128",
                key_usage="TR31_XX_MADE_UP",
                key_class="SYMMETRIC_KEY",
                exportable=False,
            )
        mock_boto3.client.assert_not_called()
        assert "error" in result

    def test_single_des_blocked_before_boto3_call(self, tools):
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            result = tools["create_key"](
                key_algorithm="DES",
                key_usage="TR31_P0_PIN_ENCRYPTION_KEY",
                key_class="SYMMETRIC_KEY",
                exportable=False,
            )
        mock_boto3.client.assert_not_called()
        assert "error" in result
        assert "pci_requirement" in result

    def test_rsa_1024_blocked_before_boto3_call(self, tools):
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            result = tools["create_key"](
                key_algorithm="RSA_1024",
                key_usage="TR31_D1_ASYMMETRIC_KEY_FOR_DATA_ENCRYPTION",
                key_class="ASYMMETRIC_KEY_PAIR",
                exportable=False,
            )
        mock_boto3.client.assert_not_called()
        assert "error" in result
        assert "pci_requirement" in result

    def test_create_key_passes_correct_params_to_boto3(self, tools):
        mock_client = MagicMock()
        mock_client.create_key.return_value = {
            "Key": {
                "KeyArn": "arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123",
                "KeyAttributes": {
                    "KeyAlgorithm": "AES_128",
                    "KeyUsage": "TR31_P0_PIN_ENCRYPTION_KEY",
                    "KeyClass": "SYMMETRIC_KEY",
                    "KeyModesOfUse": {"Encrypt": True, "Decrypt": True},
                },
                "Enabled": True,
                "Exportable": False,
            }
        }
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["create_key"](
                key_algorithm="AES_128",
                key_usage="TR31_P0_PIN_ENCRYPTION_KEY",
                key_class="SYMMETRIC_KEY",
                exportable=False,
                enabled=True,
                key_check_value_algorithm="CMAC",
            )
        call_kwargs = mock_client.create_key.call_args.kwargs
        assert call_kwargs["KeyAttributes"]["KeyAlgorithm"] == "AES_128"
        assert call_kwargs["KeyAttributes"]["KeyUsage"] == "TR31_P0_PIN_ENCRYPTION_KEY"
        assert call_kwargs["KeyAttributes"]["KeyClass"] == "SYMMETRIC_KEY"
        assert call_kwargs["Exportable"] is False
        assert call_kwargs["Enabled"] is True
        assert call_kwargs["KeyCheckValueAlgorithm"] == "CMAC"

    def test_create_key_omits_kcv_algorithm_when_not_specified(self, tools):
        mock_client = MagicMock()
        mock_client.create_key.return_value = {"Key": {}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["create_key"](
                key_algorithm="AES_256",
                key_usage="TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
                key_class="SYMMETRIC_KEY",
                exportable=True,
            )
        call_kwargs = mock_client.create_key.call_args.kwargs
        assert "KeyCheckValueAlgorithm" not in call_kwargs

    def test_tags_passed_when_provided(self, tools):
        mock_client = MagicMock()
        mock_client.create_key.return_value = {"Key": {}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["create_key"](
                key_algorithm="AES_128",
                key_usage="TR31_P0_PIN_ENCRYPTION_KEY",
                key_class="SYMMETRIC_KEY",
                exportable=False,
                tags=[{"Key": "env", "Value": "test"}],
            )
        call_kwargs = mock_client.create_key.call_args.kwargs
        assert call_kwargs.get("Tags") == [{"Key": "env", "Value": "test"}]


# ── list_keys / describe_key ──────────────────────────────────────────────────

class TestListAndDescribeKey:
    def test_list_keys_calls_boto3_and_returns_response(self, tools):
        mock_client = MagicMock()
        mock_client.list_keys.return_value = {"Keys": [], "NextToken": None}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = tools["list_keys"]()
        mock_client.list_keys.assert_called_once()
        assert "Keys" in result

    def test_get_key_passes_identifier(self, tools):
        mock_client = MagicMock()
        mock_client.get_key.return_value = {"Key": {"KeyArn": "arn:..."}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["get_key"](key_identifier="alias/my-pin-key")
        mock_client.get_key.assert_called_once_with(KeyIdentifier="alias/my-pin-key")
