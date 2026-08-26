"""
Unit tests for control_plane.py tool layer.

Uses unittest.mock to assert that tools construct correct boto3 call parameters.
moto is applied automatically by conftest but our explicit patches take precedence,
so these tests run without real AWS credentials.
"""

from unittest.mock import MagicMock, patch

import pytest

from apc_agent.control_plane import register_control_plane_tools

from .test_api_surface import assert_params_valid


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


# ── key replication ───────────────────────────────────────────────────────────

class TestKeyReplication:
    def test_add_regions_passes_key_and_regions(self, tools):
        mock_client = MagicMock()
        mock_client.add_key_replication_regions.return_value = {"Key": {"KeyArn": "arn:..."}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["add_key_replication_regions"](
                key_identifier="alias/my-pin-key",
                replication_regions=["us-west-2", "eu-west-1"],
            )
        mock_client.add_key_replication_regions.assert_called_once_with(
            KeyIdentifier="alias/my-pin-key",
            ReplicationRegions=["us-west-2", "eu-west-1"],
        )

    def test_remove_regions_passes_key_and_regions(self, tools):
        mock_client = MagicMock()
        mock_client.remove_key_replication_regions.return_value = {"Key": {"KeyArn": "arn:..."}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["remove_key_replication_regions"](
                key_identifier="alias/my-pin-key",
                replication_regions=["eu-west-1"],
            )
        mock_client.remove_key_replication_regions.assert_called_once_with(
            KeyIdentifier="alias/my-pin-key",
            ReplicationRegions=["eu-west-1"],
        )

    def test_get_defaults_takes_no_arguments(self, tools):
        mock_client = MagicMock()
        mock_client.get_default_key_replication_regions.return_value = {
            "EnabledReplicationRegions": ["us-west-2"]
        }
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = tools["get_default_key_replication_regions"]()
        mock_client.get_default_key_replication_regions.assert_called_once_with()
        assert result["EnabledReplicationRegions"] == ["us-west-2"]

    def test_enable_defaults_passes_regions(self, tools):
        mock_client = MagicMock()
        mock_client.enable_default_key_replication_regions.return_value = {
            "EnabledReplicationRegions": ["us-west-2"]
        }
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["enable_default_key_replication_regions"](replication_regions=["us-west-2"])
        mock_client.enable_default_key_replication_regions.assert_called_once_with(
            ReplicationRegions=["us-west-2"]
        )

    def test_disable_defaults_passes_regions(self, tools):
        mock_client = MagicMock()
        mock_client.disable_default_key_replication_regions.return_value = {
            "EnabledReplicationRegions": []
        }
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["disable_default_key_replication_regions"](replication_regions=["eu-west-1"])
        mock_client.disable_default_key_replication_regions.assert_called_once_with(
            ReplicationRegions=["eu-west-1"]
        )

    def test_create_key_forwards_replication_regions(self, tools):
        mock_client = MagicMock()
        mock_client.create_key.return_value = {"Key": {"KeyArn": "arn:..."}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["create_key"](
                key_algorithm="AES_256",
                key_usage="TR31_P0_PIN_ENCRYPTION_KEY",
                key_class="SYMMETRIC_KEY",
                exportable=False,
                replication_regions=["us-west-2"],
            )
        call_kwargs = mock_client.create_key.call_args.kwargs
        assert call_kwargs["ReplicationRegions"] == ["us-west-2"]

    def test_create_key_omits_replication_regions_when_unset(self, tools):
        """Omitted, not sent empty — an empty list would override the account default."""
        mock_client = MagicMock()
        mock_client.create_key.return_value = {"Key": {"KeyArn": "arn:..."}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["create_key"](
                key_algorithm="AES_256",
                key_usage="TR31_P0_PIN_ENCRYPTION_KEY",
                key_class="SYMMETRIC_KEY",
                exportable=False,
            )
        assert "ReplicationRegions" not in mock_client.create_key.call_args.kwargs

    def test_import_key_forwards_replication_regions(self, tools):
        mock_client = MagicMock()
        mock_client.import_key.return_value = {"Key": {"KeyArn": "arn:..."}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["import_key"](
                key_material={"Tr31KeyBlock": {"WrappingKeyIdentifier": "arn:...",
                                               "WrappedKeyBlock": "AAAA"}},
                replication_regions=["eu-west-1"],
            )
        assert mock_client.import_key.call_args.kwargs["ReplicationRegions"] == ["eu-west-1"]


# ── certificates ──────────────────────────────────────────────────────────────

class TestCertificates:
    def test_csr_passes_key_algorithm_and_subject(self, tools):
        mock_client = MagicMock()
        mock_client.get_certificate_signing_request.return_value = {
            "CertificateSigningRequest": "base64csr"
        }
        subject = {"CommonName": "acquirer-tr34-2026", "Country": "US"}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = tools["get_certificate_signing_request"](
                key_identifier="alias/tr34-signing",
                signing_algorithm="SHA256",
                certificate_subject=subject,
            )
        mock_client.get_certificate_signing_request.assert_called_once_with(
            KeyIdentifier="alias/tr34-signing",
            SigningAlgorithm="SHA256",
            CertificateSubject=subject,
        )
        assert result["CertificateSigningRequest"] == "base64csr"

    def test_public_key_certificate_passes_identifier(self, tools):
        mock_client = MagicMock()
        mock_client.get_public_key_certificate.return_value = {
            "KeyCertificate": "cert", "KeyCertificateChain": "chain"
        }
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = tools["get_public_key_certificate"](key_identifier="alias/tr34-signing")
        mock_client.get_public_key_certificate.assert_called_once_with(
            KeyIdentifier="alias/tr34-signing"
        )
        assert result["KeyCertificate"] == "cert"


# ── multi-party approval ──────────────────────────────────────────────────────

class TestMultiPartyApproval:
    def test_associate_passes_action_and_team(self, tools):
        mock_client = MagicMock()
        mock_client.associate_mpa_team.return_value = {"MpaTeamAssociation": {}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["associate_mpa_team"](
                action="IMPORT_ROOT_PUBLIC_KEY_CERTIFICATE",
                mpa_team_arn="arn:aws:mpa:us-east-1:123456789012:approval-team/key-custodians",
            )
        mock_client.associate_mpa_team.assert_called_once_with(
            Action="IMPORT_ROOT_PUBLIC_KEY_CERTIFICATE",
            MpaTeamArn="arn:aws:mpa:us-east-1:123456789012:approval-team/key-custodians",
        )

    def test_associate_omits_comment_when_unset(self, tools):
        mock_client = MagicMock()
        mock_client.associate_mpa_team.return_value = {"MpaTeamAssociation": {}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["associate_mpa_team"](
                action="IMPORT_ROOT_PUBLIC_KEY_CERTIFICATE",
                mpa_team_arn="arn:aws:mpa:us-east-1:123456789012:approval-team/kc",
            )
        assert "RequesterComment" not in mock_client.associate_mpa_team.call_args.kwargs

    def test_associate_forwards_comment(self, tools):
        mock_client = MagicMock()
        mock_client.associate_mpa_team.return_value = {"MpaTeamAssociation": {}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["associate_mpa_team"](
                action="IMPORT_ROOT_PUBLIC_KEY_CERTIFICATE",
                mpa_team_arn="arn:aws:mpa:us-east-1:123456789012:approval-team/kc",
                requester_comment="PCI PIN dual control for root CA import",
            )
        kwargs = mock_client.associate_mpa_team.call_args.kwargs
        assert kwargs["RequesterComment"] == "PCI PIN dual control for root CA import"

    def test_disassociate_passes_action_only(self, tools):
        mock_client = MagicMock()
        mock_client.disassociate_mpa_team.return_value = {"MpaTeamAssociation": {}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["disassociate_mpa_team"](action="IMPORT_ROOT_PUBLIC_KEY_CERTIFICATE")
        mock_client.disassociate_mpa_team.assert_called_once_with(
            Action="IMPORT_ROOT_PUBLIC_KEY_CERTIFICATE"
        )

    def test_get_association_passes_action(self, tools):
        mock_client = MagicMock()
        mock_client.get_mpa_team_association.return_value = {
            "MpaTeamAssociation": {"AssociationState": "ACTIVE"}
        }
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = tools["get_mpa_team_association"](
                action="IMPORT_ROOT_PUBLIC_KEY_CERTIFICATE"
            )
        mock_client.get_mpa_team_association.assert_called_once_with(
            Action="IMPORT_ROOT_PUBLIC_KEY_CERTIFICATE"
        )
        assert result["MpaTeamAssociation"]["AssociationState"] == "ACTIVE"

    def test_import_key_forwards_requester_comment(self, tools):
        mock_client = MagicMock()
        mock_client.import_key.return_value = {"Key": {"KeyArn": "arn:..."}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["import_key"](
                key_material={"Tr31KeyBlock": {"WrappingKeyIdentifier": "arn:...",
                                               "WrappedKeyBlock": "AAAA"}},
                requester_comment="quarterly BDK rotation",
            )
        kwargs = mock_client.import_key.call_args.kwargs
        assert kwargs["RequesterComment"] == "quarterly BDK rotation"

    def test_import_key_omits_requester_comment_when_unset(self, tools):
        mock_client = MagicMock()
        mock_client.import_key.return_value = {"Key": {"KeyArn": "arn:..."}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["import_key"](
                key_material={"Tr31KeyBlock": {"WrappingKeyIdentifier": "arn:...",
                                               "WrappedKeyBlock": "AAAA"}},
            )
        assert "RequesterComment" not in mock_client.import_key.call_args.kwargs

    def test_pending_mpa_status_is_passed_through_not_swallowed(self, tools):
        """A gated import returns PENDING — the caller must be able to see it."""
        mock_client = MagicMock()
        mock_client.import_key.return_value = {
            "Key": {
                "KeyArn": "arn:...",
                "MpaStatus": {
                    "MpaSessionArn": "arn:aws:mpa:us-east-1:123456789012:session/t/s",
                    "Status": "PENDING",
                    "InitiationDate": "2026-08-22T12:00:00Z",
                },
            }
        }
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            result = tools["import_key"](
                key_material={"Tr31KeyBlock": {"WrappingKeyIdentifier": "arn:...",
                                               "WrappedKeyBlock": "AAAA"}},
            )
        assert result["Key"]["MpaStatus"]["Status"] == "PENDING"


# ── export_key ────────────────────────────────────────────────────────────────

class TestExportKey:
    """
    These assert against the real service model, not just against captured kwargs.

    export_key previously sent KeyIdentifier and KeyMaterialType — neither of which is a
    member of ExportKey — so every call failed client-side with ParamValidationError before
    reaching AWS. It had been wrong since the service launched and no test caught it,
    because a MagicMock accepts any keyword argument.
    """

    def test_tr31_export_params_are_accepted_by_the_service_model(self, tools):
        mock_client = MagicMock()
        mock_client.export_key.return_value = {"WrappedKey": {}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["export_key"](
                export_key_identifier="alias/bdk-2026",
                key_material={"Tr31KeyBlock": {"WrappingKeyIdentifier": "alias/kbpk"}},
            )
        params = mock_client.export_key.call_args.kwargs
        assert params["ExportKeyIdentifier"] == "alias/bdk-2026"
        assert "KeyMaterial" in params
        assert_params_valid("payment-cryptography", "ExportKey", params)

    def test_tr34_export_params_are_accepted_by_the_service_model(self, tools):
        mock_client = MagicMock()
        mock_client.export_key.return_value = {"WrappedKey": {}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["export_key"](
                export_key_identifier="arn:aws:payment-cryptography:us-east-1:1:key/abc",
                key_material={
                    "Tr34KeyBlock": {
                        "CertificateAuthorityPublicKeyIdentifier": "alias/ca",
                        "WrappingKeyCertificate": "Zm9v",
                        "KeyBlockFormat": "X9_TR34_2012",
                    }
                },
            )
        assert_params_valid(
            "payment-cryptography", "ExportKey", mock_client.export_key.call_args.kwargs
        )

    def test_export_attributes_are_forwarded_and_valid(self, tools):
        mock_client = MagicMock()
        mock_client.export_key.return_value = {"WrappedKey": {}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["export_key"](
                export_key_identifier="alias/bdk-2026",
                key_material={"Tr31KeyBlock": {"WrappingKeyIdentifier": "alias/kbpk"}},
                export_attributes={"KeyCheckValueAlgorithm": "CMAC"},
            )
        params = mock_client.export_key.call_args.kwargs
        assert params["ExportAttributes"] == {"KeyCheckValueAlgorithm": "CMAC"}
        assert_params_valid("payment-cryptography", "ExportKey", params)


# ── import/export token reuse ─────────────────────────────────────────────────

class TestTokenReuse:
    def test_import_params_omit_reuse_flag_by_default(self, tools):
        mock_client = MagicMock()
        mock_client.get_parameters_for_import.return_value = {"ImportToken": "t"}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["get_parameters_for_import"](
                key_material_type="KEY_CRYPTOGRAM", wrapping_key_algorithm="RSA_4096"
            )
        params = mock_client.get_parameters_for_import.call_args.kwargs
        assert "ReuseLastGeneratedToken" not in params
        assert_params_valid("payment-cryptography", "GetParametersForImport", params)

    def test_import_params_forward_reuse_flag(self, tools):
        mock_client = MagicMock()
        mock_client.get_parameters_for_import.return_value = {"ImportToken": "t"}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["get_parameters_for_import"](
                key_material_type="KEY_CRYPTOGRAM",
                wrapping_key_algorithm="RSA_4096",
                reuse_last_generated_token=True,
            )
        params = mock_client.get_parameters_for_import.call_args.kwargs
        assert params["ReuseLastGeneratedToken"] is True
        assert_params_valid("payment-cryptography", "GetParametersForImport", params)

    def test_export_params_forward_reuse_flag(self, tools):
        mock_client = MagicMock()
        mock_client.get_parameters_for_export.return_value = {"ExportToken": "t"}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["get_parameters_for_export"](
                key_material_type="Tr34KeyBlock",
                signing_key_algorithm="RSA_4096",
                reuse_last_generated_token=True,
            )
        params = mock_client.get_parameters_for_export.call_args.kwargs
        assert params["ReuseLastGeneratedToken"] is True
        assert_params_valid("payment-cryptography", "GetParametersForExport", params)

    def test_create_key_forwards_derive_key_usage(self, tools):
        mock_client = MagicMock()
        mock_client.create_key.return_value = {"Key": {"KeyArn": "arn:..."}}
        with patch("apc_agent.control_plane.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_client
            tools["create_key"](
                key_algorithm="AES_128",
                key_usage="TR31_B0_BASE_DERIVATION_KEY",
                key_class="SYMMETRIC_KEY",
                exportable=True,
                key_check_value_algorithm="CMAC",
                derive_key_usage="TR31_P0_PIN_ENCRYPTION_KEY",
            )
        params = mock_client.create_key.call_args.kwargs
        assert params["DeriveKeyUsage"] == "TR31_P0_PIN_ENCRYPTION_KEY"
        assert_params_valid("payment-cryptography", "CreateKey", params)
