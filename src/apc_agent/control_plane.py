"""APC control plane MCP tools — key lifecycle management."""

import boto3
from mcp.server.fastmcp import FastMCP

from .compliance import (
    get_key_usage_info,
    list_key_usages,
)


def register_control_plane_tools(mcp: FastMCP) -> None:

    def client():
        return boto3.client("payment-cryptography")

    # ── Key Management ────────────────────────────────────────────────────────

    @mcp.tool()
    def create_key(
        key_algorithm: str,
        key_usage: str,
        key_class: str,
        exportable: bool,
        enabled: bool = True,
        key_check_value_algorithm: str | None = None,
        tags: list[dict] | None = None,
    ) -> dict:
        """
        Create a new APC key.

        Args:
            key_algorithm: e.g. AES_128, AES_256, TDES_3KEY, RSA_2048
            key_usage: TR-31 key usage code, e.g. TR31_P0_PIN_ENCRYPTION_KEY
            key_class: SYMMETRIC_KEY, ASYMMETRIC_KEY_PAIR, or PRIVATE_KEY
            exportable: Whether the key can be exported
            enabled: Whether the key is immediately active
            key_check_value_algorithm: CMAC or ANSI_X9_24 (TDES only; AES must use CMAC)
            tags: Optional list of {Key, Value} tag dicts
        """
        usage_info = get_key_usage_info(key_usage)
        if usage_info is None:
            return {
                "error": f"Unknown key usage code: {key_usage}",
                "valid_codes": [entry["code"] for entry in list_key_usages()],
            }

        # AES keys must use CMAC for KCV — enforce per PCI PIN Annex C
        if "AES" in key_algorithm and key_check_value_algorithm == "ANSI_X9_24":
            return {
                "error": (
                    "AES keys must use CMAC for key check value calculation, not ANSI_X9_24 "
                    "(ECB-zeros method). This is required by PCI PIN v3.1 Annex C. "
                    "Set key_check_value_algorithm to 'CMAC'."
                ),
                "pci_requirement": "Annex C",
            }

        params: dict = {
            "KeyAttributes": {
                "KeyAlgorithm": key_algorithm,
                "KeyUsage": key_usage,
                "KeyClass": key_class,
                "KeyModesOfUse": _default_modes_of_use(key_usage),
            },
            "Exportable": exportable,
            "Enabled": enabled,
        }
        if key_check_value_algorithm:
            params["KeyCheckValueAlgorithm"] = key_check_value_algorithm
        if tags:
            params["Tags"] = tags

        return client().create_key(**params)

    @mcp.tool()
    def get_key(key_identifier: str) -> dict:
        """
        Retrieve metadata for a key by ARN or alias.

        Args:
            key_identifier: Key ARN (arn:aws:payment-cryptography:...) or alias (alias/name)
        """
        return client().get_key(KeyIdentifier=key_identifier)

    @mcp.tool()
    def list_keys(
        key_state: str | None = None,
        max_results: int = 100,
        next_token: str | None = None,
    ) -> dict:
        """
        List APC keys with optional state filter.

        Args:
            key_state: CREATE_COMPLETE, CREATE_IN_PROGRESS, DELETE_PENDING, DELETE_COMPLETE
            max_results: Max keys to return (1-100)
            next_token: Pagination token from a previous response
        """
        params: dict = {"MaxResults": max_results}
        if key_state:
            params["KeyState"] = key_state
        if next_token:
            params["NextToken"] = next_token
        return client().list_keys(**params)

    @mcp.tool()
    def delete_key(key_identifier: str, delete_key_in_days: int = 7) -> dict:
        """
        Schedule a key for deletion.

        Args:
            key_identifier: Key ARN or alias
            delete_key_in_days: Waiting period before deletion (3-180 days, default 7)
        """
        return client().delete_key(
            KeyIdentifier=key_identifier,
            DeleteKeyInDays=delete_key_in_days,
        )

    @mcp.tool()
    def restore_key(key_identifier: str) -> dict:
        """
        Cancel a pending key deletion.

        Args:
            key_identifier: Key ARN or alias in DELETE_PENDING state
        """
        return client().restore_key(KeyIdentifier=key_identifier)

    @mcp.tool()
    def start_key_usage(key_identifier: str) -> dict:
        """
        Activate a key that was created in disabled state.

        Args:
            key_identifier: Key ARN or alias
        """
        return client().start_key_usage(KeyIdentifier=key_identifier)

    @mcp.tool()
    def stop_key_usage(key_identifier: str) -> dict:
        """
        Deactivate a key without deleting it.

        Args:
            key_identifier: Key ARN or alias
        """
        return client().stop_key_usage(KeyIdentifier=key_identifier)

    # ── Alias Management ──────────────────────────────────────────────────────

    @mcp.tool()
    def create_alias(alias_name: str, key_arn: str | None = None) -> dict:
        """
        Create a friendly-name alias for a key.

        Args:
            alias_name: Must start with 'alias/' — e.g. alias/prod-bdk
            key_arn: Key ARN to associate (optional at creation time)
        """
        params: dict = {"AliasName": alias_name}
        if key_arn:
            params["KeyArn"] = key_arn
        return client().create_alias(**params)

    @mcp.tool()
    def get_alias(alias_name: str) -> dict:
        """
        Retrieve alias details.

        Args:
            alias_name: Full alias name including 'alias/' prefix
        """
        return client().get_alias(AliasName=alias_name)

    @mcp.tool()
    def update_alias(alias_name: str, key_arn: str) -> dict:
        """
        Point an alias to a different key (enables key rotation without code changes).

        Args:
            alias_name: Full alias name including 'alias/' prefix
            key_arn: New key ARN to associate
        """
        return client().update_alias(AliasName=alias_name, KeyArn=key_arn)

    @mcp.tool()
    def delete_alias(alias_name: str) -> dict:
        """
        Delete an alias (does not delete the underlying key).

        Args:
            alias_name: Full alias name including 'alias/' prefix
        """
        return client().delete_alias(AliasName=alias_name)

    @mcp.tool()
    def list_aliases(
        key_arn: str | None = None,
        max_results: int = 100,
        next_token: str | None = None,
    ) -> dict:
        """
        List aliases, optionally filtered by key ARN.

        Args:
            key_arn: Filter to aliases associated with this key
            max_results: Max results (1-100)
            next_token: Pagination token
        """
        params: dict = {"MaxResults": max_results}
        if key_arn:
            params["KeyArn"] = key_arn
        if next_token:
            params["NextToken"] = next_token
        return client().list_aliases(**params)

    # ── Key Import / Export ───────────────────────────────────────────────────

    @mcp.tool()
    def get_parameters_for_import(
        key_material_type: str,
        wrapping_key_algorithm: str,
    ) -> dict:
        """
        Get APC's public key and import token needed to import a key.
        Use this as the first step in TR-34 or KeyCryptogram key import flows.

        Args:
            key_material_type: KEY_CRYPTOGRAM, Tr34KeyBlock, Tr31KeyBlock,
                               RootCertificatePublicKey, or TrustedCertificatePublicKey
            wrapping_key_algorithm: RSA_2048, RSA_3072, RSA_4096 (for asymmetric flows).
                                    AES-128 requires RSA_3072 or higher (key-strength rule).
        """
        return client().get_parameters_for_import(
            KeyMaterialType=key_material_type,
            WrappingKeyAlgorithm=wrapping_key_algorithm,
        )

    @mcp.tool()
    def get_parameters_for_export(
        key_material_type: str,
        signing_key_algorithm: str,
    ) -> dict:
        """
        Get APC's signing certificate needed to export a key to an external system.
        Use this as the first step in TR-34 key export flows.

        Args:
            key_material_type: Tr31KeyBlock or Tr34KeyBlock
            signing_key_algorithm: RSA_2048, RSA_3072, RSA_4096
        """
        return client().get_parameters_for_export(
            KeyMaterialType=key_material_type,
            SigningKeyAlgorithm=signing_key_algorithm,
        )

    @mcp.tool()
    def import_key(
        key_material: dict,
        key_check_value_algorithm: str | None = None,
        enabled: bool = True,
        tags: list[dict] | None = None,
    ) -> dict:
        """
        Import key material into APC via TR-31 key block or TR-34.
        The key_material dict structure depends on the import method.

        For TR-31 (wrapping an existing key):
          key_material = {
            "Tr31KeyBlock": {
              "WrappingKeyIdentifier": "<ARN or alias of KBPK>",
              "WrappedKeyBlock": "<TR-31 key block string>"
            }
          }

        For TR-34 (distributing a symmetric key using asymmetric techniques):
          key_material = {
            "Tr34KeyBlock": {
              "CertificateAuthorityPublicKeyIdentifier": "<CA key ARN>",
              "ImportToken": "<token from get_parameters_for_import>",
              "KeyBlockFormat": "X9_TR34_2012",
              "WrappingKeyCertificate": "<base64 cert>",
              "SigningKeyCertificate": "<base64 cert>",
              "EncryptedKeyBlock": "<TR-34 key block>"
            }
          }

        Args:
            key_material: Import method and wrapped key material
            key_check_value_algorithm: CMAC (required for AES) or ANSI_X9_24 (TDES only)
            enabled: Activate key immediately after import
            tags: Optional list of {Key, Value} tag dicts
        """
        params: dict = {
            "KeyMaterial": key_material,
            "Enabled": enabled,
        }
        if key_check_value_algorithm:
            params["KeyCheckValueAlgorithm"] = key_check_value_algorithm
        if tags:
            params["Tags"] = tags
        return client().import_key(**params)

    @mcp.tool()
    def export_key(
        key_identifier: str,
        key_material_type: str,
        export_attributes: dict | None = None,
    ) -> dict:
        """
        Export a key from APC wrapped in a TR-31 key block or TR-34 structure.

        Args:
            key_identifier: ARN or alias of the key to export
            key_material_type: Tr31KeyBlock or Tr34KeyBlock
            export_attributes: Export-method-specific parameters (wrapping key, etc.)
        """
        params: dict = {
            "KeyIdentifier": key_identifier,
            "KeyMaterialType": key_material_type,
        }
        if export_attributes:
            params["ExportAttributes"] = export_attributes
        return client().export_key(**params)

    # ── Tags ──────────────────────────────────────────────────────────────────

    @mcp.tool()
    def tag_resource(resource_arn: str, tags: list[dict]) -> dict:
        """
        Add or update tags on an APC key.

        Args:
            resource_arn: Key ARN
            tags: List of {Key, Value} dicts
        """
        return client().tag_resource(ResourceArn=resource_arn, Tags=tags)

    @mcp.tool()
    def untag_resource(resource_arn: str, tag_keys: list[str]) -> dict:
        """
        Remove tags from an APC key.

        Args:
            resource_arn: Key ARN
            tag_keys: List of tag key names to remove
        """
        return client().untag_resource(ResourceArn=resource_arn, TagKeys=tag_keys)

    @mcp.tool()
    def list_tags_for_resource(
        resource_arn: str,
        max_results: int = 100,
        next_token: str | None = None,
    ) -> dict:
        """
        List all tags on an APC key.

        Args:
            resource_arn: Key ARN
            max_results: Max results (1-100)
            next_token: Pagination token
        """
        params: dict = {"ResourceArn": resource_arn, "MaxResults": max_results}
        if next_token:
            params["NextToken"] = next_token
        return client().list_tags_for_resource(**params)

    # ── Resource Policies ─────────────────────────────────────────────────────

    @mcp.tool()
    def put_resource_policy(resource_arn: str, policy: str) -> dict:
        """
        Attach an IAM resource policy to a key.

        Args:
            resource_arn: Key ARN
            policy: JSON policy document string
        """
        return client().put_resource_policy(ResourceArn=resource_arn, Policy=policy)

    @mcp.tool()
    def get_resource_policy(resource_arn: str) -> dict:
        """
        Retrieve the resource policy attached to a key.

        Args:
            resource_arn: Key ARN
        """
        return client().get_resource_policy(ResourceArn=resource_arn)

    @mcp.tool()
    def delete_resource_policy(resource_arn: str) -> dict:
        """
        Remove the resource policy from a key.

        Args:
            resource_arn: Key ARN
        """
        return client().delete_resource_policy(ResourceArn=resource_arn)

    # ── Compliance Helper ─────────────────────────────────────────────────────

    @mcp.tool()
    def explain_key_usage(key_usage: str) -> dict:
        """
        Explain a TR-31 key usage code — what it is, what operations it supports,
        and any compliance considerations.

        Args:
            key_usage: TR-31 key usage code, e.g. TR31_P0_PIN_ENCRYPTION_KEY
        """
        info = get_key_usage_info(key_usage)
        if info is None:
            return {
                "error": f"Unknown key usage: {key_usage}",
                "all_codes": list_key_usages(),
            }
        return info

    @mcp.tool()
    def list_all_key_usages() -> list[dict]:
        """Return all supported TR-31 key usage codes with descriptions."""
        return list_key_usages()


def _default_modes_of_use(key_usage: str) -> dict:
    """Return sensible default modes of use for a given key usage code."""
    # TR-31 prohibits Encrypt+Decrypt as a combined mode — use NoRestrictions instead
    no_restrictions_keys = {
        "TR31_P0_PIN_ENCRYPTION_KEY",
        "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "TR31_D1_ASYMMETRIC_KEY_FOR_DATA_ENCRYPTION",
    }
    mac_keys = {
        "TR31_M0_ISO_16609_MAC_KEY", "TR31_M1_ISO_9797_1_MAC_KEY",
        "TR31_M3_ISO_9797_3_MAC_KEY", "TR31_M6_ISO_9797_5_CMAC_KEY", "TR31_M7_HMAC_KEY",
    }
    generate_verify_keys = {
        "TR31_V1_IBM3624_PIN_VERIFICATION_KEY", "TR31_V2_VISA_PIN_VERIFICATION_KEY",
        "TR31_C0_CARD_VERIFICATION_KEY",
    }
    wrap_unwrap_keys = {
        "TR31_K0_KEY_ENCRYPTION_KEY", "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
    }
    derive_key_keys = {
        "TR31_B0_BASE_DERIVATION_KEY",
        # EMV master keys derive per-card session keys — DeriveKey is the correct mode
        "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
        "TR31_E1_EMV_MKEY_CONFIDENTIALITY",
        "TR31_E2_EMV_MKEY_INTEGRITY",
        "TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS",
        "TR31_E6_EMV_MKEY_OTHER",
    }

    if key_usage in no_restrictions_keys:
        return {"NoRestrictions": True}
    if key_usage in mac_keys:
        return {"Generate": True, "Verify": True}
    if key_usage in generate_verify_keys:
        return {"Generate": True, "Verify": True}
    if key_usage in wrap_unwrap_keys:
        return {"Wrap": True, "Unwrap": True}
    if key_usage in derive_key_keys:
        return {"DeriveKey": True}
    return {"NoRestrictions": True}
