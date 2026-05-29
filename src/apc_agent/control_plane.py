"""APC control plane MCP tools — key lifecycle management."""

import boto3
from botocore.exceptions import ClientError, ParamValidationError
from mcp.server.fastmcp import FastMCP

from .compliance import (
    Severity,
    check_algorithm,
    get_key_usage_info,
    list_key_usages,
)


def _call(method, **kwargs) -> dict:
    try:
        return method(**kwargs)
    except ClientError as e:
        err = e.response["Error"]
        return {"error": err["Message"], "aws_error_code": err["Code"]}
    except ParamValidationError as e:
        return {"error": str(e), "aws_error_code": "ParamValidationError"}
    except Exception as e:
        return {"error": str(e)}


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
        Call this when creating a new cryptographic key — BDK, ZPK, CVK, MAC key, KEK, etc.
        Call explain_key_usage first to confirm the right key usage code — APC keys are
        typed at creation and the type cannot change.

        AES keys must use CMAC for KCV (not ANSI_X9_24). Enforced here.

        Args:
            key_algorithm: AES_128, AES_256, TDES_3KEY, RSA_2048, RSA_3072, RSA_4096, ECC_NIST_P256, etc.
            key_usage: TR-31 key usage code, e.g. TR31_P0_PIN_ENCRYPTION_KEY
            key_class: SYMMETRIC_KEY, ASYMMETRIC_KEY_PAIR, or PRIVATE_KEY
            exportable: Whether the key can be exported via TR-31 or TR-34
            enabled: Whether the key is immediately active (default true)
            key_check_value_algorithm: CMAC (required for AES) or ANSI_X9_24 (TDES only)
            tags: Optional list of {Key, Value} tag dicts
        """
        usage_info = get_key_usage_info(key_usage)
        if usage_info is None:
            return {
                "error": f"Unknown key usage code: {key_usage}",
                "valid_codes": [entry["code"] for entry in list_key_usages()],
            }

        algo_check = check_algorithm(key_algorithm)
        if algo_check and algo_check.severity == Severity.HARD_STOP:
            return {
                "error": algo_check.message,
                "modern_alternative": algo_check.modern_alternative,
                "pci_requirement": algo_check.pci_requirement,
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

        return _call(client().create_key, **params)

    @mcp.tool()
    def get_key(key_identifier: str) -> dict:
        """
        Call this when you need the current state, algorithm, usage, or enabled status
        of a key before using it in an operation.

        Retrieve metadata for a key by ARN or alias.

        Args:
            key_identifier: Key ARN (arn:aws:payment-cryptography:...) or alias (alias/name)
        """
        return _call(client().get_key, KeyIdentifier=key_identifier)

    @mcp.tool()
    def list_keys(
        key_state: str | None = None,
        max_results: int = 100,
        next_token: str | None = None,
    ) -> dict:
        """
        Call this when auditing which keys exist, finding a key ARN, or checking
        key state before an import or operation.

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
        return _call(client().list_keys, **params)

    @mcp.tool()
    def delete_key(key_identifier: str, delete_key_in_days: int = 7) -> dict:
        """
        Call this when decommissioning a test key or retiring a key that is no longer
        needed. Deletion is scheduled — the key enters DELETE_PENDING state first.

        Schedule a key for deletion.

        Args:
            key_identifier: Key ARN or alias
            delete_key_in_days: Waiting period before deletion (3-180 days, default 7)
        """
        return _call(client().delete_key,
            KeyIdentifier=key_identifier,
            DeleteKeyInDays=delete_key_in_days,
        )

    @mcp.tool()
    def restore_key(key_identifier: str) -> dict:
        """
        Call this when a key was scheduled for deletion by mistake and needs to be
        recovered before the waiting period expires.

        Cancel a pending key deletion.

        Args:
            key_identifier: Key ARN or alias in DELETE_PENDING state
        """
        return _call(client().restore_key, KeyIdentifier=key_identifier)

    @mcp.tool()
    def start_key_usage(key_identifier: str) -> dict:
        """
        Call this when enabling a key that was created with enabled=False or that was
        previously disabled with stop_key_usage.

        Activate a key that was created in disabled state.

        Args:
            key_identifier: Key ARN or alias
        """
        return _call(client().start_key_usage, KeyIdentifier=key_identifier)

    @mcp.tool()
    def stop_key_usage(key_identifier: str) -> dict:
        """
        Call this when temporarily disabling a key — for example during key rotation
        before the old key is confirmed unused and can be deleted.

        Deactivate a key without deleting it.

        Args:
            key_identifier: Key ARN or alias
        """
        return _call(client().stop_key_usage, KeyIdentifier=key_identifier)

    # ── Alias Management ──────────────────────────────────────────────────────

    @mcp.tool()
    def create_alias(alias_name: str, key_arn: str | None = None) -> dict:
        """
        Call this when establishing a stable name for a key so application code
        does not need to change when keys are rotated.

        Create a friendly-name alias for a key.

        Args:
            alias_name: Must start with 'alias/' — e.g. alias/prod-bdk
            key_arn: Key ARN to associate (optional at creation time)
        """
        params: dict = {"AliasName": alias_name}
        if key_arn:
            params["KeyArn"] = key_arn
        return _call(client().create_alias, **params)

    @mcp.tool()
    def get_alias(alias_name: str) -> dict:
        """
        Call this when resolving an alias to its key ARN, or verifying which key
        an alias currently points to.

        Retrieve alias details.

        Args:
            alias_name: Full alias name including 'alias/' prefix
        """
        return _call(client().get_alias, AliasName=alias_name)

    @mcp.tool()
    def update_alias(alias_name: str, key_arn: str) -> dict:
        """
        Call this when rotating a key — point the existing alias to the new key ARN
        so application code referencing the alias picks up the rotation automatically.

        Point an alias to a different key (enables key rotation without code changes).

        Args:
            alias_name: Full alias name including 'alias/' prefix
            key_arn: New key ARN to associate
        """
        return _call(client().update_alias, AliasName=alias_name, KeyArn=key_arn)

    @mcp.tool()
    def delete_alias(alias_name: str) -> dict:
        """
        Call this when removing a friendly name that is no longer needed.
        The underlying key is unaffected.

        Delete an alias (does not delete the underlying key).

        Args:
            alias_name: Full alias name including 'alias/' prefix
        """
        return _call(client().delete_alias, AliasName=alias_name)

    @mcp.tool()
    def list_aliases(
        key_arn: str | None = None,
        max_results: int = 100,
        next_token: str | None = None,
    ) -> dict:
        """
        Call this when auditing all friendly names in the account, or finding aliases
        associated with a specific key.

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
        return _call(client().list_aliases, **params)

    # ── Key Import / Export ───────────────────────────────────────────────────

    @mcp.tool()
    def get_parameters_for_import(
        key_material_type: str,
        wrapping_key_algorithm: str,
    ) -> dict:
        """
        Call this before import_key when using TR-34 or KeyCryptogram — you need APC's
        public wrapping key and import token before constructing the import payload.

        AES-128 keys require RSA_3072 or higher wrapping key (key-strength rule enforced by APC).

        Args:
            key_material_type: KEY_CRYPTOGRAM, Tr34KeyBlock, Tr31KeyBlock,
                               RootCertificatePublicKey, or TrustedCertificatePublicKey
            wrapping_key_algorithm: RSA_2048, RSA_3072, or RSA_4096
        """
        return _call(client().get_parameters_for_import,
            KeyMaterialType=key_material_type,
            WrappingKeyAlgorithm=wrapping_key_algorithm,
        )

    @mcp.tool()
    def get_parameters_for_export(
        key_material_type: str,
        signing_key_algorithm: str,
    ) -> dict:
        """
        Call this before export_key when using TR-34 — you need APC's signing certificate
        before constructing the export payload for an external system.

        Args:
            key_material_type: Tr31KeyBlock or Tr34KeyBlock
            signing_key_algorithm: RSA_2048, RSA_3072, RSA_4096
        """
        return _call(client().get_parameters_for_export,
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
        Call this to bring an externally generated key into APC via TR-31 key block or TR-34.
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
        return _call(client().import_key, **params)

    @mcp.tool()
    def export_key(
        key_identifier: str,
        key_material_type: str,
        export_attributes: dict | None = None,
    ) -> dict:
        """
        Call this when distributing an APC-generated key to an external HSM or system,
        wrapped in a TR-31 key block or TR-34 structure.

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
        return _call(client().export_key, **params)

    # ── Tags ──────────────────────────────────────────────────────────────────

    @mcp.tool()
    def tag_resource(resource_arn: str, tags: list[dict]) -> dict:
        """
        Call this when adding classification, environment, or ownership metadata to a key.

        Add or update tags on an APC key.

        Args:
            resource_arn: Key ARN
            tags: List of {Key, Value} dicts
        """
        return _call(client().tag_resource, ResourceArn=resource_arn, Tags=tags)

    @mcp.tool()
    def untag_resource(resource_arn: str, tag_keys: list[str]) -> dict:
        """
        Call this when removing stale or incorrect tags from a key.

        Remove tags from an APC key.

        Args:
            resource_arn: Key ARN
            tag_keys: List of tag key names to remove
        """
        return _call(client().untag_resource, ResourceArn=resource_arn, TagKeys=tag_keys)

    @mcp.tool()
    def list_tags_for_resource(
        resource_arn: str,
        max_results: int = 100,
        next_token: str | None = None,
    ) -> dict:
        """
        Call this when auditing the tags on a key or verifying classification metadata.

        List all tags on an APC key.

        Args:
            resource_arn: Key ARN
            max_results: Max results (1-100)
            next_token: Pagination token
        """
        params: dict = {"ResourceArn": resource_arn, "MaxResults": max_results}
        if next_token:
            params["NextToken"] = next_token
        return _call(client().list_tags_for_resource, **params)

    # ── Resource Policies ─────────────────────────────────────────────────────

    @mcp.tool()
    def put_resource_policy(resource_arn: str, policy: str) -> dict:
        """
        Call this when granting cross-account access to a key or restricting which
        principals may use it.

        Attach an IAM resource policy to a key.

        Args:
            resource_arn: Key ARN
            policy: JSON policy document string
        """
        return _call(client().put_resource_policy, ResourceArn=resource_arn, Policy=policy)

    @mcp.tool()
    def get_resource_policy(resource_arn: str) -> dict:
        """
        Call this when auditing who has access to a key or inspecting a cross-account policy.

        Retrieve the resource policy attached to a key.

        Args:
            resource_arn: Key ARN
        """
        return _call(client().get_resource_policy, ResourceArn=resource_arn)

    @mcp.tool()
    def delete_resource_policy(resource_arn: str) -> dict:
        """
        Call this when revoking all cross-account or resource-based access grants on a key.

        Remove the resource policy from a key.

        Args:
            resource_arn: Key ARN
        """
        return _call(client().delete_resource_policy, ResourceArn=resource_arn)

    # ── Compliance Helper ─────────────────────────────────────────────────────

    @mcp.tool()
    def explain_key_usage(key_usage: str) -> dict:
        """
        Call this whenever a TR-31 key usage code appears or someone asks "which key type
        should I use for X?" — P0, B0, E0, E1, E2, M6, C0, V1, V2, K0, K1, D0, etc.
        Works without AWS credentials.

        Returns what the key type is, what operations it permits, which APC data-plane
        calls accept it, and any PCI compliance considerations.

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
        """
        Call this when designing key infrastructure, selecting key types for a new
        payment operation, or when asked what key types APC supports.
        Works without AWS credentials.

        Returns all TR-31 key usage codes with names, descriptions, and APC support status.
        """
        return list_key_usages()


def _default_modes_of_use(key_usage: str) -> dict:
    """Return sensible default modes of use for a given key usage code."""
    # TR-31 prohibits Encrypt+Decrypt as a combined mode — use NoRestrictions instead
    no_restrictions_keys = {
        "TR31_P0_PIN_ENCRYPTION_KEY",
        "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "TR31_D1_ASYMMETRIC_KEY_FOR_DATA_ENCRYPTION",
    }
    generate_verify_keys = {
        "TR31_M0_ISO_16609_MAC_KEY", "TR31_M1_ISO_9797_1_MAC_KEY",
        "TR31_M3_ISO_9797_3_MAC_KEY", "TR31_M6_ISO_9797_5_CMAC_KEY", "TR31_M7_HMAC_KEY",
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
    if key_usage in generate_verify_keys:
        return {"Generate": True, "Verify": True}
    if key_usage in wrap_unwrap_keys:
        return {"Wrap": True, "Unwrap": True}
    if key_usage in derive_key_keys:
        return {"DeriveKey": True}
    return {"NoRestrictions": True}
