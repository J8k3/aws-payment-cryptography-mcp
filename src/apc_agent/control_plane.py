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
        replication_regions: list[str] | None = None,
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
            replication_regions: Optional list of regions to replicate this key into, e.g.
                ["us-west-2", "eu-west-1"]. Omit to use the account default (see
                get_default_key_replication_regions). Replication is a property of the key,
                so set it here or via add_key_replication_regions afterwards.
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
        if replication_regions:
            params["ReplicationRegions"] = replication_regions

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

    # ── Key Replication ───────────────────────────────────────────────────────

    @mcp.tool()
    def add_key_replication_regions(key_identifier: str, replication_regions: list[str]) -> dict:
        """
        Call this to make an existing key usable from additional regions — e.g. standing up
        a DR region, or moving an acquirer workload closer to the processor.

        Replication copies the key into the named regions so cryptographic calls can be
        served there. It does not export key material: the key never leaves APC's HSMs,
        and the replica keeps the same key ARN semantics and usage restrictions.

        Args:
            key_identifier: ARN or alias of the key
            replication_regions: Regions to add, e.g. ["us-west-2", "eu-west-1"]
        """
        return _call(client().add_key_replication_regions,
                     KeyIdentifier=key_identifier, ReplicationRegions=replication_regions)

    @mcp.tool()
    def remove_key_replication_regions(key_identifier: str, replication_regions: list[str]) -> dict:
        """
        Call this when decommissioning a region or narrowing a key's blast radius.

        Removing a region makes the key unusable there. Confirm nothing is still
        authorizing against it in that region first — in-flight PIN or ARQC traffic will
        start failing as soon as the replica is gone.

        Args:
            key_identifier: ARN or alias of the key
            replication_regions: Regions to remove, e.g. ["eu-west-1"]
        """
        return _call(client().remove_key_replication_regions,
                     KeyIdentifier=key_identifier, ReplicationRegions=replication_regions)

    @mcp.tool()
    def get_default_key_replication_regions() -> dict:
        """
        Call this to see which regions new keys replicate into by default, before creating
        keys or when auditing why a key landed in a region you did not expect.

        Keys created or imported without an explicit replication_regions inherit this
        account-level default.
        """
        return _call(client().get_default_key_replication_regions)

    @mcp.tool()
    def enable_default_key_replication_regions(replication_regions: list[str]) -> dict:
        """
        Call this to add regions to the account-wide default, so subsequently created keys
        replicate there automatically.

        This is account-level and affects future keys only — it does not retroactively
        replicate existing keys. Use add_key_replication_regions for keys that already exist.

        Args:
            replication_regions: Regions to enable by default, e.g. ["us-west-2"]
        """
        return _call(client().enable_default_key_replication_regions,
                     ReplicationRegions=replication_regions)

    @mcp.tool()
    def disable_default_key_replication_regions(replication_regions: list[str]) -> dict:
        """
        Call this to stop new keys from automatically replicating into the named regions.

        Account-level and forward-looking only: existing keys keep whatever replication
        they already have. Use remove_key_replication_regions to change those.

        Args:
            replication_regions: Regions to remove from the default, e.g. ["eu-west-1"]
        """
        return _call(client().disable_default_key_replication_regions,
                     ReplicationRegions=replication_regions)

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

        Key-strength rules enforced by APC (wrapping key strength ≥ working key strength):
          AES-128 (128-bit): RSA_3072 (~128-bit) or RSA_4096 (~140-bit) — both acceptable.
          AES-256 (256-bit): RSA of any size is too weak (~140-bit max for RSA_4096).
                             Use ECC_NIST_P521 (~261-bit) — the only KEY_CRYPTOGRAM path for AES-256.
          TDES (112-bit):    RSA_2048 (~112-bit) or higher.

        For AES-256 keys (E0, E1, E2, E4, E6, D0 at 256-bit, M6 at 256-bit):
          wrapping_key_algorithm must be ECC_NIST_P521.
          Attempting RSA_2048/RSA_3072/RSA_4096 with an AES-256 key will fail.
          Alternative: use create_key (APC generates the key material — no import needed,
          but the key value is not externally known, so cross-system test vectors are not possible).

        Args:
            key_material_type: KEY_CRYPTOGRAM, Tr34KeyBlock, Tr31KeyBlock,
                               RootCertificatePublicKey, or TrustedCertificatePublicKey
            wrapping_key_algorithm: RSA_2048, RSA_3072, RSA_4096, or ECC_NIST_P521 (required for AES-256)
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
        replication_regions: list[str] | None = None,
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
            replication_regions: Optional list of regions to replicate the imported key into.
                Omit to use the account default (see get_default_key_replication_regions).
        """
        params: dict = {
            "KeyMaterial": key_material,
            "Enabled": enabled,
        }
        if key_check_value_algorithm:
            params["KeyCheckValueAlgorithm"] = key_check_value_algorithm
        if tags:
            params["Tags"] = tags
        if replication_regions:
            params["ReplicationRegions"] = replication_regions
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

    # ── Certificates ──────────────────────────────────────────────────────────

    @mcp.tool()
    def get_certificate_signing_request(
        key_identifier: str,
        signing_algorithm: str,
        certificate_subject: dict,
    ) -> dict:
        """
        Call this to get a PKCS #10 CSR for an APC-held asymmetric key, so an external CA
        (or a partner's PKI) can issue a certificate for it. This is the APC counterpart of
        the payShield/Futurex "generate certificate request" commands — Futurex RSAR, for
        instance, is a PKCS #10 CSR generator.

        The private key stays in APC's HSMs; only the CSR leaves. Typical use is TR-34 key
        distribution or ECDH key exchange, where the counterparty must trust an APC key.

        Args:
            key_identifier: ARN or alias of the asymmetric key (RSA or ECC) to request a
                certificate for
            signing_algorithm: Hash used to sign the CSR — SHA224, SHA256, SHA384, or SHA512
            certificate_subject: X.509 subject. CommonName is required; OrganizationUnit,
                Organization, City, Country, StateOrProvince and EmailAddress are optional:
                  {"CommonName": "acquirer-tr34-2026",
                   "Organization": "Example Bank",
                   "Country": "US"}
        """
        return _call(client().get_certificate_signing_request,
                     KeyIdentifier=key_identifier,
                     SigningAlgorithm=signing_algorithm,
                     CertificateSubject=certificate_subject)

    @mcp.tool()
    def get_public_key_certificate(key_identifier: str) -> dict:
        """
        Call this to fetch the certificate and chain for an APC asymmetric key — to hand a
        counterparty the public half for TR-34 or ECDH key exchange, or to check what APC
        currently holds for a key.

        Returns KeyCertificate and KeyCertificateChain, both base64-encoded. Public material
        only; no private key is ever returned.

        Args:
            key_identifier: ARN or alias of the asymmetric key
        """
        return _call(client().get_public_key_certificate, KeyIdentifier=key_identifier)

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
    # APC KeyModesOfUse uses NoRestrictions for keys that need both Encrypt and Decrypt
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
