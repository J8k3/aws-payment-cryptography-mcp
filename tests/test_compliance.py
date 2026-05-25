"""
Unit tests for compliance.py guard-rail logic.
No AWS calls — all pure Python.
"""

import pytest

from apc_agent.compliance import (
    Severity,
    check_algorithm,
    check_key_operation_compatibility,
    check_legacy_construct,
    check_pin_format_translation,
    format_legacy_constraint_prompt,
    get_key_usage_info,
    list_key_usages,
)

# ── check_algorithm ───────────────────────────────────────────────────────────

class TestCheckAlgorithm:
    def test_single_des_is_hard_stop(self):
        result = check_algorithm("DES")
        assert result is not None
        assert result.severity == Severity.HARD_STOP

    def test_rsa_1024_is_hard_stop(self):
        result = check_algorithm("RSA_1024")
        assert result is not None
        assert result.severity == Severity.HARD_STOP

    def test_tdes_2key_is_hard_stop(self):
        result = check_algorithm("TDES_2KEY")
        assert result is not None
        assert result.severity == Severity.HARD_STOP

    def test_aes_128_is_permitted(self):
        assert check_algorithm("AES_128") is None

    def test_aes_256_is_permitted(self):
        assert check_algorithm("AES_256") is None

    def test_tdes_3key_is_permitted(self):
        assert check_algorithm("TDES_3KEY") is None

    def test_rsa_2048_is_permitted(self):
        assert check_algorithm("RSA_2048") is None

    def test_unknown_algorithm_is_permitted(self):
        assert check_algorithm("SOME_FUTURE_ALGO") is None

    def test_hard_stop_has_modern_alternative(self):
        result = check_algorithm("DES")
        assert result.modern_alternative is not None and len(result.modern_alternative) > 0

    def test_hard_stop_has_pci_requirement(self):
        for algo in ("DES", "RSA_1024", "TDES_2KEY"):
            result = check_algorithm(algo)
            assert result.pci_requirement is not None, f"{algo} missing pci_requirement"


# ── check_legacy_construct ────────────────────────────────────────────────────

class TestCheckLegacyConstruct:
    def test_fixed_tdes_pin_key_is_hard_stop(self):
        result = check_legacy_construct("TDES_FIXED_KEY_PIN")
        assert result is not None
        assert result.severity == Severity.HARD_STOP

    def test_tdes_new_deployment_is_warning(self):
        result = check_legacy_construct("TDES_NEW_DEPLOYMENT")
        assert result is not None
        assert result.severity == Severity.WARNING

    def test_pin_format_0_is_warning(self):
        result = check_legacy_construct("PIN_FORMAT_0")
        assert result is not None
        assert result.severity == Severity.WARNING

    def test_pin_format_0_requires_qsa_exception(self):
        result = check_legacy_construct("PIN_FORMAT_0")
        assert result.requires_qsa_exception is True

    def test_pin_format_1_is_warning(self):
        result = check_legacy_construct("PIN_FORMAT_1")
        assert result is not None
        assert result.severity == Severity.WARNING

    def test_pin_format_3_is_warning(self):
        result = check_legacy_construct("PIN_FORMAT_3")
        assert result is not None
        assert result.severity == Severity.WARNING

    def test_cbc_mac_is_warning(self):
        result = check_legacy_construct("CBC_MAC")
        assert result is not None
        assert result.severity == Severity.WARNING

    def test_retail_mac_is_warning(self):
        result = check_legacy_construct("RETAIL_MAC")
        assert result is not None
        assert result.severity == Severity.WARNING

    def test_tdes_dukpt_is_warning(self):
        result = check_legacy_construct("TDES_DUKPT")
        assert result is not None
        assert result.severity == Severity.WARNING

    def test_rsa_wrap_is_warning(self):
        result = check_legacy_construct("RSA_WRAP")
        assert result is not None
        assert result.severity == Severity.WARNING

    def test_unknown_construct_returns_none(self):
        assert check_legacy_construct("SOMETHING_FINE") is None

    def test_all_warnings_have_modern_alternatives(self):
        constructs = [
            "TDES_NEW_DEPLOYMENT", "PIN_FORMAT_0", "PIN_FORMAT_1",
            "PIN_FORMAT_3", "CBC_MAC", "RETAIL_MAC", "TDES_DUKPT", "RSA_WRAP",
        ]
        for c in constructs:
            result = check_legacy_construct(c)
            assert result.modern_alternative, f"{c} missing modern_alternative"


# ── check_key_operation_compatibility ────────────────────────────────────────

class TestCheckKeyOperationCompatibility:
    def test_pin_key_used_for_translate_pin_is_ok(self):
        result = check_key_operation_compatibility(
            "TR31_P0_PIN_ENCRYPTION_KEY", "translate_pin_data"
        )
        assert result is None

    def test_pin_key_used_for_generate_pin_is_ok(self):
        result = check_key_operation_compatibility(
            "TR31_P0_PIN_ENCRYPTION_KEY", "generate_pin_data"
        )
        assert result is None

    def test_pin_key_used_for_encrypt_data_is_hard_stop(self):
        result = check_key_operation_compatibility(
            "TR31_P0_PIN_ENCRYPTION_KEY", "encrypt_data"
        )
        assert result is not None
        assert result.severity == Severity.HARD_STOP

    def test_cvk_used_for_cvv_generate_is_ok(self):
        result = check_key_operation_compatibility(
            "TR31_C0_CARD_VERIFICATION_KEY", "generate_card_validation_data"
        )
        assert result is None

    def test_cvk_used_for_pin_translate_is_hard_stop(self):
        result = check_key_operation_compatibility(
            "TR31_C0_CARD_VERIFICATION_KEY", "translate_pin_data"
        )
        assert result is not None
        assert result.severity == Severity.HARD_STOP

    def test_mac_key_used_for_generate_mac_is_ok(self):
        result = check_key_operation_compatibility(
            "TR31_M6_ISO_9797_5_CMAC_KEY", "generate_mac"
        )
        assert result is None

    def test_mac_key_used_for_encrypt_data_is_hard_stop(self):
        result = check_key_operation_compatibility(
            "TR31_M6_ISO_9797_5_CMAC_KEY", "encrypt_data"
        )
        assert result is not None
        assert result.severity == Severity.HARD_STOP

    def test_kek_used_for_import_is_ok(self):
        result = check_key_operation_compatibility(
            "TR31_K1_KEY_BLOCK_PROTECTION_KEY", "import_key"
        )
        assert result is None

    def test_kek_used_for_encrypt_is_hard_stop(self):
        result = check_key_operation_compatibility(
            "TR31_K1_KEY_BLOCK_PROTECTION_KEY", "encrypt_data"
        )
        assert result is not None
        assert result.severity == Severity.HARD_STOP

    def test_bdk_used_for_translate_pin_is_ok(self):
        result = check_key_operation_compatibility(
            "TR31_B0_BASE_DERIVATION_KEY", "translate_pin_data"
        )
        assert result is None

    def test_unknown_key_usage_returns_none(self):
        result = check_key_operation_compatibility(
            "TR31_UNKNOWN_FUTURE_CODE", "encrypt_data"
        )
        assert result is None

    def test_mismatch_error_message_names_allowed_operations(self):
        result = check_key_operation_compatibility(
            "TR31_C0_CARD_VERIFICATION_KEY", "encrypt_data"
        )
        assert "generate_card_validation_data" in result.message or "allowed" in result.message.lower()

    def test_mismatch_has_pci_requirement(self):
        result = check_key_operation_compatibility(
            "TR31_P0_PIN_ENCRYPTION_KEY", "encrypt_data"
        )
        assert result.pci_requirement is not None


# ── check_pin_format_translation ──────────────────────────────────────────────

class TestCheckPinFormatTranslation:
    @pytest.mark.parametrize("src,dst", [
        ("IsoFormat0", "IsoFormat0"),
        ("IsoFormat0", "IsoFormat3"),
        ("IsoFormat0", "IsoFormat4"),
        ("IsoFormat1", "IsoFormat0"),
        ("IsoFormat1", "IsoFormat3"),
        ("IsoFormat1", "IsoFormat4"),
        ("IsoFormat3", "IsoFormat0"),
        ("IsoFormat3", "IsoFormat3"),
        ("IsoFormat3", "IsoFormat4"),
        ("IsoFormat4", "IsoFormat0"),
        ("IsoFormat4", "IsoFormat3"),
        ("IsoFormat4", "IsoFormat4"),
    ])
    def test_permitted_translations_return_none(self, src, dst):
        assert check_pin_format_translation(src, dst) is None

    @pytest.mark.parametrize("src,dst", [
        ("IsoFormat0", "IsoFormat1"),
        ("IsoFormat0", "IsoFormat2"),
        ("IsoFormat1", "IsoFormat1"),
        ("IsoFormat3", "IsoFormat1"),
        ("IsoFormat3", "IsoFormat2"),
        ("IsoFormat4", "IsoFormat1"),
        ("IsoFormat4", "IsoFormat2"),
    ])
    def test_prohibited_translations_return_hard_stop(self, src, dst):
        result = check_pin_format_translation(src, dst)
        assert result is not None
        assert result.severity == Severity.HARD_STOP, f"{src} → {dst} should be HARD_STOP"

    def test_prohibited_result_has_pci_requirement(self):
        result = check_pin_format_translation("IsoFormat0", "IsoFormat1")
        assert result.pci_requirement is not None

    def test_unknown_format_pair_returns_none(self):
        # Unregistered pairs are not explicitly prohibited
        assert check_pin_format_translation("IsoFormat9", "IsoFormat4") is None


# ── key usage registry helpers ────────────────────────────────────────────────

class TestKeyUsageRegistry:
    def test_known_usage_returns_info(self):
        info = get_key_usage_info("TR31_P0_PIN_ENCRYPTION_KEY")
        assert info is not None
        assert "allowed_operations" in info
        assert "name" in info

    def test_unknown_usage_returns_none(self):
        assert get_key_usage_info("TR31_XX_MADE_UP") is None

    def test_list_key_usages_is_nonempty(self):
        usages = list_key_usages()
        assert len(usages) > 0

    def test_list_key_usages_includes_required_codes(self):
        codes = {u["code"] for u in list_key_usages()}
        required = {
            "TR31_P0_PIN_ENCRYPTION_KEY",
            "TR31_B0_BASE_DERIVATION_KEY",
            "TR31_C0_CARD_VERIFICATION_KEY",
            "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
            "TR31_M6_ISO_9797_5_CMAC_KEY",
            "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        }
        assert required <= codes

    def test_each_usage_has_allowed_operations(self):
        for usage in list_key_usages():
            assert "allowed_operations" in usage
            assert len(usage["allowed_operations"]) > 0, f"{usage['code']} has no allowed_operations"


# ── format_legacy_constraint_prompt ──────────────────────────────────────────

class TestFormatLegacyConstraintPrompt:
    def test_interpolates_modern_alternative(self):
        prompt = format_legacy_constraint_prompt("AES DUKPT")
        assert "AES DUKPT" in prompt

    def test_mentions_qsa(self):
        prompt = format_legacy_constraint_prompt("AES DUKPT")
        assert "QSA" in prompt

    def test_returns_nonempty_string(self):
        prompt = format_legacy_constraint_prompt("ISO Format 4")
        assert isinstance(prompt, str) and len(prompt) > 50
