"""
Unit tests for hsm_analysis.py pattern recognition.
No AWS calls -- all pure Python.
"""
from apc_agent.hsm_analysis import (
    ALL_COMMANDS,
    HsmCommand,
    get_apc_mapping,
    list_commands_by_category,
    list_commands_by_vendor,
    lookup_command,
)


class TestLookupCommand:
    def test_known_futurex_excrypt_command(self):
        results = lookup_command("TPIN")
        assert len(results) > 0
        assert all(isinstance(r, HsmCommand) for r in results)

    def test_lookup_is_case_insensitive(self):
        upper = lookup_command("TPIN")
        lower = lookup_command("tpin")
        assert len(upper) == len(lower)
        assert upper[0].command_code == lower[0].command_code

    def test_unknown_command_returns_empty_list(self):
        assert lookup_command("ZZZNOTACOMMAND") == []

    def test_thales_ca_command_known(self):
        assert len(lookup_command("CA")) > 0

    def test_tpin_maps_to_translate_pin_data(self):
        results = lookup_command("TPIN")
        assert "translate_pin_data" in {r.apc_operation for r in results}

    def test_vpin_maps_to_verify_pin_data(self):
        results = lookup_command("VPIN")
        assert "verify_pin_data" in {r.apc_operation for r in results}


class TestGetApcMapping:
    def test_known_command_returns_matches(self):
        result = get_apc_mapping("TPIN")
        assert "matches" in result and len(result["matches"]) > 0

    def test_unknown_command_returns_error(self):
        assert "error" in get_apc_mapping("NOTACOMMAND")

    def test_match_has_required_fields(self):
        match = get_apc_mapping("TPIN")["matches"][0]
        required = {"vendor", "api", "command_code", "name", "category",
                    "apc_operation", "apc_key_type", "confidence"}
        assert required <= match.keys()

    def test_dukpt_command_includes_migration_note(self):
        result = get_apc_mapping("CI")
        if "matches" in result:
            assert "migration_note" in result["matches"][0]

    def test_cc_command_includes_fixed_key_migration_note(self):
        result = get_apc_mapping("CC")
        if "matches" in result:
            assert "migration_note" in result["matches"][0]

    def test_lmk_command_includes_lmk_migration_note(self):
        result = get_apc_mapping("JC")
        if "matches" in result:
            assert "migration_note" in result["matches"][0]

    def test_confidence_field_is_valid_value(self):
        for match in get_apc_mapping("TPIN")["matches"]:
            assert match["confidence"] in ("high", "medium", "directory")


class TestListCommandsByCategory:
    def test_pin_category_is_nonempty(self):
        assert len(list_commands_by_category("PIN")) > 0

    def test_mac_category_is_nonempty(self):
        assert len(list_commands_by_category("MAC")) > 0

    def test_cvv_category_is_nonempty(self):
        assert len(list_commands_by_category("CVV")) > 0

    def test_key_mgmt_category_is_nonempty(self):
        assert len(list_commands_by_category("KEY_MGMT")) > 0

    def test_category_lookup_is_case_insensitive(self):
        assert len(list_commands_by_category("PIN")) == len(list_commands_by_category("pin"))

    def test_unknown_category_returns_empty(self):
        assert list_commands_by_category("MADE_UP_CATEGORY") == []

    def test_each_result_has_required_fields(self):
        for r in list_commands_by_category("PIN"):
            assert "vendor" in r and "code" in r and "name" in r


class TestListCommandsByVendor:
    def test_futurex_commands_present(self):
        assert len(list_commands_by_vendor("Futurex")) > 0

    def test_thales_commands_present(self):
        assert len(list_commands_by_vendor("Thales")) > 0

    def test_unknown_vendor_returns_empty(self):
        assert list_commands_by_vendor("Utimaco") == []

    def test_vendor_lookup_is_case_insensitive(self):
        assert len(list_commands_by_vendor("Futurex")) == len(list_commands_by_vendor("futurex"))

    def test_each_result_has_required_fields(self):
        for r in list_commands_by_vendor("Futurex"):
            assert "api" in r and "code" in r and "name" in r


class TestCommandRegistry:
    def test_all_commands_is_nonempty(self):
        assert len(ALL_COMMANDS) > 0

    def test_all_commands_are_hsm_command_instances(self):
        assert all(isinstance(c, HsmCommand) for c in ALL_COMMANDS)

    def test_all_commands_have_vendor(self):
        for c in ALL_COMMANDS:
            assert c.vendor, f"Command {c.command_code} missing vendor"

    def test_all_commands_have_valid_category(self):
        valid = {"PIN", "MAC", "CVV", "KEY_MGMT", "ENCRYPT", "ARQC", "P2PE"}
        for c in ALL_COMMANDS:
            assert c.category.upper() in valid, f"{c.command_code}: bad category {c.category}"

    def test_commands_with_no_apc_equivalent_have_notes(self):
        for c in ALL_COMMANDS:
            if c.apc_operation is None:
                assert c.notes, f"{c.command_code} has no APC mapping and no notes"

    def test_confidence_values_are_valid(self):
        valid = {"high", "medium", "directory"}
        for c in ALL_COMMANDS:
            assert c.confidence in valid, f"{c.command_code}: bad confidence '{c.confidence}'"

    def test_futurex_excrypt_tpin_is_high_confidence(self):
        results = [c for c in ALL_COMMANDS if c.command_code == "TPIN" and c.api == "Excrypt"]
        assert len(results) > 0
        assert all(c.confidence == "high" for c in results)
