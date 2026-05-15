"""
Tests for the HSM MCP tool layer (hsm_tools.py).

Uses a minimal FastMCP stand-in to capture registered tool functions without
starting an MCP server, then calls them directly to catch interface mismatches
between hsm_tools.py and hsm_analysis.py.
"""
import json
import pytest
from apc_agent.hsm_tools import register_hsm_tools


class _CaptureMCP:
    """Minimal stand-in for FastMCP that captures @mcp.tool()-decorated functions."""

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
    register_hsm_tools(mcp)
    return mcp._tools


# ── hsm_lookup_command ────────────────────────────────────────────────────────

class TestHsmLookupCommand:
    def test_known_futurex_command_found(self, tools):
        result = tools["hsm_lookup_command"](command_code="TPIN")
        assert result["found"] is True
        assert len(result["matches"]) > 0

    def test_result_has_required_fields(self, tools):
        match = tools["hsm_lookup_command"](command_code="TPIN")["matches"][0]
        for field in ("vendor", "api", "command_code", "name", "category",
                      "apc_operation", "apc_key_type", "confidence"):
            assert field in match, f"missing field: {field}"

    def test_known_thales_command_found(self, tools):
        result = tools["hsm_lookup_command"](command_code="CA")
        assert result["found"] is True

    def test_unknown_command_not_found(self, tools):
        result = tools["hsm_lookup_command"](command_code="ZZZNOTREAL")
        assert result["found"] is False
        assert "message" in result

    def test_api_filter_narrows_results(self, tools):
        all_results = tools["hsm_lookup_command"](command_code="TPIN")
        filtered = tools["hsm_lookup_command"](command_code="TPIN", api="Excrypt")
        assert filtered["found"] is True
        assert len(filtered["matches"]) <= len(all_results["matches"])
        assert all(m["api"].lower() == "excrypt" for m in filtered["matches"])

    def test_api_filter_unknown_api_returns_not_found(self, tools):
        result = tools["hsm_lookup_command"](command_code="TPIN", api="NoSuchAPI")
        assert result["found"] is False

    def test_case_insensitive(self, tools):
        upper = tools["hsm_lookup_command"](command_code="TPIN")
        lower = tools["hsm_lookup_command"](command_code="tpin")
        assert upper["found"] == lower["found"]


# ── hsm_get_apc_mapping ───────────────────────────────────────────────────────

class TestHsmGetApcMapping:
    def test_known_command_returns_mapping(self, tools):
        result = tools["hsm_get_apc_mapping"](command_code="TPIN")
        assert result["found"] is True
        assert "apc_operation" in result
        assert "apc_key_type" in result

    def test_tpin_maps_to_translate_pin_data(self, tools):
        result = tools["hsm_get_apc_mapping"](command_code="TPIN")
        assert result["apc_operation"] == "translate_pin_data"

    def test_unknown_command_not_found(self, tools):
        result = tools["hsm_get_apc_mapping"](command_code="NOTREAL")
        assert result["found"] is False

    def test_result_is_not_tuple(self, tools):
        result = tools["hsm_get_apc_mapping"](command_code="TPIN")
        assert isinstance(result, dict)


# ── hsm_list_commands ─────────────────────────────────────────────────────────

class TestHsmListCommands:
    def test_all_commands_returned_with_no_filter(self, tools):
        result = tools["hsm_list_commands"]()
        assert result["count"] > 0
        assert len(result["commands"]) == result["count"]

    def test_category_filter(self, tools):
        result = tools["hsm_list_commands"](category="PIN")
        assert result["count"] > 0
        assert all(c["category"] == "PIN" for c in result["commands"])

    def test_vendor_filter(self, tools):
        result = tools["hsm_list_commands"](vendor="Futurex")
        assert result["count"] > 0
        assert all("futurex" in c["vendor"].lower() for c in result["commands"])

    def test_combined_filter(self, tools):
        result = tools["hsm_list_commands"](category="PIN", vendor="Futurex")
        assert result["count"] > 0
        for cmd in result["commands"]:
            assert cmd["category"] == "PIN"
            assert "futurex" in cmd["vendor"].lower()

    def test_each_command_has_required_fields(self, tools):
        result = tools["hsm_list_commands"]()
        for cmd in result["commands"]:
            for field in ("vendor", "api", "command_code", "name", "category", "confidence"):
                assert field in cmd, f"missing field: {field}"

    def test_unknown_category_returns_empty(self, tools):
        result = tools["hsm_list_commands"](category="NOTACATEGORY")
        assert result["count"] == 0


# ── hsm_analyze_code ──────────────────────────────────────────────────────────

class TestHsmAnalyzeCode:
    FUTUREX_SAMPLE = '[TPIN;PAN=4111111111111111;KSN=FFFF9876543210E00001;]'
    THALES_SAMPLE = 'send_command("CA" + key_block + "00")'

    def test_detects_futurex_excrypt_command(self, tools):
        result = tools["hsm_analyze_code"](source_code=self.FUTUREX_SAMPLE)
        assert result["commands_detected"] > 0
        codes = {d["command_code"] for d in result["detected"]}
        assert "TPIN" in codes

    def test_detects_thales_international_command(self, tools):
        result = tools["hsm_analyze_code"](source_code=self.THALES_SAMPLE)
        assert result["commands_detected"] > 0

    def test_detected_entries_have_required_fields(self, tools):
        result = tools["hsm_analyze_code"](source_code=self.FUTUREX_SAMPLE)
        for entry in result["detected"]:
            for field in ("command_code", "known", "detected_api"):
                assert field in entry, f"missing field: {field}"

    def test_known_command_has_apc_mapping(self, tools):
        result = tools["hsm_analyze_code"](source_code=self.FUTUREX_SAMPLE)
        tpin = next(d for d in result["detected"] if d["command_code"] == "TPIN")
        assert tpin["apc_operation"] is not None
        assert tpin["apc_key_type"] is not None

    def test_unrelated_source_returns_zero_commands(self, tools):
        result = tools["hsm_analyze_code"](source_code="x = 42\ny = x + 1")
        assert result["commands_detected"] == 0

    def test_migration_notes_is_list(self, tools):
        result = tools["hsm_analyze_code"](source_code=self.FUTUREX_SAMPLE)
        assert isinstance(result["migration_notes"], list)


# ── hsm_analyze_discovery_log ─────────────────────────────────────────────────

class TestHsmAnalyzeDiscoveryLog:
    SAMPLE_LOG = "\n".join([
        json.dumps({"vendor": "futurex_excrypt", "cmd": "TPIN",
                    "params": {"PAN": "[REDACTED]", "KSN": "FFFF9876543210E00001"}}),
        json.dumps({"vendor": "thales_payshield", "cmd": "CA", "payload_len": 32}),
        json.dumps({"vendor": "futurex_excrypt", "cmd": "ZZZUNKNOWN", "params": {}}),
    ])

    def test_parses_valid_log(self, tools):
        result = tools["hsm_analyze_discovery_log"](log_content=self.SAMPLE_LOG)
        assert result["commands_observed"] == 3

    def test_known_commands_mapped(self, tools):
        result = tools["hsm_analyze_discovery_log"](log_content=self.SAMPLE_LOG)
        assert result["mapped_to_apc"] >= 2

    def test_unknown_commands_flagged(self, tools):
        result = tools["hsm_analyze_discovery_log"](log_content=self.SAMPLE_LOG)
        assert result["unknown_commands"] >= 1

    def test_mapped_entries_have_apc_fields(self, tools):
        result = tools["hsm_analyze_discovery_log"](log_content=self.SAMPLE_LOG)
        for cmd in result["commands"]:
            assert "apc_operation" in cmd
            assert "apc_key_type" in cmd

    def test_existing_handler_detected(self, tools):
        result = tools["hsm_analyze_discovery_log"](log_content=self.SAMPLE_LOG)
        tpin = next((c for c in result["commands"] if c["cmd"] == "TPIN"), None)
        assert tpin is not None
        assert tpin["handler_exists"] is True

    def test_parse_error_reported(self, tools):
        bad_log = "not json\n" + json.dumps({"vendor": "futurex_excrypt", "cmd": "TPIN", "params": {}})
        result = tools["hsm_analyze_discovery_log"](log_content=bad_log)
        assert result["parse_errors"] >= 1

    def test_next_steps_populated(self, tools):
        result = tools["hsm_analyze_discovery_log"](log_content=self.SAMPLE_LOG)
        assert len(result["next_steps"]) > 0
