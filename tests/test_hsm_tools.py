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

    # ── per-category pattern coverage ────────────────────────────────────────

    def test_pin_tdes_dukpt_detected(self, tools):
        # CI = TDES DUKPT PIN translate (BDK+KSN → ZPK)
        src = 'cmd = "CI"\nresp = hsm.send(cmd + bdk + ksn + pin_block)'
        result = tools["hsm_analyze_code"](source_code=src)
        codes = {d["command_code"] for d in result["detected"]}
        assert "CI" in codes

    def test_pin_zpk_translate_detected(self, tools):
        # CC = ZPK-to-ZPK PIN translate (static key, compliance risk)
        src = 'cmd = "CC"\nresp = hsm.send(cmd + zpk_src + zpk_dst + pin_block)'
        result = tools["hsm_analyze_code"](source_code=src)
        codes = {d["command_code"] for d in result["detected"]}
        assert "CC" in codes

    def test_encrypt_bucket_detected(self, tools):
        # M0/M2/M4 = data encrypt/decrypt/translate; previously missed before pattern fix
        for code in ("M0", "M2", "M4"):
            src = f'command = "{code}"\nresult = hsm.send(command + key + data)'
            result = tools["hsm_analyze_code"](source_code=src)
            codes = {d["command_code"] for d in result["detected"]}
            assert code in codes, f"{code} not detected in ENCRYPT bucket"

    def test_mac_generate_verify_detected(self, tools):
        # M6 = generate MAC, M8 = verify MAC
        for code in ("M6", "M8"):
            src = f'msg = "{code}" + mak + data'
            result = tools["hsm_analyze_code"](source_code=src)
            codes = {d["command_code"] for d in result["detected"]}
            assert code in codes, f"{code} not detected in MAC bucket"

    def test_mac_verify_translate_detected(self, tools):
        # MY = verify and translate MAC (added in prior session)
        src = 'command = "MY"\nresult = hsm.send(command + mak_in + mak_out + data + mac)'
        result = tools["hsm_analyze_code"](source_code=src)
        codes = {d["command_code"] for d in result["detected"]}
        assert "MY" in codes

    def test_cvv_generate_verify_detected(self, tools):
        # CW = generate CVV, CY = verify CVV
        for code in ("CW", "CY"):
            src = f'cmd = "{code}" + cvk + pan + expiry + service_code'
            result = tools["hsm_analyze_code"](source_code=src)
            codes = {d["command_code"] for d in result["detected"]}
            assert code in codes, f"{code} not detected in CVV bucket"

    def test_arqc_thales_variants_detected(self, tools):
        # KQ = EMV/Mastercard ARQC, KW = cloud-based SKD, JS = UnionPay/CUP
        for code in ("KQ", "KW", "JS"):
            src = f'arqc_cmd = "{code}" + imk + pan + atc + txn_data + arqc'
            result = tools["hsm_analyze_code"](source_code=src)
            codes = {d["command_code"] for d in result["detected"]}
            assert code in codes, f"{code} not detected in ARQC bucket"

    def test_arqc_futurex_excrypt_detected(self, tools):
        # EMVA = Futurex Excrypt ARQC verify
        src = '[EMVA;AC4111111111111111;KSN001;AT0001;]'
        result = tools["hsm_analyze_code"](source_code=src)
        codes = {d["command_code"] for d in result["detected"]}
        assert "EMVA" in codes

    def test_dukpt_note_attached_for_ci(self, tools):
        src = 'cmd = "CI"\nresp = hsm.send(cmd + bdk + ksn + pin_block)'
        result = tools["hsm_analyze_code"](source_code=src)
        notes_text = " ".join(result["migration_notes"])
        assert "DUKPT" in notes_text

    def test_key_mgmt_note_attached_for_a0(self, tools):
        # A0 = generate key (KEY_MGMT category) → triggers LMK migration note
        src = 'cmd = "A0"\nresp = hsm.send(cmd + key_type + lmk_flag)'
        result = tools["hsm_analyze_code"](source_code=src)
        notes_text = " ".join(result["migration_notes"])
        assert "LMK" in notes_text

    def test_each_detected_command_maps_to_known_apc_op(self, tools):
        # All commands in these samples must resolve to a known APC operation
        samples = [
            '[TPIN;PAN=4111111111111111;KSN=FFFF9876543210E00001;]',
            'cmd = "CI"\nresp = hsm.send(cmd)',
            'cmd = "M6"\nresp = hsm.send(cmd)',
            'cmd = "CW"\nresp = hsm.send(cmd)',
            'cmd = "KQ"\nresp = hsm.send(cmd)',
        ]
        for src in samples:
            result = tools["hsm_analyze_code"](source_code=src)
            for entry in result["detected"]:
                if entry["known"]:
                    assert entry["apc_operation"] is not None, (
                        f"{entry['command_code']} known=True but apc_operation is None"
                    )


# ── _PROXY_HANDLERS consistency ───────────────────────────────────────────────

class TestProxyHandlersConsistency:
    def test_all_proxy_handler_codes_exist_in_all_commands(self, tools):
        from apc_agent.hsm_tools import register_hsm_tools
        from apc_agent.hsm_analysis import ALL_COMMANDS

        # Extract _PROXY_HANDLERS by re-registering and reading the module attribute
        import apc_agent.hsm_tools as ht_mod
        import importlib, types

        known_codes = {c.command_code for c in ALL_COMMANDS}

        class _Cap:
            _proxy: dict = {}
            def tool(self, **kw):
                def d(fn): return fn
                return d

        # _PROXY_HANDLERS is a local inside register_hsm_tools; access via the closure
        # workaround: re-read the source and extract the set literal
        import ast, pathlib, re as _re
        src = pathlib.Path(ht_mod.__file__).read_text()
        # find _PROXY_HANDLERS dict in source, collect all quoted 2-char codes
        proxy_codes = set(_re.findall(r'"([A-Z]{2,4})"', src[src.find("_PROXY_HANDLERS"):src.find("_PROXY_HANDLERS") + 2000]))

        missing = proxy_codes - known_codes
        assert not missing, f"_PROXY_HANDLERS codes not in ALL_COMMANDS: {sorted(missing)}"


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
