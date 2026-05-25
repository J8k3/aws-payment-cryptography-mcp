"""MCP tools for HSM legacy code analysis and APC migration (R8)."""

import json
import re

from mcp.server.fastmcp import FastMCP

from .hsm_analysis import (
    ALL_COMMANDS,
    FUTUREX_EXCRYPT_PATTERNS,
    NUMERIC_HSM_PATTERNS,
    HSM_SOCKET_PATTERNS,
    INTERNATIONAL_AND_THALES_PATTERNS,
    LMK_MIGRATION_NOTE,
    DUKPT_MIGRATION_NOTE,
    FIXED_KEY_MIGRATION_NOTE,
    get_apc_mapping,
    lookup_command,
)


def register_hsm_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    def hsm_lookup_command(command_code: str, api: str | None = None) -> dict:
        """
        Call this whenever you see an HSM command code in legacy payment code,
        documentation, or logs — e.g. "TPIN", "CA", "G0", "M6", "CC", "CI",
        "CW", "CY", "B2", "KQ", "GW", or numeric Atalla codes like "31", "5D".
        Works without AWS credentials.

        Returns the command name, category (PIN/MAC/CVV/KEY_MGMT/ENCRYPT/ARQC),
        description, and the APC operation + key type that replaces it.

        Coverage: Futurex Excrypt (authoritative), Thales payShield legacy + international
        (authoritative/reference quality), Atalla numeric codes (directory quality).

        Args:
            command_code: The HSM command code, e.g. "TPIN", "CA", "31"
            api: Optional API filter — "Excrypt", "Standard", or "International"
        """
        results = lookup_command(command_code)
        if api:
            results = [c for c in results if c.api.lower() == api.lower()]
        if not results:
            return {
                "found": False,
                "command_code": command_code,
                "message": (
                    f"Command '{command_code}' not found. "
                    "Coverage: Futurex Excrypt (authoritative), Thales payShield Legacy/International "
                    "(authoritative/reference quality), Atalla (directory quality — function names only). "
                    "Numeric codes may be Atalla; check the Atalla NCR Payments documentation."
                ),
            }
        return {
            "found": True,
            "matches": [
                {
                    "vendor": c.vendor,
                    "api": c.api,
                    "command_code": c.command_code,
                    "name": c.name,
                    "category": c.category,
                    "description": c.description,
                    "apc_operation": c.apc_operation,
                    "apc_key_type": c.apc_key_type,
                    "notes": c.notes,
                    "confidence": c.confidence,
                }
                for c in results
            ],
        }

    @mcp.tool()
    def hsm_get_apc_mapping(command_code: str) -> dict:
        """
        Call this for a quick command-code → APC operation lookup when you already
        know the command and just need the migration target — faster than hsm_lookup_command
        when you don't need the full description and notes. Works without AWS credentials.

        Returns just the APC operation and key type for an HSM command.

        Args:
            command_code: The HSM command code, e.g. "TPIN", "CA", "31"
        """
        mapping = get_apc_mapping(command_code)
        if "error" in mapping:
            return {
                "found": False,
                "command_code": command_code,
                "message": f"No APC mapping found for '{command_code}'.",
            }
        first = mapping["matches"][0]
        return {
            "found": True,
            "command_code": command_code,
            "apc_operation": first["apc_operation"],
            "apc_key_type": first["apc_key_type"],
        }

    @mcp.tool()
    def hsm_list_commands(
        category: str | None = None,
        vendor: str | None = None,
    ) -> dict:
        """
        Call this to discover which HSM commands are known and what APC operations they
        map to — useful when scoping a migration, reviewing an HSM integration, or
        deciding which APC operations a proxy handler needs to implement.
        Works without AWS credentials.

        Args:
            category: PIN, MAC, CVV, KEY_MGMT, ENCRYPT, ARQC, or P2PE — omit for all
            vendor: "Futurex" or "Thales" — omit for all vendors
        """
        if category and vendor:
            cmds = [c for c in ALL_COMMANDS
                    if c.category.upper() == category.upper()
                    and vendor.lower() in c.vendor.lower()]
        elif category:
            cmds = [c for c in ALL_COMMANDS if c.category.upper() == category.upper()]
        elif vendor:
            cmds = [c for c in ALL_COMMANDS if vendor.lower() in c.vendor.lower()]
        else:
            cmds = ALL_COMMANDS

        return {
            "count": len(cmds),
            "commands": [
                {
                    "vendor": c.vendor,
                    "api": c.api,
                    "command_code": c.command_code,
                    "name": c.name,
                    "category": c.category,
                    "apc_operation": c.apc_operation,
                    "confidence": c.confidence,
                }
                for c in cmds
            ],
        }

    @mcp.tool()
    def hsm_analyze_code(source_code: str) -> dict:
        """
        Call this whenever reviewing legacy payment code that may contain HSM socket calls —
        Python, Java, C, Go, or any language. Even a single file or function is worth scanning.
        Works without AWS credentials.

        Detects Futurex Excrypt commands ([AOCCCC;...] frames), Thales/International 2-char
        command codes, and Atalla/Futurex Standard numeric codes. Returns identified commands,
        their APC migration path, and migration notes for LMK, DUKPT, and fixed-key patterns.

        Args:
            source_code: Raw source code containing HSM socket calls or command strings.
        """
        detected: list[dict] = []
        seen: set[str] = set()

        pattern_sets = [
            ("Futurex_Excrypt", FUTUREX_EXCRYPT_PATTERNS),
            ("Numeric_Atalla_or_Futurex_Standard", NUMERIC_HSM_PATTERNS),
            ("International_and_Thales_Legacy", INTERNATIONAL_AND_THALES_PATTERNS),
        ]

        for api_name, patterns in pattern_sets:
            for pattern in patterns:
                for m in re.finditer(pattern, source_code, re.IGNORECASE):
                    code = m.group(1).upper()
                    key = f"{api_name}:{code}"
                    if key in seen:
                        continue
                    seen.add(key)

                    matches = lookup_command(code)
                    first = matches[0] if matches else None

                    detected.append({
                        "detected_api": api_name,
                        "command_code": code,
                        "match_context": m.group(0)[:80],
                        "known": bool(matches),
                        "name": first.name if first else None,
                        "category": first.category if first else None,
                        "apc_operation": first.apc_operation if first else None,
                        "apc_key_type": first.apc_key_type if first else None,
                        "notes": first.notes if first else None,
                        "confidence": first.confidence if first else None,
                    })

        # Generic socket pattern sweep — detect HSM connection context without command extraction
        hsm_context_found = any(
            re.search(pattern, source_code, re.IGNORECASE)
            for pattern in HSM_SOCKET_PATTERNS
        )

        migration_notes = []
        categories_found = {d["category"] for d in detected if d.get("category")}
        if "KEY_MGMT" in categories_found:
            migration_notes.append(LMK_MIGRATION_NOTE)
        if any("DUKPT" in (d.get("name") or "") for d in detected):
            migration_notes.append(DUKPT_MIGRATION_NOTE)
        if any("Fixed" in (d.get("name") or "") or "ZPK" in (d.get("name") or "") for d in detected):
            migration_notes.append(FIXED_KEY_MIGRATION_NOTE)

        return {
            "commands_detected": len(detected),
            "hsm_connection_patterns_found": hsm_context_found,
            "detected": detected,
            "migration_notes": migration_notes,
        }

    # Command codes with working handlers in apc-hsm-proxy (github.com/J8k3/aws-payment-cryptography-hsm-proxy)
    _PROXY_HANDLERS: dict[str, set[str]] = {
        "futurex_excrypt": {"ECHO", "TPIN"},
        "thales_payshield": {
            "CA", "CC", "CI", "G0",           # PIN translation
            "CK", "CM", "CO", "CQ",           # DUKPT PIN verify (original single-length)
            "DA", "DC", "EA", "EC",           # Non-DUKPT PIN verify (TPK/ZPK)
            "GO", "GQ", "GS", "GU",           # DUKPT PIN verify (3DES & AES)
            "CW", "CY",                        # CVV generate/verify
            "C2", "C4",                        # AS2805 MAC
            "M6", "M8",                        # MAC generate/verify (extended)
            "MY",                              # MAC verify and translate
            "MA", "MC", "ME",                  # Legacy MAK
            "M0", "M2", "M4",                  # Data encrypt/decrypt/translate
            "HE", "HG",                        # Legacy TAK encrypt/decrypt
            "GW",                              # DUKPT MAC generate/verify (3DES & AES)
            "KQ",                              # ARQC/ARPC
            "KW",                              # ARQC/ARPC (EMV & Cloud-Based SKD)
            "JS",                              # ARQC/ARPC (UnionPay/CUP)
            "B2",                              # Heartbeat/diagnostics
        },
    }

    @mcp.tool()
    def hsm_analyze_discovery_log(log_content: str) -> dict:
        """
        Call this when analyzing the output of apc-hsm-proxy running in discovery mode
        (a discovery.jsonl file). Returns per-command APC mappings, which proxy handlers
        already exist, which still need to be written, and migration notes.
        Works without AWS credentials.

        Each log line is a JSON object:
          vendor      — "futurex_excrypt" or "thales_payshield"
          cmd         — HSM command code, e.g. "TPIN" or "CA"
          params      — Futurex: parameter codes → values (sensitive fields = "[REDACTED]")
          payload_len — Thales: observed payload length in bytes

        Args:
            log_content: Full text of the discovery.jsonl file (newline-delimited JSON).
        """
        mapped = []
        unknown = []
        parse_errors = []

        for i, line in enumerate(log_content.strip().splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                parse_errors.append({"line": i, "error": str(e), "content": line[:80]})
                continue

            cmd = record.get("cmd", "").upper()
            vendor = record.get("vendor", "unknown")
            params = record.get("params") or {}
            payload_len = record.get("payload_len")

            matches = lookup_command(cmd)
            handler_exists = cmd in _PROXY_HANDLERS.get(vendor, set())

            entry = {
                "cmd": cmd,
                "vendor": vendor,
                "handler_exists": handler_exists,
                "params_observed": sorted(params.keys()) if params else None,
                "payload_len": payload_len,
            }

            if matches:
                first = matches[0]
                entry.update({
                    "known": True,
                    "name": first.name,
                    "category": first.category,
                    "apc_operation": first.apc_operation,
                    "apc_key_type": first.apc_key_type,
                    "confidence": first.confidence,
                    "notes": first.notes,
                })
                mapped.append(entry)
            else:
                entry["known"] = False
                entry["message"] = (
                    f"'{cmd}' is not in the command registry. "
                    "Check the Futurex HSM Reference Manual or Thales payShield Host Reference Manual "
                    "for parameter layout, then add it to hsm_analysis.py."
                )
                unknown.append(entry)

        needs_handler = [c for c in mapped if not c["handler_exists"]]
        has_handler = [c for c in mapped if c["handler_exists"]]

        migration_notes = []
        categories = {c.get("category") for c in mapped if c.get("category")}
        if "KEY_MGMT" in categories:
            migration_notes.append(LMK_MIGRATION_NOTE)
        if any("DUKPT" in (c.get("name") or "") for c in mapped):
            migration_notes.append(DUKPT_MIGRATION_NOTE)
        if any("Fixed" in (c.get("name") or "") or "ZPK" in (c.get("name") or "") for c in mapped):
            migration_notes.append(FIXED_KEY_MIGRATION_NOTE)

        next_steps = []
        if has_handler:
            codes = ", ".join(c["cmd"] for c in has_handler)
            next_steps.append(f"Handlers already implemented in the proxy: {codes}. No action needed.")
        if needs_handler:
            for c in needs_handler:
                next_steps.append(
                    f"{c['cmd']} ({c.get('name', 'unknown')}) → implement src/handlers/"
                    f"{'futurex' if 'futurex' in c['vendor'] else 'thales'}/"
                    f"{c['cmd'].lower()}.rs calling APC {c.get('apc_operation', 'unknown')} "
                    f"with key type {c.get('apc_key_type', 'unknown')}."
                )
        if unknown:
            codes = ", ".join(c["cmd"] for c in unknown)
            next_steps.append(
                f"Unknown commands (not in registry): {codes}. "
                "Look up in vendor documentation and add to hsm_analysis.py before implementing handlers."
            )

        return {
            "commands_observed": len(mapped) + len(unknown),
            "mapped_to_apc": len(mapped),
            "handlers_already_exist": len(has_handler),
            "handlers_needed": len(needs_handler),
            "unknown_commands": len(unknown),
            "parse_errors": len(parse_errors),
            "commands": mapped,
            "unknown": unknown,
            "errors": parse_errors,
            "next_steps": next_steps,
            "migration_notes": migration_notes,
        }

    @mcp.tool()
    def hsm_migration_notes(topic: str) -> dict:
        """
        Call this when discussing HSM migration for concepts that have no direct APC
        equivalent — LMK (Local Master Key), DUKPT initial key loading, or fixed ZPK
        key schemes. Returns detailed migration guidance for the selected topic.
        Works without AWS credentials.

        Args:
            topic: One of "lmk", "dukpt", "fixed_key"
        """
        notes_map = {
            "lmk": LMK_MIGRATION_NOTE,
            "dukpt": DUKPT_MIGRATION_NOTE,
            "fixed_key": FIXED_KEY_MIGRATION_NOTE,
        }
        key = topic.lower().replace("-", "_").replace(" ", "_")
        note = notes_map.get(key)
        if note is None:
            return {
                "found": False,
                "available_topics": list(notes_map.keys()),
                "message": f"No migration note for '{topic}'.",
            }
        return {"topic": key, "guidance": note}
