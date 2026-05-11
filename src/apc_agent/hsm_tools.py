"""MCP tools for HSM legacy code analysis and APC migration (R8)."""

import re

from mcp.server.fastmcp import FastMCP

from .hsm_analysis import (
    ALL_COMMANDS,
    FUTUREX_EXCRYPT_PATTERNS,
    FUTUREX_STANDARD_PATTERNS,
    HSM_SOCKET_PATTERNS,
    IMPLEMENTATION_STATUS,
    INTERNATIONAL_PATTERNS,
    LMK_MIGRATION_NOTE,
    DUKPT_MIGRATION_NOTE,
    FIXED_KEY_MIGRATION_NOTE,
    get_apc_mapping,
    list_commands_by_category,
    list_commands_by_vendor,
    lookup_command,
)


def register_hsm_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    def hsm_lookup_command(command_code: str, api: str | None = None) -> dict:
        """
        Look up an HSM vendor command and return its APC equivalent.

        Args:
            command_code: The HSM command code, e.g. "TPIN", "CA", "31"
            api: Optional API filter — "Excrypt", "Standard", or "International"

        Returns dict with command metadata and APC mapping, or a not-found message.
        Coverage: Futurex (authoritative), Thales International (reference quality), Atalla (not available).
        """
        results = lookup_command(command_code, api)
        if not results:
            return {
                "found": False,
                "command_code": command_code,
                "message": (
                    f"Command '{command_code}' not found. "
                    "Atalla commands are not yet in the registry. "
                    f"Coverage status: {IMPLEMENTATION_STATUS}"
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
        Return just the APC operation and key type for an HSM command. Useful for
        quick refactoring lookups without full metadata.

        Args:
            command_code: The HSM command code, e.g. "TPIN", "CA", "31"
        """
        mapping = get_apc_mapping(command_code)
        if mapping is None:
            return {
                "found": False,
                "command_code": command_code,
                "message": f"No APC mapping found for '{command_code}'.",
            }
        apc_op, apc_key = mapping
        return {
            "found": True,
            "command_code": command_code,
            "apc_operation": apc_op,
            "apc_key_type": apc_key,
        }

    @mcp.tool()
    def hsm_list_commands(
        category: str | None = None,
        vendor: str | None = None,
    ) -> dict:
        """
        List known HSM commands, optionally filtered by category or vendor.

        Args:
            category: One of PIN, MAC, CVV, KEY_MGMT, ENCRYPT, ARQC, P2PE — or omit for all
            vendor: "Futurex" or "Thales" — or omit for all vendors

        Returns a list of commands with their APC mappings.
        """
        if category and vendor:
            by_cat = {c.command_code for c in list_commands_by_category(category)}
            cmds = [c for c in list_commands_by_vendor(vendor) if c.command_code in by_cat]
        elif category:
            cmds = list_commands_by_category(category)
        elif vendor:
            cmds = list_commands_by_vendor(vendor)
        else:
            cmds = ALL_COMMANDS

        return {
            "count": len(cmds),
            "coverage_status": IMPLEMENTATION_STATUS,
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
        Analyze a snippet of legacy payment code (Python, Java, C, etc.) and detect
        HSM socket calls. Returns identified commands and their APC migration paths.

        Recognizes Futurex Excrypt ([ ] delimiters), Futurex Standard (numeric codes),
        and International/Thales (2-char codes with fixed-length fields).

        Args:
            source_code: Raw source code containing HSM socket calls or command strings.
        """
        detected: list[dict] = []
        seen: set[str] = set()

        pattern_sets = [
            ("Futurex_Excrypt", FUTUREX_EXCRYPT_PATTERNS),
            ("Futurex_Standard", FUTUREX_STANDARD_PATTERNS),
            ("International_Thales", INTERNATIONAL_PATTERNS),
        ]

        for api_name, patterns in pattern_sets:
            for pattern in patterns:
                for m in re.finditer(pattern, source_code, re.IGNORECASE):
                    code = m.group(1).upper()
                    key = f"{api_name}:{code}"
                    if key in seen:
                        continue
                    seen.add(key)

                    # Look up the command — try with api hint derived from api_name
                    api_hint = api_name.split("_")[1] if "_" in api_name else None
                    matches = lookup_command(code)
                    mapping = get_apc_mapping(code)

                    detected.append({
                        "detected_api": api_name,
                        "command_code": code,
                        "match_context": m.group(0)[:80],
                        "known": bool(matches),
                        "name": matches[0].name if matches else None,
                        "category": matches[0].category if matches else None,
                        "apc_operation": mapping[0] if mapping else None,
                        "apc_key_type": mapping[1] if mapping else None,
                        "notes": matches[0].notes if matches else None,
                        "confidence": matches[0].confidence if matches else None,
                    })

        # Generic socket pattern sweep for anything missed
        for pattern in HSM_SOCKET_PATTERNS:
            for m in re.finditer(pattern, source_code, re.IGNORECASE):
                code = m.group(1).upper()
                key = f"generic:{code}"
                if key in seen:
                    continue
                seen.add(key)
                matches = lookup_command(code)
                if matches:
                    mapping = get_apc_mapping(code)
                    detected.append({
                        "detected_api": "unknown",
                        "command_code": code,
                        "match_context": m.group(0)[:80],
                        "known": True,
                        "name": matches[0].name,
                        "category": matches[0].category,
                        "apc_operation": mapping[0] if mapping else None,
                        "apc_key_type": mapping[1] if mapping else None,
                        "notes": matches[0].notes,
                        "confidence": matches[0].confidence,
                    })

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
            "detected": detected,
            "migration_notes": migration_notes,
            "coverage_status": IMPLEMENTATION_STATUS,
        }

    @mcp.tool()
    def hsm_migration_notes(topic: str) -> dict:
        """
        Return migration guidance for a specific HSM concept that has no direct APC equivalent.

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
