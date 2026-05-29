"""MCP server entry point for the AWS Payment Cryptography agent."""

import textwrap
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .control_plane import register_control_plane_tools
from .data_plane import register_data_plane_tools
from .hsm_tools import register_hsm_tools
from .system_prompt import SYSTEM_PROMPT

mcp = FastMCP(
    name="apc-agent",
    instructions=SYSTEM_PROMPT,
)

register_control_plane_tools(mcp)
register_data_plane_tools(mcp)
register_hsm_tools(mcp)

_KB_PATH = Path(__file__).parent.parent.parent / "payment-knowledge-base.md"


@mcp.resource(
    "payment://knowledge-base",
    name="Payment Knowledge Base",
    description=(
        "Reference for payment domain concepts and APC-specific operational detail. "
        "Covers: card data, PIN blocks, card verification values (CVV/CVC/CSC/PVV/iCVV), "
        "EMV tags, ISO 8583 fields, key types, HSM commands, cryptographic algorithms, "
        "TR-31/TR-34/DUKPT (TDES and AES) specifics, APC key lifecycle and multi-region "
        "keys, APC dynamic keys (MPoC), ECDH key agreement, supported TR-31 key usage "
        "codes, EMV CVN session key derivation, and APC constraint rules (wrapping key "
        "strength, KCV algorithm by key type, RSA padding, key attribute immutability, "
        "ISO Format 4 requirements for AES PIN keys, and more)."
    ),
    mime_type="text/markdown",
)
def payment_knowledge_base() -> str:
    return _KB_PATH.read_text(encoding="utf-8")


_APC_USE_CASE_PATH = Path(__file__).parent.parent.parent / "aws-payment-cryptography-data-plane-use-cases.json"


@mcp.resource(
    "payment://apc-use-cases",
    name="AWS Payment Cryptography supported use cases",
    description=(
        "Supportability analysis of AWS Payment Cryptography data plane operations, "
        "derived from public API documentation. Authoritative source for which key "
        "algorithms, union branches, and enum values are valid for each operation."
    ),
    mime_type="application/json",
)
def apc_use_cases() -> str:
    return _APC_USE_CASE_PATH.read_text(encoding="utf-8")


_REPO = "J8k3/aws-payment-cryptography-mcp"

_FINDING_TYPE_TO_FILE: dict[str, str] = {
    "kb_entry":        "payment-knowledge-base.md",
    "hsm_command":     "hsm_analysis.py  — ALL_COMMANDS list",
    "proxy_handler":   "hsm_tools.py     — _PROXY_HANDLERS dict",
    "compliance_rule": "compliance.py    — LEGACY_CONSTRUCTS or PROHIBITED_ALGORITHMS",
    "apc_constraint":  "AGENTS.md        — Key Constraints section",
}


@mcp.tool()
def contribute_kb_finding(
    finding_type: str,
    summary: str,
    content: str,
    source_repo: str,
    context: str | None = None,
) -> dict:
    """
    Call this whenever you discover a gap while working in any repo — apc-hsm-proxy,
    CyberChef-Payments, or any other session — and the finding belongs in this MCP
    server's knowledge base, HSM command registry, proxy handler list, or compliance rules.
    Works without AWS credentials.

    Stages the finding as a GitHub issue so the MCP server session can apply it at the
    next session start. Returns a formatted issue body and the exact gh CLI command to run.

    finding_type options:
      "kb_entry"         — new or corrected entry for payment-knowledge-base.md
      "hsm_command"      — new HSM command to add to hsm_analysis.py ALL_COMMANDS
      "proxy_handler"    — handler completed in apc-hsm-proxy; needs _PROXY_HANDLERS update
      "compliance_rule"  — new PCI or scheme rule for compliance.py
      "apc_constraint"   — APC API gap or undocumented constraint for AGENTS.md

    Args:
        finding_type: One of the five types above
        summary: One-line description — becomes the GitHub issue title
        content: The content to add, formatted for the target file (KB YAML, HsmCommand(), etc.)
        source_repo: Which repo or context revealed this — e.g. "apc-hsm-proxy GW handler"
        context: Optional additional context — related files, downstream impact, etc.
    """
    if finding_type not in _FINDING_TYPE_TO_FILE:
        return {
            "error": f"Unknown finding_type '{finding_type}'",
            "valid_types": sorted(_FINDING_TYPE_TO_FILE),
        }

    target_file = _FINDING_TYPE_TO_FILE[finding_type]
    title = f"[kb] {summary}"

    body_parts = [
        f"## Contribution Type\n{finding_type}",
        f"## Target File\n{target_file}",
        f"## Source\n{source_repo}",
        f"## Content to Add\n\n{content}",
    ]
    if context:
        body_parts.append(f"## Context\n{context}")
    issue_body = "\n\n".join(body_parts)

    return {
        "title": title,
        "label": "kb-contribution",
        "target_file": target_file,
        "issue_body": issue_body,
        "instructions": textwrap.dedent(f"""
            Write the issue_body to a temp file, then run:

              # bash / zsh
              gh issue create \\
                --repo {_REPO} \\
                --title "{title}" \\
                --label kb-contribution \\
                --body-file /tmp/kb-contribution.md

              # PowerShell
              Set-Content $env:TEMP\\kb-contribution.md -Value $issue_body
              gh issue create `
                --repo {_REPO} `
                --title "{title}" `
                --label kb-contribution `
                --body-file $env:TEMP\\kb-contribution.md

            The MCP server session will apply this contribution at next session start.
        """).strip(),
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
