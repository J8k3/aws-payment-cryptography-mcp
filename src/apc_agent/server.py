"""MCP server entry point for the AWS Payment Cryptography agent."""

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


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
