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
        "Vendor-neutral reference for payment domain concepts: card data, PIN blocks, "
        "card verification values, EMV tags, ISO 8583 fields, key types, HSM commands, "
        "cryptographic algorithms, and cross-cutting constraint rules."
    ),
    mime_type="text/markdown",
)
def payment_knowledge_base() -> str:
    return _KB_PATH.read_text(encoding="utf-8")


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
