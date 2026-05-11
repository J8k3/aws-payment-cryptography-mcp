"""MCP server entry point for the AWS Payment Cryptography agent."""

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


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
