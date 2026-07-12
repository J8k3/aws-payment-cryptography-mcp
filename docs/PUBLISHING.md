# Publishing to the official MCP Registry

This server is listed in the official [MCP Registry](https://registry.modelcontextprotocol.io/)
under the namespace **`io.github.J8k3/aws-payment-cryptography-mcp`**, distributed as the
`.mcpb` bundle attached to each GitHub release. The registry entry is described by
[`server.json`](../server.json) in the repo root.

## One-time setup

Install the publisher CLI (see the [registry docs](https://github.com/modelcontextprotocol/registry)):

```bash
# via Go, or download a release binary for your platform
go install github.com/modelcontextprotocol/registry/cmd/mcp-publisher@latest
```

## Publish / update (run after each release)

The `.mcpb` download URL, `version`, and `fileSha256` in `server.json` are **pinned to a
specific release tag** — they must be updated every time a new version ships.

1. Cut the release first (tag `vX.Y.Z` → the release workflow builds and attaches
   `aws-payment-cryptography-mcp-X.Y.Z.mcpb`).
2. Update `server.json`:
   - `version` and each `packages[].version` → `X.Y.Z`
   - `packages[].identifier` → the new release's `.mcpb` download URL
   - `packages[].fileSha256` → the new bundle's SHA-256:
     ```bash
     curl -sL -o /tmp/b.mcpb \
       https://github.com/J8k3/aws-payment-cryptography-mcp/releases/download/vX.Y.Z/aws-payment-cryptography-mcp-X.Y.Z.mcpb
     sha256sum /tmp/b.mcpb
     ```
3. Authenticate with the GitHub namespace (browser OAuth; only the repo owner can do this):
   ```bash
   mcp-publisher login github
   ```
   The `io.github.J8k3/...` namespace is authorized by your GitHub login. If the CLI rejects
   the case, try the lowercase form `io.github.j8k3/...`.
4. Publish:
   ```bash
   mcp-publisher publish     # reads ./server.json
   ```
5. Verify:
   ```bash
   curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=aws-payment-cryptography" | jq .
   ```

## Human-browsable directories (optional, secondary)

Smithery, Glama, PulseMCP, and mcp.so crawl public GitHub repos — the server may already be
discoverable there; claim ownership rather than re-submitting. The official registry above is
the machine-readable source MCP clients query, so it is the primary target.
