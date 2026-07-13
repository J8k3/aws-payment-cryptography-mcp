# Publishing to the official MCP Registry

This server is listed in the official [MCP Registry](https://registry.modelcontextprotocol.io/)
under the namespace **`io.github.J8k3/aws-payment-cryptography-mcp`**, distributed as the
`.mcpb` bundle attached to each GitHub release. The registry entry is described by
[`server.json`](../server.json) in the repo root.

## Automated (default) — the release workflow does it

`.github/workflows/release.yml` publishes to the registry on every `v*.*.*` tag. The
`publish-mcp-registry` job (after the `.mcpb` is built and the release is created):

1. Downloads the release's `.mcpb`, computes its SHA-256, and **pins `server.json`** for that
   release — `version`, `packages[].version`, `packages[].identifier` (the `.mcpb` download URL),
   and `packages[].fileSha256`.
2. Authenticates with **GitHub OIDC** (`mcp-publisher login github-oidc`) — no secret required,
   just the job's `id-token: write` permission; the `io.github.J8k3` namespace is authorized by
   the repo owner.
3. Runs `mcp-publisher publish`.
4. Commits the pinned `server.json` back to `master` so the repo reflects the last-published state.

So the normal flow is just: **`chore: bump version` → tag `vX.Y.Z` → push tag.** The registry
entry updates itself. Verify with:

```bash
curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=aws-payment-cryptography" | jq .
```

> Namespace note: if OIDC ever rejects `io.github.J8k3` on capitalization, lowercase it to
> `io.github.j8k3/...` in `server.json` (GitHub logins are case-insensitive for auth).

## Manual fallback (first-time bootstrap / troubleshooting)

If you need to publish by hand:

```bash
# 1. download the mcp-publisher CLI (or `go install github.com/modelcontextprotocol/registry/cmd/mcp-publisher@latest`)
curl -sL "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" | tar xz mcp-publisher

# 2. pin server.json to the target release (version, .mcpb URL, sha256)
VERSION=X.Y.Z
curl -sL -o /tmp/b.mcpb "https://github.com/J8k3/aws-payment-cryptography-mcp/releases/download/v${VERSION}/aws-payment-cryptography-mcp-${VERSION}.mcpb"
sha256sum /tmp/b.mcpb   # paste into packages[0].fileSha256; also update version + identifier URL

# 3. authenticate (browser OAuth) and publish
./mcp-publisher login github     # or: login github-oidc inside CI
./mcp-publisher publish          # reads ./server.json
```

## Human-browsable directories (optional, secondary)

Smithery, Glama, PulseMCP, and mcp.so crawl public GitHub repos — the server may already be
discoverable there; claim ownership rather than re-submitting. The official registry above is
the machine-readable source MCP clients query, so it is the primary target.
