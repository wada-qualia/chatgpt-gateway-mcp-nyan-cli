# ChatGPT Gateway MCP Nyan CLI

Standalone CLI and thin client for [ChatGPT Gateway MCP Nyan](https://github.com/wada-qualia/chatgpt-gateway-mcp-nyan).

The client connects an explicitly selected local directory and client runtime to a Gateway instance. It supports device-code login, local MCP bridging, long-lived WebSocket sessions, bounded filesystem operations, browser automation through an isolated Playwright session, update verification and rollback.

## Install from source

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
gateway-cli --version
```

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
gateway-cli --version
```

## Connect

```bash
gateway-cli login --gateway https://gateway.example.com --directory ./workspace --serve
```

The authorization flow requires explicit user confirmation in the browser. Session state is stored locally for reconnects.

## Security model

The selected directory is a filesystem boundary for client file operations, but it is **not a complete operating-system sandbox for shell commands**. Commands execute with the permissions of the account running the client.

For machines that accept remote execution through a Gateway:

- use a dedicated unprivileged account, VM or container;
- expose a dedicated working directory instead of a home directory or whole disk;
- do not inherit cloud credentials, SSH private keys or unrelated tokens into the process environment;
- do not use a personal browser profile for Playwright automation;
- trust the Gateway operator and its authorization policy before connecting.

See [SECURITY.md](SECURITY.md) for the complete boundary.

## Local MCP bridging

The client can expose local MCP servers to the Gateway while preserving a stable descriptor hash for tool metadata. Local child-process environment/header bindings are explicit and bounded.

## Updates

`gateway-cli update` verifies a signed `release-manifest.json` before installing a release. The repository contains only the public Ed25519 verification key. The signing private key is not part of this repository.

The default release URL is the GitHub Releases channel for this repository. Until a signed release is published, install from source instead. A custom trusted release endpoint may be supplied with `GATEWAY_RELEASE_BASE_URL`.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
python -m build
```

## Related repositories

- Gateway core: https://github.com/wada-qualia/chatgpt-gateway-mcp-nyan
- Browser extension: https://github.com/wada-qualia/chatgpt-gateway-mcp-nyan-browser-extension

## License

MIT License. See [LICENSE](LICENSE).
