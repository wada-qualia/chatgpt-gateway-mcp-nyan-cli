# Security Policy

## Trust model

The CLI creates outbound HTTPS/WebSocket connections to a configured ChatGPT Gateway MCP Nyan instance and executes authorized operations as the local operating-system user. Connect only to a Gateway operator and authorization policy you trust.

## Filesystem and command boundary

Client file operations are rooted in the directory selected during login. That directory boundary is not a complete OS sandbox for shell commands: a spawned process inherits the permissions and environment of the user running `gateway-cli`.

For remote-execution use:

- run under a dedicated unprivileged account, VM or container;
- use a dedicated working directory;
- do not expose a home directory or entire disk;
- remove unrelated credentials from the process environment;
- do not run as root or Administrator unless that privilege is explicitly required and understood.

## Browser automation

The browser integration uses a dedicated Playwright browser session. Do not import a personal browser profile, cookies or saved passwords into that session.

## Authentication state

Device authorization produces local session state used for reconnects. Treat that state as sensitive, keep it out of shared archives/backups and revoke the corresponding Gateway client registration when access should end.

## Update trust

The updater verifies a signed release manifest with the public key shipped in `gateway_cli/release-signing-key.pub`. It fails closed on signature, fingerprint, HTTPS, hash, size or archive-structure mismatches. The release signing private key is not part of this repository.

Until a signed GitHub release exists, install from source instead of relying on `gateway-cli update`.

## Reporting

Use GitHub private vulnerability reporting once enabled for the repository. Do not place credentials, active session material or private infrastructure data in public issues.
