# Contributing

Contributions to the CLI should preserve its role as a standalone, least-privilege client for ChatGPT Gateway MCP Nyan.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
python -m build
```

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e '.[dev]'
pytest -q
python -m build
```

Changes to session persistence, filesystem boundaries, browser automation, local MCP environment/header handling, update verification or archive extraction should include fail-closed tests.

Do not add production credentials, private deployment topology, release-signing private keys, personal browser state or server-only Gateway code to this repository.
