from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from gateway_cli.local_mcp import (
    MCP_THIN_CLIENT_PROTOCOL_VERSION,
    LocalMcpConfigError,
    LocalMcpHost,
    LocalMcpServerConfig,
)


def test_local_config_keeps_execution_and_secrets_client_owned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCAL_MCP_TOKEN", "secret-value")
    command = tmp_path / "server"
    command.write_text("#!/bin/sh\n")
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "runtime_id": "runtime-a",
                "servers": [
                    {
                        "id": "stdio-a",
                        "display_name": "Private stdio",
                        "transport": "stdio",
                        "command": str(command),
                        "args": ["--fixed"],
                        "cwd": str(tmp_path),
                        "environment_bindings": {"TOKEN": "LOCAL_MCP_TOKEN"},
                    }
                ],
            }
        )
    )
    host = LocalMcpHost.from_path(config_path)
    host.connection_instance_id = "connection-a"
    registration = host.registration_payload()
    serialized = json.dumps(registration)
    assert "secret-value" not in serialized
    assert str(command) not in serialized
    assert "LOCAL_MCP_TOKEN" not in serialized
    assert registration["servers"] == [
        {
            "local_server_id": "stdio-a",
            "display_name": "Private stdio",
            "transport": "stdio",
        }
    ]

    with pytest.raises(LocalMcpConfigError, match="override"):
        host._validate_gateway_call(
            {
                "connection_instance_id": "connection-a",
                "runtime_id": "runtime-a",
                "local_server_id": "stdio-a",
                "request_id": "request-a",
                "server_id": "server-a",
                "revision_id": "revision-a",
                "tool_name": "tool-a",
                "schema_hash": "a" * 64,
                "catalog_generation": 1,
                "arguments": {},
                "action_class": "read",
                "command": "/bin/sh",
            }
        )


def test_local_config_rejects_unapproved_or_public_network_targets(
    tmp_path: Path,
) -> None:
    with pytest.raises(LocalMcpConfigError, match="absolute"):
        LocalMcpServerConfig.from_dict(
            {"id": "relative", "transport": "stdio", "command": "python"}
        )
    with pytest.raises(LocalMcpConfigError, match="approved_private_network"):
        LocalMcpServerConfig.from_dict(
            {
                "id": "private",
                "transport": "private_http",
                "url": "http://10.0.1.20:9000/mcp",
            }
        )
    with pytest.raises(LocalMcpConfigError, match="private network"):
        LocalMcpServerConfig.from_dict(
            {
                "id": "public",
                "transport": "private_http",
                "url": "https://8.8.8.8/mcp",
                "approved_private_network": True,
            }
        )
    with pytest.raises(LocalMcpConfigError, match="loopback-only"):
        LocalMcpServerConfig.from_dict(
            {
                "id": "not-localhost",
                "transport": "streamable_http",
                "url": "http://10.0.1.20:9000/mcp",
            }
        )


def test_runtime_hello_and_metadata_state_survive_reconnect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = LocalMcpServerConfig.from_dict(
        {
            "id": "loopback-a",
            "display_name": "Loopback MCP",
            "transport": "streamable_http",
            "url": "http://127.0.0.1:9000/mcp",
        }
    )
    state_path = tmp_path / "state.json"
    host = LocalMcpHost(runtime_id="runtime-a", servers=[config], state_path=state_path)
    sent: list[dict] = []

    async def send(payload: dict) -> None:
        sent.append(payload)

    async def no_notification_listeners(_send) -> None:
        return None

    monkeypatch.setattr(host, "_start_notification_listeners", no_notification_listeners)

    assert asyncio.run(
        host.handle_gateway_message(
            {
                "type": "mcp_gateway_hello",
                "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                "connection_instance_id": "connection-a",
            },
            send,
        )
    )
    assert sent[-1]["type"] == "mcp_runtime_registered"
    assert sent[-1]["runtime_id"] == "runtime-a"
    host.states["loopback-a"].catalog_generation = 7
    host.states["loopback-a"].snapshot_sha256 = "b" * 64
    host._save_state()
    restored = LocalMcpHost(
        runtime_id="runtime-a", servers=[config], state_path=state_path
    )
    assert restored.states["loopback-a"].catalog_generation == 7
    assert restored.states["loopback-a"].snapshot_sha256 == "b" * 64
    if os.name != "nt":
        assert state_path.stat().st_mode & 0o777 == 0o600


def test_http_session_disables_environment_proxies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = LocalMcpServerConfig.from_dict(
        {
            "id": "loopback-a",
            "transport": "streamable_http",
            "url": "http://127.0.0.1:9000/mcp",
        }
    )
    host = LocalMcpHost(
        runtime_id="runtime-a", servers=[config], state_path=tmp_path / "state.json"
    )
    captured: dict[str, object] = {}

    def fake_async_client(**kwargs):
        captured.update(kwargs)
        raise RuntimeError("client-construction-stop")

    monkeypatch.setattr("gateway_cli.local_mcp.httpx.AsyncClient", fake_async_client)

    async def exercise() -> None:
        with pytest.raises(RuntimeError, match="client-construction-stop"):
            async with host._session(config):
                pass

    asyncio.run(exercise())
    assert captured["trust_env"] is False
