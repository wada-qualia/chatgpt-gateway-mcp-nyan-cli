from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable
from urllib.parse import urlparse

import httpx
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

MCP_THIN_CLIENT_PROTOCOL_VERSION = "1.0"
MCP_THIN_CLIENT_CAPABILITIES = (
    "mcp_runtime_v1",
    "mcp_catalog_snapshot",
    "mcp_catalog_delta",
    "mcp_call",
    "mcp_cancel",
    "mcp_progress",
    "mcp_unknown_outcome",
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,119}$")


class LocalMcpConfigError(RuntimeError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _model_json(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return value


def _tool_descriptor(tool: types.Tool) -> dict[str, Any]:
    return {
        "input": dict(tool.inputSchema or {}),
        "output": dict(tool.outputSchema) if tool.outputSchema else None,
        "title": getattr(tool, "title", None),
        "description": tool.description or "",
        "annotations": _model_json(tool.annotations) or {},
        "icons": [_model_json(item) for item in (getattr(tool, "icons", None) or [])],
        "execution": _model_json(getattr(tool, "execution", None)) or {},
        "component_meta": dict(getattr(tool, "meta", None) or {}),
    }


def _tool_schema_hash(tool: types.Tool) -> str:
    return _sha256_json(_tool_descriptor(tool))


def _identifier(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise LocalMcpConfigError(f"{name} must be a stable identifier")
    return text


def _binding_map(value: Any, name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 100:
        raise LocalMcpConfigError(f"{name} must be a bounded object")
    result: dict[str, str] = {}
    for target, source in value.items():
        target_text = str(target)
        source_text = str(source)
        if name == "environment_bindings":
            if not _ENV_NAME.fullmatch(target_text):
                raise LocalMcpConfigError("Invalid child environment variable name")
        elif not _HEADER_NAME.fullmatch(target_text):
            raise LocalMcpConfigError("Invalid HTTP header name")
        if not _ENV_NAME.fullmatch(source_text):
            raise LocalMcpConfigError(
                "Secret binding must name a local environment variable"
            )
        result[target_text] = source_text
    return result


def _resolved_bindings(bindings: dict[str, str]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for target, source in bindings.items():
        value = os.environ.get(source)
        if value is None:
            raise LocalMcpConfigError(
                f"Required local environment variable is missing: {source}"
            )
        resolved[target] = value
    return resolved


def _validated_http_url(value: Any, *, private: bool) -> str:
    url = str(value or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LocalMcpConfigError("Local MCP URL must be absolute HTTP or HTTPS")
    if parsed.username or parsed.password or parsed.fragment:
        raise LocalMcpConfigError(
            "Local MCP URL must not contain credentials or fragments"
        )
    hostname = parsed.hostname.casefold()
    if hostname == "localhost":
        return url
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError as exc:
        raise LocalMcpConfigError(
            "Local/private MCP endpoints must use localhost or a literal IP address"
        ) from exc
    if private:
        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise LocalMcpConfigError(
                "private_http endpoint is not on a private network"
            )
    elif not address.is_loopback:
        raise LocalMcpConfigError(
            "streamable_http local endpoints must be loopback-only"
        )
    return url


@dataclass(frozen=True)
class LocalMcpServerConfig:
    local_server_id: str
    display_name: str
    transport: str
    command: str | None = None
    args: tuple[str, ...] = ()
    cwd: str | None = None
    environment_bindings: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    header_bindings: dict[str, str] = field(default_factory=dict)
    approved_private_network: bool = False
    call_timeout_seconds: float = 30.0

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "LocalMcpServerConfig":
        allowed = {
            "id",
            "display_name",
            "transport",
            "command",
            "args",
            "cwd",
            "environment_bindings",
            "url",
            "header_bindings",
            "approved_private_network",
            "call_timeout_seconds",
        }
        extra = set(raw).difference(allowed)
        if extra:
            raise LocalMcpConfigError(
                f"Unsupported local MCP configuration fields: {sorted(extra)}"
            )
        local_server_id = _identifier(raw.get("id"), "server id")
        display_name = " ".join(
            str(raw.get("display_name") or local_server_id).split()
        )[:180]
        transport = str(raw.get("transport", ""))
        timeout = float(raw.get("call_timeout_seconds", 30.0))
        if not 0.1 <= timeout <= 3600:
            raise LocalMcpConfigError(
                "call_timeout_seconds is outside the allowed range"
            )
        env = _binding_map(raw.get("environment_bindings"), "environment_bindings")
        headers = _binding_map(raw.get("header_bindings"), "header_bindings")
        if transport == "stdio":
            command = Path(str(raw.get("command") or ""))
            if not command.is_absolute():
                raise LocalMcpConfigError(
                    "stdio command must be an absolute fixed path"
                )
            args = raw.get("args", [])
            if (
                not isinstance(args, list)
                or len(args) > 100
                or not all(isinstance(item, str) for item in args)
            ):
                raise LocalMcpConfigError("stdio args must be a bounded string list")
            cwd_value = raw.get("cwd")
            cwd = Path(str(cwd_value)) if cwd_value is not None else None
            if cwd is not None and not cwd.is_absolute():
                raise LocalMcpConfigError("stdio cwd must be an absolute fixed path")
            if raw.get("url") or headers:
                raise LocalMcpConfigError("stdio server cannot configure HTTP fields")
            return cls(
                local_server_id=local_server_id,
                display_name=display_name,
                transport=transport,
                command=str(command),
                args=tuple(args),
                cwd=str(cwd) if cwd else None,
                environment_bindings=env,
                call_timeout_seconds=timeout,
            )
        if transport not in {"streamable_http", "private_http"}:
            raise LocalMcpConfigError("Unsupported local MCP transport")
        if raw.get("command") or raw.get("args") or raw.get("cwd") or env:
            raise LocalMcpConfigError("HTTP server cannot configure stdio fields")
        approved = bool(raw.get("approved_private_network", False))
        if transport == "private_http" and not approved:
            raise LocalMcpConfigError(
                "private_http requires approved_private_network=true in local config"
            )
        url = _validated_http_url(raw.get("url"), private=transport == "private_http")
        return cls(
            local_server_id=local_server_id,
            display_name=display_name,
            transport=transport,
            url=url,
            header_bindings=headers,
            approved_private_network=approved,
            call_timeout_seconds=timeout,
        )

    def public_descriptor(self) -> dict[str, str]:
        return {
            "local_server_id": self.local_server_id,
            "display_name": self.display_name,
            "transport": self.transport,
        }


@dataclass
class LocalMcpServerState:
    catalog_generation: int = 0
    snapshot_sha256: str | None = None
    status: str = "offline"


class LocalMcpHost:
    def __init__(
        self,
        *,
        runtime_id: str,
        servers: list[LocalMcpServerConfig],
        state_path: Path,
    ) -> None:
        self.runtime_id = _identifier(runtime_id, "runtime_id")
        if not servers or len(servers) > 100:
            raise LocalMcpConfigError(
                "Local MCP runtime must configure 1 to 100 servers"
            )
        if len({item.local_server_id for item in servers}) != len(servers):
            raise LocalMcpConfigError("Local MCP server ids must be unique")
        self.servers = {item.local_server_id: item for item in servers}
        self.state_path = state_path
        self.states = {server_id: LocalMcpServerState() for server_id in self.servers}
        self.connection_instance_id: str | None = None
        self._active_calls: dict[str, asyncio.Task[None]] = {}
        self._call_metadata: dict[str, dict[str, Any]] = {}
        self._load_state()

    @classmethod
    def from_path(cls, path: str | Path) -> "LocalMcpHost":
        config_path = Path(path).expanduser().resolve()
        try:
            raw = json.loads(config_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise LocalMcpConfigError(f"Cannot read local MCP config: {exc}") from exc
        if not isinstance(raw, dict):
            raise LocalMcpConfigError("Local MCP config must be a JSON object")
        extra = set(raw).difference({"runtime_id", "servers", "state_file"})
        if extra:
            raise LocalMcpConfigError(f"Unsupported runtime fields: {sorted(extra)}")
        server_values = raw.get("servers")
        if not isinstance(server_values, list):
            raise LocalMcpConfigError("servers must be a list")
        servers = [
            LocalMcpServerConfig.from_dict(item)
            for item in server_values
            if isinstance(item, dict)
        ]
        if len(servers) != len(server_values):
            raise LocalMcpConfigError("Every server entry must be an object")
        state_file = raw.get("state_file")
        state_path = (
            Path(str(state_file)).expanduser().resolve()
            if state_file
            else config_path.with_suffix(config_path.suffix + ".state.json")
        )
        return cls(
            runtime_id=str(raw.get("runtime_id", "")),
            servers=servers,
            state_path=state_path,
        )

    def _load_state(self) -> None:
        try:
            raw = json.loads(self.state_path.read_text())
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, dict) or raw.get("runtime_id") != self.runtime_id:
            return
        values = raw.get("servers")
        if not isinstance(values, dict):
            return
        for server_id, state in values.items():
            if server_id not in self.states or not isinstance(state, dict):
                continue
            self.states[server_id].catalog_generation = max(
                0, int(state.get("catalog_generation", 0))
            )
            digest = state.get("snapshot_sha256")
            self.states[server_id].snapshot_sha256 = (
                str(digest) if isinstance(digest, str) else None
            )

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "runtime_id": self.runtime_id,
            "servers": {
                server_id: {
                    "catalog_generation": state.catalog_generation,
                    "snapshot_sha256": state.snapshot_sha256,
                }
                for server_id, state in self.states.items()
            },
        }
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
        os.chmod(temporary, 0o600)
        temporary.replace(self.state_path)

    def registration_payload(self) -> dict[str, Any]:
        return {
            "type": "mcp_runtime_registered",
            "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
            "connection_instance_id": self.connection_instance_id,
            "runtime_id": self.runtime_id,
            "capabilities": list(MCP_THIN_CLIENT_CAPABILITIES),
            "servers": [server.public_descriptor() for server in self.servers.values()],
            "unresolved_calls": [
                {
                    "request_id": request_id,
                    "local_server_id": metadata["local_server_id"],
                    "action_class": metadata["action_class"],
                    "status": "unknown",
                }
                for request_id, metadata in self._call_metadata.items()
                if metadata.get("dispatched")
                and metadata.get("action_class")
                in {"write", "destructive", "production"}
            ],
        }

    @contextlib.asynccontextmanager
    async def _session(
        self, config: LocalMcpServerConfig
    ) -> AsyncIterator[tuple[ClientSession, types.InitializeResult]]:
        if config.transport == "stdio":
            parameters = StdioServerParameters(
                command=str(config.command),
                args=list(config.args),
                cwd=config.cwd,
                env=_resolved_bindings(config.environment_bindings),
            )
            async with stdio_client(parameters) as (read_stream, write_stream):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    client_info=types.Implementation(
                        name="gateway-thin-client-local-mcp", version="1"
                    ),
                ) as session:
                    initialized = await session.initialize()
                    yield session, initialized
            return
        headers = _resolved_bindings(config.header_bindings)
        timeout = httpx.Timeout(
            connect=min(config.call_timeout_seconds, 30.0),
            read=None,
            write=min(config.call_timeout_seconds, 30.0),
            pool=min(config.call_timeout_seconds, 30.0),
        )
        async with httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            async with streamable_http_client(
                str(config.url), http_client=client, terminate_on_close=True
            ) as (read_stream, write_stream, _):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    client_info=types.Implementation(
                        name="gateway-thin-client-local-mcp", version="1"
                    ),
                ) as session:
                    initialized = await session.initialize()
                    yield session, initialized

    async def _list_tools(
        self, config: LocalMcpServerConfig
    ) -> tuple[types.InitializeResult, list[types.Tool]]:
        tools: list[types.Tool] = []
        async with self._session(config) as (session, initialized):
            cursor: str | None = None
            while True:
                page = await session.list_tools(cursor=cursor)
                tools.extend(page.tools)
                if len(tools) > 500:
                    raise LocalMcpConfigError("Local MCP catalog exceeds 500 tools")
                cursor = page.nextCursor
                if not cursor:
                    break
        return initialized, tools

    async def catalog_snapshot(self, local_server_id: str) -> dict[str, Any]:
        config = self.servers[local_server_id]
        state = self.states[local_server_id]
        try:
            initialized, tools = await self._list_tools(config)
            snapshot = []
            for tool in tools:
                descriptor = _tool_descriptor(tool)
                snapshot.append(
                    {
                        "upstream_name": tool.name,
                        "input_schema": descriptor["input"],
                        "output_schema": descriptor["output"],
                        "title": descriptor["title"],
                        "description": descriptor["description"],
                        "annotations": descriptor["annotations"],
                        "icons": descriptor["icons"],
                        "execution": descriptor["execution"],
                        "component_meta": descriptor["component_meta"],
                    }
                )
            server_instructions = str(initialized.instructions or "")
            digest = _sha256_json(
                {"tools": snapshot, "server_instructions": server_instructions}
            )
            if digest != state.snapshot_sha256:
                state.catalog_generation += 1
                state.snapshot_sha256 = digest
                self._save_state()
            state.status = "online"
            return {
                "type": "mcp_catalog_snapshot",
                "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                "mcp_protocol_version": "2025-11-25",
                "connection_instance_id": self.connection_instance_id,
                "runtime_id": self.runtime_id,
                "local_server_id": local_server_id,
                "catalog_generation": max(1, state.catalog_generation),
                "server_instructions": server_instructions,
                "tools": snapshot,
            }
        except Exception:
            state.status = "failed"
            raise

    async def _find_tool(self, session: ClientSession, name: str) -> types.Tool:
        cursor: str | None = None
        while True:
            page = await session.list_tools(cursor=cursor)
            for tool in page.tools:
                if tool.name == name:
                    return tool
            cursor = page.nextCursor
            if not cursor:
                raise LocalMcpConfigError("Local MCP tool no longer exists")

    async def _execute_call(
        self,
        message: dict[str, Any],
        send: Callable[[dict[str, Any]], Awaitable[Any]],
    ) -> None:
        request_id = str(message["request_id"])
        local_server_id = str(message["local_server_id"])
        action_class = str(message.get("action_class", "read"))
        config = self.servers[local_server_id]
        metadata = self._call_metadata[request_id]
        try:
            async with self._session(config) as (session, _):
                tool = await self._find_tool(session, str(message["tool_name"]))
                if _tool_schema_hash(tool) != str(message["schema_hash"]):
                    raise LocalMcpConfigError(
                        "Local MCP schema changed after Gateway selection"
                    )
                metadata["dispatched"] = True
                result = await asyncio.wait_for(
                    session.call_tool(
                        str(message["tool_name"]), dict(message.get("arguments") or {})
                    ),
                    timeout=config.call_timeout_seconds,
                )
            await send(
                {
                    "type": "mcp_call_result",
                    "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message["schema_hash"],
                    "catalog_generation": message["catalog_generation"],
                    "result": result.model_dump(by_alias=True, exclude_none=True),
                }
            )
            metadata["terminal_sent"] = True
        except asyncio.CancelledError:
            await send(
                {
                    "type": "mcp_call_failed",
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message["schema_hash"],
                    "catalog_generation": message["catalog_generation"],
                    "code": "MCP_CALL_CANCELLED",
                    "message": "Local MCP call was cancelled",
                    "unknown_outcome": bool(metadata.get("dispatched"))
                    and action_class in {"write", "destructive", "production"},
                    "retryable": False,
                    "http_status": 499,
                }
            )
            raise
        except Exception as exc:
            unknown = bool(metadata.get("dispatched")) and action_class in {
                "write",
                "destructive",
                "production",
            }
            await send(
                {
                    "type": "mcp_call_failed",
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message.get("schema_hash"),
                    "catalog_generation": message.get("catalog_generation"),
                    "code": "MCP_LOCAL_RUNTIME_FAILED",
                    "message": str(exc)[:500],
                    "unknown_outcome": unknown,
                    "retryable": not unknown,
                    "http_status": 502,
                }
            )
            metadata["terminal_sent"] = True
        finally:
            self._active_calls.pop(request_id, None)
            if metadata.get("terminal_sent") or not metadata.get("dispatched"):
                self._call_metadata.pop(request_id, None)

    def _validate_gateway_call(self, message: dict[str, Any]) -> None:
        if (
            str(message.get("connection_instance_id", ""))
            != self.connection_instance_id
        ):
            raise LocalMcpConfigError("Gateway call references a stale connection")
        if str(message.get("runtime_id", "")) != self.runtime_id:
            raise LocalMcpConfigError("Gateway call references another runtime")
        local_server_id = str(message.get("local_server_id", ""))
        if local_server_id not in self.servers:
            raise LocalMcpConfigError("Gateway call references an unknown local server")
        required = {
            "request_id",
            "server_id",
            "revision_id",
            "tool_name",
            "schema_hash",
            "catalog_generation",
            "arguments",
            "action_class",
        }
        missing = [name for name in required if name not in message]
        if missing:
            raise LocalMcpConfigError(f"Gateway call is missing fields: {missing}")
        # Executable paths, process arguments, environment bindings, URLs and headers
        # are intentionally absent from the Gateway-controlled call contract.
        forbidden = {
            "command",
            "args",
            "cwd",
            "env",
            "environment",
            "environment_bindings",
            "url",
            "headers",
            "header_bindings",
        }
        if forbidden.intersection(message):
            raise LocalMcpConfigError(
                "Gateway attempted to override local MCP configuration"
            )

    async def handle_gateway_message(
        self,
        message: dict[str, Any],
        send: Callable[[dict[str, Any]], Awaitable[Any]],
    ) -> bool:
        message_type = str(message.get("type", ""))
        if message_type == "mcp_gateway_hello":
            if (
                str(message.get("protocol_version", ""))
                != MCP_THIN_CLIENT_PROTOCOL_VERSION
            ):
                raise LocalMcpConfigError(
                    "Gateway thin-client MCP protocol is incompatible"
                )
            self.connection_instance_id = str(message.get("connection_instance_id", ""))
            if not self.connection_instance_id:
                raise LocalMcpConfigError(
                    "Gateway did not issue a connection instance id"
                )
            await send(self.registration_payload())
            return True
        if message_type in {"mcp_refresh_catalog", "mcp_discover"}:
            self._validate_control_identity(message)
            local_server_id = str(message.get("local_server_id", ""))
            await send(await self.catalog_snapshot(local_server_id))
            return True
        if message_type == "mcp_call":
            self._validate_gateway_call(message)
            request_id = _identifier(message.get("request_id"), "request_id")
            if request_id in self._active_calls:
                raise LocalMcpConfigError("Duplicate active local MCP request id")
            self._call_metadata[request_id] = {
                "local_server_id": str(message["local_server_id"]),
                "action_class": str(message.get("action_class", "read")),
                "dispatched": False,
            }
            task = asyncio.create_task(self._execute_call(message, send))
            self._active_calls[request_id] = task
            return True
        if message_type == "mcp_cancel":
            self._validate_control_identity(message)
            request_id = str(message.get("request_id", ""))
            task = self._active_calls.get(request_id)
            if task is not None:
                task.cancel()
            return True
        if message_type == "mcp_restart_server":
            self._validate_control_identity(message)
            local_server_id = str(message.get("local_server_id", ""))
            await self._cancel_server_calls(local_server_id)
            await send(await self.catalog_snapshot(local_server_id))
            return True
        if message_type == "mcp_shutdown_server":
            self._validate_control_identity(message)
            local_server_id = str(message.get("local_server_id", ""))
            await self._cancel_server_calls(local_server_id)
            self.states[local_server_id].status = "offline"
            await send(
                {
                    "type": "mcp_server_status",
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "status": "offline",
                }
            )
            return True
        return False

    def _validate_control_identity(self, message: dict[str, Any]) -> None:
        if (
            str(message.get("connection_instance_id", ""))
            != self.connection_instance_id
        ):
            raise LocalMcpConfigError(
                "Gateway control message references a stale connection"
            )
        if str(message.get("runtime_id", "")) != self.runtime_id:
            raise LocalMcpConfigError(
                "Gateway control message references another runtime"
            )
        local_server_id = str(message.get("local_server_id", ""))
        if local_server_id not in self.servers:
            raise LocalMcpConfigError(
                "Gateway control message references an unknown server"
            )

    async def _cancel_server_calls(self, local_server_id: str) -> None:
        tasks = [
            task
            for request_id, task in self._active_calls.items()
            if self._call_metadata.get(request_id, {}).get("local_server_id")
            == local_server_id
        ]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def on_disconnect(self) -> None:
        tasks = list(self._active_calls.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.connection_instance_id = None
        self._save_state()
