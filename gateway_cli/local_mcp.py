from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import os
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.shared.uri_template import InvalidUriTemplate, UriTemplate

MCP_THIN_CLIENT_PROTOCOL_VERSION = "1.0"
MCP_THIN_CLIENT_CAPABILITIES = (
    "mcp_runtime_v1",
    "mcp_catalog_snapshot",
    "mcp_catalog_delta",
    "mcp_resources_v1",
    "mcp_prompts_v1",
    "mcp_completion_v1",
    "mcp_roots_v1",
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
        "input": dict(tool.input_schema or {}),
        "output": dict(tool.output_schema) if tool.output_schema else None,
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


def _path_has_link_component(path: Path) -> bool:
    for candidate in (path, *path.parents):
        try:
            if candidate.is_symlink():
                return True
            is_junction = getattr(candidate, "is_junction", None)
            if callable(is_junction) and is_junction():
                return True
        except OSError:
            return True
    return False


@dataclass(frozen=True, slots=True)
class LocalMcpRootConfig:
    uri: str
    root_uri_sha256: str
    root_name: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> LocalMcpRootConfig:
        extra = set(raw).difference({"path", "name"})
        if extra:
            raise LocalMcpConfigError(
                f"Unsupported local MCP root fields: {sorted(extra)}"
            )
        path_value = raw.get("path")
        if not isinstance(path_value, str) or not path_value.strip():
            raise LocalMcpConfigError("Local MCP root path must be an absolute directory")
        path = Path(path_value)
        if not path.is_absolute() or ".." in path.parts:
            raise LocalMcpConfigError(
                "Local MCP root path must be absolute and must not contain traversal"
            )
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise LocalMcpConfigError("Local MCP root path does not exist") from exc
        if not resolved.is_dir():
            raise LocalMcpConfigError("Local MCP root path must be a directory")
        if _path_has_link_component(path):
            raise LocalMcpConfigError(
                "Local MCP root path must not contain symlink or junction components"
            )
        name = " ".join(str(raw.get("name") or "root").split())[:120]
        if not name or any(character in name for character in ("/", "\\", "\x00")):
            raise LocalMcpConfigError("Local MCP root name is invalid")
        uri = resolved.as_uri()
        return cls(
            uri=uri,
            root_uri_sha256=hashlib.sha256(uri.encode("utf-8")).hexdigest(),
            root_name=name,
        )

    def public_descriptor(self) -> dict[str, str]:
        return {
            "root_uri_sha256": self.root_uri_sha256,
            "root_uri_hint": f"local-root:{self.root_uri_sha256[:12]}",
            "root_name": self.root_name,
        }


def _root_sync_sha256(*, policy_generation: int, roots: list[dict[str, Any]]) -> str:
    return _sha256_json(
        {
            "policy_generation": policy_generation,
            "roots": sorted(roots, key=lambda item: str(item["root_uri_sha256"])),
        }
    )


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
    roots: tuple[LocalMcpRootConfig, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> LocalMcpServerConfig:
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
            "roots",
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
        root_values = raw.get("roots", [])
        if not isinstance(root_values, list) or len(root_values) > 64:
            raise LocalMcpConfigError("Local MCP roots must be a bounded list")
        if not all(isinstance(item, dict) for item in root_values):
            raise LocalMcpConfigError("Every local MCP root must be an object")
        roots = tuple(LocalMcpRootConfig.from_dict(item) for item in root_values)
        root_hashes = [item.root_uri_sha256 for item in roots]
        if len(set(root_hashes)) != len(root_hashes):
            raise LocalMcpConfigError("Local MCP root identities must be unique")
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
                roots=roots,
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
        if transport == "private_http" and roots:
            raise LocalMcpConfigError(
                "private_http servers cannot receive thin-client filesystem roots"
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
            roots=roots,
        )

    def public_descriptor(self) -> dict[str, Any]:
        descriptor: dict[str, Any] = {
            "local_server_id": self.local_server_id,
            "display_name": self.display_name,
            "transport": self.transport,
        }
        if self.roots:
            descriptor["roots"] = [root.public_descriptor() for root in self.roots]
        return descriptor


@dataclass(frozen=True, slots=True)
class LocalMcpHandshake:
    protocol_version: str
    instructions: str


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
        self._notification_tasks: dict[str, asyncio.Task[None]] = {}
        self._call_metadata: dict[str, dict[str, Any]] = {}
        self._approved_roots: dict[str, dict[str, LocalMcpRootConfig]] = {
            server_id: {} for server_id in self.servers
        }
        self._root_policy_generation = {server_id: 0 for server_id in self.servers}
        self._root_server_ids: dict[str, str | None] = {
            server_id: None for server_id in self.servers
        }
        self._root_notification_events = {
            server_id: asyncio.Event() for server_id in self.servers
        }
        self._load_state()

    @classmethod
    def from_path(cls, path: str | Path) -> LocalMcpHost:
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

    def _clear_root_authority(self) -> None:
        for local_server_id in self.servers:
            self._approved_roots[local_server_id].clear()
            self._root_policy_generation[local_server_id] = 0
            self._root_server_ids[local_server_id] = None
            self._root_notification_events[local_server_id].clear()

    def _configured_roots(self, local_server_id: str) -> dict[str, LocalMcpRootConfig]:
        return {
            root.root_uri_sha256: root
            for root in self.servers[local_server_id].roots
        }

    def _root_list_result(self, local_server_id: str) -> types.ListRootsResult:
        roots = [
            types.Root(uri=root.uri, name=root.root_name)
            for _, root in sorted(self._approved_roots[local_server_id].items())
        ]
        return types.ListRootsResult(roots=roots)

    def _root_list_callback(
        self, local_server_id: str
    ) -> Callable[[Any], Awaitable[types.ListRootsResult]]:
        async def callback(_context: Any) -> types.ListRootsResult:
            return self._root_list_result(local_server_id)

        return callback

    def _validate_gateway_roots_update(
        self, message: dict[str, Any]
    ) -> tuple[str, str, int, list[dict[str, Any]]]:
        self._validate_control_identity(message)
        forbidden = {
            "path",
            "uri",
            "url",
            "cwd",
            "command",
            "args",
            "env",
            "environment",
            "environment_bindings",
            "headers",
            "header_bindings",
        }
        if forbidden.intersection(message):
            raise LocalMcpConfigError(
                "Gateway attempted to override local MCP root configuration"
            )
        required = {"server_id", "policy_generation", "root_set_sha256", "roots"}
        missing = [name for name in required if name not in message]
        if missing:
            raise LocalMcpConfigError(
                f"Gateway roots update is missing fields: {missing}"
            )
        local_server_id = str(message["local_server_id"])
        server_id = _identifier(message.get("server_id"), "server_id")
        bound_server_id = self._root_server_ids[local_server_id]
        if bound_server_id is not None and bound_server_id != server_id:
            raise LocalMcpConfigError(
                "Gateway roots update references another Gateway server"
            )
        generation = message.get("policy_generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise LocalMcpConfigError("policy_generation must be a positive integer")
        if generation < self._root_policy_generation[local_server_id]:
            raise LocalMcpConfigError("Gateway roots update policy generation is stale")
        digest = str(message.get("root_set_sha256") or "")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise LocalMcpConfigError("root_set_sha256 must be a lowercase SHA-256 digest")
        raw_roots = message.get("roots")
        if not isinstance(raw_roots, list) or len(raw_roots) > 64:
            raise LocalMcpConfigError("Gateway roots update must contain a bounded list")
        configured = self._configured_roots(local_server_id)
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for value in raw_roots:
            if not isinstance(value, dict) or set(value) != {
                "root_uri_sha256",
                "root_name",
                "version",
            }:
                raise LocalMcpConfigError(
                    "Gateway roots update contains an invalid root descriptor"
                )
            root_hash = str(value.get("root_uri_sha256") or "")
            if re.fullmatch(r"[0-9a-f]{64}", root_hash) is None or root_hash in seen:
                raise LocalMcpConfigError(
                    "Gateway roots update contains an invalid root identity"
                )
            local_root = configured.get(root_hash)
            if local_root is None:
                raise LocalMcpConfigError(
                    "Gateway roots update references a root outside the local allowlist"
                )
            root_name = " ".join(str(value.get("root_name") or "").split())
            if root_name != local_root.root_name:
                raise LocalMcpConfigError(
                    "Gateway roots update root name does not match local configuration"
                )
            version = value.get("version")
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                raise LocalMcpConfigError("Gateway roots update version is invalid")
            seen.add(root_hash)
            normalized.append(
                {
                    "root_uri_sha256": root_hash,
                    "root_name": root_name,
                    "version": version,
                }
            )
        normalized.sort(key=lambda item: str(item["root_uri_sha256"]))
        expected_digest = _root_sync_sha256(
            policy_generation=generation, roots=normalized
        )
        if digest != expected_digest:
            raise LocalMcpConfigError("Gateway roots update digest does not match payload")
        return local_server_id, server_id, generation, normalized

    def _apply_gateway_roots_update(self, message: dict[str, Any]) -> dict[str, Any]:
        local_server_id, server_id, generation, roots = (
            self._validate_gateway_roots_update(message)
        )
        configured = self._configured_roots(local_server_id)
        previous_hashes = set(self._approved_roots[local_server_id])
        approved = {
            str(item["root_uri_sha256"]): configured[str(item["root_uri_sha256"])]
            for item in roots
        }
        self._approved_roots[local_server_id] = approved
        self._root_policy_generation[local_server_id] = generation
        self._root_server_ids[local_server_id] = server_id
        if previous_hashes != set(approved):
            self._root_notification_events[local_server_id].set()
        return {
            "type": "mcp_roots_update_ack",
            "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
            "connection_instance_id": self.connection_instance_id,
            "runtime_id": self.runtime_id,
            "local_server_id": local_server_id,
            "server_id": server_id,
            "policy_generation": generation,
            "root_set_sha256": str(message["root_set_sha256"]),
        }

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

    async def _negotiate_session(
        self, session: ClientSession, *, roots_required: bool = False
    ) -> LocalMcpHandshake:
        if roots_required:
            initialized = await session.initialize()
            return LocalMcpHandshake(
                protocol_version=initialized.protocol_version,
                instructions=str(initialized.instructions or ""),
            )
        try:
            discovered = await session.discover()
        except MCPError as exc:
            if exc.code != -32601:
                raise
            initialized = await session.initialize()
            return LocalMcpHandshake(
                protocol_version=initialized.protocol_version,
                instructions=str(initialized.instructions or ""),
            )
        protocol_version = session.protocol_version
        if not isinstance(protocol_version, str) or not protocol_version:
            raise LocalMcpConfigError(
                "Local MCP discovery did not establish a protocol version"
            )
        return LocalMcpHandshake(
            protocol_version=protocol_version,
            instructions=str(discovered.instructions or ""),
        )

    @contextlib.asynccontextmanager
    async def _session(
        self,
        config: LocalMcpServerConfig,
        *,
        message_handler: Callable[[Any], Awaitable[None]] | None = None,
    ) -> AsyncIterator[tuple[ClientSession, LocalMcpHandshake]]:
        list_roots_callback = (
            self._root_list_callback(config.local_server_id) if config.roots else None
        )
        if config.transport == "stdio":
            parameters = StdioServerParameters(
                command=str(config.command),
                args=list(config.args),
                cwd=config.cwd,
                env=_resolved_bindings(config.environment_bindings),
            )
            async with stdio_client(parameters) as (
                read_stream,
                write_stream,
            ), ClientSession(
                read_stream,
                write_stream,
                client_info=types.Implementation(
                    name="gateway-thin-client-local-mcp", version="1"
                ),
                message_handler=message_handler,
                list_roots_callback=list_roots_callback,
            ) as session:
                handshake = await self._negotiate_session(
                    session, roots_required=bool(config.roots)
                )
                yield session, handshake
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
            trust_env=False,
        ) as client, streamable_http_client(
            str(config.url), http_client=client, terminate_on_close=True
        ) as (read_stream, write_stream), ClientSession(
            read_stream,
            write_stream,
            client_info=types.Implementation(
                name="gateway-thin-client-local-mcp", version="1"
            ),
            message_handler=message_handler,
            list_roots_callback=list_roots_callback,
        ) as session:
            handshake = await self._negotiate_session(
                session, roots_required=bool(config.roots)
            )
            yield session, handshake

    async def _list_tools(
        self, config: LocalMcpServerConfig
    ) -> tuple[LocalMcpHandshake, list[types.Tool]]:
        tools: list[types.Tool] = []
        async with self._session(config) as (session, handshake):
            cursor: str | None = None
            while True:
                page = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
                tools.extend(page.tools)
                if len(tools) > 500:
                    raise LocalMcpConfigError("Local MCP catalog exceeds 500 tools")
                cursor = page.next_cursor
                if not cursor:
                    break
        return handshake, tools

    async def _collect_session_resource_catalog(
        self, session: ClientSession
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        async def collect(method_name: str, field_name: str) -> list[dict[str, Any]]:
            result: list[dict[str, Any]] = []
            cursor: str | None = None
            while True:
                params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
                try:
                    page = await getattr(session, method_name)(params=params)
                except MCPError as exc:
                    if exc.code == -32601:
                        return []
                    raise
                values = getattr(page, field_name, None)
                if not isinstance(values, list):
                    raise LocalMcpConfigError(
                        f"Local MCP {method_name} response is invalid"
                    )
                for item in values:
                    payload = _model_json(item)
                    if not isinstance(payload, dict):
                        raise LocalMcpConfigError(
                            "Local MCP resource descriptor is invalid"
                        )
                    result.append(payload)
                if len(result) > 5000:
                    raise LocalMcpConfigError(
                        "Local MCP resource catalog exceeds 5000 entries"
                    )
                cursor = page.next_cursor
                if not cursor:
                    return result

        resources = await collect("list_resources", "resources")
        templates = await collect("list_resource_templates", "resource_templates")
        return resources, templates

    async def _list_resource_catalog(
        self, config: LocalMcpServerConfig
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        async with self._session(config) as (session, _handshake):
            return await self._collect_session_resource_catalog(session)

    async def _collect_session_prompt_catalog(
        self, session: ClientSession
    ) -> list[dict[str, Any]]:
        prompts: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            try:
                page = await session.list_prompts(params=params)
            except MCPError as exc:
                if exc.code == -32601:
                    return []
                raise
            values = getattr(page, "prompts", None)
            if not isinstance(values, list):
                raise LocalMcpConfigError("Local MCP list_prompts response is invalid")
            for item in values:
                payload = _model_json(item)
                if not isinstance(payload, dict):
                    raise LocalMcpConfigError("Local MCP prompt descriptor is invalid")
                prompts.append(payload)
            if len(prompts) > 5000:
                raise LocalMcpConfigError("Local MCP prompt catalog exceeds 5000 entries")
            cursor = page.next_cursor
            if not cursor:
                return prompts

    async def _list_prompt_catalog(
        self, config: LocalMcpServerConfig
    ) -> list[dict[str, Any]]:
        async with self._session(config) as (session, _handshake):
            return await self._collect_session_prompt_catalog(session)

    async def _find_prompt_descriptor(
        self,
        session: ClientSession,
        prompt_name_sha256: str,
    ) -> dict[str, Any]:
        prompts = await self._collect_session_prompt_catalog(session)
        for candidate in prompts:
            name = candidate.get("name")
            if not isinstance(name, str):
                continue
            normalized = name.strip()
            if hashlib.sha256(normalized.encode("utf-8")).hexdigest() == prompt_name_sha256:
                return candidate
        raise LocalMcpConfigError("Local MCP prompt no longer exists")

    async def catalog_snapshot(self, local_server_id: str) -> dict[str, Any]:
        config = self.servers[local_server_id]
        state = self.states[local_server_id]
        try:
            handshake, tools = await self._list_tools(config)
            resources, resource_templates = await self._list_resource_catalog(config)
            prompts = await self._list_prompt_catalog(config)
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
            server_instructions = handshake.instructions
            digest = _sha256_json(
                {
                    "tools": snapshot,
                    "resources": resources,
                    "resource_templates": resource_templates,
                    "prompts": prompts,
                    "server_instructions": server_instructions,
                }
            )
            if digest != state.snapshot_sha256:
                state.catalog_generation += 1
                state.snapshot_sha256 = digest
                self._save_state()
            state.status = "online"
            return {
                "type": "mcp_catalog_snapshot",
                "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                "mcp_protocol_version": handshake.protocol_version,
                "connection_instance_id": self.connection_instance_id,
                "runtime_id": self.runtime_id,
                "local_server_id": local_server_id,
                "catalog_generation": max(1, state.catalog_generation),
                "server_instructions": server_instructions,
                "tools": snapshot,
                "resources": resources,
                "resource_templates": resource_templates,
                "prompts": prompts,
            }
        except Exception:
            state.status = "failed"
            raise

    async def _find_tool(self, session: ClientSession, name: str) -> types.Tool:
        cursor: str | None = None
        while True:
            page = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
            for tool in page.tools:
                if tool.name == name:
                    return tool
            cursor = page.next_cursor
            if not cursor:
                raise LocalMcpConfigError("Local MCP tool no longer exists")

    @staticmethod
    def _resource_uri_identity(raw: dict[str, Any], *, entity_kind: str) -> tuple[str, str]:
        if entity_kind not in {"resource", "resource_template"}:
            raise LocalMcpConfigError("Gateway resource kind is invalid")
        key = "uri" if entity_kind == "resource" else "uriTemplate"
        value = raw.get(key)
        if not isinstance(value, str):
            raise LocalMcpConfigError("Local MCP resource descriptor has no URI identity")
        uri = value.strip()
        if (
            not uri
            or len(uri.encode("utf-8")) > 4096
            or any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in uri)
            or not urlparse(uri).scheme
        ):
            raise LocalMcpConfigError("Local MCP resource URI identity is invalid")
        return uri, hashlib.sha256(uri.encode("utf-8")).hexdigest()

    async def _find_resource_descriptor(
        self,
        session: ClientSession,
        *,
        entity_kind: str,
        uri_sha256: str,
    ) -> dict[str, Any]:
        resources, templates = await self._collect_session_resource_catalog(session)
        candidates = resources if entity_kind == "resource" else templates
        for candidate in candidates:
            try:
                _uri, candidate_hash = self._resource_uri_identity(
                    candidate, entity_kind=entity_kind
                )
            except LocalMcpConfigError:
                continue
            if candidate_hash == uri_sha256:
                return candidate
        raise LocalMcpConfigError("Local MCP resource no longer exists")

    @staticmethod
    def _expand_resource_descriptor(
        descriptor: dict[str, Any],
        *,
        entity_kind: str,
        arguments: dict[str, str],
    ) -> str:
        uri, _uri_hash = LocalMcpHost._resource_uri_identity(
            descriptor, entity_kind=entity_kind
        )
        if entity_kind == "resource":
            if arguments:
                raise LocalMcpConfigError("Concrete MCP resource does not accept arguments")
            return uri
        try:
            template = UriTemplate.parse(uri, max_length=4096, max_variables=128)
            expanded = template.expand(arguments)
        except (InvalidUriTemplate, TypeError, ValueError) as exc:
            raise LocalMcpConfigError(
                "Local MCP resource template cannot be expanded safely"
            ) from exc
        if not isinstance(expanded, str) or not expanded or len(expanded.encode("utf-8")) > 4096:
            raise LocalMcpConfigError("Expanded local MCP resource URI is invalid")
        return expanded

    async def _execute_resource_read(
        self,
        message: dict[str, Any],
        send: Callable[[dict[str, Any]], Awaitable[Any]],
    ) -> None:
        request_id = str(message["request_id"])
        local_server_id = str(message["local_server_id"])
        config = self.servers[local_server_id]
        metadata = self._call_metadata[request_id]
        entity_kind = str(message["entity_kind"])
        arguments = dict(message.get("arguments") or {})
        try:
            state_generation = max(1, self.states[local_server_id].catalog_generation)
            if int(message["catalog_generation"]) != state_generation:
                raise LocalMcpConfigError(
                    "Local MCP resource catalog changed after Gateway selection"
                )
            async with self._session(config) as (session, handshake):
                descriptor = await self._find_resource_descriptor(
                    session,
                    entity_kind=entity_kind,
                    uri_sha256=str(message["uri_sha256"]),
                )
                exact_uri = self._expand_resource_descriptor(
                    descriptor,
                    entity_kind=entity_kind,
                    arguments=arguments,
                )
                metadata["dispatched"] = True
                result = await asyncio.wait_for(
                    session.read_resource(exact_uri),
                    timeout=config.call_timeout_seconds,
                )
            payload = _model_json(result)
            if not isinstance(payload, dict):
                raise LocalMcpConfigError("Local MCP resource read result is invalid")
            await send(
                {
                    "type": "mcp_resource_read_result",
                    "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message["schema_hash"],
                    "catalog_generation": message["catalog_generation"],
                    "mcp_protocol_version": handshake.protocol_version,
                    "descriptor": descriptor,
                    "result": payload,
                }
            )
            metadata["terminal_sent"] = True
        except asyncio.CancelledError:
            await send(
                {
                    "type": "mcp_resource_read_failed",
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message.get("schema_hash"),
                    "catalog_generation": message.get("catalog_generation"),
                    "code": "MCP_RESOURCE_READ_CANCELLED",
                    "message": "Local MCP resource read was cancelled",
                    "retryable": False,
                    "http_status": 499,
                }
            )
            metadata["terminal_sent"] = True
            raise
        except (
            MCPError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            httpx.HTTPError,
        ) as exc:
            await send(
                {
                    "type": "mcp_resource_read_failed",
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message.get("schema_hash"),
                    "catalog_generation": message.get("catalog_generation"),
                    "code": "MCP_LOCAL_RESOURCE_READ_FAILED",
                    "message": str(exc)[:500],
                    "retryable": True,
                    "http_status": 502,
                }
            )
            metadata["terminal_sent"] = True
        finally:
            self._active_calls.pop(request_id, None)
            if metadata.get("terminal_sent") or not metadata.get("dispatched"):
                self._call_metadata.pop(request_id, None)

    async def _execute_prompt_get(
        self,
        message: dict[str, Any],
        send: Callable[[dict[str, Any]], Awaitable[Any]],
    ) -> None:
        request_id = str(message["request_id"])
        local_server_id = str(message["local_server_id"])
        config = self.servers[local_server_id]
        metadata = self._call_metadata[request_id]
        try:
            state_generation = max(1, self.states[local_server_id].catalog_generation)
            if int(message["catalog_generation"]) != state_generation:
                raise LocalMcpConfigError(
                    "Local MCP prompt catalog changed after Gateway selection"
                )
            async with self._session(config) as (session, handshake):
                descriptor = await self._find_prompt_descriptor(
                    session,
                    str(message["prompt_name_sha256"]),
                )
                prompt_name = str(descriptor.get("name") or "").strip()
                if not prompt_name:
                    raise LocalMcpConfigError("Local MCP prompt descriptor has no name")
                metadata["dispatched"] = True
                result = await asyncio.wait_for(
                    session.get_prompt(
                        prompt_name,
                        dict(message.get("arguments") or {}),
                        allow_input_required=False,
                    ),
                    timeout=config.call_timeout_seconds,
                )
            payload = _model_json(result)
            if not isinstance(payload, dict):
                raise LocalMcpConfigError("Local MCP prompt result is invalid")
            await send(
                {
                    "type": "mcp_prompt_get_result",
                    "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message["schema_hash"],
                    "catalog_generation": message["catalog_generation"],
                    "mcp_protocol_version": handshake.protocol_version,
                    "descriptor": descriptor,
                    "result": payload,
                }
            )
            metadata["terminal_sent"] = True
        except asyncio.CancelledError:
            await send(
                {
                    "type": "mcp_prompt_get_failed",
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message.get("schema_hash"),
                    "catalog_generation": message.get("catalog_generation"),
                    "code": "MCP_PROMPT_GET_CANCELLED",
                    "message": "Local MCP prompt retrieval was cancelled",
                    "retryable": False,
                    "http_status": 499,
                }
            )
            metadata["terminal_sent"] = True
            raise
        except (
            MCPError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            httpx.HTTPError,
        ) as exc:
            await send(
                {
                    "type": "mcp_prompt_get_failed",
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message.get("schema_hash"),
                    "catalog_generation": message.get("catalog_generation"),
                    "code": "MCP_LOCAL_PROMPT_GET_FAILED",
                    "message": str(exc)[:500],
                    "retryable": True,
                    "http_status": 502,
                }
            )
            metadata["terminal_sent"] = True
        finally:
            self._active_calls.pop(request_id, None)
            if metadata.get("terminal_sent") or not metadata.get("dispatched"):
                self._call_metadata.pop(request_id, None)

    async def _execute_completion(
        self,
        message: dict[str, Any],
        send: Callable[[dict[str, Any]], Awaitable[Any]],
    ) -> None:
        request_id = str(message["request_id"])
        local_server_id = str(message["local_server_id"])
        config = self.servers[local_server_id]
        metadata = self._call_metadata[request_id]
        try:
            state_generation = max(1, self.states[local_server_id].catalog_generation)
            if int(message["catalog_generation"]) != state_generation:
                raise LocalMcpConfigError(
                    "Local MCP completion catalog changed after Gateway selection"
                )
            ref_kind = str(message["ref_kind"])
            async with self._session(config) as (session, handshake):
                if ref_kind == "prompt":
                    descriptor = await self._find_prompt_descriptor(
                        session,
                        str(message["ref_key_sha256"]),
                    )
                    prompt_name = str(descriptor.get("name") or "").strip()
                    if not prompt_name:
                        raise LocalMcpConfigError("Local MCP prompt descriptor has no name")
                    reference: types.PromptReference | types.ResourceTemplateReference = (
                        types.PromptReference(name=prompt_name)
                    )
                else:
                    descriptor = await self._find_resource_descriptor(
                        session,
                        entity_kind="resource_template",
                        uri_sha256=str(message["ref_key_sha256"]),
                    )
                    uri, _uri_sha256 = self._resource_uri_identity(
                        descriptor,
                        entity_kind="resource_template",
                    )
                    reference = types.ResourceTemplateReference(uri=uri)
                metadata["dispatched"] = True
                result = await asyncio.wait_for(
                    session.complete(
                        reference,
                        dict(message["argument"]),
                        dict(message.get("context_arguments") or {}),
                    ),
                    timeout=config.call_timeout_seconds,
                )
            payload = _model_json(result)
            if not isinstance(payload, dict):
                raise LocalMcpConfigError("Local MCP completion result is invalid")
            await send(
                {
                    "type": "mcp_completion_result",
                    "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message["schema_hash"],
                    "catalog_generation": message["catalog_generation"],
                    "mcp_protocol_version": handshake.protocol_version,
                    "ref_kind": ref_kind,
                    "descriptor": descriptor,
                    "result": payload,
                }
            )
            metadata["terminal_sent"] = True
        except asyncio.CancelledError:
            await send(
                {
                    "type": "mcp_completion_failed",
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message.get("schema_hash"),
                    "catalog_generation": message.get("catalog_generation"),
                    "code": "MCP_COMPLETION_CANCELLED",
                    "message": "Local MCP completion was cancelled",
                    "retryable": False,
                    "http_status": 499,
                }
            )
            metadata["terminal_sent"] = True
            raise
        except (
            MCPError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            httpx.HTTPError,
        ) as exc:
            await send(
                {
                    "type": "mcp_completion_failed",
                    "connection_instance_id": self.connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "request_id": request_id,
                    "schema_hash": message.get("schema_hash"),
                    "catalog_generation": message.get("catalog_generation"),
                    "code": "MCP_LOCAL_COMPLETION_FAILED",
                    "message": str(exc)[:500],
                    "retryable": True,
                    "http_status": 502,
                }
            )
            metadata["terminal_sent"] = True
        finally:
            self._active_calls.pop(request_id, None)
            if metadata.get("terminal_sent") or not metadata.get("dispatched"):
                self._call_metadata.pop(request_id, None)

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
        except (
            MCPError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            httpx.HTTPError,
        ) as exc:
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

    def _validate_gateway_prompt(self, message: dict[str, Any]) -> None:
        self._validate_control_identity(message)
        required = {
            "request_id",
            "server_id",
            "entity_id",
            "revision_id",
            "schema_hash",
            "prompt_name_sha256",
            "catalog_generation",
            "arguments",
        }
        missing = [name for name in required if name not in message]
        if missing:
            raise LocalMcpConfigError(f"Gateway prompt request is missing fields: {missing}")
        for name in ("request_id", "server_id", "entity_id", "revision_id"):
            _identifier(message.get(name), name)
        for name in ("schema_hash", "prompt_name_sha256"):
            value = str(message.get(name) or "")
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise LocalMcpConfigError(f"{name} must be a lowercase SHA-256 digest")
        generation = message.get("catalog_generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise LocalMcpConfigError("catalog_generation must be a positive integer")
        arguments = message.get("arguments")
        if not isinstance(arguments, dict) or len(arguments) > 64:
            raise LocalMcpConfigError("Gateway prompt arguments must be a bounded object")
        total_bytes = 0
        for raw_name, raw_value in arguments.items():
            name = str(raw_name)
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", name) is None:
                raise LocalMcpConfigError("Gateway prompt argument name is invalid")
            if not isinstance(raw_value, str) or len(raw_value.encode("utf-8")) > 8192:
                raise LocalMcpConfigError("Gateway prompt argument value is invalid")
            total_bytes += len(name.encode("utf-8")) + len(raw_value.encode("utf-8"))
        if total_bytes > 65536:
            raise LocalMcpConfigError("Gateway prompt arguments exceed the total size limit")
        forbidden = {
            "prompt_name",
            "name",
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
                "Gateway attempted to override local MCP prompt configuration"
            )

    def _validate_gateway_completion(self, message: dict[str, Any]) -> None:
        self._validate_control_identity(message)
        required = {
            "request_id",
            "server_id",
            "entity_id",
            "revision_id",
            "schema_hash",
            "ref_kind",
            "ref_key_sha256",
            "catalog_generation",
            "argument",
            "context_arguments",
        }
        missing = [name for name in required if name not in message]
        if missing:
            raise LocalMcpConfigError(
                f"Gateway completion request is missing fields: {missing}"
            )
        for name in ("request_id", "server_id", "entity_id", "revision_id"):
            _identifier(message.get(name), name)
        for name in ("schema_hash", "ref_key_sha256"):
            value = str(message.get(name) or "")
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise LocalMcpConfigError(f"{name} must be a lowercase SHA-256 digest")
        if str(message.get("ref_kind")) not in {"prompt", "resource_template"}:
            raise LocalMcpConfigError("Gateway completion reference kind is invalid")
        generation = message.get("catalog_generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise LocalMcpConfigError("catalog_generation must be a positive integer")
        argument = message.get("argument")
        if not isinstance(argument, dict) or set(argument) != {"name", "value"}:
            raise LocalMcpConfigError("Gateway completion argument is invalid")
        argument_name = argument.get("name")
        argument_value = argument.get("value")
        if not isinstance(argument_name, str) or not isinstance(argument_value, str):
            raise LocalMcpConfigError("Gateway completion argument must contain strings")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", argument_name) is None:
            raise LocalMcpConfigError("Gateway completion argument name is invalid")
        if len(argument_value.encode("utf-8")) > 8192:
            raise LocalMcpConfigError("Gateway completion argument value is invalid")
        context_arguments = message.get("context_arguments")
        if not isinstance(context_arguments, dict) or len(context_arguments) > 64:
            raise LocalMcpConfigError("Gateway completion context must be a bounded object")
        total_bytes = len(argument_name.encode("utf-8")) + len(argument_value.encode("utf-8"))
        for raw_name, raw_value in context_arguments.items():
            name = str(raw_name)
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", name) is None:
                raise LocalMcpConfigError("Gateway completion context name is invalid")
            if not isinstance(raw_value, str) or len(raw_value.encode("utf-8")) > 8192:
                raise LocalMcpConfigError("Gateway completion context value is invalid")
            total_bytes += len(name.encode("utf-8")) + len(raw_value.encode("utf-8"))
        if total_bytes > 65536:
            raise LocalMcpConfigError("Gateway completion request exceeds the total size limit")
        forbidden = {
            "ref",
            "prompt_name",
            "uri",
            "uriTemplate",
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
                "Gateway attempted to override local MCP completion configuration"
            )

    def _validate_gateway_resource(self, message: dict[str, Any]) -> None:
        if (
            str(message.get("connection_instance_id", ""))
            != self.connection_instance_id
        ):
            raise LocalMcpConfigError("Gateway resource request references a stale connection")
        if str(message.get("runtime_id", "")) != self.runtime_id:
            raise LocalMcpConfigError("Gateway resource request references another runtime")
        local_server_id = str(message.get("local_server_id", ""))
        if local_server_id not in self.servers:
            raise LocalMcpConfigError("Gateway resource request references an unknown server")
        required = {
            "request_id",
            "server_id",
            "entity_kind",
            "entity_id",
            "revision_id",
            "schema_hash",
            "uri_sha256",
            "catalog_generation",
            "arguments",
        }
        missing = [name for name in required if name not in message]
        if missing:
            raise LocalMcpConfigError(f"Gateway resource request is missing fields: {missing}")
        if str(message.get("entity_kind")) not in {"resource", "resource_template"}:
            raise LocalMcpConfigError("Gateway resource request kind is invalid")
        for name in ("request_id", "server_id", "entity_id", "revision_id"):
            _identifier(message.get(name), name)
        for name in ("schema_hash", "uri_sha256"):
            value = str(message.get(name) or "")
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise LocalMcpConfigError(f"{name} must be a lowercase SHA-256 digest")
        generation = message.get("catalog_generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise LocalMcpConfigError("catalog_generation must be a positive integer")
        arguments = message.get("arguments")
        if not isinstance(arguments, dict) or len(arguments) > 128:
            raise LocalMcpConfigError("Gateway resource arguments must be a bounded object")
        for raw_name, raw_value in arguments.items():
            name = str(raw_name)
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", name) is None:
                raise LocalMcpConfigError("Gateway resource template argument name is invalid")
            if not isinstance(raw_value, str) or len(raw_value.encode("utf-8")) > 4096:
                raise LocalMcpConfigError("Gateway resource template argument value is invalid")
        forbidden = {
            "uri",
            "uriTemplate",
            "resource_uri",
            "resource_url",
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
                "Gateway attempted to override local MCP resource configuration"
            )

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

    async def _notification_listener(
        self,
        local_server_id: str,
        send: Callable[[dict[str, Any]], Awaitable[Any]],
    ) -> None:
        config = self.servers[local_server_id]

        async def handler(message: Any) -> None:
            root = getattr(message, "root", message)
            if isinstance(root, types.ToolListChangedNotification):
                method = "notifications/tools/list_changed"
            elif isinstance(root, types.PromptListChangedNotification):
                method = "notifications/prompts/list_changed"
            else:
                return
            connection_instance_id = self.connection_instance_id
            if not connection_instance_id:
                return
            await send(
                {
                    "type": "mcp_notification",
                    "protocol_version": MCP_THIN_CLIENT_PROTOCOL_VERSION,
                    "connection_instance_id": connection_instance_id,
                    "runtime_id": self.runtime_id,
                    "local_server_id": local_server_id,
                    "method": method,
                }
            )

        try:
            async with self._session(config, message_handler=handler) as (session, _):
                event = self._root_notification_events[local_server_id]
                while True:
                    await event.wait()
                    event.clear()
                    await session.send_roots_list_changed()
        except asyncio.CancelledError:
            raise
        except (MCPError, OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError):
            self.states[local_server_id].status = "failed"

    async def _start_notification_listeners(
        self, send: Callable[[dict[str, Any]], Awaitable[Any]]
    ) -> None:
        await self._stop_notification_listeners()
        for local_server_id in self.servers:
            self._notification_tasks[local_server_id] = asyncio.create_task(
                self._notification_listener(local_server_id, send)
            )

    async def _stop_notification_listeners(self) -> None:
        tasks = list(self._notification_tasks.values())
        self._notification_tasks.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

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
            self._clear_root_authority()
            await send(self.registration_payload())
            await self._start_notification_listeners(send)
            return True
        if message_type in {"mcp_refresh_catalog", "mcp_discover"}:
            self._validate_control_identity(message)
            local_server_id = str(message.get("local_server_id", ""))
            await send(await self.catalog_snapshot(local_server_id))
            return True
        if message_type == "mcp_roots_update":
            await send(self._apply_gateway_roots_update(message))
            return True
        if message_type == "mcp_prompt_get":
            self._validate_gateway_prompt(message)
            request_id = _identifier(message.get("request_id"), "request_id")
            if request_id in self._active_calls:
                raise LocalMcpConfigError("Duplicate active local MCP request id")
            self._call_metadata[request_id] = {
                "local_server_id": str(message["local_server_id"]),
                "action_class": "read",
                "dispatched": False,
            }
            task = asyncio.create_task(self._execute_prompt_get(message, send))
            self._active_calls[request_id] = task
            return True
        if message_type == "mcp_completion":
            self._validate_gateway_completion(message)
            request_id = _identifier(message.get("request_id"), "request_id")
            if request_id in self._active_calls:
                raise LocalMcpConfigError("Duplicate active local MCP request id")
            self._call_metadata[request_id] = {
                "local_server_id": str(message["local_server_id"]),
                "action_class": "read",
                "dispatched": False,
            }
            task = asyncio.create_task(self._execute_completion(message, send))
            self._active_calls[request_id] = task
            return True
        if message_type == "mcp_resource_read":
            self._validate_gateway_resource(message)
            request_id = _identifier(message.get("request_id"), "request_id")
            if request_id in self._active_calls:
                raise LocalMcpConfigError("Duplicate active local MCP request id")
            self._call_metadata[request_id] = {
                "local_server_id": str(message["local_server_id"]),
                "action_class": "read",
                "dispatched": False,
            }
            task = asyncio.create_task(self._execute_resource_read(message, send))
            self._active_calls[request_id] = task
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
            listener = self._notification_tasks.pop(local_server_id, None)
            if listener is not None:
                listener.cancel()
                await asyncio.gather(listener, return_exceptions=True)
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
        await self._stop_notification_listeners()
        tasks = list(self._active_calls.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._clear_root_authority()
        self.connection_instance_id = None
        self._save_state()
