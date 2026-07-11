from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import random
import socket
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urljoin, urlencode
from urllib.request import Request, urlopen

from . import __version__
from .browser import BrowserError, ThinClientBrowserRuntime
from .sandbox import SandboxError, ThinClientSandbox

SESSION_REUSE_MIN_TTL_SECONDS = 60
WEBSOCKET_RECONNECT_SECONDS = 1.0
WEBSOCKET_RECONNECT_FACTOR = 1.6
WEBSOCKET_RECONNECT_JITTER_RATIO = 0.2
TERMINAL_WEBSOCKET_CLOSE_CODES = {4401, 4404}
DASHBOARD_EVENT_CACHE_SIZE = 64


@dataclass(frozen=True)
class ReconnectPolicy:
    initial_delay: float = WEBSOCKET_RECONNECT_SECONDS
    max_delay: float = 30.0
    factor: float = WEBSOCKET_RECONNECT_FACTOR
    jitter_ratio: float = WEBSOCKET_RECONNECT_JITTER_RATIO

    def delay_for_attempt(self, attempt: int) -> float:
        safe_attempt = max(1, attempt)
        base = min(self.max_delay, self.initial_delay * (self.factor ** (safe_attempt - 1)))
        if self.jitter_ratio <= 0:
            return base
        spread = base * self.jitter_ratio
        return max(0.0, min(self.max_delay, base + random.uniform(-spread, spread)))


def websocket_close_code(exc: BaseException) -> int | None:
    received = getattr(exc, "rcvd", None)
    received_code = getattr(received, "code", None)
    if received_code is not None:
        try:
            return int(received_code)
        except (TypeError, ValueError):
            return None
    raw_code = getattr(exc, "code", None)
    if raw_code is not None:
        try:
            return int(raw_code)
        except (TypeError, ValueError):
            return None
    return None


def websocket_status_code(exc: BaseException) -> int | None:
    for attr in ("status_code", "status"):
        raw_value = getattr(exc, attr, None)
        if raw_value is not None:
            try:
                return int(raw_value)
            except (TypeError, ValueError):
                pass
    response = getattr(exc, "response", None)
    raw_status = getattr(response, "status_code", None) or getattr(response, "status", None)
    if raw_status is not None:
        try:
            return int(raw_status)
        except (TypeError, ValueError):
            return None
    return None


def is_terminal_websocket_error(exc: BaseException) -> bool:
    return websocket_close_code(exc) in TERMINAL_WEBSOCKET_CLOSE_CODES


def is_retryable_websocket_error(exc: BaseException, websockets_module: object) -> bool:
    if is_terminal_websocket_error(exc):
        return False
    if isinstance(exc, (OSError, EOFError, TimeoutError, asyncio.TimeoutError, json.JSONDecodeError)):
        return True

    exceptions_module = getattr(websockets_module, "exceptions", None)
    retryable_exception_types = []
    for name in (
        "ConnectionClosed",
        "ConnectionClosedError",
        "ConnectionClosedOK",
        "InvalidHandshake",
        "InvalidMessage",
        "NegotiationError",
        "ProtocolError",
    ):
        candidate = getattr(exceptions_module, name, None)
        if isinstance(candidate, type):
            retryable_exception_types.append(candidate)

    if retryable_exception_types and isinstance(exc, tuple(retryable_exception_types)):
        status_code = websocket_status_code(exc)
        if status_code is not None and status_code not in {408, 425, 429, 500, 502, 503, 504}:
            return False
        return True

    return False


def compact_exception_message(exc: BaseException) -> str:
    message = str(exc).strip()
    if not message:
        message = exc.__class__.__name__
    return f"{exc.__class__.__name__}: {message}"


@dataclass(frozen=True)
class TerminalDashboardConfig:
    client_id: str
    directory: Path
    gateway: str
    hostname: str
    history_path: Path | None = None
    no_color: bool = False
    persist_history: bool = True
    use_tui: bool = False


@dataclass
class TerminalDashboardState:
    active_sessions: list[dict] = field(default_factory=list)
    recent_events: list[dict] = field(default_factory=list)
    attempt: int = 0
    connection_state: str = "INITIALIZING"
    event_count: int = 0
    history_error: str | None = None
    history_path: str | None = None
    last_error: str | None = None
    last_online_at: float | None = None
    next_retry_seconds: float | None = None


def truncate_dashboard_text(value: object, limit: int = 120) -> str:
    text = str(value).replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 3)]}..."


@dataclass(frozen=True)
class LocalCommandSnapshot:
    command: str
    cwd: str
    pid: int | None
    returncode: int | None
    session_id: str
    started_at: float
    status: str

    def as_dict(self) -> dict:
        return {
            "command": self.command,
            "cwd": self.cwd,
            "pid": self.pid,
            "returncode": self.returncode,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "status": self.status,
        }


@dataclass
class LocalCommandHandle:
    command: str
    cwd: str
    process: asyncio.subprocess.Process
    session_id: str
    started_at: float = field(default_factory=time.time)

    def snapshot(self) -> LocalCommandSnapshot:
        return LocalCommandSnapshot(
            command=self.command,
            cwd=self.cwd,
            pid=self.process.pid,
            returncode=self.process.returncode,
            session_id=self.session_id,
            started_at=self.started_at,
            status="running" if self.process.returncode is None else "finished",
        )


class LocalCommandRegistry:
    def __init__(self) -> None:
        self._handles: dict[str, LocalCommandHandle] = {}

    def register(self, session_id: str, process: asyncio.subprocess.Process, *, command: str, cwd: str) -> LocalCommandHandle:
        handle = LocalCommandHandle(command=command, cwd=cwd, process=process, session_id=session_id)
        self._handles[session_id] = handle
        return handle

    def remove(self, session_id: str) -> None:
        self._handles.pop(session_id, None)

    def get(self, session_id: str) -> LocalCommandHandle | None:
        return self._handles.get(session_id)

    def terminate(self, session_id: str, *, force: bool = False) -> bool:
        handle = self.get(session_id)
        if handle is None:
            return False
        if force:
            handle.process.kill()
        else:
            handle.process.terminate()
        return True

    def snapshot(self) -> list[dict]:
        return [handle.snapshot().as_dict() for _, handle in sorted(self._handles.items())]

    def active_count(self) -> int:
        return len(self._handles)


LOCAL_COMMAND_REGISTRY = LocalCommandRegistry()


class TerminalDashboardRenderer:
    def __init__(self, config: TerminalDashboardConfig, stream=None) -> None:
        self.config = config
        self.stream = stream or sys.stderr
        self.state = TerminalDashboardState()
        self._console = None
        self._history_handle = None
        self._last_plain_line: str | None = None
        self._live = None
        self._rich_available = False
        self._started = False
        self._tui_active = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._open_history()
        if not self.config.use_tui:
            self._print_plain("INITIALIZING")
            self._print_plain_history_path()
            return
        try:
            from rich.console import Console
            from rich.live import Live
        except ImportError:
            self._print_plain("INITIALIZING")
            self._print_plain_history_path()
            return
        self._rich_available = True
        self._tui_active = True
        self._console = Console(file=self.stream, no_color=self.config.no_color)
        self._console.print(self._render_rich_history_header())
        for event in self.state.recent_events:
            self._console.print(self._render_rich_event(event))
        self._live = Live(
            self._render_rich(),
            console=self._console,
            auto_refresh=False,
            transient=False,
            vertical_overflow="visible",
        )
        self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None
        self._close_history()
        self._started = False
        self._tui_active = False

    def update(
        self,
        connection_state: str,
        *,
        attempt: int | None = None,
        last_error: str | None = None,
        next_retry_seconds: float | None = None,
    ) -> None:
        self.state.connection_state = connection_state
        if attempt is not None:
            self.state.attempt = attempt
        if last_error is not None:
            self.state.last_error = last_error
        self.state.next_retry_seconds = next_retry_seconds
        self.state.active_sessions = monitored_process_snapshots()
        if connection_state == "ONLINE":
            self.state.last_online_at = time.time()
        if self._live is not None:
            self._live.update(self._render_rich(), refresh=True)
        elif self._started:
            self._print_plain(connection_state)

    def record_event(self, kind: str, title: str, detail: str = "", status: str = "info", payload: dict | None = None) -> None:
        self.state.event_count += 1
        event = {
            "detail": truncate_dashboard_text(detail, 180),
            "kind": kind,
            "payload": payload or {},
            "sequence": self.state.event_count,
            "status": status,
            "time": time.strftime("%H:%M:%S"),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "title": truncate_dashboard_text(title, 80),
        }
        self.state.recent_events.append(event)
        self.state.recent_events = self.state.recent_events[-DASHBOARD_EVENT_CACHE_SIZE:]
        self.state.active_sessions = monitored_process_snapshots()
        self._write_history_record({"type": "event", **event})
        if self._tui_active and self._console is not None:
            self._console.print(self._render_rich_event(event))
            if self._live is not None:
                self._live.update(self._render_rich(), refresh=True)
        elif self._started:
            detail_suffix = f" {event['detail']}" if event["detail"] else ""
            print(f"gateway-cli: event={event['kind']} status={event['status']} {event['title']}{detail_suffix}", file=self.stream)

    def _default_history_path(self) -> Path:
        session_root = Path(os.environ.get("GATEWAY_THIN_CLIENT_HOME", Path.home() / ".local/share/gateway-thin-client")).expanduser()
        identity = f"{self.config.gateway.rstrip('/')}\0{self.config.client_id}\0{self.config.directory.resolve()}"
        identity_hash = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        nonce = f"{os.getpid()}-{time.time_ns() & 0xFFFFFF:06x}"
        return session_root / "history" / identity_hash / f"{stamp}-{nonce}.jsonl"

    def _open_history(self) -> None:
        if not self.config.persist_history:
            return
        managed_history_path = self.config.history_path is None
        history_path = self.config.history_path.expanduser() if self.config.history_path is not None else self._default_history_path()
        if not history_path.is_absolute():
            history_path = Path.cwd() / history_path
        self.state.history_path = str(history_path)
        try:
            history_path.parent.mkdir(parents=True, exist_ok=True)
            if managed_history_path:
                try:
                    history_path.parent.chmod(0o700)
                except OSError:
                    pass
            self._history_handle = history_path.open("a", encoding="utf-8", buffering=1)
            try:
                history_path.chmod(0o600)
            except OSError:
                pass
        except OSError as exc:
            self.state.history_error = compact_exception_message(exc)
            self._history_handle = None
            return
        self._write_history_record(
            {
                "type": "session_start",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "client_id": self.config.client_id,
                "directory": str(self.config.directory),
                "gateway": self.config.gateway,
                "hostname": self.config.hostname,
                "pid": os.getpid(),
                "version": __version__,
            }
        )

    def _close_history(self) -> None:
        if self._history_handle is None:
            return
        self._write_history_record(
            {
                "type": "session_end",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "event_count": self.state.event_count,
            }
        )
        try:
            self._history_handle.close()
        except OSError as exc:
            self.state.history_error = compact_exception_message(exc)
        finally:
            self._history_handle = None

    def _write_history_record(self, record: dict) -> None:
        if self._history_handle is None:
            return
        try:
            self._history_handle.write(json.dumps(record, ensure_ascii=False, default=str, separators=(",", ":")) + "\n")
        except (OSError, TypeError, ValueError) as exc:
            self.state.history_error = compact_exception_message(exc)

    def _print_plain_history_path(self) -> None:
        if self.state.history_path:
            print(f"gateway-cli: session_history={self.state.history_path}", file=self.stream)
        elif self.state.history_error:
            print(f"gateway-cli: session_history_error={self.state.history_error}", file=self.stream)

    def _print_plain(self, connection_state: str) -> None:
        suffix = ""
        if connection_state == "RECONNECTING":
            suffix = f" attempt={self.state.attempt}"
            if self.state.next_retry_seconds is not None:
                suffix += f" next_retry={self.state.next_retry_seconds:.1f}s"
            if self.state.last_error:
                suffix += f" last_error={self.state.last_error}"
        elif connection_state == "ONLINE":
            suffix = f" active_commands={len(self.state.active_sessions)} events={self.state.event_count}"
        line = f"gateway-cli: state={connection_state}{suffix}"
        if line != self._last_plain_line:
            print(line, file=self.stream)
            self._last_plain_line = line

    def _render_rich(self):
        return self._render_rich_bottom_bar()

    def _render_rich_history_header(self):
        from rich.text import Text

        header = Text()
        header.append("Session activity", style="bold")
        header.append(" — append-only terminal scrollback; newest events appear at the bottom", style="dim")
        if self.state.history_path:
            header.append(f"\nPersistent JSONL: {self.state.history_path}", style="dim")
        elif self.state.history_error:
            header.append(f"\nHistory persistence unavailable: {self.state.history_error}", style="yellow")
        return header

    def _render_rich_bottom_bar(self):
        from rich import box
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        summary = Table.grid(padding=(0, 1))
        summary.add_column(style="bold")
        summary.add_column()
        summary.add_row("Client", self.config.client_id)
        summary.add_row("Host", self.config.hostname)
        summary.add_row("Gateway", self.config.gateway)
        summary.add_row("Directory", str(self.config.directory))
        summary.add_row("State", self.state.connection_state)
        summary.add_row("Events", str(self.state.event_count))
        if self.state.history_path:
            summary.add_row("History", truncate_dashboard_text(self.state.history_path, 96))
        if self.state.history_error:
            summary.add_row("History error", Text(truncate_dashboard_text(self.state.history_error, 120), style="yellow"))
        if self.state.connection_state == "RECONNECTING":
            summary.add_row("Attempt", str(self.state.attempt))
            if self.state.next_retry_seconds is not None:
                summary.add_row("Next retry", f"{self.state.next_retry_seconds:.1f}s")
        if self.state.last_error:
            summary.add_row("Last error", Text(self.state.last_error, overflow="fold"))

        commands = Table(title="Active monitored commands", box=box.SIMPLE_HEAVY, expand=True)
        commands.add_column("Session", no_wrap=True)
        commands.add_column("PID", justify="right")
        commands.add_column("Command")
        commands.add_column("CWD")
        commands.add_column("Returncode", justify="right")
        if self.state.active_sessions:
            for item in self.state.active_sessions:
                commands.add_row(
                    str(item["session_id"]),
                    str(item["pid"]),
                    str(item.get("command") or "-"),
                    str(item.get("cwd") or "-"),
                    str(item["returncode"]),
                )
        else:
            commands.add_row("none", "-", "-", "-", "-")

        bottom = Table.grid(expand=True)
        bottom.add_column(ratio=1)
        bottom.add_column(ratio=2)
        bottom.add_row(
            Panel(summary, title="Client info", border_style="cyan"),
            Panel(commands, title="Active monitored commands", border_style="cyan"),
        )
        return Panel(bottom, title="Thin client bottom bar", border_style="blue")

    def _render_rich_activity(self):
        from rich.console import Group
        from rich.panel import Panel
        from rich.text import Text

        rows = [Text("Cached activity snapshot — complete history remains in terminal scrollback and JSONL", style="italic")]
        if not self.state.recent_events:
            rows.append(Panel(Text("No tool activity yet", style="dim"), border_style="dim"))
            return Group(*rows)
        rows.extend(self._render_rich_event(event) for event in self.state.recent_events)
        return Group(*rows)

    def _render_rich_event(self, event: dict):
        from rich.panel import Panel
        from rich.text import Text

        if event.get("kind") == "file" and isinstance(event.get("payload"), dict):
            return self._render_rich_file_event(event)
        title = Text()
        title.append("● ", style=self._event_dot_style(str(event.get("status", "info"))))
        title.append(f"{event.get('title', '')}", style="bold")
        title.append(f"  {event.get('time', '')}", style="dim")
        detail = str(event.get("detail") or "")
        if detail:
            title.append(f"\n  ⎿  {detail}", style="dim")
        return Panel(title, border_style="dim", padding=(0, 1))

    def _render_rich_file_event(self, event: dict):
        from rich.table import Table
        from rich.text import Text

        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        diff = payload.get("diff") if isinstance(payload.get("diff"), dict) else {}
        path = truncate_dashboard_text(payload.get("path") or event.get("detail") or "file", 100)
        added = int(diff.get("added_lines", 0) or 0)
        removed = int(diff.get("removed_lines", 0) or 0)
        card = Table.grid(expand=True)
        title = Text()
        title.append("● ", style="green")
        title.append(f"Update({path})", style="bold underline")
        title.append(f"  {event.get('time', '')}", style="dim")
        card.add_row(title)
        summary = Text()
        summary.append("  ⎿  ", style="dim")
        summary.append(f"Added {added} lines", style="green")
        summary.append(", ", style="dim")
        summary.append(f"removed {removed} lines", style="red")
        if diff.get("truncated"):
            summary.append("  truncated", style="yellow")
        if diff.get("suppressed"):
            summary.append(f"  suppressed: {diff.get('reason') or 'policy'}", style="yellow")
        card.add_row(summary)
        if not diff or diff.get("suppressed"):
            return card
        rendered = 0
        for hunk in list(diff.get("hunks") or [])[:3]:
            card.add_row(Text(f"     @@ -{hunk.get('old_start', 0)},{hunk.get('old_count', 0)} +{hunk.get('new_start', 0)},{hunk.get('new_count', 0)} @@", style="blue"))
            old_line = int(hunk.get("old_start", 1) or 1)
            new_line = int(hunk.get("new_start", 1) or 1)
            for line in list(hunk.get("lines") or [])[:18]:
                kind = str(line.get("kind", "context"))
                value = str(line.get("text", ""))
                if kind == "insert":
                    number = new_line
                    new_line += 1
                elif kind == "delete":
                    number = old_line
                    old_line += 1
                else:
                    number = old_line
                    old_line += 1
                    new_line += 1
                card.add_row(self._render_rich_diff_line(number, kind, value))
                rendered += 1
                if rendered >= 42:
                    card.add_row(Text("     … diff truncated in terminal view", style="yellow"))
                    return card
        return card

    def _render_rich_diff_line(self, line_number: int, kind: str, value: str):
        from rich.text import Text

        sign = "+" if kind == "insert" else "-" if kind == "delete" else " "
        style = "white on dark_green" if kind == "insert" else "white on dark_red" if kind == "delete" else "dim"
        line = Text()
        line.append(f"     {line_number:>4} ", style="dim")
        line.append(f"{sign}{value or ' '}", style=style)
        return line

    def _event_dot_style(self, status: str) -> str:
        if status in {"success", "completed"}:
            return "green"
        if status in {"failed", "error"}:
            return "red"
        if status in {"running", "pending"}:
            return "yellow"
        return "cyan"


def monitored_process_snapshots() -> list[dict]:
    return LOCAL_COMMAND_REGISTRY.snapshot()


def stderr_supports_tui() -> bool:
    return bool(sys.stderr.isatty() and os.environ.get("TERM", "") not in {"", "dumb"})


def terminal_dashboard_from_args(gateway: str, client_id: str, directory: Path, args: argparse.Namespace) -> TerminalDashboardRenderer:
    history_path = Path(args.history_file).expanduser() if args.history_file else None
    return TerminalDashboardRenderer(
        TerminalDashboardConfig(
            client_id=client_id,
            directory=directory,
            gateway=gateway,
            hostname=socket.gethostname(),
            history_path=history_path,
            no_color=bool(args.no_color),
            persist_history=not bool(args.no_history_file),
            use_tui=bool(not args.no_tui and not args.plain_output and stderr_supports_tui()),
        )
    )


def request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
    body = json.dumps(payload or {}).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=body, method=method, headers=headers)
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def http_error_message(exc: HTTPError) -> str:
    body = exc.read().decode("utf-8", errors="replace")
    if body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return body
        detail = payload.get("detail")
        if detail:
            return str(detail)
        return body
    return f"HTTP {exc.code} {exc.reason}"


def poll_token(gateway: str, device_code: str, interval: int) -> str:
    token_url = urljoin(gateway, "/api/thin-clients/token")
    while True:
        try:
            payload = request_json("POST", token_url, {"device_code": device_code})
            return str(payload["access_token"])
        except HTTPError as exc:
            if exc.code == 428:
                time.sleep(interval)
                continue
            raise


def legacy_comment_user_code(values: list[str]) -> str | None:
    if not values:
        return None
    if len(values) == 3 and values[0] == "#" and values[1].lower() == "code":
        return values[2]
    raise ValueError("Unexpected trailing arguments. Remove shell comments from the command.")


def session_home() -> Path:
    return Path(os.environ.get("GATEWAY_THIN_CLIENT_HOME", Path.home() / ".local/share/gateway-thin-client")).expanduser()


def session_store_path() -> Path:
    return session_home() / "sessions.json"


def session_key(gateway: str, directory: Path) -> str:
    value = f"{gateway.rstrip('/')}\0{directory.resolve()}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_jwt_exp(token: str) -> int | None:
    try:
        payload_segment = token.split(".")[1]
        payload_segment += "=" * (-len(payload_segment) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_segment.encode("ascii")))
        exp = payload.get("exp")
        return int(exp) if exp is not None else None
    except Exception:
        return None


def load_sessions() -> dict:
    path = session_store_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def write_sessions(sessions: dict) -> None:
    path = session_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sessions, indent=2, sort_keys=True), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_valid_session(gateway: str, directory: Path) -> dict | None:
    session = load_sessions().get(session_key(gateway, directory))
    if not isinstance(session, dict):
        return None
    if session.get("gateway") != gateway.rstrip("/") or session.get("directory") != str(directory.resolve()):
        return None
    expires_at = session.get("expires_at")
    if not isinstance(expires_at, int) or expires_at <= int(time.time()) + SESSION_REUSE_MIN_TTL_SECONDS:
        return None
    if not session.get("client_id") or not session.get("token"):
        return None
    return session


def save_session(gateway: str, directory: Path, *, client: dict, token: str) -> None:
    sessions = load_sessions()
    expires_at = read_jwt_exp(token)
    key = session_key(gateway, directory)
    sessions[key] = {
        "client_id": str(client["id"]),
        "directory": str(directory.resolve()),
        "expires_at": expires_at,
        "gateway": gateway.rstrip("/"),
        "hostname": str(client.get("hostname") or socket.gethostname()),
        "saved_at": int(time.time()),
        "token": token,
        "version": __version__,
    }
    write_sessions(sessions)


def load_monitor_session(gateway: str, directory: Path) -> dict:
    session = load_valid_session(gateway, directory)
    if session is None:
        raise RuntimeError("No valid saved thin-client session found. Run gateway-cli login --gateway <url> --directory <path> first.")
    return session


def monitor_request(
    args: argparse.Namespace,
    method: str,
    path: str,
    payload: dict | None = None,
    query: dict[str, object | None] | None = None,
) -> dict | list:
    gateway = args.gateway.rstrip("/")
    directory = Path(args.directory).resolve()
    session = load_monitor_session(gateway, directory)
    suffix = ""
    if query:
        filtered = {key: value for key, value in query.items() if value is not None}
        if filtered:
            suffix = f"?{urlencode(filtered)}"
    return request_json(method, urljoin(gateway, path) + suffix, payload=payload, token=str(session["token"]))


def print_json_payload(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def monitor_list(args: argparse.Namespace) -> int:
    try:
        sessions = monitor_request(args, "GET", "/api/command-sessions", query={"status": args.status})
    except HTTPError as exc:
        print(f"gateway-cli monitor list: {http_error_message(exc)}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"gateway-cli monitor list: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print_json_payload(sessions)
        return 0
    if not isinstance(sessions, list) or not sessions:
        print("No command sessions.")
        return 0
    print(f"{'SESSION':36}  {'STATUS':14}  {'ORIGIN':12}  {'LINES':>5}  COMMAND")
    for session in sessions:
        command = str(session.get("command", "")).replace("\n", " ")
        if len(command) > 90:
            command = f"{command[:87]}..."
        print(
            f"{str(session.get('id', '')):36}  "
            f"{str(session.get('status', '')):14}  "
            f"{str(session.get('origin', '')):12}  "
            f"{int(session.get('line_count') or 0):5d}  "
            f"{command}"
        )
    return 0


def monitor_tail(args: argparse.Namespace) -> int:
    query = {
        "start_line": args.start_line,
        "limit": args.limit,
        "tail": args.tail if args.start_line is None else None,
    }
    try:
        output = monitor_request(args, "GET", f"/api/command-sessions/{args.session_id}/output", query=query)
    except HTTPError as exc:
        print(f"gateway-cli monitor tail: {http_error_message(exc)}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"gateway-cli monitor tail: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print_json_payload(output)
        return 0
    if not isinstance(output, dict):
        print(str(output))
        return 0
    for line in output.get("lines") or []:
        if args.with_metadata:
            prefix = f"{int(line.get('line', 0)):>6} {str(line.get('stream', 'stdout')):<6} | "
        else:
            prefix = ""
        print(f"{prefix}{line.get('text', '')}")
    return 0


def monitor_kill(args: argparse.Namespace) -> int:
    try:
        session = monitor_request(args, "POST", f"/api/command-sessions/{args.session_id}/terminate", payload={"force": bool(args.force)})
    except HTTPError as exc:
        print(f"gateway-cli monitor kill: {http_error_message(exc)}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"gateway-cli monitor kill: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print_json_payload(session)
    else:
        status = session.get("status") if isinstance(session, dict) else "unknown"
        print(f"Requested termination for {args.session_id}; status={status}; force={bool(args.force)}")
    return 0


async def serve_ws_once(
    gateway: str,
    client_id: str,
    token: str,
    sandbox: ThinClientSandbox,
    *,
    open_timeout: float = 10.0,
    ping_interval: float = 20.0,
    ping_timeout: float = 20.0,
    on_connected=None,
    on_dashboard_event=None,
) -> None:
    try:
        import websockets
    except ImportError as exc:
        raise RuntimeError("Install websockets to use --serve") from exc
    ws_base = gateway.replace("https://", "wss://").replace("http://", "ws://").rstrip("/")
    url = f"{ws_base}/api/thin-clients/ws/{client_id}?{urlencode({'token': token})}"
    async with websockets.connect(url, open_timeout=open_timeout, ping_interval=ping_interval, ping_timeout=ping_timeout) as websocket:
        if on_connected is not None:
            on_connected()
        send_lock = asyncio.Lock()
        browser_runtime = ThinClientBrowserRuntime(sandbox.root)

        async def send_json(payload: dict) -> None:
            async with send_lock:
                await websocket.send(json.dumps(payload))

        def record_dashboard_event(kind: str, title: str, detail: str = "", status: str = "info", payload: dict | None = None) -> None:
            if on_dashboard_event is not None:
                on_dashboard_event(kind, title, detail, status, payload=payload)

        def record_tool_result(tool: str, arguments: dict, result: dict | None = None, error: str | None = None) -> None:
            if error is not None:
                record_dashboard_event("tool", f"{tool} failed", error, "failed")
                return
            result = result or {}
            if tool == "write_file":
                diff = result.get("diff") if isinstance(result.get("diff"), dict) else {}
                detail = (
                    f"{result.get('operation', arguments.get('operation', 'write'))} "
                    f"{result.get('path', arguments.get('path', ''))} "
                    f"+{diff.get('added_lines', 0)} -{diff.get('removed_lines', 0)}"
                )
                record_dashboard_event("file", "file edited", detail, "success", payload={"path": result.get("path", arguments.get("path", "")), "operation": result.get("operation", arguments.get("operation", "write")), "diff": diff})
                return
            if tool == "run_command":
                command = truncate_dashboard_text(arguments.get("command", ""), 90)
                detail = f"exit={result.get('exit_code')} cwd={arguments.get('cwd', '.')} {command}"
                status = "success" if int(result.get("exit_code", 1) or 0) == 0 else "failed"
                record_dashboard_event("command", "command completed", detail, status)
                return
            title = f"{tool} completed"
            target = arguments.get("path") or arguments.get("url") or arguments.get("selector") or ""
            record_dashboard_event("tool", title, truncate_dashboard_text(target, 120), "success")

        async def stream_process_output(session_id: str, stream_name: str, reader: asyncio.StreamReader | None) -> None:
            if reader is None:
                return
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                await send_json(
                    {
                        "type": "session_output",
                        "session_id": session_id,
                        "stream": stream_name,
                        "text": raw.decode("utf-8", errors="replace"),
                    }
                )

        async def run_monitored_command(request_id: str, arguments: dict) -> None:
            session_id = str(arguments.get("session_id", ""))
            command = str(arguments.get("command", "")).strip()
            cwd = str(arguments.get("cwd", "."))
            if not session_id or not command:
                await send_json({"type": "tool_result", "request_id": request_id, "ok": False, "error": "session_id and command are required"})
                return
            try:
                working_dir = sandbox.safe_path(cwd)
                process = await asyncio.create_subprocess_shell(
                    command,
                    cwd=str(working_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                LOCAL_COMMAND_REGISTRY.register(session_id, process, command=command, cwd=cwd)
                record_dashboard_event("command", "monitored command started", f"{session_id} pid={process.pid} cwd={cwd} {truncate_dashboard_text(command, 90)}", "running")
                await send_json(
                    {
                        "type": "tool_result",
                        "request_id": request_id,
                        "ok": True,
                        "result": {"session_id": session_id, "status": "running", "pid": process.pid},
                    }
                )
                await asyncio.gather(
                    stream_process_output(session_id, "stdout", process.stdout),
                    stream_process_output(session_id, "stderr", process.stderr),
                )
                exit_code = await process.wait()
                status = "completed" if exit_code == 0 else "failed"
                await send_json(
                    {
                        "type": "session_finished",
                        "session_id": session_id,
                        "exit_code": exit_code,
                        "status": status,
                    }
                )
                LOCAL_COMMAND_REGISTRY.remove(session_id)
                record_dashboard_event("command", f"monitored command {status}", f"{session_id} exit={exit_code} {truncate_dashboard_text(command, 90)}", status)
            except Exception as exc:
                record_dashboard_event("command", "monitored command failed", f"{session_id} {exc}", "failed")
                await send_json({"type": "session_failed", "session_id": session_id, "error": str(exc)})
                if request_id:
                    await send_json({"type": "tool_result", "request_id": request_id, "ok": False, "error": str(exc)})
            finally:
                LOCAL_COMMAND_REGISTRY.remove(session_id)

        async def terminate_monitored_command(request_id: str, arguments: dict) -> None:
            session_id = str(arguments.get("session_id", ""))
            force = bool(arguments.get("force", False))
            if not LOCAL_COMMAND_REGISTRY.terminate(session_id, force=force):
                await send_json({"type": "tool_result", "request_id": request_id, "ok": False, "error": "Monitored process not found"})
                return
            record_dashboard_event("command", "termination requested", f"{session_id} force={force}", "running")
            await send_json({"type": "tool_result", "request_id": request_id, "ok": True, "result": {"session_id": session_id, "terminated": True, "force": force}})

        if LOCAL_COMMAND_REGISTRY.active_count():
            await send_json(
                {
                    "type": "session_snapshot",
                    "sessions": monitored_process_snapshots(),
                }
            )

        async def heartbeat() -> None:
            while True:
                await send_json({"type": "heartbeat", "ts": time.time(), "version": __version__})
                await asyncio.sleep(15)

        async def receive() -> None:
            async for raw in websocket:
                message = json.loads(raw)
                if message.get("type") != "tool_call":
                    continue
                request_id = str(message.get("request_id", ""))
                tool = str(message.get("tool", ""))
                arguments = dict(message.get("arguments") or {})
                if tool == "run_monitored_command":
                    asyncio.create_task(run_monitored_command(request_id, arguments))
                    continue
                if tool == "terminate_session":
                    asyncio.create_task(terminate_monitored_command(request_id, arguments))
                    continue
                try:
                    if tool.startswith("browser_"):
                        result = await browser_runtime.call(tool, arguments)
                    else:
                        result = await asyncio.to_thread(sandbox.call, tool, arguments)
                    record_tool_result(tool, arguments, result=result)
                    await send_json({"type": "tool_result", "request_id": request_id, "ok": True, "result": result})
                except (BrowserError, Exception) as exc:
                    record_tool_result(tool, arguments, error=str(exc))
                    await send_json({"type": "tool_result", "request_id": request_id, "ok": False, "error": str(exc)})

        heartbeat_task = asyncio.create_task(heartbeat())
        receive_task = asyncio.create_task(receive())
        try:
            await asyncio.gather(heartbeat_task, receive_task)
        finally:
            heartbeat_task.cancel()
            receive_task.cancel()
            await browser_runtime.close_all()


async def serve_ws(
    gateway: str,
    client_id: str,
    token: str,
    sandbox: ThinClientSandbox,
    *,
    reconnect_policy: ReconnectPolicy | None = None,
    max_reconnect_attempts: int | None = None,
    open_timeout: float = 10.0,
    ping_interval: float = 20.0,
    ping_timeout: float = 20.0,
    debug: bool = False,
    dashboard: TerminalDashboardRenderer | None = None,
) -> None:
    try:
        import websockets
    except ImportError as exc:
        raise RuntimeError("Install websockets to use --serve") from exc
    policy = reconnect_policy or ReconnectPolicy()
    renderer = dashboard or TerminalDashboardRenderer(
        TerminalDashboardConfig(
            client_id=client_id,
            directory=sandbox.root,
            gateway=gateway,
            hostname=socket.gethostname(),
            use_tui=False,
        )
    )
    attempt = 0
    renderer.start()
    try:
        while True:
            try:
                renderer.update("CONNECTING", attempt=attempt)
                await serve_ws_once(
                    gateway,
                    client_id,
                    token,
                    sandbox,
                    open_timeout=open_timeout,
                    ping_interval=ping_interval,
                    ping_timeout=ping_timeout,
                    on_connected=lambda: renderer.update("ONLINE", attempt=0),
                    on_dashboard_event=getattr(renderer, "record_event", None),
                )
                attempt = 0
            except Exception as exc:
                if is_terminal_websocket_error(exc):
                    renderer.update("AUTH_EXPIRED", last_error=compact_exception_message(exc))
                    raise RuntimeError(
                        "Saved thin-client session is no longer valid. Run gateway-cli login --force-auth to authorize again."
                    ) from exc
                if not is_retryable_websocket_error(exc, websockets):
                    renderer.update("STOPPED", last_error=compact_exception_message(exc))
                    raise
                attempt += 1
                if max_reconnect_attempts is not None and attempt > max_reconnect_attempts:
                    renderer.update("STOPPED", attempt=attempt, last_error=compact_exception_message(exc))
                    raise RuntimeError(
                        f"WebSocket reconnect attempts exhausted after {max_reconnect_attempts} attempts: "
                        f"{compact_exception_message(exc)}"
                    ) from exc
                delay = policy.delay_for_attempt(attempt)
                message = compact_exception_message(exc)
                renderer.update("RECONNECTING", attempt=attempt, last_error=message, next_retry_seconds=delay)
                if debug:
                    traceback.print_exception(exc, file=sys.stderr)
                await asyncio.sleep(delay)
    finally:
        renderer.stop()


def print_version(_: argparse.Namespace) -> int:
    print(f"gateway-cli {__version__}")
    return 0


def sandbox_call(args: argparse.Namespace) -> int:
    sandbox = ThinClientSandbox(args.directory)
    arguments = json.loads(args.arguments) if args.arguments else {}
    try:
        result = sandbox.call(args.tool, arguments)
    except SandboxError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "result": result}, indent=2))
    return 0


def reconnect_policy_from_args(args: argparse.Namespace) -> ReconnectPolicy:
    return ReconnectPolicy(
        initial_delay=max(0.1, float(args.reconnect_initial_delay)),
        max_delay=max(0.1, float(args.max_reconnect_delay)),
        jitter_ratio=0.0 if args.no_reconnect_jitter else WEBSOCKET_RECONNECT_JITTER_RATIO,
    )


def serve_ws_kwargs_from_args(args: argparse.Namespace, gateway: str, client_id: str, directory: Path) -> dict:
    return {
        "dashboard": terminal_dashboard_from_args(gateway, client_id, directory, args),
        "debug": bool(args.debug),
        "max_reconnect_attempts": args.max_reconnect_attempts,
        "open_timeout": float(args.connect_timeout),
        "ping_interval": float(args.ping_interval),
        "ping_timeout": float(args.ping_timeout),
        "reconnect_policy": reconnect_policy_from_args(args),
    }


def login(args: argparse.Namespace) -> int:
    gateway = args.gateway.rstrip("/")
    root = Path(args.directory).resolve()
    sandbox = ThinClientSandbox(root)
    try:
        legacy_user_code = legacy_comment_user_code(args.legacy_comment)
    except ValueError as exc:
        print(f"gateway-cli login: error: {exc}", file=sys.stderr)
        return 2

    if not args.device_code and not args.force_auth:
        session = load_valid_session(gateway, root)
        if session:
            print(
                json.dumps(
                    {
                        "client_id": session["client_id"],
                        "directory": session["directory"],
                        "hostname": session.get("hostname") or socket.gethostname(),
                        "reused_session": True,
                        "version": __version__,
                    },
                    indent=2,
                )
            )
            if args.serve:
                try:
                    asyncio.run(
                        serve_ws(
                            gateway,
                            str(session["client_id"]),
                            str(session["token"]),
                            sandbox,
                            **serve_ws_kwargs_from_args(args, gateway, str(session["client_id"]), root),
                        )
                    )
                except RuntimeError as exc:
                    print(f"gateway-cli login: {exc}", file=sys.stderr)
                    return 1
            return 0

    if args.device_code:
        device_code = str(args.device_code)
        user_code = args.user_code or legacy_user_code
        verification_uri = args.verification_uri
        interval = int(args.interval)
    else:
        try:
            device = request_json("POST", urljoin(gateway, "/api/thin-clients/device-code"))
        except HTTPError as exc:
            print(f"gateway-cli login: device-code request failed: {http_error_message(exc)}", file=sys.stderr)
            return 1
        device_code = str(device["device_code"])
        user_code = str(device["user_code"])
        verification_uri = str(device["verification_uri"])
        interval = int(device.get("interval", args.interval))

    if user_code and verification_uri:
        print(f"Open {verification_uri} and enter code {user_code}")
    elif user_code:
        print(f"Authorize thin client with code {user_code}")
    else:
        print("Waiting for thin-client device-code authorization")
    try:
        token = poll_token(gateway, device_code, interval)
    except HTTPError as exc:
        print(f"gateway-cli login: device-code authorization failed: {http_error_message(exc)}", file=sys.stderr)
        return 1
    register_payload = {
        "hostname": socket.gethostname(),
        "directory": str(root),
        "labels": {"client": "gateway-cli", "version": __version__},
    }
    try:
        client = request_json("POST", urljoin(gateway, "/api/thin-clients/register"), register_payload, token=token)
    except HTTPError as exc:
        print(f"gateway-cli login: registration failed: {http_error_message(exc)}", file=sys.stderr)
        return 1
    save_session(gateway, root, client=client, token=token)
    print(json.dumps({"client_id": client["id"], "hostname": client["hostname"], "directory": client["directory"], "version": __version__}, indent=2))
    if args.serve:
        try:
            asyncio.run(
                serve_ws(
                    gateway,
                    str(client["id"]),
                    token,
                    sandbox,
                    **serve_ws_kwargs_from_args(args, gateway, str(client["id"]), root),
                )
            )
        except RuntimeError as exc:
            print(f"gateway-cli login: {exc}", file=sys.stderr)
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gateway-cli")
    parser.add_argument("--version", action="version", version=f"gateway-cli {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser("version")
    version_parser.set_defaults(func=print_version)

    sandbox_parser = subparsers.add_parser("sandbox-call")
    sandbox_parser.add_argument("tool", choices=["list_files", "read_file", "write_file", "run_command"])
    sandbox_parser.add_argument("--arguments", default="{}")
    sandbox_parser.add_argument("--directory", default=".")
    sandbox_parser.set_defaults(func=sandbox_call)

    login_parser = subparsers.add_parser("login")
    login_parser.add_argument("--gateway", default="http://localhost:8000")
    login_parser.add_argument("--directory", default=".")
    login_parser.add_argument("--device-code")
    login_parser.add_argument("--user-code")
    login_parser.add_argument("--verification-uri")
    login_parser.add_argument("--interval", type=int, default=3)
    login_parser.add_argument("--serve", action="store_true")
    login_parser.add_argument("--connect-timeout", type=float, default=10.0)
    login_parser.add_argument("--ping-interval", type=float, default=20.0)
    login_parser.add_argument("--ping-timeout", type=float, default=20.0)
    login_parser.add_argument("--reconnect-initial-delay", type=float, default=WEBSOCKET_RECONNECT_SECONDS)
    login_parser.add_argument("--max-reconnect-delay", type=float, default=30.0)
    login_parser.add_argument("--max-reconnect-attempts", type=int)
    login_parser.add_argument("--no-tui", action="store_true")
    login_parser.add_argument("--plain-output", action="store_true")
    login_parser.add_argument("--no-color", action="store_true")
    history_group = login_parser.add_mutually_exclusive_group()
    history_group.add_argument("--history-file", help="Append the complete session activity stream to this JSONL file.")
    history_group.add_argument("--no-history-file", action="store_true", help="Disable persistent JSONL session history.")
    login_parser.add_argument("--no-reconnect-jitter", action="store_true")
    login_parser.add_argument("--debug", action="store_true", help="Print retryable WebSocket tracebacks while serving.")
    login_parser.add_argument("--force-auth", action="store_true", help="Ignore saved session and authorize again.")
    login_parser.add_argument("legacy_comment", nargs="*", help=argparse.SUPPRESS)
    login_parser.set_defaults(func=login)

    monitor_parser = subparsers.add_parser("monitor")
    monitor_parser.add_argument("--gateway", default="http://localhost:8000")
    monitor_parser.add_argument("--directory", default=".")
    monitor_subparsers = monitor_parser.add_subparsers(dest="monitor_command", required=True)

    monitor_list_parser = monitor_subparsers.add_parser("list")
    monitor_list_parser.add_argument("--status")
    monitor_list_parser.add_argument("--json", action="store_true")
    monitor_list_parser.set_defaults(func=monitor_list)

    monitor_tail_parser = monitor_subparsers.add_parser("tail")
    monitor_tail_parser.add_argument("session_id")
    monitor_tail_parser.add_argument("--tail", type=int, default=50)
    monitor_tail_parser.add_argument("--start-line", type=int)
    monitor_tail_parser.add_argument("--limit", type=int, default=200)
    monitor_tail_parser.add_argument("--with-metadata", action="store_true")
    monitor_tail_parser.add_argument("--json", action="store_true")
    monitor_tail_parser.set_defaults(func=monitor_tail)

    monitor_kill_parser = monitor_subparsers.add_parser("kill")
    monitor_kill_parser.add_argument("session_id")
    monitor_kill_parser.add_argument("--force", action="store_true")
    monitor_kill_parser.add_argument("--json", action="store_true")
    monitor_kill_parser.set_defaults(func=monitor_kill)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
