from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urljoin, urlencode
from urllib.request import Request, urlopen

from . import __version__
from .sandbox import SandboxError, ThinClientSandbox

SESSION_REUSE_MIN_TTL_SECONDS = 60
WEBSOCKET_RECONNECT_SECONDS = 3
MONITORED_PROCESSES: dict[str, asyncio.subprocess.Process] = {}


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


async def serve_ws_once(gateway: str, client_id: str, token: str, sandbox: ThinClientSandbox) -> None:
    try:
        import websockets
    except ImportError as exc:
        raise RuntimeError("Install websockets to use --serve") from exc
    ws_base = gateway.replace("https://", "wss://").replace("http://", "ws://").rstrip("/")
    url = f"{ws_base}/api/thin-clients/ws/{client_id}?{urlencode({'token': token})}"
    async with websockets.connect(url) as websocket:
        send_lock = asyncio.Lock()

        async def send_json(payload: dict) -> None:
            async with send_lock:
                await websocket.send(json.dumps(payload))

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
                MONITORED_PROCESSES[session_id] = process
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
                await send_json(
                    {
                        "type": "session_finished",
                        "session_id": session_id,
                        "exit_code": exit_code,
                        "status": "completed" if exit_code == 0 else "failed",
                    }
                )
            except Exception as exc:
                await send_json({"type": "session_failed", "session_id": session_id, "error": str(exc)})
                if request_id:
                    await send_json({"type": "tool_result", "request_id": request_id, "ok": False, "error": str(exc)})
            finally:
                MONITORED_PROCESSES.pop(session_id, None)

        async def terminate_monitored_command(request_id: str, arguments: dict) -> None:
            session_id = str(arguments.get("session_id", ""))
            force = bool(arguments.get("force", False))
            process = MONITORED_PROCESSES.get(session_id)
            if process is None:
                await send_json({"type": "tool_result", "request_id": request_id, "ok": False, "error": "Monitored process not found"})
                return
            if force:
                process.kill()
            else:
                process.terminate()
            await send_json({"type": "tool_result", "request_id": request_id, "ok": True, "result": {"session_id": session_id, "terminated": True, "force": force}})

        if MONITORED_PROCESSES:
            await send_json(
                {
                    "type": "session_snapshot",
                    "sessions": [
                        {"session_id": session_id, "pid": process.pid, "returncode": process.returncode}
                        for session_id, process in MONITORED_PROCESSES.items()
                    ],
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
                    result = await asyncio.to_thread(sandbox.call, tool, arguments)
                    await send_json({"type": "tool_result", "request_id": request_id, "ok": True, "result": result})
                except Exception as exc:
                    await send_json({"type": "tool_result", "request_id": request_id, "ok": False, "error": str(exc)})

        await asyncio.gather(heartbeat(), receive())


async def serve_ws(gateway: str, client_id: str, token: str, sandbox: ThinClientSandbox) -> None:
    try:
        import websockets
    except ImportError as exc:
        raise RuntimeError("Install websockets to use --serve") from exc
    while True:
        try:
            await serve_ws_once(gateway, client_id, token, sandbox)
        except websockets.exceptions.ConnectionClosed as exc:
            code = exc.rcvd.code if exc.rcvd else getattr(exc, "code", None)
            if code in {4401, 4404}:
                raise RuntimeError("Saved thin-client session is no longer valid. Run gateway-cli login --force-auth to authorize again.") from exc
            print(f"gateway-cli: websocket closed with code {code}; reconnecting in {WEBSOCKET_RECONNECT_SECONDS}s", file=sys.stderr)
            await asyncio.sleep(WEBSOCKET_RECONNECT_SECONDS)
        except OSError as exc:
            print(f"gateway-cli: websocket connection failed: {exc}; reconnecting in {WEBSOCKET_RECONNECT_SECONDS}s", file=sys.stderr)
            await asyncio.sleep(WEBSOCKET_RECONNECT_SECONDS)


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
                    asyncio.run(serve_ws(gateway, str(session["client_id"]), str(session["token"]), sandbox))
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
            asyncio.run(serve_ws(gateway, client["id"], token, sandbox))
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
    login_parser.add_argument("--force-auth", action="store_true", help="Ignore saved session and authorize again.")
    login_parser.add_argument("legacy_comment", nargs="*", help=argparse.SUPPRESS)
    login_parser.set_defaults(func=login)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
