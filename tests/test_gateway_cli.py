from __future__ import annotations

import asyncio
import base64
import io
import json
import subprocess
import sys
import time
import types
from pathlib import Path
from urllib.error import HTTPError, URLError

from gateway_cli import __main__ as cli
from gateway_cli.browser import ThinClientBrowserRuntime
from gateway_cli.sandbox import SandboxError, ThinClientSandbox


class NoteError(AssertionError):
    pass


def fake_jwt(exp: int | None = None) -> str:
    payload = {"exp": exp or int(time.time()) + 3600}
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
    return f"header.{encoded}.signature"


def test_login_registers_current_directory(monkeypatch, tmp_path: Path, capsys) -> None:
    calls: list[tuple[str, str, dict | None, str | None]] = []
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        calls.append((method, url, payload, token))
        if url.endswith("/api/thin-clients/device-code"):
            return {"device_code": "device-1", "user_code": "ABC123", "verification_uri": "http://gateway/activate", "interval": 0}
        if url.endswith("/api/thin-clients/token"):
            return {"access_token": fake_jwt()}
        if url.endswith("/api/thin-clients/register"):
            return {"id": "client-1", "hostname": "host", "directory": payload["directory"]}
        raise NoteError(url)

    monkeypatch.setattr(cli, "request_json", fake_request_json)

    assert cli.main(["login", "--gateway", "http://gateway", "--directory", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "ABC123" in output
    assert "client-1" in output
    assert calls[-1][2]["directory"] == str(tmp_path.resolve())
    assert calls[-1][2]["labels"]["version"]
    assert calls[-1][3].startswith("header.")


def test_login_uses_preissued_device_code(monkeypatch, tmp_path: Path, capsys) -> None:
    calls: list[tuple[str, str, dict | None, str | None]] = []
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        calls.append((method, url, payload, token))
        if url.endswith("/api/thin-clients/token"):
            assert payload == {"device_code": "device-preissued"}
            return {"access_token": fake_jwt()}
        if url.endswith("/api/thin-clients/register"):
            return {"id": "client-1", "hostname": "host", "directory": payload["directory"]}
        raise NoteError(url)

    monkeypatch.setattr(cli, "request_json", fake_request_json)

    assert cli.main(
        [
            "login",
            "--gateway",
            "http://gateway",
            "--directory",
            str(tmp_path),
            "--device-code",
            "device-preissued",
            "--user-code",
            "ABC123",
            "--verification-uri",
            "http://gateway/thin-clients/activate",
        ]
    ) == 0

    output = capsys.readouterr().out
    assert "ABC123" in output
    assert "client-1" in output
    assert not any(call[1].endswith("/api/thin-clients/device-code") for call in calls)


def test_login_tolerates_legacy_shell_comment_tail(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        if url.endswith("/api/thin-clients/device-code"):
            return {"device_code": "device-1", "user_code": "NEW123", "verification_uri": "http://gateway/activate", "interval": 0}
        if url.endswith("/api/thin-clients/token"):
            return {"access_token": fake_jwt()}
        if url.endswith("/api/thin-clients/register"):
            return {"id": "client-1", "hostname": "host", "directory": payload["directory"]}
        raise NoteError(url)

    monkeypatch.setattr(cli, "request_json", fake_request_json)

    assert cli.main(["login", "--gateway", "http://gateway", "--directory", str(tmp_path), "#", "code", "DDCB85"]) == 0

    output = capsys.readouterr().out
    assert "NEW123" in output
    assert "client-1" in output


def test_login_reports_device_code_http_error_without_traceback(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        if url.endswith("/api/thin-clients/token"):
            raise HTTPError(url, 400, "Bad Request", {}, None)
        raise NoteError(url)

    monkeypatch.setattr(cli, "request_json", fake_request_json)
    monkeypatch.setattr(cli, "http_error_message", lambda exc: "Invalid device_code")

    assert cli.main(["login", "--gateway", "http://gateway", "--directory", str(tmp_path), "--device-code", "bad-code"]) == 1

    captured = capsys.readouterr()
    assert "Invalid device_code" in captured.err
    assert "Traceback" not in captured.err


def test_login_reports_device_code_connection_error_without_traceback(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        if url.endswith("/api/thin-clients/token"):
            raise URLError(ConnectionRefusedError(61, "Connection refused"))
        raise NoteError(url)

    monkeypatch.setattr(cli, "request_json", fake_request_json)

    assert cli.main(["login", "--gateway", "http://gateway", "--directory", str(tmp_path), "--device-code", "code"]) == 1

    captured = capsys.readouterr()
    assert "device-code authorization failed" in captured.err
    assert "Connection refused" in captured.err
    assert "Traceback" not in captured.err


def test_login_reuses_saved_session_without_device_code(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))
    saved_token = fake_jwt()
    cli.save_session(
        "http://gateway",
        tmp_path,
        client={"id": "client-1", "hostname": "host", "directory": str(tmp_path.resolve())},
        token=saved_token,
    )
    calls: list[str] = []
    served: list[tuple[str, str, str]] = []

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        calls.append(url)
        assert url.endswith("/api/thin-clients/register")
        assert token == saved_token
        return {"id": "client-1", "hostname": "host", "directory": str(tmp_path.resolve())}

    async def fake_serve_ws(gateway: str, client_id: str, token_arg: str, sandbox: ThinClientSandbox, **kwargs) -> None:
        served.append((gateway, client_id, token_arg, kwargs))

    monkeypatch.setattr(cli, "request_json", fake_request_json)
    monkeypatch.setattr(cli, "serve_ws", fake_serve_ws)

    assert cli.main(["login", "--gateway", "http://gateway", "--directory", str(tmp_path), "--serve"]) == 0

    output = capsys.readouterr().out
    assert "reauthorized_session" in output
    assert "reused_session" in output
    assert "client-1" in output
    assert calls == ["http://gateway/api/thin-clients/register"]
    assert served == [("http://gateway", "client-1", saved_token, served[0][3])]
    assert served[0][3]["open_timeout"] == 10.0
    assert served[0][3]["ping_interval"] == 20.0
    assert served[0][3]["ping_timeout"] == 20.0
    assert served[0][3]["max_reconnect_attempts"] is None


def test_cli_version(capsys) -> None:
    assert cli.main(["version"]) == 0
    assert "gateway-cli 0.7.0" in capsys.readouterr().out


def test_login_falls_back_to_device_code_when_saved_token_is_rejected(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))
    old_token = fake_jwt(exp=int(time.time()) + 1800)
    new_token = fake_jwt(exp=int(time.time()) + 3600)
    cli.save_session(
        "http://gateway",
        tmp_path,
        client={"id": "old-client", "hostname": "host", "directory": str(tmp_path.resolve())},
        token=old_token,
    )

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        if url.endswith("/api/thin-clients/register") and token == old_token:
            raise HTTPError(url, 401, "Unauthorized", {}, io.BytesIO(b'{"detail":"Invalid bearer token"}'))
        if url.endswith("/api/thin-clients/device-code"):
            return {"device_code": "new-device", "user_code": "NEW123", "verification_uri": "http://gateway/activate", "interval": 0}
        if url.endswith("/api/thin-clients/token"):
            return {"access_token": new_token}
        if url.endswith("/api/thin-clients/register"):
            return {"id": "new-client", "hostname": "host", "directory": str(tmp_path.resolve())}
        raise NoteError(url)

    monkeypatch.setattr(cli, "request_json", fake_request_json)

    assert cli.main(["login", "--gateway", "http://gateway", "--directory", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "NEW123" in output
    assert "new-client" in output


def test_activation_url_is_clickable_in_supported_terminal(monkeypatch) -> None:
    monkeypatch.setattr(cli, "stdout_supports_hyperlinks", lambda: True)
    url = "https://gateway.example/thin-clients/activate"

    rendered = cli.terminal_hyperlink(url)

    assert rendered == f"\033]8;;{url}\033\\{url}\033]8;;\033\\"


def test_activation_url_stays_plain_outside_terminal(monkeypatch) -> None:
    monkeypatch.setattr(cli, "stdout_supports_hyperlinks", lambda: False)
    url = "https://gateway.example/thin-clients/activate"

    assert cli.terminal_hyperlink(url) == url


def test_activation_prompt_opens_browser_after_enter(monkeypatch) -> None:
    class InteractiveInput:
        @staticmethod
        def isatty() -> bool:
            return True

    prompts: list[str] = []
    opened: list[tuple[str, int, bool]] = []
    url = "https://gateway.example/thin-clients/activate"
    monkeypatch.setattr(cli.sys, "stdin", InteractiveInput())
    monkeypatch.setattr(cli, "stdout_supports_hyperlinks", lambda: False)
    monkeypatch.setattr("builtins.input", lambda prompt: prompts.append(prompt) or "")
    monkeypatch.setattr(
        cli.webbrowser,
        "open",
        lambda value, new=0, autoraise=True: opened.append((value, new, autoraise)) or True,
    )

    cli.open_verification_uri_on_enter(url, "107804")

    assert prompts == [
        (
            "Open https://gateway.example/thin-clients/activate and enter code 107804. "
            "Press ENTER to open the site..."
        )
    ]
    assert opened == [(url, 2, True)]


def test_activation_prompt_does_not_block_noninteractive_input(monkeypatch, capsys) -> None:
    class NonInteractiveInput:
        @staticmethod
        def isatty() -> bool:
            return False

    opened: list[str] = []
    url = "https://gateway.example/thin-clients/activate"
    monkeypatch.setattr(cli.sys, "stdin", NonInteractiveInput())
    monkeypatch.setattr(cli, "stdout_supports_hyperlinks", lambda: False)
    monkeypatch.setattr(cli.webbrowser, "open", lambda value, **kwargs: opened.append(value) or True)

    cli.open_verification_uri_on_enter(url, "107804")

    assert "Press ENTER to open the site..." in capsys.readouterr().out
    assert opened == []


def test_default_gateway_url_uses_environment(monkeypatch) -> None:
    monkeypatch.setenv("GATEWAY_URL", "https://gateway.example.test/")

    assert cli.default_gateway_url() == "https://gateway.example.test"
    assert cli.build_parser().parse_args(["login"]).gateway == "https://gateway.example.test"
    assert cli.build_parser().parse_args(["monitor", "list"]).gateway == "https://gateway.example.test"


def test_default_gateway_url_falls_back_for_blank_environment(monkeypatch) -> None:
    monkeypatch.setenv("GATEWAY_URL", "   ")

    assert cli.default_gateway_url() == cli.DEFAULT_GATEWAY_URL


def test_send_json_if_connected_ignores_retryable_connection_close() -> None:
    class ConnectionClosedError(Exception):
        pass

    fake_websockets = types.SimpleNamespace(
        exceptions=types.SimpleNamespace(ConnectionClosedError=ConnectionClosedError)
    )

    async def send_json(payload: dict) -> None:
        raise ConnectionClosedError("keepalive ping timeout")

    assert asyncio.run(cli.send_json_if_connected(send_json, {"type": "session_failed"}, fake_websockets)) is False


def test_reconnect_outbound_buffer_replays_failed_send_in_order() -> None:
    async def run() -> None:
        buffer = cli.ReconnectOutboundBuffer(max_messages=4)
        first = {"type": "session_output", "text": "one"}
        second = {"type": "session_finished", "exit_code": 0}
        await buffer.put(first)
        await buffer.put(second)

        async def fail_once(payload: dict) -> None:
            assert payload is first
            raise ConnectionError("restart")

        try:
            await buffer.send_forever(fail_once)
        except ConnectionError:
            pass
        else:
            raise NoteError("buffer did not propagate transport failure")

        assert buffer.pending_count() == 2
        sent: list[dict] = []

        async def send(payload: dict) -> None:
            sent.append(payload)
            if len(sent) == 2:
                raise asyncio.CancelledError()

        try:
            await buffer.send_forever(send)
        except asyncio.CancelledError:
            pass

        assert sent == [first, second]
        assert buffer.pending_count() == 1

    asyncio.run(run())


def test_serve_ws_reuses_outbound_buffer_across_reconnects(monkeypatch, tmp_path: Path) -> None:
    class InvalidMessage(Exception):
        pass

    class StopRetry(Exception):
        pass

    fake_websockets = types.SimpleNamespace(
        exceptions=types.SimpleNamespace(InvalidMessage=InvalidMessage)
    )
    seen: list[cli.ReconnectOutboundBuffer] = []

    async def fake_serve_ws_once(*args, **kwargs) -> None:
        buffer = kwargs["outbound_buffer"]
        seen.append(buffer)
        if len(seen) == 1:
            await buffer.put({"type": "session_output", "text": "queued"})
            raise InvalidMessage("restart")
        assert buffer.pending_count() == 1
        raise InvalidMessage("second restart")

    sleep_count = 0

    async def fake_sleep(delay: float) -> None:
        nonlocal sleep_count
        assert delay == 1.0
        sleep_count += 1
        if sleep_count == 2:
            raise StopRetry()

    monkeypatch.setitem(sys.modules, "websockets", fake_websockets)
    monkeypatch.setattr(cli, "serve_ws_once", fake_serve_ws_once)
    monkeypatch.setattr(cli.asyncio, "sleep", fake_sleep)

    try:
        asyncio.run(
            cli.serve_ws(
                "http://gateway",
                "client-1",
                "token",
                ThinClientSandbox(tmp_path),
                reconnect_policy=cli.ReconnectPolicy(
                    initial_delay=1.0,
                    max_delay=1.0,
                    jitter_ratio=0.0,
                ),
            )
        )
    except StopRetry:
        pass
    else:
        raise NoteError("serve_ws did not enter the second connection")

    assert len(seen) == 2
    assert seen[0] is seen[1]


def test_send_json_if_connected_reraises_non_transport_error() -> None:
    fake_websockets = types.SimpleNamespace(exceptions=types.SimpleNamespace())

    async def send_json(payload: dict) -> None:
        raise ValueError("invalid payload")

    try:
        asyncio.run(cli.send_json_if_connected(send_json, {"type": "tool_result"}, fake_websockets))
    except ValueError as exc:
        assert str(exc) == "invalid payload"
    else:
        raise NoteError("send_json_if_connected swallowed a non-transport error")


def test_serve_ws_once_consumes_background_failure_when_transport_closes(monkeypatch, tmp_path: Path) -> None:
    class ConnectionClosedError(Exception):
        pass

    class EmptyReader:
        async def readline(self) -> bytes:
            return b""

    class FailingProcess:
        def __init__(self) -> None:
            self.pid = 4242
            self.returncode = None
            self.stdout = EmptyReader()
            self.stderr = EmptyReader()

        async def wait(self) -> int:
            raise RuntimeError("process wait failed")

    class FakeWebSocket:
        def __init__(self) -> None:
            self.sent: list[dict] = []
            self.session_failed = asyncio.Event()

        async def send(self, raw: str) -> None:
            payload = json.loads(raw)
            self.sent.append(payload)
            if payload.get("type") == "session_failed":
                self.session_failed.set()
                raise ConnectionClosedError("keepalive ping timeout")

        def __aiter__(self):
            return self.messages()

        async def messages(self):
            yield json.dumps(
                {
                    "type": "tool_call",
                    "request_id": "request-1",
                    "tool": "run_monitored_command",
                    "arguments": {"session_id": "session-1", "command": "false", "cwd": "."},
                }
            )
            await self.session_failed.wait()
            raise ConnectionClosedError("keepalive ping timeout")

    class FakeConnectionContext:
        def __init__(self, websocket: FakeWebSocket) -> None:
            self.websocket = websocket

        async def __aenter__(self) -> FakeWebSocket:
            return self.websocket

        async def __aexit__(self, exc_type, exc, traceback_value) -> bool:
            return False

    class FakeBrowserRuntime:
        def __init__(self, root: Path) -> None:
            self.root = root

        async def close_all(self) -> None:
            browser_closed.append(True)

    websocket = FakeWebSocket()
    browser_closed: list[bool] = []
    dashboard_events: list[tuple[str, str]] = []
    loop_errors: list[dict] = []
    registry = cli.LocalCommandRegistry()
    fake_websockets = types.SimpleNamespace(
        connect=lambda *args, **kwargs: FakeConnectionContext(websocket),
        exceptions=types.SimpleNamespace(ConnectionClosedError=ConnectionClosedError),
    )

    async def create_subprocess_shell(*args, **kwargs) -> FailingProcess:
        return FailingProcess()

    def record_event(kind: str, title: str, detail: str, status: str, payload: dict | None = None) -> None:
        dashboard_events.append((kind, title))

    async def run() -> None:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda current_loop, context: loop_errors.append(context))
        try:
            await cli.serve_ws_once(
                "http://gateway",
                "client-1",
                "token",
                ThinClientSandbox(tmp_path),
                on_dashboard_event=record_event,
            )
        except ConnectionClosedError:
            pass
        else:
            raise NoteError("serve_ws_once did not propagate the transport close")
        await asyncio.sleep(0)

    monkeypatch.setitem(sys.modules, "websockets", fake_websockets)
    monkeypatch.setattr(cli, "ThinClientBrowserRuntime", FakeBrowserRuntime)
    monkeypatch.setattr(cli.asyncio, "create_subprocess_shell", create_subprocess_shell)
    monkeypatch.setattr(cli, "LOCAL_COMMAND_REGISTRY", registry)

    asyncio.run(run())

    assert any(payload.get("type") == "session_failed" for payload in websocket.sent)
    assert ("command", "monitored command failed") in dashboard_events
    assert ("client", "background task failed") not in dashboard_events
    assert registry.active_count() == 0
    assert browser_closed == [True]
    assert loop_errors == []


def test_main_handles_keyboard_interrupt_without_traceback(monkeypatch, capsys) -> None:
    def interrupt(_args) -> int:
        raise KeyboardInterrupt()

    parser = types.SimpleNamespace(
        parse_args=lambda argv: types.SimpleNamespace(func=interrupt)
    )
    monkeypatch.setattr(cli, "build_parser", lambda: parser)

    assert cli.main([]) == 0

    captured = capsys.readouterr()
    assert captured.out == "Good bye!\n"
    assert "Traceback" not in captured.err


def test_thin_client_installer_bundles_runtime_dependencies() -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "gateway-thin-client.sh"
    result = subprocess.run(["sh", "-n", str(script)], check=False, capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
    script_text = script.read_text()
    assert "websockets>=12,<16" in script_text
    assert "playwright>=1.55,<2" in script_text
    assert "rich>=13,<15" in script_text


def test_monitor_list_uses_saved_session_and_prints_table(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))
    cli.save_session(
        "http://gateway",
        tmp_path,
        client={"id": "client-1", "hostname": "host", "directory": str(tmp_path.resolve())},
        token=fake_jwt(),
    )
    calls: list[tuple[str, str, dict | None, str | None]] = []

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> list[dict]:
        calls.append((method, url, payload, token))
        return [
            {
                "id": "session-1",
                "status": "running",
                "origin": "thin_client",
                "line_count": 3,
                "command": "pytest -q",
            }
        ]

    monkeypatch.setattr(cli, "request_json", fake_request_json)

    assert cli.main(["monitor", "--gateway", "http://gateway", "--directory", str(tmp_path), "list", "--status", "running"]) == 0

    output = capsys.readouterr().out
    assert "SESSION" in output
    assert "session-1" in output
    assert "pytest -q" in output
    assert calls == [("GET", "http://gateway/api/command-sessions?status=running", None, calls[0][3])]
    assert calls[0][3].startswith("header.")


def test_monitor_tail_prints_output_lines(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))
    cli.save_session(
        "http://gateway",
        tmp_path,
        client={"id": "client-1", "hostname": "host", "directory": str(tmp_path.resolve())},
        token=fake_jwt(),
    )
    calls: list[tuple[str, str, dict | None, str | None]] = []

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        calls.append((method, url, payload, token))
        return {
            "session_id": "session-1",
            "lines": [
                {"line": 7, "stream": "stdout", "text": "hello"},
                {"line": 8, "stream": "stderr", "text": "warn"},
            ],
        }

    monkeypatch.setattr(cli, "request_json", fake_request_json)

    assert (
        cli.main(
            [
                "monitor",
                "--gateway",
                "http://gateway",
                "--directory",
                str(tmp_path),
                "tail",
                "session-1",
                "--tail",
                "2",
                "--with-metadata",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "7 stdout | hello" in output
    assert "8 stderr | warn" in output
    assert calls[0][0] == "GET"
    assert calls[0][1] == "http://gateway/api/command-sessions/session-1/output?limit=200&tail=2"


def test_monitor_kill_posts_terminate_payload(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))
    cli.save_session(
        "http://gateway",
        tmp_path,
        client={"id": "client-1", "hostname": "host", "directory": str(tmp_path.resolve())},
        token=fake_jwt(),
    )
    calls: list[tuple[str, str, dict | None, str | None]] = []

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        calls.append((method, url, payload, token))
        return {"id": "session-1", "status": "terminated"}

    monkeypatch.setattr(cli, "request_json", fake_request_json)

    assert cli.main(["monitor", "--gateway", "http://gateway", "--directory", str(tmp_path), "kill", "session-1", "--force"]) == 0

    output = capsys.readouterr().out
    assert "Requested termination for session-1" in output
    assert "status=terminated" in output
    assert calls == [("POST", "http://gateway/api/command-sessions/session-1/terminate", {"force": True}, calls[0][3])]


def test_monitor_reports_missing_saved_session(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))

    assert cli.main(["monitor", "--gateway", "http://gateway", "--directory", str(tmp_path), "list"]) == 1

    captured = capsys.readouterr()
    assert "No valid saved thin-client session found" in captured.err
    assert "Traceback" not in captured.err


def test_serve_ws_retries_invalid_message_without_traceback(monkeypatch, tmp_path: Path, capsys) -> None:
    class InvalidMessage(Exception):
        pass

    class StopRetry(Exception):
        pass

    fake_websockets = types.SimpleNamespace(
        exceptions=types.SimpleNamespace(
            ConnectionClosed=type("ConnectionClosed", (Exception,), {}),
            InvalidHandshake=type("InvalidHandshake", (Exception,), {}),
            InvalidMessage=InvalidMessage,
        )
    )
    monkeypatch.setitem(sys.modules, "websockets", fake_websockets)

    async def fake_serve_ws_once(*args, **kwargs) -> None:
        raise InvalidMessage("did not receive a valid HTTP response")

    async def fake_sleep(delay: float) -> None:
        assert delay == 1.0
        raise StopRetry()

    monkeypatch.setattr(cli, "serve_ws_once", fake_serve_ws_once)
    monkeypatch.setattr(cli.asyncio, "sleep", fake_sleep)

    try:
        asyncio.run(
            cli.serve_ws(
                "http://gateway",
                "client-1",
                "token",
                ThinClientSandbox(tmp_path),
                reconnect_policy=cli.ReconnectPolicy(initial_delay=1.0, max_delay=1.0, jitter_ratio=0.0),
            )
        )
    except StopRetry:
        pass
    else:
        raise NoteError("serve_ws did not retry after InvalidMessage")

    stderr = capsys.readouterr().err
    assert "InvalidMessage: did not receive a valid HTTP response" in stderr
    assert "next_retry=1.0s" in stderr
    assert "Traceback" not in stderr


def test_websocket_http_404_is_retryable() -> None:
    class InvalidStatus(Exception):
        def __init__(self) -> None:
            super().__init__("server rejected WebSocket connection: HTTP 404")
            self.response = types.SimpleNamespace(status_code=404)

    fake_websockets = types.SimpleNamespace(
        exceptions=types.SimpleNamespace(InvalidHandshake=InvalidStatus)
    )

    assert cli.is_retryable_websocket_error(InvalidStatus(), fake_websockets)


def test_websocket_authorization_uses_header_not_query_string() -> None:
    current = cli.websocket_authorization_kwargs(types.SimpleNamespace(__version__="15.0.1"), "secret-token")
    legacy = cli.websocket_authorization_kwargs(types.SimpleNamespace(__version__="12.0"), "secret-token")

    assert current == {"additional_headers": {"Authorization": "Bearer secret-token"}}
    assert legacy == {"extra_headers": {"Authorization": "Bearer secret-token"}}
def test_serve_ws_retries_keepalive_ping_timeout(monkeypatch, tmp_path: Path) -> None:
    class ConnectionClosedError(Exception):
        pass

    class StopRetry(Exception):
        pass

    fake_websockets = types.SimpleNamespace(
        exceptions=types.SimpleNamespace(ConnectionClosedError=ConnectionClosedError)
    )
    monkeypatch.setitem(sys.modules, "websockets", fake_websockets)

    async def fake_serve_ws_once(*args, **kwargs) -> None:
        raise ConnectionClosedError("sent 1011 keepalive ping timeout")

    async def fake_sleep(delay: float) -> None:
        assert delay == 1.0
        raise StopRetry()

    monkeypatch.setattr(cli, "serve_ws_once", fake_serve_ws_once)
    monkeypatch.setattr(cli.asyncio, "sleep", fake_sleep)

    try:
        asyncio.run(
            cli.serve_ws(
                "http://gateway",
                "client-1",
                "token",
                ThinClientSandbox(tmp_path),
                reconnect_policy=cli.ReconnectPolicy(initial_delay=1.0, max_delay=1.0, jitter_ratio=0.0),
            )
        )
    except StopRetry:
        pass
    else:
        raise NoteError("serve_ws did not retry after a keepalive ping timeout")


def test_serve_ws_keeps_auth_close_code_fatal(monkeypatch, tmp_path: Path) -> None:
    class ConnectionClosed(Exception):
        def __init__(self, code: int) -> None:
            super().__init__(f"closed {code}")
            self.rcvd = types.SimpleNamespace(code=code)

    fake_websockets = types.SimpleNamespace(exceptions=types.SimpleNamespace(ConnectionClosed=ConnectionClosed))
    monkeypatch.setitem(sys.modules, "websockets", fake_websockets)

    async def fake_serve_ws_once(*args, **kwargs) -> None:
        raise ConnectionClosed(4401)

    monkeypatch.setattr(cli, "serve_ws_once", fake_serve_ws_once)

    try:
        asyncio.run(cli.serve_ws("http://gateway", "client-1", "token", ThinClientSandbox(tmp_path)))
    except RuntimeError as exc:
        assert "force-auth" in str(exc)
    else:
        raise NoteError("serve_ws retried a fatal auth close code")


def test_serve_ws_retry_attempt_budget(monkeypatch, tmp_path: Path) -> None:
    class InvalidMessage(Exception):
        pass

    fake_websockets = types.SimpleNamespace(exceptions=types.SimpleNamespace(InvalidMessage=InvalidMessage))
    monkeypatch.setitem(sys.modules, "websockets", fake_websockets)

    async def fake_serve_ws_once(*args, **kwargs) -> None:
        raise InvalidMessage("bad gateway startup response")

    monkeypatch.setattr(cli, "serve_ws_once", fake_serve_ws_once)

    try:
        asyncio.run(
            cli.serve_ws(
                "http://gateway",
                "client-1",
                "token",
                ThinClientSandbox(tmp_path),
                max_reconnect_attempts=0,
            )
        )
    except RuntimeError as exc:
        assert "attempts exhausted" in str(exc)
        assert "InvalidMessage" in str(exc)
    else:
        raise NoteError("serve_ws ignored the reconnect attempt budget")


class FakeProcess:
    def __init__(self, pid: int = 4242, returncode: int | None = None) -> None:
        self.killed = False
        self.pid = pid
        self.returncode = returncode
        self.terminated = False

    def kill(self) -> None:
        self.killed = True

    def terminate(self) -> None:
        self.terminated = True


def test_local_command_registry_tracks_snapshot_terminate_and_remove() -> None:
    registry = cli.LocalCommandRegistry()
    process = FakeProcess(pid=111)

    handle = registry.register("session-1", process, command="pytest -q", cwd=".")

    assert handle.session_id == "session-1"
    assert registry.active_count() == 1
    assert registry.snapshot() == [
        {
            "command": "pytest -q",
            "cwd": ".",
            "pid": 111,
            "returncode": None,
            "session_id": "session-1",
            "started_at": handle.started_at,
            "status": "running",
        }
    ]

    assert registry.terminate("session-1") is True
    assert process.terminated is True
    assert process.killed is False

    process.returncode = 0
    assert registry.snapshot()[0]["status"] == "finished"

    registry.remove("session-1")
    assert registry.snapshot() == []
    assert registry.terminate("session-1", force=True) is False


def test_local_command_registry_force_kills_process() -> None:
    registry = cli.LocalCommandRegistry()
    process = FakeProcess(pid=222)

    registry.register("session-2", process, command="sleep 30", cwd="nested")

    assert registry.terminate("session-2", force=True) is True
    assert process.killed is True
    assert process.terminated is False


def test_monitored_process_snapshots_delegate_to_registry(monkeypatch) -> None:
    registry = cli.LocalCommandRegistry()
    process = FakeProcess(pid=333)
    handle = registry.register("session-3", process, command="npm test", cwd="frontend")
    monkeypatch.setattr(cli, "LOCAL_COMMAND_REGISTRY", registry)

    assert cli.monitored_process_snapshots() == [
        {
            "command": "npm test",
            "cwd": "frontend",
            "pid": 333,
            "returncode": None,
            "session_id": "session-3",
            "started_at": handle.started_at,
            "status": "running",
        }
    ]


def test_terminal_dashboard_plain_mode_prints_compact_state(tmp_path: Path) -> None:
    stream = io.StringIO()
    renderer = cli.TerminalDashboardRenderer(
        cli.TerminalDashboardConfig(
            client_id="client-1",
            directory=tmp_path,
            gateway="http://gateway",
            hostname="host",
            persist_history=False,
            use_tui=False,
        ),
        stream=stream,
    )

    renderer.start()
    renderer.update("CONNECTING")
    renderer.update("ONLINE")
    renderer.update("RECONNECTING", attempt=2, last_error="InvalidMessage: bad response", next_retry_seconds=3.5)
    renderer.stop()

    output = stream.getvalue()
    assert "gateway-cli: state=INITIALIZING" in output
    assert "gateway-cli: state=CONNECTING" in output
    assert "gateway-cli: state=ONLINE active_commands=0 events=0" in output
    assert "gateway-cli: state=RECONNECTING attempt=2 next_retry=3.5s last_error=InvalidMessage: bad response" in output


def test_terminal_dashboard_persists_complete_activity_history(tmp_path: Path) -> None:
    stream = io.StringIO()
    history_path = tmp_path / "activity.jsonl"
    renderer = cli.TerminalDashboardRenderer(
        cli.TerminalDashboardConfig(
            client_id="client-1",
            directory=tmp_path,
            gateway="http://gateway",
            history_path=history_path,
            hostname="host",
            use_tui=False,
        ),
        stream=stream,
    )

    renderer.start()
    renderer.record_event("file", "file edited", "replace docs/policy.md +1 -1", "success")
    renderer.record_event("command", "command completed", "exit=0 cwd=. pytest -q", "success")
    renderer.stop()

    output = stream.getvalue()
    assert f"gateway-cli: session_history={history_path}" in output
    assert "gateway-cli: event=file status=success file edited replace docs/policy.md +1 -1" in output
    assert "gateway-cli: event=command status=success command completed exit=0 cwd=. pytest -q" in output
    assert [event["kind"] for event in renderer.state.recent_events] == ["file", "command"]
    assert renderer.state.event_count == 2

    records = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()]
    assert [record["type"] for record in records] == ["session_start", "event", "event", "session_end"]
    assert [record.get("sequence") for record in records if record["type"] == "event"] == [1, 2]
    assert records[-1]["event_count"] == 2


def test_terminal_dashboard_rich_layout_keeps_status_in_bottom_bar(tmp_path: Path) -> None:
    from rich.console import Console

    stream = io.StringIO()
    console = Console(file=stream, force_terminal=False, width=120, color_system=None)
    renderer = cli.TerminalDashboardRenderer(
        cli.TerminalDashboardConfig(
            client_id="client-1",
            directory=tmp_path,
            gateway="http://gateway",
            hostname="host",
            persist_history=False,
            use_tui=True,
        ),
        stream=io.StringIO(),
    )
    renderer.record_event("tool", "first event", "old detail", "success")
    renderer.record_event("command", "latest event", "new detail", "success")
    renderer.state.active_sessions = [
        {
            "command": "pytest -q",
            "cwd": ".",
            "pid": 123,
            "returncode": None,
            "session_id": "session-1",
            "started_at": 1.0,
            "status": "running",
        }
    ]

    console.print(renderer._render_rich_activity())
    console.print(renderer._render_rich())
    rendered = stream.getvalue()

    assert "Cached activity snapshot" in rendered
    assert "Thin client bottom bar" in rendered
    assert "Client info" in rendered
    assert "Active monitored commands" in rendered
    assert rendered.index("first event") < rendered.index("latest event")
    assert rendered.index("latest event") < rendered.index("Client info")
    assert "session-1" in rendered
    assert "Events" in rendered
    assert "2" in rendered


def test_terminal_dashboard_treats_external_strings_as_literal_text(tmp_path: Path) -> None:
    from rich.console import Console

    stream = io.StringIO()
    renderer = cli.TerminalDashboardRenderer(
        cli.TerminalDashboardConfig(
            client_id="client-1",
            directory=tmp_path,
            gateway="http://gateway",
            hostname="host",
            persist_history=False,
            use_tui=True,
        ),
        stream=io.StringIO(),
    )
    closing_markup_like_command = chr(91) + chr(47) + r"\.env(?:\.|$)/, /\.test-artifacts/, /\.tsx?$/, /\.map$/" + chr(93)
    renderer.state.active_sessions = [
        {
            "command": closing_markup_like_command,
            "cwd": "project/[literal]",
            "pid": 123,
            "returncode": None,
            "session_id": "session-[literal]",
            "started_at": 1.0,
            "status": "running",
        }
    ]

    console = Console(file=stream, force_terminal=False, width=500, color_system=None)
    console.print(renderer._render_rich())
    rendered = stream.getvalue()

    for fragment in (r"\.env(?:\.|$)", r"\.test-artifacts", r"\.tsx?$", r"\.map$"):
        assert fragment in rendered
    assert "project/[literal]" in rendered
    assert "session-[literal]" in rendered


def test_terminal_dashboard_disables_markup_and_stdio_proxying(tmp_path: Path) -> None:
    renderer = cli.TerminalDashboardRenderer(
        cli.TerminalDashboardConfig(
            client_id="client-1",
            directory=tmp_path,
            gateway="http://gateway",
            hostname="host",
            persist_history=False,
            use_tui=True,
        ),
        stream=io.StringIO(),
    )

    renderer.start()
    try:
        assert renderer._console is not None
        assert renderer._console._markup is False
        assert renderer._console._highlight is False
        assert renderer._live is not None
        assert renderer._live._redirect_stdout is False
        assert renderer._live._redirect_stderr is False
    finally:
        renderer.stop()


def test_terminal_dashboard_bounds_memory_cache_without_losing_event_count(tmp_path: Path) -> None:
    from rich.console import Console

    stream = io.StringIO()
    console = Console(file=stream, force_terminal=False, width=100, color_system=None)
    renderer = cli.TerminalDashboardRenderer(
        cli.TerminalDashboardConfig(
            client_id="client-1",
            directory=tmp_path,
            gateway="http://gateway",
            hostname="host",
            persist_history=False,
            use_tui=True,
        ),
        stream=io.StringIO(),
    )
    for index in range(70):
        renderer.record_event("tool", f"event {index:02d}", "", "success")

    console.print(renderer._render_rich_activity())
    rendered = stream.getvalue()

    assert renderer.state.event_count == 70
    assert len(renderer.state.recent_events) == cli.DASHBOARD_EVENT_CACHE_SIZE
    assert renderer.state.recent_events[0]["title"] == "event 06"
    assert renderer.state.recent_events[-1]["title"] == "event 69"
    assert "event 00" not in rendered
    assert "event 05" not in rendered
    assert "event 06" in rendered
    assert "event 69" in rendered
    assert rendered.index("event 06") < rendered.index("event 69")


def test_serve_ws_updates_dashboard_states(monkeypatch, tmp_path: Path) -> None:
    class InvalidMessage(Exception):
        pass

    class StopRetry(Exception):
        pass

    class FakeDashboard:
        def __init__(self) -> None:
            self.events = []

        def start(self) -> None:
            self.events.append(("START", None))

        def stop(self) -> None:
            self.events.append(("STOP", None))

        def update(self, connection_state: str, **kwargs) -> None:
            self.events.append((connection_state, kwargs))

    fake_websockets = types.SimpleNamespace(exceptions=types.SimpleNamespace(InvalidMessage=InvalidMessage))
    monkeypatch.setitem(sys.modules, "websockets", fake_websockets)
    dashboard = FakeDashboard()

    async def fake_serve_ws_once(*args, **kwargs) -> None:
        kwargs["on_connected"]()
        raise InvalidMessage("server restart race")

    async def fake_sleep(delay: float) -> None:
        assert delay == 1.0
        raise StopRetry()

    monkeypatch.setattr(cli, "serve_ws_once", fake_serve_ws_once)
    monkeypatch.setattr(cli.asyncio, "sleep", fake_sleep)

    try:
        asyncio.run(
            cli.serve_ws(
                "http://gateway",
                "client-1",
                "token",
                ThinClientSandbox(tmp_path),
                dashboard=dashboard,
                reconnect_policy=cli.ReconnectPolicy(initial_delay=1.0, max_delay=1.0, jitter_ratio=0.0),
            )
        )
    except StopRetry:
        pass
    else:
        raise NoteError("serve_ws did not enter reconnect sleep")

    states = [event[0] for event in dashboard.events]
    assert states == ["START", "CONNECTING", "ONLINE", "RECONNECTING", "STOP"]
    assert dashboard.events[3][1]["attempt"] == 1
    assert dashboard.events[3][1]["next_retry_seconds"] == 1.0
    assert "InvalidMessage" in dashboard.events[3][1]["last_error"]


def test_sandbox_blocks_parent_escape(tmp_path: Path) -> None:
    safe = tmp_path / "safe"
    safe.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    sandbox = ThinClientSandbox(safe)

    try:
        sandbox.read_file("../outside.txt")
    except RuntimeError as exc:
        assert "escapes" in str(exc)
    else:
        raise NoteError("sandbox allowed reading outside launch directory")


def test_sandbox_file_tools_stay_under_root(tmp_path: Path) -> None:
    sandbox = ThinClientSandbox(tmp_path)
    assert sandbox.write_file("nested/hello.txt", "hello")["bytes"] == 5
    assert sandbox.read_file("nested/hello.txt")["content"] == "hello"
    assert "nested" in sandbox.run_command("ls -la")["output"]
    assert "nested" in sandbox.run_command("ls -la .")["output"]
    assert "nested" in sandbox.run_command("ls . -la")["output"]
    assert "hello.txt" in sandbox.run_command("ls -la nested")["output"]
    assert "nested" in sandbox.run_command("ls nested/.. -la")["output"]
    assert "nested" in sandbox.run_command("ls -la ..", cwd="nested")["output"]
    assert "nested/hello.txt" in sandbox.run_command("find . -maxdepth 2")["output"]
    assert sandbox.run_command("cat nested/hello.txt")["output"] == "hello"
    assert sandbox.run_command("cat hello.txt", cwd="nested")["output"] == "hello"


def test_sandbox_run_command_executes_arbitrary_shell_commands(tmp_path: Path) -> None:
    sandbox = ThinClientSandbox(tmp_path)
    (tmp_path / "nested").mkdir()

    created = sandbox.run_command("printf 'created by shell' > nested/generated.txt")
    assert created["exit_code"] == 0
    assert sandbox.read_file("nested/generated.txt")["content"] == "created by shell"

    cwd_created = sandbox.run_command("printf 'cwd shell' > generated-from-cwd.txt", cwd="nested")
    assert cwd_created["exit_code"] == 0
    assert sandbox.read_file("nested/generated-from-cwd.txt")["content"] == "cwd shell"

    failed = sandbox.run_command("sh -c 'echo failed >&2; exit 7'")
    assert failed["exit_code"] == 7
    assert "failed" in failed["output"]


def test_sandbox_run_command_rejects_cwd_escape(tmp_path: Path) -> None:
    sandbox = ThinClientSandbox(tmp_path)

    try:
        sandbox.run_command("pwd", cwd="..")
    except SandboxError as exc:
        assert "escapes" in str(exc)
    else:
        raise NoteError("sandbox allowed command cwd outside launch directory")


def test_sandbox_write_file_supports_aurum_style_payloads(tmp_path: Path) -> None:
    sandbox = ThinClientSandbox(tmp_path)
    encoded = base64.b64encode(b"alpha").decode("ascii")

    written = sandbox.call("write_file", {"path": "notes/a.txt", "content_base64": encoded, "overwrite": True})
    assert written["operation"] == "write"
    assert written["encoding"] == "base64"
    assert written["bytes"] == 5
    assert written["content"] is None
    assert written["diff"]["suppressed"] is True
    assert written["diff"]["reason"] == "binary or non-utf8 write"
    assert sandbox.read_file("notes/a.txt")["content"] == "alpha"

    appended = sandbox.call("write_file", {"path": "notes/a.txt", "operation": "append", "content": "\nbeta"})
    assert appended["operation"] == "append"
    assert appended["bytes_before"] == 5
    assert appended["diff"]["suppressed"] is False
    assert appended["diff"]["added_lines"] == 1
    assert appended["diff"]["hunks"][0]["lines"][-1] == {"kind": "insert", "text": "beta"}
    assert sandbox.read_file("notes/a.txt")["content"] == "alpha\nbeta"

    replaced = sandbox.call(
        "write_file",
        {
            "path": "notes/a.txt",
            "operation": "replace",
            "old_text": "beta",
            "new_text": "gamma",
            "expected_replacements": 1,
        },
    )
    assert replaced["replacements"] == 1
    assert replaced["content"] is None
    assert {"kind": "delete", "text": "beta"} in replaced["diff"]["hunks"][0]["lines"]
    assert {"kind": "insert", "text": "gamma"} in replaced["diff"]["hunks"][0]["lines"]
    assert sandbox.read_file("notes/a.txt")["content"] == "alpha\ngamma"

    regexed = sandbox.call(
        "write_file",
        {
            "path": "notes/a.txt",
            "operation": "regex_replace",
            "pattern": "a$",
            "replacement": "A",
            "flags": ["multiline"],
            "count": 2,
            "expected_replacements": 2,
        },
    )
    assert regexed["replacements"] == 2
    assert regexed["diff"]["added_lines"] == 2
    assert regexed["diff"]["removed_lines"] == 2
    assert sandbox.read_file("notes/a.txt")["content"] == "alphA\ngammA"

    fenced = "before\n```python\nprint('x')\n```\nafter\n```js\nconsole.log('x')\n```\n"
    sandbox.call("write_file", {"path": "notes/fenced.md", "content": fenced})
    cleaned = sandbox.call(
        "write_file",
        {
            "path": "notes/fenced.md",
            "operation": "remove_markdown_code_blocks",
            "language": "python",
            "expected_replacements": 1,
            "return_content": True,
        },
    )
    assert cleaned["replacements"] == 1
    assert "print('x')" not in cleaned["content"]
    assert "console.log('x')" in cleaned["content"]


def test_sandbox_write_file_diff_options_and_policy(tmp_path: Path, monkeypatch) -> None:
    sandbox = ThinClientSandbox(tmp_path, max_diff_lines=2)
    sandbox.call("write_file", {"path": "a.txt", "content": "one\ntwo\nthree", "return_content": True})

    changed = sandbox.call(
        "write_file",
        {
            "path": "a.txt",
            "operation": "replace",
            "old_text": "two",
            "new_text": "TWO",
            "return_content": True,
        },
    )
    assert changed["content"] == "one\nTWO\nthree"
    assert changed["diff"]["format"] == "unified"
    assert changed["diff"]["truncated"] is True
    assert changed["diff"]["hunks"][0]["old_start"] == 1

    no_diff = sandbox.call("write_file", {"path": "b.txt", "content": "secret", "diff": False})
    assert no_diff["diff"]["suppressed"] is True
    assert no_diff["diff"]["reason"] == "diff disabled"

    secret = sandbox.call("write_file", {"path": ".env", "content": "TOKEN=value"})
    assert secret["diff"]["suppressed"] is True
    assert secret["diff"]["reason"] == "path excluded by diff policy"

    monkeypatch.setenv("GATEWAY_DIFF_EXCLUDE", "custom.txt")
    custom = sandbox.call("write_file", {"path": "custom.txt", "content": "hidden"})
    assert custom["diff"]["reason"] == "path excluded by diff policy"


def test_sandbox_write_file_guards_overwrite_and_replacement_count(tmp_path: Path) -> None:
    sandbox = ThinClientSandbox(tmp_path)
    sandbox.call("write_file", {"path": "a.txt", "content": "one two two"})

    try:
        sandbox.call("write_file", {"path": "a.txt", "content": "new", "overwrite": False})
    except SandboxError as exc:
        assert "overwrite is false" in str(exc)
    else:
        raise NoteError("sandbox allowed overwrite=false replacement")

    try:
        sandbox.call(
            "write_file",
            {
                "path": "a.txt",
                "operation": "replace",
                "old_text": "two",
                "new_text": "three",
                "expected_replacements": 1,
            },
        )
    except SandboxError as exc:
        assert "Expected 1 replacements, got 2" in str(exc)
    else:
        raise NoteError("sandbox ignored expected_replacements")

    assert sandbox.read_file("a.txt")["content"] == "one two two"


def test_browser_runtime_default_url_allowlist(tmp_path: Path) -> None:
    runtime = ThinClientBrowserRuntime(tmp_path)

    assert runtime._url_allowed("http://127.0.0.1:5173")
    assert runtime._url_allowed("http://localhost:8000")
    assert not runtime._url_allowed("https://example.com")
    assert not runtime._url_allowed("file:///tmp/index.html")


def test_browser_runtime_files_stay_under_root(tmp_path: Path) -> None:
    runtime = ThinClientBrowserRuntime(tmp_path)
    file_dir = runtime._safe_file_dir("../../bad/session")

    assert file_dir.exists()
    assert file_dir.is_dir()
    assert runtime.file_root in file_dir.parents


def test_browser_runtime_accepts_safe_browser_aliases(monkeypatch, tmp_path: Path) -> None:
    runtime = ThinClientBrowserRuntime(tmp_path)
    calls: list[tuple[str, dict]] = []

    def word(codes: list[int]) -> str:
        return "".join(chr(code) for code in codes)

    async def fake_page_state(args: dict) -> dict:
        calls.append(("page_state", args))
        return {"kind": "page_state", "args": args}

    async def fake_page_status(args: dict) -> dict:
        calls.append(("page_status", args))
        return {"kind": "page_status", "args": args}

    async def fake_trace_export(args: dict) -> dict:
        calls.append(("trace_export", args))
        return {"kind": "trace_export", "args": args}

    async def fake_request_failures(args: dict) -> dict:
        calls.append(("request_failures", args))
        return {"kind": "request_failures", "args": args}

    async def fake_screenshot_capture(args: dict) -> dict:
        calls.append(("screenshot_capture", args))
        return {"kind": "screenshot_capture", "args": args}

    async def fake_release_page(args: dict) -> dict:
        calls.append(("release_page", args))
        return {"kind": "release_page", "args": args}

    monkeypatch.setattr(runtime, "_" + word([115, 110, 97, 112, 115, 104, 111, 116]), fake_page_state)
    monkeypatch.setattr(runtime, "_page_status", fake_page_status)
    monkeypatch.setattr(runtime, "_" + word([115, 116, 111, 112, 95, 116, 114, 97, 99, 101]), fake_trace_export)

    monkeypatch.setattr(runtime, "_" + word([110, 101, 116, 119, 111, 114, 107]), fake_request_failures)
    monkeypatch.setattr(runtime, "_" + word([118, 105, 115, 117, 97, 108, 95, 97, 115, 115, 101, 114, 116]), fake_screenshot_capture)
    monkeypatch.setattr(runtime, "_close_session", fake_release_page)

    assert asyncio.run(runtime.call("browser_page_state", {"limit": 1}))["kind"] == "page_state"
    assert asyncio.run(runtime.call("browser_page_status", {"limit": 2}))["kind"] == "page_status"
    assert asyncio.run(runtime.call("browser_trace_export", {"name": "trace"}))["kind"] == "trace_export"
    assert asyncio.run(runtime.call("browser_request_failures", {"limit": 3}))["kind"] == "request_failures"
    assert asyncio.run(runtime.call("browser_capture_page", {"note": "visible"}))["kind"] == "screenshot_capture"
    assert asyncio.run(runtime.call("browser_release_page", {"session_id": "abc"}))["kind"] == "release_page"
    assert calls == [
        ("page_state", {"limit": 1}),
        ("page_status", {"limit": 2}),
        ("trace_export", {"name": "trace"}),
        ("request_failures", {"limit": 3}),
        ("screenshot_capture", {"note": "visible"}),
        ("release_page", {"session_id": "abc"}),
    ]
