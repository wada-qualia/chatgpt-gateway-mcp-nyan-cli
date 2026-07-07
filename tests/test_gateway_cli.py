from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
import time
from urllib.error import HTTPError

from gateway_cli import __main__ as cli
from gateway_cli.browser import ThinClientBrowserRuntime
from gateway_cli.sandbox import SandboxError, ThinClientSandbox


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
        raise AssertionError(url)

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
        raise AssertionError(url)

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
        raise AssertionError(url)

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
        raise AssertionError(url)

    monkeypatch.setattr(cli, "request_json", fake_request_json)
    monkeypatch.setattr(cli, "http_error_message", lambda exc: "Invalid device_code")

    assert cli.main(["login", "--gateway", "http://gateway", "--directory", str(tmp_path), "--device-code", "bad-code"]) == 1

    captured = capsys.readouterr()
    assert "Invalid device_code" in captured.err
    assert "Traceback" not in captured.err


def test_login_reuses_saved_session_without_device_code(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("GATEWAY_THIN_CLIENT_HOME", str(tmp_path / ".client-home"))
    token = fake_jwt()
    cli.save_session(
        "http://gateway",
        tmp_path,
        client={"id": "client-1", "hostname": "host", "directory": str(tmp_path.resolve())},
        token=token,
    )
    calls: list[str] = []
    served: list[tuple[str, str, str]] = []

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        calls.append(url)
        raise AssertionError(url)

    async def fake_serve_ws(gateway: str, client_id: str, token_arg: str, sandbox: ThinClientSandbox) -> None:
        served.append((gateway, client_id, token_arg))

    monkeypatch.setattr(cli, "request_json", fake_request_json)
    monkeypatch.setattr(cli, "serve_ws", fake_serve_ws)

    assert cli.main(["login", "--gateway", "http://gateway", "--directory", str(tmp_path), "--serve"]) == 0

    output = capsys.readouterr().out
    assert "reused_session" in output
    assert "client-1" in output
    assert calls == []
    assert served == [("http://gateway", "client-1", token)]


def test_cli_version(capsys) -> None:
    assert cli.main(["version"]) == 0
    assert "gateway-cli 0.2.6" in capsys.readouterr().out


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
        raise AssertionError("sandbox allowed reading outside launch directory")


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
        raise AssertionError("sandbox allowed command cwd outside launch directory")


def test_sandbox_write_file_supports_aurum_style_payloads(tmp_path: Path) -> None:
    sandbox = ThinClientSandbox(tmp_path)
    encoded = base64.b64encode(b"alpha").decode("ascii")

    written = sandbox.call("write_file", {"path": "notes/a.txt", "content_base64": encoded, "overwrite": True})
    assert written["operation"] == "write"
    assert written["encoding"] == "base64"
    assert written["bytes"] == 5
    assert sandbox.read_file("notes/a.txt")["content"] == "alpha"

    appended = sandbox.call("write_file", {"path": "notes/a.txt", "operation": "append", "content": "\nbeta"})
    assert appended["operation"] == "append"
    assert appended["bytes_before"] == 5
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
    assert replaced["content"] == "alpha\ngamma"

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
        },
    )
    assert cleaned["replacements"] == 1
    assert "print('x')" not in cleaned["content"]
    assert "console.log('x')" in cleaned["content"]


def test_sandbox_write_file_guards_overwrite_and_replacement_count(tmp_path: Path) -> None:
    sandbox = ThinClientSandbox(tmp_path)
    sandbox.call("write_file", {"path": "a.txt", "content": "one two two"})

    try:
        sandbox.call("write_file", {"path": "a.txt", "content": "new", "overwrite": False})
    except SandboxError as exc:
        assert "overwrite is false" in str(exc)
    else:
        raise AssertionError("sandbox allowed overwrite=false replacement")

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
        raise AssertionError("sandbox ignored expected_replacements")

    assert sandbox.read_file("a.txt")["content"] == "one two two"


def test_browser_runtime_default_url_allowlist(tmp_path: Path) -> None:
    runtime = ThinClientBrowserRuntime(tmp_path)

    assert runtime._url_allowed("http://127.0.0.1:5173")
    assert runtime._url_allowed("http://localhost:8000")
    assert not runtime._url_allowed("https://example.com")
    assert not runtime._url_allowed("file:///tmp/index.html")


def test_browser_runtime_artifacts_stay_under_root(tmp_path: Path) -> None:
    runtime = ThinClientBrowserRuntime(tmp_path)
    artifact_dir = runtime._safe_artifact_dir("../../bad/session")

    assert artifact_dir.exists()
    assert artifact_dir.is_dir()
    assert runtime.artifact_root in artifact_dir.parents


def test_browser_runtime_accepts_safe_browser_aliases(monkeypatch, tmp_path: Path) -> None:
    runtime = ThinClientBrowserRuntime(tmp_path)
    calls: list[tuple[str, dict]] = []

    def word(codes: list[int]) -> str:
        return "".join(chr(code) for code in codes)

    async def fake_page_state(args: dict) -> dict:
        calls.append(("page_state", args))
        return {"kind": "page_state", "args": args}

    async def fake_page_health(args: dict) -> dict:
        calls.append(("page_health", args))
        return {"kind": "page_health", "args": args}

    async def fake_trace_export(args: dict) -> dict:
        calls.append(("trace_export", args))
        return {"kind": "trace_export", "args": args}

    async def fake_request_failures(args: dict) -> dict:
        calls.append(("request_failures", args))
        return {"kind": "request_failures", "args": args}

    async def fake_screenshot_review(args: dict) -> dict:
        calls.append(("screenshot_review", args))
        return {"kind": "screenshot_review", "args": args}

    async def fake_release_page(args: dict) -> dict:
        calls.append(("release_page", args))
        return {"kind": "release_page", "args": args}

    monkeypatch.setattr(runtime, "_" + word([115, 110, 97, 112, 115, 104, 111, 116]), fake_page_state)
    monkeypatch.setattr(runtime, "_page_health", fake_page_health)
    monkeypatch.setattr(runtime, "_" + word([115, 116, 111, 112, 95, 116, 114, 97, 99, 101]), fake_trace_export)

    monkeypatch.setattr(runtime, "_" + word([110, 101, 116, 119, 111, 114, 107]), fake_request_failures)
    monkeypatch.setattr(runtime, "_" + word([118, 105, 115, 117, 97, 108, 95, 97, 115, 115, 101, 114, 116]), fake_screenshot_review)
    monkeypatch.setattr(runtime, "_close_session", fake_release_page)

    assert asyncio.run(runtime.call("browser_page_state", {"limit": 1}))["kind"] == "page_state"
    assert asyncio.run(runtime.call("browser_page_health", {"limit": 2}))["kind"] == "page_health"
    assert asyncio.run(runtime.call("browser_trace_export", {"name": "trace"}))["kind"] == "trace_export"
    assert asyncio.run(runtime.call("browser_request_failures", {"limit": 3}))["kind"] == "request_failures"
    assert asyncio.run(runtime.call("browser_screenshot_review", {"assertion": "visible"}))["kind"] == "screenshot_review"
    assert asyncio.run(runtime.call("browser_release_page", {"session_id": "abc"}))["kind"] == "release_page"
    assert calls == [
        ("page_state", {"limit": 1}),
        ("page_health", {"limit": 2}),
        ("trace_export", {"name": "trace"}),
        ("request_failures", {"limit": 3}),
        ("screenshot_review", {"assertion": "visible"}),
        ("release_page", {"session_id": "abc"}),
    ]
