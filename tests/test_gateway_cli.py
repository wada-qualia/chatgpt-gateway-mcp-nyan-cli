from __future__ import annotations

from pathlib import Path

from gateway_cli import __main__ as cli


def test_login_registers_current_directory(monkeypatch, tmp_path: Path, capsys) -> None:
    calls: list[tuple[str, str, dict | None, str | None]] = []

    def fake_request_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
        calls.append((method, url, payload, token))
        if url.endswith("/api/thin-clients/device-code"):
            return {"device_code": "device-1", "user_code": "ABC123", "verification_uri": "http://gateway/activate", "interval": 0}
        if url.endswith("/api/thin-clients/token"):
            return {"access_token": "agent-token"}
        if url.endswith("/api/thin-clients/register"):
            return {"id": "client-1", "hostname": "host", "directory": payload["directory"]}
        raise AssertionError(url)

    monkeypatch.setattr(cli, "request_json", fake_request_json)

    assert cli.main(["login", "--gateway", "http://gateway", "--directory", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "ABC123" in output
    assert "client-1" in output
    assert calls[-1][2]["directory"] == str(tmp_path.resolve())
    assert calls[-1][3] == "agent-token"
