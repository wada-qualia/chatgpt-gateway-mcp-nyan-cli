from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urljoin, urlencode
from urllib.request import Request, urlopen


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


async def serve_ws(gateway: str, client_id: str, token: str) -> None:
    try:
        import websockets
    except ImportError as exc:
        raise RuntimeError("Install websockets to use --serve") from exc
    ws_base = gateway.replace("https://", "wss://").replace("http://", "ws://").rstrip("/")
    url = f"{ws_base}/api/thin-clients/ws/{client_id}?{urlencode({'token': token})}"
    async with websockets.connect(url) as websocket:
        while True:
            await websocket.send(json.dumps({"type": "heartbeat", "ts": time.time()}))
            await websocket.recv()
            await asyncio.sleep(15)


def login(args: argparse.Namespace) -> int:
    gateway = args.gateway.rstrip("/")
    device = request_json("POST", urljoin(gateway, "/api/thin-clients/device-code"))
    print(f"Open {device['verification_uri']} and enter code {device['user_code']}")
    token = poll_token(gateway, str(device["device_code"]), int(device.get("interval", 3)))
    register_payload = {
        "hostname": socket.gethostname(),
        "directory": str(Path(args.directory).resolve()),
        "labels": {"client": "gateway-cli"},
    }
    client = request_json("POST", urljoin(gateway, "/api/thin-clients/register"), register_payload, token=token)
    print(json.dumps({"client_id": client["id"], "hostname": client["hostname"], "directory": client["directory"]}, indent=2))
    if args.serve:
        asyncio.run(serve_ws(gateway, client["id"], token))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gateway-cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    login_parser = subparsers.add_parser("login")
    login_parser.add_argument("--gateway", default="http://localhost:8000")
    login_parser.add_argument("--directory", default=".")
    login_parser.add_argument("--serve", action="store_true")
    login_parser.set_defaults(func=login)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
