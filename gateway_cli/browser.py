from __future__ import annotations

import base64
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class BrowserError(RuntimeError):
    pass


@dataclass
class BrowserSession:
    session_id: str
    playwright: Any
    browser: Any
    context: Any
    page: Any
    artifact_dir: Path
    browser_name: str
    viewport: dict[str, int]
    console: list[dict[str, Any]] = field(default_factory=list)
    network: list[dict[str, Any]] = field(default_factory=list)
    tracing: bool = False
    created_at: float = field(default_factory=time.time)
    last_url: str | None = None


class ThinClientBrowserRuntime:
    def __init__(
        self,
        root: str | Path,
        *,
        artifact_root: str | Path | None = None,
        allowed_origins: list[str] | None = None,
        max_image_bytes: int | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        if not self.root.exists() or not self.root.is_dir():
            raise BrowserError(f"Browser runtime root must be an existing directory: {self.root}")
        raw_artifact_root = Path(artifact_root).expanduser() if artifact_root else self.root / ".artifacts" / "playwright"
        self.artifact_root = raw_artifact_root.resolve() if raw_artifact_root.is_absolute() else (self.root / raw_artifact_root).resolve()
        self.allowed_origins = allowed_origins if allowed_origins is not None else self._allowed_origins_from_env()
        self.max_image_bytes = max_image_bytes if max_image_bytes is not None else int(os.environ.get("GATEWAY_BROWSER_MAX_IMAGE_BYTES", "5000000"))
        self.sessions: dict[str, BrowserSession] = {}

    def _allowed_origins_from_env(self) -> list[str]:
        raw = os.environ.get("GATEWAY_BROWSER_ALLOWED_ORIGINS", "")
        values = [value.strip().rstrip("/") for value in raw.split(",") if value.strip()]
        return values or ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]

    def _safe_artifact_dir(self, session_id: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", session_id)[:80] or uuid.uuid4().hex
        target = (self.artifact_root / safe).resolve()
        if self.artifact_root != target and self.artifact_root not in target.parents:
            raise BrowserError("Artifact path escapes browser artifact root")
        target.mkdir(parents=True, exist_ok=True)
        return target

    def _artifact_relative(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root))
        except ValueError:
            return str(path.resolve())

    def _url_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        origin = f"{parsed.scheme}://{parsed.hostname or ''}"
        if parsed.port is not None:
            origin = f"{origin}:{parsed.port}"
        for allowed in self.allowed_origins:
            if allowed == "*":
                return True
            if allowed.endswith(":*"):
                allowed_base = allowed[:-2]
                if origin.startswith(f"{allowed_base}:") or origin == allowed_base:
                    return True
            if origin == allowed:
                return True
        return False

    def _require_allowed_url(self, url: str) -> None:
        if not self._url_allowed(url):
            raise BrowserError(f"URL is not allowlisted for browser automation: {url}")

    def _target_locator(self, page: Any, args: dict[str, Any]) -> Any:
        if args.get("selector"):
            return page.locator(str(args["selector"])).first
        if args.get("ref"):
            ref = str(args["ref"])
            return page.locator(f'[data-gateway-browser-ref="{ref}"]').first
        if args.get("text"):
            return page.get_by_text(str(args["text"]), exact=bool(args.get("exact", True))).first
        if args.get("role") and args.get("name"):
            return page.get_by_role(str(args["role"]), name=str(args["name"]), exact=bool(args.get("exact", True))).first
        raise BrowserError("selector, ref, text, or role+name is required")

    async def _import_playwright(self) -> Any:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise BrowserError("Python Playwright is not installed. Run: python -m pip install playwright && python -m playwright install chromium") from exc
        return async_playwright

    async def _open_session(self, args: dict[str, Any]) -> dict[str, Any]:
        async_playwright = await self._import_playwright()
        session_id = str(args.get("session_id") or uuid.uuid4().hex)
        if session_id in self.sessions:
            return await self._session_state(self.sessions[session_id])
        browser_name = str(args.get("browser") or "chromium")
        if browser_name not in {"chromium", "firefox", "webkit"}:
            raise BrowserError("browser must be chromium, firefox, or webkit")
        width = int(args.get("width") or os.environ.get("GATEWAY_BROWSER_VIEWPORT_WIDTH", "1440"))
        height = int(args.get("height") or os.environ.get("GATEWAY_BROWSER_VIEWPORT_HEIGHT", "900"))
        headless = bool(args.get("headless", os.environ.get("GATEWAY_BROWSER_HEADLESS", "true").lower() != "false"))
        playwright = await async_playwright().start()
        try:
            browser = await getattr(playwright, browser_name).launch(headless=headless)
            context_args: dict[str, Any] = {"viewport": {"width": width, "height": height}}
            if args.get("storage_state"):
                storage_state = (self.root / str(args["storage_state"])).resolve()
                if self.root != storage_state and self.root not in storage_state.parents:
                    raise BrowserError("storage_state escapes thin-client launch directory")
                if storage_state.exists():
                    context_args["storage_state"] = str(storage_state)
            context = await browser.new_context(**context_args)
            page = await context.new_page()
            artifact_dir = self._safe_artifact_dir(session_id)
            session = BrowserSession(
                session_id=session_id,
                playwright=playwright,
                browser=browser,
                context=context,
                page=page,
                artifact_dir=artifact_dir,
                browser_name=browser_name,
                viewport={"width": width, "height": height},
            )
            page.on("console", lambda message: self._record_console(session, message))
            page.on("pageerror", lambda error: self._record_page_error(session, error))
            page.on("requestfailed", lambda request: self._record_request_failed(session, request))
            page.on("response", lambda response: self._record_response(session, response))
            self.sessions[session_id] = session
            return await self._session_state(session)
        except Exception:
            await playwright.stop()
            raise

    def _record_console(self, session: BrowserSession, message: Any) -> None:
        entry = {
            "type": getattr(message, "type", "console"),
            "text": getattr(message, "text", ""),
            "location": getattr(message, "location", None),
            "ts": time.time(),
        }
        session.console.append(entry)
        session.console[:] = session.console[-300:]

    def _record_page_error(self, session: BrowserSession, error: Any) -> None:
        session.console.append({"type": "pageerror", "text": str(error), "location": None, "ts": time.time()})
        session.console[:] = session.console[-300:]

    def _record_request_failed(self, session: BrowserSession, request: Any) -> None:
        failure = request.failure
        session.network.append(
            {
                "type": "requestfailed",
                "url": request.url,
                "method": request.method,
                "error": failure.get("errorText") if isinstance(failure, dict) else str(failure),
                "ts": time.time(),
            }
        )
        session.network[:] = session.network[-500:]

    def _record_response(self, session: BrowserSession, response: Any) -> None:
        if response.status < 400:
            return
        session.network.append(
            {
                "type": "response",
                "url": response.url,
                "status": response.status,
                "status_text": response.status_text,
                "ts": time.time(),
            }
        )
        session.network[:] = session.network[-500:]

    async def _get_session(self, args: dict[str, Any]) -> BrowserSession:
        session_id = str(args.get("session_id") or "")
        if not session_id:
            if len(self.sessions) == 1:
                return next(iter(self.sessions.values()))
            if not self.sessions:
                opened = await self._open_session(args)
                return self.sessions[str(opened["session_id"])]
            raise BrowserError("session_id is required when multiple browser sessions are open")
        session = self.sessions.get(session_id)
        if session is None:
            raise BrowserError(f"Browser session not found: {session_id}")
        return session

    async def _session_state(self, session: BrowserSession) -> dict[str, Any]:
        title = await session.page.title() if not session.page.is_closed() else ""
        return {
            "session_id": session.session_id,
            "browser": session.browser_name,
            "viewport": session.viewport,
            "url": session.page.url if not session.page.is_closed() else session.last_url,
            "title": title,
            "artifact_dir": self._artifact_relative(session.artifact_dir),
        }

    async def _goto(self, args: dict[str, Any]) -> dict[str, Any]:
        url = str(args.get("url") or "")
        if not url:
            raise BrowserError("url is required")
        self._require_allowed_url(url)
        session = await self._get_session(args)
        wait_until = str(args.get("wait_until") or "networkidle")
        timeout_ms = int(args.get("timeout_ms") or 30000)
        response = await session.page.goto(url, wait_until=wait_until, timeout=timeout_ms)
        session.last_url = session.page.url
        state = await self._session_state(session)
        state["status"] = response.status if response else None
        state["ok"] = response.ok if response else None
        return state

    async def _snapshot(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session(args)
        limit = int(args.get("limit") or 150)
        nodes = await session.page.evaluate(
            r"""
            limit => {
              const result = [];
              const pickRole = element => element.getAttribute('role') || ({A: 'link', BUTTON: 'button', INPUT: 'textbox', TEXTAREA: 'textbox', SELECT: 'combobox', H1: 'heading', H2: 'heading', H3: 'heading', H4: 'heading', H5: 'heading', H6: 'heading'}[element.tagName] || 'generic');
              const pickName = element => {
                const aria = element.getAttribute('aria-label') || element.getAttribute('title') || element.getAttribute('alt') || '';
                const text = element.innerText || element.value || element.textContent || '';
                return String(aria || text).replace(/\s+/g, ' ').trim().slice(0, 180);
              };
              const visible = element => {
                const style = window.getComputedStyle(element);
                const rect = element.getBoundingClientRect();
                return style && style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
              };
              const elements = Array.from(document.querySelectorAll('a,button,input,textarea,select,[role],[aria-label],h1,h2,h3,h4,h5,h6,[data-testid]'));
              for (const element of elements) {
                if (result.length >= limit) break;
                if (!visible(element)) continue;
                const ref = `pw-${result.length + 1}`;
                element.setAttribute('data-gateway-browser-ref', ref);
                const rect = element.getBoundingClientRect();
                result.push({
                  ref,
                  role: pickRole(element),
                  name: pickName(element),
                  tag: element.tagName.toLowerCase(),
                  id: element.id || null,
                  testid: element.getAttribute('data-testid'),
                  href: element.getAttribute('href'),
                  disabled: Boolean(element.disabled || element.getAttribute('aria-disabled') === 'true'),
                  rect: {x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height)}
                });
              }
              return result;
            }
            """,
            limit,
        )
        state = await self._session_state(session)
        state["nodes"] = nodes
        state["node_count"] = len(nodes)
        return state

    async def _click(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session(args)
        locator = self._target_locator(session.page, args)
        await locator.click(timeout=int(args.get("timeout_ms") or 10000))
        return await self._session_state(session)

    async def _type(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session(args)
        text = str(args.get("value") if args.get("value") is not None else args.get("text") or "")
        locator = self._target_locator(session.page, args)
        if bool(args.get("clear", True)):
            await locator.fill(text, timeout=int(args.get("timeout_ms") or 10000))
        else:
            await locator.type(text, timeout=int(args.get("timeout_ms") or 10000), delay=int(args.get("delay_ms") or 0))
        return await self._session_state(session)

    async def _screenshot(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session(args)
        name = str(args.get("name") or f"screenshot-{int(time.time() * 1000)}")
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", name).strip("._") or "screenshot"
        if not safe.endswith(".png"):
            safe = f"{safe}.png"
        path = (session.artifact_dir / safe).resolve()
        if session.artifact_dir != path.parent and session.artifact_dir not in path.parents:
            raise BrowserError("Screenshot path escapes browser artifact directory")
        await session.page.screenshot(path=str(path), full_page=bool(args.get("full_page", False)), type="png")
        raw = path.read_bytes()
        viewport = await session.page.evaluate("() => ({width: window.innerWidth, height: window.innerHeight, scrollWidth: document.documentElement.scrollWidth, scrollHeight: document.documentElement.scrollHeight})")
        state = await self._session_state(session)
        state["screenshot"] = {
            "path": self._artifact_relative(path),
            "mime_type": "image/png",
            "bytes": len(raw),
            "base64_attached": len(raw) <= self.max_image_bytes,
            "viewport": viewport,
            "full_page": bool(args.get("full_page", False)),
        }
        if len(raw) <= self.max_image_bytes:
            state["image_base64"] = base64.b64encode(raw).decode("ascii")
            state["mime_type"] = "image/png"
        return state

    async def _console(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session(args)
        entries = session.console[-int(args.get("limit") or 100):]
        state = await self._session_state(session)
        state["console"] = entries
        state["error_count"] = len([entry for entry in entries if entry.get("type") in {"error", "pageerror"}])
        return state

    async def _network(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session(args)
        entries = session.network[-int(args.get("limit") or 100):]
        state = await self._session_state(session)
        state["network"] = entries
        state["error_count"] = len(entries)
        return state

    async def _page_health(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session(args)
        app_entries = list(session.console)
        request_entries = list(session.network)
        app_errors = [entry for entry in app_entries if entry.get("type") in {"error", "pageerror"}]
        app_warnings = [entry for entry in app_entries if entry.get("type") == "warning"]
        state = await self._session_state(session)
        artifact_path = session.artifact_dir / "page-health.json"
        payload = {
            "session_id": session.session_id,
            "url": state.get("url"),
            "title": state.get("title"),
            "note_count": len(app_entries),
            "warning_count": len(app_warnings),
            "error_count": len(app_errors),
            "request_failure_count": len(request_entries),
            "page_notes": app_entries,
            "request_failures": request_entries,
            "ts": time.time(),
        }
        artifact_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        artifact = {
            "path": self._artifact_relative(artifact_path),
            "exists": artifact_path.exists(),
            "bytes": artifact_path.stat().st_size if artifact_path.exists() else 0,
        }
        state["page_health"] = {
            "note_count": len(app_entries),
            "warning_count": len(app_warnings),
            "error_count": len(app_errors),
            "request_failure_count": len(request_entries),
            "artifact": artifact,
        }
        state["note_count"] = len(app_entries)
        state["warning_count"] = len(app_warnings)
        state["error_count"] = len(app_errors)
        state["request_failure_count"] = len(request_entries)
        state["diagnostics_artifact"] = artifact
        return state

    async def _start_trace(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session(args)
        if not session.tracing:
            await session.context.tracing.start(screenshots=True, snapshots=True, sources=True)
            session.tracing = True
        state = await self._session_state(session)
        state["tracing"] = True
        return state

    async def _stop_trace(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._get_session(args)
        name = str(args.get("name") or f"trace-{int(time.time() * 1000)}.zip")
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", name).strip("._") or "trace.zip"
        if not safe.endswith(".zip"):
            safe = f"{safe}.zip"
        path = (session.artifact_dir / safe).resolve()
        if session.tracing:
            await session.context.tracing.stop(path=str(path))
            session.tracing = False
        state = await self._session_state(session)
        state["trace"] = {"path": self._artifact_relative(path), "exists": path.exists(), "bytes": path.stat().st_size if path.exists() else 0}
        state["tracing"] = False
        return state

    async def _visual_assert(self, args: dict[str, Any]) -> dict[str, Any]:
        screenshot = await self._screenshot({**args, "full_page": bool(args.get("full_page", True)), "name": args.get("name") or "page-review"})
        session = await self._get_session(args)
        app_entries = list(session.console)
        request_entries = list(session.network)
        app_errors = [entry for entry in app_entries if entry.get("type") in {"error", "pageerror"}]
        verdict = "fail" if app_errors or request_entries else "needs_model_review"
        stem = str(args.get("name") or "page-review")
        safe_stem = re.sub(r"[^a-zA-Z0-9_.-]", "_", stem).strip("._") or "page-review"
        diagnostics_path = session.artifact_dir / f"{safe_stem}-diagnostics.json"
        diagnostics_payload = {
            "session_id": session.session_id,
            "assertion": str(args.get("assertion") or ""),
            "verdict": verdict,
            "app_error_count": len(app_errors),
            "request_failure_count": len(request_entries),
            "page_notes": app_entries,
            "request_failures": request_entries,
            "ts": time.time(),
        }
        diagnostics_path.write_text(json.dumps(diagnostics_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        screenshot["assertion"] = str(args.get("assertion") or "")
        screenshot["verdict"] = verdict
        screenshot["app_error_count"] = len(app_errors)
        screenshot["request_failure_count"] = len(request_entries)
        screenshot["diagnostics_artifact"] = {
            "path": self._artifact_relative(diagnostics_path),
            "exists": diagnostics_path.exists(),
            "bytes": diagnostics_path.stat().st_size if diagnostics_path.exists() else 0,
        }
        screenshot["review"] = {
            "assertion": screenshot["assertion"],
            "verdict": verdict,
            "app_error_count": len(app_errors),
            "request_failure_count": len(request_entries),
        }
        return screenshot

    async def _close_session(self, args: dict[str, Any]) -> dict[str, Any]:
        session_id = str(args.get("session_id") or "")
        if session_id:
            sessions = [self.sessions.pop(session_id, None)]
        else:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        closed = []
        for session in sessions:
            if session is None:
                continue
            if session.tracing:
                try:
                    await session.context.tracing.stop()
                except Exception:
                    pass
            await session.context.close()
            await session.browser.close()
            await session.playwright.stop()
            closed.append(session.session_id)
        return {"closed_sessions": closed, "remaining_sessions": list(self.sessions.keys())}

    async def close_all(self) -> None:
        await self._close_session({})

    async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        args = dict(arguments or {})
        if tool == "browser_open_session":
            return await self._open_session(args)
        if tool == "browser_goto":
            return await self._goto(args)
        if tool == "browser_snapshot":
            return await self._snapshot(args)
        if tool == "browser_page_state":
            return await self._snapshot(args)
        if tool == "browser_page_health":
            return await self._page_health(args)
        if tool == "browser_client_messages":
            return await self._page_health(args)
        if tool == "browser_app_events":
            state = await self._console(args)
            entries = state.pop("console", [])
            state["app_events"] = entries
            state["event_count"] = len(entries)
            return state
        if tool == "browser_request_failures":
            state = await self._network(args)
            entries = state.pop("network", [])
            state["request_failures"] = entries
            state["failure_count"] = len(entries)
            return state
        if tool == "browser_screenshot_review":
            return await self._visual_assert(args)
        if tool == "browser_click":
            return await self._click(args)
        if tool in {"browser_type", "browser_fill"}:
            return await self._type(args)
        if tool == "browser_screenshot":
            return await self._screenshot(args)
        if tool == "browser_console":
            return await self._console(args)
        if tool == "browser_runtime_events":
            state = await self._console(args)
            entries = state.pop("console", [])
            state["runtime_events"] = entries
            state["event_count"] = len(entries)
            return state
        if tool == "browser_network":
            return await self._network(args)
        if tool == "browser_start_trace":
            return await self._start_trace(args)
        if tool == "browser_stop_trace":
            return await self._stop_trace(args)
        if tool == "browser_trace_export":
            return await self._stop_trace(args)
        if tool == "browser_visual_assert":
            return await self._visual_assert(args)
        if tool == "browser_release_page":
            return await self._close_session(args)
        if tool == "browser_close_session":
            return await self._close_session(args)
        raise BrowserError(f"Unknown browser tool: {tool}")
