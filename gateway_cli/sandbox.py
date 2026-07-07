from __future__ import annotations

import base64
import binascii
import re
import subprocess
from pathlib import Path
from typing import Any


class SandboxError(RuntimeError):
    pass


class ThinClientSandbox:
    def __init__(
        self,
        root: str | Path,
        *,
        max_read_bytes: int = 200_000,
        max_write_bytes: int = 1_000_000,
        max_output_chars: int = 30_000,
    ) -> None:
        self.root = Path(root).resolve()
        if not self.root.exists() or not self.root.is_dir():
            raise SandboxError(f"Sandbox root must be an existing directory: {self.root}")
        self.max_read_bytes = max_read_bytes
        self.max_write_bytes = max_write_bytes
        self.max_output_chars = max_output_chars

    def safe_path(self, relative: str | None = ".") -> Path:
        value = relative or "."
        candidate = Path(value)
        target = candidate.resolve() if candidate.is_absolute() else (self.root / candidate).resolve()
        if target != self.root and self.root not in target.parents:
            raise SandboxError("Path escapes thin-client launch directory")
        return target

    def safe_command_path(self, working_dir: Path, value: str | None = ".") -> Path:
        raw = value or "."
        candidate = Path(raw)
        target = candidate.resolve() if candidate.is_absolute() else (working_dir / candidate).resolve()
        if target != self.root and self.root not in target.parents:
            raise SandboxError("Path escapes thin-client launch directory")
        return target

    def relative(self, path: Path) -> str:
        return "." if path == self.root else str(path.relative_to(self.root))

    def list_files(self, path: str = ".") -> dict[str, Any]:
        target = self.safe_path(path)
        if not target.exists():
            raise SandboxError("Path not found")
        if not target.is_dir():
            raise SandboxError("Path is not a directory")
        entries = []
        for child in sorted(target.iterdir()):
            entries.append(
                {
                    "path": self.relative(child),
                    "kind": "dir" if child.is_dir() else "file",
                    "size": child.stat().st_size if child.is_file() else None,
                }
            )
        return {"root": str(self.root), "entries": entries}

    def read_file(self, path: str) -> dict[str, Any]:
        target = self.safe_path(path)
        if not target.is_file():
            raise SandboxError("Path is not a file")
        data = target.read_bytes()[: self.max_read_bytes]
        return {"path": self.relative(target), "content": data.decode("utf-8", errors="replace"), "truncated": target.stat().st_size > len(data)}

    def decode_write_content(self, arguments: dict[str, Any], *, required: bool = True) -> tuple[bytes, str | None]:
        if "content_base64" in arguments and arguments.get("content_base64") is not None:
            try:
                return base64.b64decode(str(arguments["content_base64"]), validate=True), "base64"
            except (binascii.Error, ValueError) as exc:
                raise SandboxError("content_base64 is not valid base64") from exc
        if "content" in arguments and arguments.get("content") is not None:
            return str(arguments.get("content", "")).encode("utf-8"), "utf-8"
        if required:
            raise SandboxError("content or content_base64 is required")
        return b"", None

    def write_file(
        self,
        path: str,
        content: str | None = None,
        *,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        args = dict(arguments or {})
        if content is not None and "content" not in args and "content_base64" not in args:
            args["content"] = content
        operation = str(args.get("operation") or "write")
        target = self.safe_path(path)
        bytes_before = target.stat().st_size if target.exists() and target.is_file() else 0

        if operation in {"write", "append"}:
            raw, encoding = self.decode_write_content(args)
            if operation == "append" and target.exists() and not target.is_file():
                raise SandboxError("Path is not a file")
            if operation == "write" and target.exists() and not bool(args.get("overwrite", True)):
                raise SandboxError("File already exists and overwrite is false")
            if operation == "append" and "content_base64" in args:
                raise SandboxError("append supports UTF-8 content only")
            final = (target.read_bytes() if operation == "append" and target.exists() else b"") + raw
            self.write_bytes(target, final, mode=args.get("mode"))
            return {
                "path": self.relative(target),
                "operation": operation,
                "bytes": len(raw),
                "bytes_before": bytes_before,
                "bytes_after": len(final),
                "encoding": encoding,
                "replacements": 0,
            }

        if operation in {"replace", "regex_replace", "remove_markdown_code_blocks"}:
            original = self.read_text_for_edit(target)
            edited, replacements = self.apply_text_edit(original, operation=operation, arguments=args)
            expected = args.get("expected_replacements")
            if expected is not None and int(expected) != replacements:
                raise SandboxError(f"Expected {int(expected)} replacements, got {replacements}")
            if replacements <= 0 and operation != "remove_markdown_code_blocks":
                raise SandboxError(f"No text matched operation {operation!r}")
            raw = edited.encode("utf-8")
            self.write_bytes(target, raw, mode=args.get("mode"))
            return {
                "path": self.relative(target),
                "operation": operation,
                "bytes": len(raw),
                "bytes_before": len(original.encode("utf-8")),
                "bytes_after": len(raw),
                "encoding": "utf-8",
                "replacements": replacements,
                "content": edited,
            }

        raise SandboxError("operation must be write, append, replace, regex_replace, or remove_markdown_code_blocks")

    def write_bytes(self, target: Path, raw: bytes, *, mode: Any = None) -> None:
        if len(raw) > self.max_write_bytes:
            raise SandboxError("File content is too large")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        if mode is not None:
            try:
                target.chmod(int(mode))
            except (TypeError, ValueError, OSError) as exc:
                raise SandboxError("mode must be an integer file mode") from exc

    def read_text_for_edit(self, target: Path) -> str:
        if not target.is_file():
            raise SandboxError("Path is not a file")
        data = target.read_bytes()
        if len(data) > self.max_read_bytes:
            raise SandboxError("File is too large to edit")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SandboxError("Path is not a UTF-8 text file") from exc

    def apply_text_edit(self, content: str, *, operation: str, arguments: dict[str, Any]) -> tuple[str, int]:
        if operation == "replace":
            old_text = arguments.get("old_text")
            if not isinstance(old_text, str) or old_text == "":
                raise SandboxError("old_text is required for replace")
            new_text = arguments.get("new_text")
            replacement = new_text if isinstance(new_text, str) else ""
            count = max(0, int(arguments.get("count", 0) or 0))
            total_matches = content.count(old_text)
            replacements = total_matches if count <= 0 else min(total_matches, count)
            return content.replace(old_text, replacement, count if count > 0 else -1), replacements

        if operation == "regex_replace":
            pattern = arguments.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                raise SandboxError("pattern is required for regex_replace")
            replacement = arguments.get("replacement")
            return re.subn(
                pattern,
                replacement if isinstance(replacement, str) else "",
                content,
                count=max(0, int(arguments.get("count", 0) or 0)),
                flags=self.regex_flags(arguments.get("flags")),
            )

        if operation == "remove_markdown_code_blocks":
            language = arguments.get("language")
            language_pattern = re.escape(language) if isinstance(language, str) and language else r"[^\n`]*"
            pattern = rf"\n?```[ \t]*{language_pattern}[^\n`]*\n.*?\n```[ \t]*\n?"
            return re.subn(pattern, "\n", content, flags=re.DOTALL)

        raise SandboxError("operation must be replace, regex_replace, or remove_markdown_code_blocks")

    @staticmethod
    def regex_flags(raw_flags: Any) -> int:
        flags = 0
        values = raw_flags if isinstance(raw_flags, list) else []
        for item in values:
            if item == "ignorecase":
                flags |= re.IGNORECASE
            elif item == "multiline":
                flags |= re.MULTILINE
            elif item == "dotall":
                flags |= re.DOTALL
            else:
                raise SandboxError(f"Unsupported regex flag: {item}")
        return flags

    def run_command(self, command: str, cwd: str = ".", timeout_seconds: int = 120) -> dict[str, Any]:
        command = command.strip()
        if not command:
            raise SandboxError("Command is empty")
        working_dir = self.safe_path(cwd)
        if not working_dir.is_dir():
            raise SandboxError("cwd is not a directory")
        try:
            completed = subprocess.run(
                command,
                shell=True,
                cwd=working_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(1, int(timeout_seconds)),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            output = (stdout + stderr + f"\nCommand timed out after {max(1, int(timeout_seconds))}s\n")[: self.max_output_chars]
            return {"exit_code": 124, "output": output, "timed_out": True}
        output = (completed.stdout + completed.stderr)[: self.max_output_chars]
        return {"exit_code": completed.returncode, "output": output, "timed_out": False}

    def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool == "list_files":
            return self.list_files(str(arguments.get("path", ".")))
        if tool == "read_file":
            return self.read_file(str(arguments.get("path", "")))
        if tool == "write_file":
            return self.write_file(str(arguments.get("path", "")), arguments=arguments)
        if tool == "run_command":
            return self.run_command(
                str(arguments.get("command", "")),
                str(arguments.get("cwd", ".")),
                int(arguments.get("timeout_seconds", 120) or 120),
            )
        raise SandboxError(f"Unknown thin-client tool: {tool}")
