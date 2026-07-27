from __future__ import annotations

import base64
import binascii
import difflib
import fnmatch
import hashlib
import os
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
        max_diff_lines: int = 300,
    ) -> None:
        self.root = Path(root).resolve()
        if not self.root.exists() or not self.root.is_dir():
            raise SandboxError(f"Sandbox root must be an existing directory: {self.root}")
        self.max_read_bytes = max_read_bytes
        self.max_write_bytes = max_write_bytes
        self.max_output_chars = max_output_chars
        self.max_diff_lines = max_diff_lines

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

    def file_state(self, path: str) -> dict[str, Any]:
        target = self.safe_path(path)
        if not target.exists():
            return {"path": self.relative(target), "exists": False, "kind": None, "size": None, "sha256": None}
        if target.is_dir():
            return {"path": self.relative(target), "exists": True, "kind": "dir", "size": None, "sha256": None}
        raw = target.read_bytes()
        return {
            "path": self.relative(target),
            "exists": True,
            "kind": "file",
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    def git_state(self, worktree_path: str, base_commit: str) -> dict[str, Any]:
        worktree = self.safe_path(worktree_path)
        if not worktree.is_dir():
            raise SandboxError("Git worktree path is not a directory")

        def git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
            completed = subprocess.run(
                ["git", "-C", str(worktree), *arguments],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
            if check and completed.returncode != 0:
                detail = (completed.stderr or completed.stdout).strip() or "git command failed"
                raise SandboxError(detail)
            return completed

        root = Path(git("rev-parse", "--show-toplevel").stdout.strip()).resolve()
        branch = git("symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
        head = git("rev-parse", "HEAD").stdout.strip()
        ancestor = git("merge-base", "--is-ancestor", base_commit, head, check=False).returncode == 0
        return {
            "worktree_path": self.relative(worktree),
            "toplevel": self.relative(root) if root == self.root or self.root in root.parents else str(root),
            "branch_name": branch,
            "head": head,
            "base_commit": base_commit,
            "base_is_ancestor": ancestor,
        }

    def read_file(self, path: str) -> dict[str, Any]:
        target = self.safe_path(path)
        if not target.is_file():
            raise SandboxError("Path is not a file")
        raw = target.read_bytes()
        data = raw[: self.max_read_bytes]
        return {
            "path": self.relative(target),
            "content": data.decode("utf-8", errors="replace"),
            "truncated": len(raw) > len(data),
            "exists": True,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

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
        relative_path = self.relative(target)
        existed_before = target.exists() and target.is_file()
        bytes_before = target.stat().st_size if existed_before else 0
        expected_sha256 = str(args.get("expected_sha256") or "").strip() or None
        expected_absent = bool(args.get("expected_absent", False))
        if expected_sha256 and expected_absent:
            raise SandboxError("expected_sha256 and expected_absent are mutually exclusive")
        if expected_absent and target.exists():
            raise SandboxError("File precondition failed: path already exists")
        if expected_sha256:
            if not existed_before:
                raise SandboxError("File precondition failed: path is not a file")
            current_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
            if current_sha256 != expected_sha256:
                raise SandboxError("File precondition failed: sha256 mismatch")
        return_content = bool(args.get("return_content", False))
        include_diff = bool(args.get("diff", True))

        if operation in {"write", "append"}:
            raw, encoding = self.decode_write_content(args)
            if operation == "append" and target.exists() and not target.is_file():
                raise SandboxError("Path is not a file")
            if operation == "write" and target.exists() and not bool(args.get("overwrite", True)):
                raise SandboxError("File already exists and overwrite is false")
            if operation == "append" and "content_base64" in args:
                raise SandboxError("append supports UTF-8 content only")
            original_raw = target.read_bytes() if existed_before else b""
            final = original_raw + raw if operation == "append" else raw
            diff_payload = self.build_write_diff(relative_path, original_raw, final, encoding=encoding, include_diff=include_diff)
            self.write_bytes(target, final, mode=args.get("mode"))
            result = {
                "path": relative_path,
                "operation": operation,
                "bytes": len(raw),
                "bytes_before": bytes_before,
                "bytes_after": len(final),
                "encoding": encoding,
                "replacements": 0,
                "content": None,
                "before_sha256": hashlib.sha256(original_raw).hexdigest() if existed_before else None,
                "after_sha256": hashlib.sha256(final).hexdigest(),
                "diff": diff_payload,
            }
            if return_content and encoding == "utf-8":
                result["content"] = final.decode("utf-8", errors="replace")
            return result

        if operation in {"replace", "regex_replace", "remove_markdown_code_blocks"}:
            original = self.read_text_for_edit(target)
            edited, replacements = self.apply_text_edit(original, operation=operation, arguments=args)
            expected = args.get("expected_replacements")
            if expected is not None and int(expected) != replacements:
                raise SandboxError(f"Expected {int(expected)} replacements, got {replacements}")
            if replacements <= 0 and operation != "remove_markdown_code_blocks":
                raise SandboxError(f"No text matched operation {operation!r}")
            original_raw = original.encode("utf-8")
            raw = edited.encode("utf-8")
            diff_payload = self.build_text_diff(relative_path, original, edited, include_diff=include_diff)
            self.write_bytes(target, raw, mode=args.get("mode"))
            return {
                "path": relative_path,
                "operation": operation,
                "bytes": len(raw),
                "bytes_before": len(original.encode("utf-8")),
                "bytes_after": len(raw),
                "encoding": "utf-8",
                "replacements": replacements,
                "content": edited if return_content else None,
                "before_sha256": hashlib.sha256(original_raw).hexdigest(),
                "after_sha256": hashlib.sha256(raw).hexdigest(),
                "diff": diff_payload,
            }

        raise SandboxError("operation must be write, append, replace, regex_replace, or remove_markdown_code_blocks")

    def build_write_diff(self, relative_path: str, original_raw: bytes, final_raw: bytes, *, encoding: str | None, include_diff: bool) -> dict[str, Any]:
        if not include_diff:
            return {"format": "unified", "suppressed": True, "reason": "diff disabled", "truncated": False, "added_lines": 0, "removed_lines": 0, "hunks": []}
        if self.diff_path_excluded(relative_path):
            return {"format": "unified", "suppressed": True, "reason": "path excluded by diff policy", "truncated": False, "added_lines": 0, "removed_lines": 0, "hunks": []}
        if encoding != "utf-8":
            return {"format": "unified", "suppressed": True, "reason": "binary or non-utf8 write", "truncated": False, "added_lines": 0, "removed_lines": 0, "hunks": []}
        if len(original_raw) > self.max_read_bytes or len(final_raw) > self.max_write_bytes:
            return {"format": "unified", "suppressed": True, "reason": "file too large for inline diff", "truncated": False, "added_lines": 0, "removed_lines": 0, "hunks": []}
        try:
            original = original_raw.decode("utf-8")
            final = final_raw.decode("utf-8")
        except UnicodeDecodeError:
            return {"format": "unified", "suppressed": True, "reason": "content is not utf-8", "truncated": False, "added_lines": 0, "removed_lines": 0, "hunks": []}
        return self.build_text_diff(relative_path, original, final, include_diff=True)

    def build_text_diff(self, relative_path: str, original: str, edited: str, *, include_diff: bool) -> dict[str, Any]:
        if not include_diff:
            return {"format": "unified", "suppressed": True, "reason": "diff disabled", "truncated": False, "added_lines": 0, "removed_lines": 0, "hunks": []}
        if self.diff_path_excluded(relative_path):
            return {"format": "unified", "suppressed": True, "reason": "path excluded by diff policy", "truncated": False, "added_lines": 0, "removed_lines": 0, "hunks": []}
        old_lines = original.splitlines()
        new_lines = edited.splitlines()
        matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
        hunks = []
        emitted_lines = 0
        truncated = False
        added_lines = 0
        removed_lines = 0
        for group in matcher.get_grouped_opcodes(n=3):
            first = group[0]
            last = group[-1]
            old_start = first[1] + 1
            new_start = first[3] + 1
            old_count = last[2] - first[1]
            new_count = last[4] - first[3]
            hunk_lines = []
            for tag, i1, i2, j1, j2 in group:
                if tag == "equal":
                    for line in old_lines[i1:i2]:
                        if emitted_lines >= self.max_diff_lines:
                            truncated = True
                            break
                        hunk_lines.append({"kind": "context", "text": line})
                        emitted_lines += 1
                elif tag == "delete":
                    for line in old_lines[i1:i2]:
                        if emitted_lines >= self.max_diff_lines:
                            truncated = True
                            break
                        hunk_lines.append({"kind": "delete", "text": line})
                        emitted_lines += 1
                        removed_lines += 1
                elif tag == "insert":
                    for line in new_lines[j1:j2]:
                        if emitted_lines >= self.max_diff_lines:
                            truncated = True
                            break
                        hunk_lines.append({"kind": "insert", "text": line})
                        emitted_lines += 1
                        added_lines += 1
                elif tag == "replace":
                    for line in old_lines[i1:i2]:
                        if emitted_lines >= self.max_diff_lines:
                            truncated = True
                            break
                        hunk_lines.append({"kind": "delete", "text": line})
                        emitted_lines += 1
                        removed_lines += 1
                    if not truncated:
                        for line in new_lines[j1:j2]:
                            if emitted_lines >= self.max_diff_lines:
                                truncated = True
                                break
                            hunk_lines.append({"kind": "insert", "text": line})
                            emitted_lines += 1
                            added_lines += 1
                if truncated:
                    break
            hunks.append({"old_start": old_start, "old_count": old_count, "new_start": new_start, "new_count": new_count, "lines": hunk_lines})
            if truncated:
                break
        return {"format": "unified", "suppressed": False, "truncated": truncated, "added_lines": added_lines, "removed_lines": removed_lines, "hunks": hunks}

    def diff_path_excluded(self, relative_path: str) -> bool:
        patterns = [".env", ".env.*", "*.pem", "*.key", "id_rsa", "id_ed25519", "**/.ssh/**", ".ssh/**"]
        raw = os.environ.get("GATEWAY_DIFF_EXCLUDE")
        if raw:
            patterns.extend(item.strip() for item in raw.split(",") if item.strip())
        return any(fnmatch.fnmatch(relative_path, pattern) for pattern in patterns)

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
                check=False,
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
        if tool == "file_state":
            return self.file_state(str(arguments.get("path", "")))
        if tool == "git_state":
            return self.git_state(
                str(arguments.get("worktree_path", "")),
                str(arguments.get("base_commit", "")),
            )
        if tool == "write_file":
            return self.write_file(str(arguments.get("path", "")), arguments=arguments)
        if tool == "run_command":
            return self.run_command(
                str(arguments.get("command", "")),
                str(arguments.get("cwd", ".")),
                int(arguments.get("timeout_seconds", 120) or 120),
            )
        raise SandboxError(f"Unknown thin-client tool: {tool}")
