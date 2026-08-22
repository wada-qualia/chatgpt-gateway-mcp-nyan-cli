from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from . import __version__

DEFAULT_RELEASE_BASE_URL = "https://releases.example.com/artem.darius.weber/2026q3-int-art-chatgpt-gateway-thin-client-distribution/-/releases/permalink/latest/downloads"
RELEASE_NAMESPACE = "gateway-thin-client-release"
RELEASE_IDENTITY = "gateway-thin-client"
RELEASE_ARTIFACT = "chatgpt-gateway-thin-client"
SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SOURCE_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class UpdateError(RuntimeError):
    pass


def trusted_public_key_path() -> Path:
    return Path(__file__).with_name("release-signing-key.pub")


def release_base_url(value: str | None = None) -> str:
    candidate = (value or os.environ.get("GATEWAY_RELEASE_BASE_URL") or DEFAULT_RELEASE_BASE_URL).strip().rstrip("/")
    parsed = urlsplit(candidate)
    local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
    if parsed.scheme != "https" and not local_http:
        raise UpdateError("Release URL must use HTTPS. HTTP is accepted only for localhost.")
    if not parsed.netloc:
        raise UpdateError("Release URL must include a host.")
    return candidate


def parse_semver(value: str) -> tuple[int, int, int, tuple[str, ...] | None]:
    match = SEMVER_PATTERN.fullmatch(value.strip())
    if match is None:
        raise UpdateError(f"Invalid semantic version: {value!r}")
    prerelease = tuple(match.group(4).split(".")) if match.group(4) else None
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease


def compare_versions(left: str, right: str) -> int:
    left_major, left_minor, left_patch, left_pre = parse_semver(left)
    right_major, right_minor, right_patch, right_pre = parse_semver(right)
    left_core = (left_major, left_minor, left_patch)
    right_core = (right_major, right_minor, right_patch)
    if left_core < right_core:
        return -1
    if left_core > right_core:
        return 1
    if left_pre is None and right_pre is None:
        return 0
    if left_pre is None:
        return 1
    if right_pre is None:
        return -1
    for left_part, right_part in zip(left_pre, right_pre):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_part) < int(right_part) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_part < right_part else 1
    if len(left_pre) == len(right_pre):
        return 0
    return -1 if len(left_pre) < len(right_pre) else 1


def fetch_bytes(url: str, *, timeout: float = 30.0) -> bytes:
    request = Request(url, headers={"User-Agent": f"gateway-cli/{__version__}"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"Unable to download {url}: {exc}") from exc


def verify_release_manifest(
    manifest_bytes: bytes,
    signature_bytes: bytes,
    *,
    public_key_path: Path | None = None,
) -> None:
    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen is None:
        raise UpdateError("ssh-keygen is required to verify thin-client releases.")
    public_key = (public_key_path or trusted_public_key_path()).resolve()
    if not public_key.is_file():
        raise UpdateError(f"Trusted release public key is missing: {public_key}")
    with tempfile.TemporaryDirectory(prefix="gateway-cli-release-verify-") as temporary_directory:
        root = Path(temporary_directory)
        signature_path = root / "release-manifest.json.sig"
        allowed_signers_path = root / "allowed_signers"
        signature_path.write_bytes(signature_bytes)
        key_text = public_key.read_text(encoding="utf-8").strip()
        allowed_signers_path.write_text(f"{RELEASE_IDENTITY} {key_text}\n", encoding="utf-8")
        result = subprocess.run(
            [
                ssh_keygen,
                "-Y",
                "verify",
                "-f",
                str(allowed_signers_path),
                "-I",
                RELEASE_IDENTITY,
                "-n",
                RELEASE_NAMESPACE,
                "-s",
                str(signature_path),
            ],
            input=manifest_bytes,
            capture_output=True,
            check=False,
        )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise UpdateError(f"Thin-client release signature verification failed: {detail or 'invalid signature'}")


def validate_artifact_entry(entry: object, *, name: str) -> dict[str, object]:
    if not isinstance(entry, dict):
        raise UpdateError(f"Release manifest artifact {name!r} is invalid.")
    url = str(entry.get("url", "")).strip()
    digest = str(entry.get("sha256", "")).strip().lower()
    try:
        size = int(entry.get("size", -1))
    except (TypeError, ValueError) as exc:
        raise UpdateError(f"Release manifest artifact {name!r} has an invalid size.") from exc
    parsed = urlsplit(url)
    local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
    if parsed.scheme != "https" and not local_http:
        raise UpdateError(f"Release artifact {name!r} must use HTTPS.")
    if not parsed.netloc:
        raise UpdateError(f"Release artifact {name!r} URL has no host.")
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise UpdateError(f"Release artifact {name!r} has an invalid SHA-256 digest.")
    if size < 1:
        raise UpdateError(f"Release artifact {name!r} has an invalid size.")
    return {"url": url, "sha256": digest, "size": size}


def parse_release_manifest(manifest_bytes: bytes) -> dict[str, object]:
    try:
        payload = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError("Release manifest is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict):
        raise UpdateError("Release manifest root must be an object.")
    if payload.get("schema_version") != 1:
        raise UpdateError("Unsupported release manifest schema version.")
    if payload.get("artifact") != RELEASE_ARTIFACT:
        raise UpdateError("Release manifest artifact identity does not match gateway-cli.")
    if payload.get("channel") != "stable":
        raise UpdateError("Only the stable thin-client release channel is supported.")
    version = str(payload.get("version", "")).strip()
    parse_semver(version)
    source_commit = str(payload.get("source_commit", "")).strip().lower()
    if SOURCE_COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise UpdateError("Release manifest source_commit must be a full Git SHA-1.")
    minimum_python = str(payload.get("minimum_python", "")).strip()
    if minimum_python != "3.11":
        raise UpdateError("Release manifest minimum_python is unsupported.")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, dict):
        raise UpdateError("Release manifest artifacts must be an object.")
    validated_artifacts = {
        "zip": validate_artifact_entry(artifacts.get("zip"), name="zip"),
        "tar_gz": validate_artifact_entry(artifacts.get("tar_gz"), name="tar_gz"),
    }
    return {
        "schema_version": 1,
        "artifact": RELEASE_ARTIFACT,
        "channel": "stable",
        "version": version,
        "source_commit": source_commit,
        "minimum_python": minimum_python,
        "published_at": str(payload.get("published_at", "")).strip(),
        "artifacts": validated_artifacts,
    }


def fetch_verified_release(base_url: str | None = None) -> dict[str, object]:
    base = release_base_url(base_url)
    manifest_bytes = fetch_bytes(urljoin(f"{base}/", "release-manifest.json"))
    signature_bytes = fetch_bytes(urljoin(f"{base}/", "release-manifest.json.sig"))
    verify_release_manifest(manifest_bytes, signature_bytes)
    return parse_release_manifest(manifest_bytes)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_artifact(entry: dict[str, object], destination: Path) -> None:
    payload = fetch_bytes(str(entry["url"]), timeout=120.0)
    if len(payload) != int(entry["size"]):
        raise UpdateError("Downloaded release artifact size does not match the signed manifest.")
    destination.write_bytes(payload)
    if sha256_file(destination) != str(entry["sha256"]):
        raise UpdateError("Downloaded release artifact SHA-256 does not match the signed manifest.")


def safe_archive_path(root: Path, member_name: str) -> Path:
    if not member_name or member_name.startswith(("/", "\\")):
        raise UpdateError(f"Unsafe archive member: {member_name!r}")
    candidate = (root / member_name).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise UpdateError(f"Unsafe archive member: {member_name!r}") from exc
    return candidate


def extract_zip(path: Path, destination: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            safe_archive_path(destination, info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise UpdateError(f"Symlinks are not allowed in release archives: {info.filename}")
        archive.extractall(destination)


def extract_tar(path: Path, destination: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            safe_archive_path(destination, member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise UpdateError(f"Links and device files are not allowed in release archives: {member.name}")
        archive.extractall(destination)


def managed_install_paths() -> tuple[Path, Path]:
    install_root = os.environ.get("GATEWAY_CLIENT_INSTALL_ROOT", "").strip()
    bin_dir = os.environ.get("GATEWAY_CLIENT_BIN_DIR", "").strip()
    if not install_root or not bin_dir:
        raise UpdateError(
            "This gateway-cli installation is not managed by the public installer. Run the current bootstrap installer once before using self-update."
        )
    return Path(install_root).expanduser().resolve(), Path(bin_dir).expanduser().resolve()


def invoke_bundle_installer(bundle_root: Path, *, install_root: Path, bin_dir: Path, skip_browser: bool) -> None:
    environment = os.environ.copy()
    if os.name == "nt":
        installer = bundle_root / "install.ps1"
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("pwsh")
        if powershell is None:
            raise UpdateError("PowerShell is required to install the thin-client update.")
        command = [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(installer),
            "-Action",
            "Update",
            "-InstallRoot",
            str(install_root),
            "-BinDir",
            str(bin_dir),
        ]
        if skip_browser:
            command.append("-SkipBrowser")
    else:
        installer = bundle_root / "install.sh"
        command = [
            "sh",
            str(installer),
            "update",
            "--install-root",
            str(install_root),
            "--bin-dir",
            str(bin_dir),
        ]
        if skip_browser:
            command.append("--skip-browser")
    if not installer.is_file():
        raise UpdateError(f"Release installer is missing: {installer}")
    result = subprocess.run(command, env=environment, check=False)
    if result.returncode != 0:
        raise UpdateError(f"Release installer failed with exit code {result.returncode}.")


def update_client(*, base_url: str | None = None, check_only: bool = False, force: bool = False, skip_browser: bool = False) -> int:
    release = fetch_verified_release(base_url)
    latest = str(release["version"])
    comparison = compare_versions(__version__, latest)
    update_available = comparison < 0
    if check_only:
        print(
            json.dumps(
                {
                    "current_version": __version__,
                    "latest_version": latest,
                    "update_available": update_available,
                    "channel": "stable",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if comparison > 0 and not force:
        raise UpdateError(
            f"Installed gateway-cli {__version__} is newer than published stable {latest}; use --force only for an intentional downgrade."
        )
    if comparison == 0 and not force:
        print(f"gateway-cli {__version__} is already the latest stable release.")
        return 0
    install_root, bin_dir = managed_install_paths()
    artifact_key = "zip" if os.name == "nt" else "tar_gz"
    artifact = release["artifacts"][artifact_key]
    suffix = ".zip" if artifact_key == "zip" else ".tar.gz"
    with tempfile.TemporaryDirectory(prefix="gateway-cli-update-") as temporary_directory:
        root = Path(temporary_directory)
        archive_path = root / f"release{suffix}"
        extracted = root / "extracted"
        extracted.mkdir()
        download_artifact(artifact, archive_path)
        if artifact_key == "zip":
            extract_zip(archive_path, extracted)
        else:
            extract_tar(archive_path, extracted)
        bundles = [path for path in extracted.iterdir() if path.is_dir()]
        if len(bundles) != 1:
            raise UpdateError("Release archive must contain exactly one top-level bundle directory.")
        invoke_bundle_installer(
            bundles[0],
            install_root=install_root,
            bin_dir=bin_dir,
            skip_browser=skip_browser,
        )
    print(f"Updated gateway-cli {__version__} -> {latest}.")
    print("Any already-running gateway-cli process continues using its previous runtime until restarted.")
    return 0


def atomic_write_pointer(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(f"{value}\n", encoding="utf-8")
    os.replace(temporary, path)


def rollback_client() -> int:
    install_root, _ = managed_install_paths()
    current_path = install_root / "current"
    previous_path = install_root / "previous"
    if not current_path.is_file() or not previous_path.is_file():
        raise UpdateError("No managed previous thin-client release is available for rollback.")
    current = current_path.read_text(encoding="utf-8").strip()
    previous = previous_path.read_text(encoding="utf-8").strip()
    if not current or not previous or current == previous:
        raise UpdateError("No distinct previous thin-client release is available for rollback.")
    previous_release = install_root / "releases" / previous
    executable = previous_release / "venv" / ("Scripts/gateway-cli.exe" if os.name == "nt" else "bin/gateway-cli")
    if not executable.is_file():
        raise UpdateError(f"Previous thin-client runtime is incomplete: {previous_release}")
    atomic_write_pointer(previous_path, current)
    atomic_write_pointer(current_path, previous)
    print(f"Rolled back gateway-cli {current} -> {previous}.")
    print("Any already-running gateway-cli process continues using its current runtime until restarted.")
    return 0
