# -*- coding: utf-8 -*-
"""Download the exact runtime artifacts named by the immutable artifact lock.

This is a release-engineering helper, not application networking.  It uses the
developer/CI Python TLS stack to populate a wheelhouse, then verifies size and
SHA-256 before publishing each file with no-overwrite semantics.  The portable
application itself continues to use WinHTTP/Schannel and does not ship Python
OpenSSL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import BinaryIO, Callable, Iterable
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = PROJECT_ROOT / "App" / "runtime_artifacts.lock.json"
USER_AGENT = "SankakuSyncer-Runtime-Fetch/0.1"
MAX_REDIRECTS = 5
CHUNK_SIZE = 1024 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class ArtifactFetchError(RuntimeError):
    """Raised when an artifact cannot be fetched and authenticated safely."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _read_lock(path: Path) -> list[dict[str, object]]:
    try:
        payload = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactFetchError(f"artifact lock is unreadable ({type(exc).__name__})") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ArtifactFetchError("unsupported artifact lock schema")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ArtifactFetchError("artifact lock has no artifacts")

    clean: list[dict[str, object]] = []
    filenames: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise ArtifactFetchError("artifact lock contains a non-object record")
        filename = item.get("filename")
        url = item.get("url")
        digest = item.get("sha256")
        byte_count = item.get("bytes")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ArtifactFetchError("artifact lock contains an unsafe filename")
        if filename.casefold() in filenames:
            raise ArtifactFetchError(f"duplicate artifact filename: {filename}")
        filenames.add(filename.casefold())
        if not isinstance(url, str):
            raise ArtifactFetchError(f"artifact URL is missing: {filename}")
        _validate_https_url(url, allowed_hosts=None)
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest.casefold()) is None:
            raise ArtifactFetchError(f"artifact SHA-256 is invalid: {filename}")
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count <= 0:
            raise ArtifactFetchError(f"artifact byte count is invalid: {filename}")
        clean.append(
            {
                "filename": filename,
                "url": url,
                "sha256": digest.casefold(),
                "bytes": byte_count,
            }
        )
    return clean


def _validate_https_url(url: str, allowed_hosts: set[str] | None) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ArtifactFetchError("artifact URL must be credential-free HTTPS")
    try:
        if parsed.port not in (None, 443):
            raise ArtifactFetchError("artifact URL uses a non-default port")
    except ValueError as exc:
        raise ArtifactFetchError("artifact URL contains an invalid port") from exc
    host = parsed.hostname.casefold().rstrip(".")
    if allowed_hosts is not None and host not in allowed_hosts:
        raise ArtifactFetchError(f"artifact redirect host is not locked: {host}")
    return host


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_existing(path: Path, expected_bytes: int, expected_sha256: str) -> bool:
    if not path.exists():
        return False
    if _is_link_or_reparse(path) or not path.is_file():
        raise ArtifactFetchError(f"artifact destination is not a plain file: {path.name}")
    if path.stat().st_size != expected_bytes or _sha256(path) != expected_sha256:
        raise ArtifactFetchError(f"existing artifact does not match the lock: {path.name}")
    return True


def _default_open(url: str):
    # The release builder runs this helper with a full developer Python, but
    # the packaged runtime deliberately omits Python's OpenSSL-backed _ssl
    # module.  Keep the import local so the offline regression suite can
    # import and exercise the lock-verification logic inside that runtime.
    import ssl
    from urllib.request import HTTPSHandler

    context = ssl.create_default_context()
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())
    request = Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
        method="GET",
    )
    return opener.open(request, timeout=60)


def _open_with_locked_redirects(
    url: str,
    allowed_hosts: set[str],
    opener: Callable[[str], BinaryIO],
):
    current = url
    for _attempt in range(MAX_REDIRECTS + 1):
        _validate_https_url(current, allowed_hosts)
        try:
            response = opener(current)
        except HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                raise ArtifactFetchError(f"artifact server returned HTTP {exc.code}") from exc
            location = exc.headers.get("Location", "")
            exc.close()
            if not location:
                raise ArtifactFetchError("artifact redirect omitted Location")
            current = urljoin(current, location)
            continue
        final_url = getattr(response, "geturl", lambda: current)()
        _validate_https_url(final_url, allowed_hosts)
        return response
    raise ArtifactFetchError("artifact redirect limit exceeded")


def _download_one(
    record: dict[str, object],
    wheelhouse: Path,
    allowed_hosts: set[str],
    opener: Callable[[str], BinaryIO],
) -> str:
    filename = str(record["filename"])
    expected_bytes = int(record["bytes"])
    expected_sha256 = str(record["sha256"])
    destination = wheelhouse / filename
    if _verify_existing(destination, expected_bytes, expected_sha256):
        return "verified"

    part = wheelhouse / f".{filename}.part"
    if part.exists() or _is_link_or_reparse(part):
        raise ArtifactFetchError(f"stale artifact part file exists: {part.name}")
    response = _open_with_locked_redirects(
        str(record["url"]), allowed_hosts, opener
    )
    digest = hashlib.sha256()
    written = 0
    try:
        encoding = str(getattr(response, "headers", {}).get("Content-Encoding", ""))
        if encoding and encoding.casefold() != "identity":
            raise ArtifactFetchError("artifact response used content encoding")
        header_length = str(getattr(response, "headers", {}).get("Content-Length", ""))
        if header_length:
            try:
                if int(header_length) != expected_bytes:
                    raise ArtifactFetchError("artifact Content-Length differs from lock")
            except ValueError as exc:
                raise ArtifactFetchError("artifact Content-Length is invalid") from exc
        with part.open("xb") as file_obj:
            while True:
                chunk = response.read(min(CHUNK_SIZE, expected_bytes - written + 1))
                if not chunk:
                    break
                written += len(chunk)
                if written > expected_bytes:
                    raise ArtifactFetchError("artifact exceeded locked byte count")
                digest.update(chunk)
                file_obj.write(chunk)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        if written != expected_bytes or digest.hexdigest() != expected_sha256:
            raise ArtifactFetchError("artifact payload does not match the lock")
        try:
            os.link(part, destination)
        except FileExistsError as exc:
            raise ArtifactFetchError(f"artifact destination appeared concurrently: {filename}") from exc
        part.unlink()
        return "downloaded"
    finally:
        try:
            response.close()
        finally:
            try:
                part.unlink()
            except FileNotFoundError:
                pass


def fetch_artifacts(
    lock_path: Path,
    wheelhouse: Path,
    *,
    opener: Callable[[str], BinaryIO] = _default_open,
) -> list[tuple[str, str]]:
    records = _read_lock(lock_path)
    wheelhouse.mkdir(parents=True, exist_ok=True)
    if _is_link_or_reparse(wheelhouse) or not wheelhouse.is_dir():
        raise ArtifactFetchError("wheelhouse must be a plain directory")
    allowed_hosts = {
        _validate_https_url(str(record["url"]), allowed_hosts=None)
        for record in records
    }
    return [
        (
            str(record["filename"]),
            _download_one(record, wheelhouse, allowed_hosts, opener),
        )
        for record in records
    ]


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    try:
        results = fetch_artifacts(arguments.lock, arguments.wheelhouse)
    # ssl.SSLError is an OSError subclass, so this also covers TLS failures
    # without requiring the portable runtime to import Python's ssl module.
    except (ArtifactFetchError, OSError) as exc:
        parser.exit(1, f"runtime artifact fetch failed: {exc}\n")
    for filename, status in results:
        print(f"{status}: {filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
