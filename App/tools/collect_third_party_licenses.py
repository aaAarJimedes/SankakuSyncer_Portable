# -*- coding: utf-8 -*-
"""Build and verify the final portable Runtime compliance bundle.

The collector uses version-pinned authoritative HTTPS sources and the exact
lean Runtime supplied on the command line.  It freezes upstream notices and
source checksums, verifies every CPython/wheel ZIP member against the artifact
lock (including wheel ``RECORD`` itself), hashes every shipped payload file,
and emits deterministic SPDX 2.3,
runtime-inventory, source-manifest, and OpenVEX documents.

Running with ``--check`` is offline and read-only.  A refresh downloads every
source before changing the existing managed bundle, overwrites files
atomically, and removes only stale files named by the previous valid manifest.
Unknown files are never deleted and make verification fail.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
from html.parser import HTMLParser
import http.client
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Callable, Iterable, Mapping
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET
import zipfile

try:
    from . import runtime_compliance
except ImportError:  # Direct execution from App/tools.
    tools_directory = str(Path(__file__).resolve().parent)
    if tools_directory not in sys.path:
        sys.path.insert(0, tools_directory)
    import runtime_compliance


APP_DIR = Path(__file__).resolve().parents[1]
ROOT = APP_DIR.parent
DEFAULT_OUTPUT = ROOT / "THIRD_PARTY_LICENSES"
DEFAULT_SBOM = ROOT / "SBOM.spdx.json"
DEFAULT_INVENTORY = ROOT / "RUNTIME_INVENTORY.json"
DEFAULT_VEX = ROOT / "VEX.openvex.json"
DEFAULT_RUNTIME = ROOT / "Runtime"
ARTIFACT_LOCK_FILE = APP_DIR / "runtime_artifacts.lock.json"
LOCK_FILE = APP_DIR / "requirements.lock.txt"

APP_VERSION = runtime_compliance.APP_VERSION
PYTHON_VERSION = "3.13.15"
PYSIDE_VERSION = "6.11.2"
QT_VERSION = "6.11.2"
BUNDLE_SCHEMA_VERSION = 2

CPYTHON_LICENSE_URL = (
    f"https://raw.githubusercontent.com/python/cpython/v{PYTHON_VERSION}/LICENSE"
)
CPYTHON_ARTIFACT_SBOM_URL = (
    f"https://www.python.org/ftp/python/{PYTHON_VERSION}/"
    f"python-{PYTHON_VERSION}-embed-amd64.zip.spdx.json"
)
PYSIDE_LICENSE_BASE = (
    "https://code.qt.io/cgit/pyside/pyside-setup.git/plain/LICENSES/"
)
PYSIDE_LICENSE_NAMES = (
    "Apache-2.0.txt",
    "BSD-3-Clause.txt",
    "GFDL-1.3-no-invariants-only.txt",
    "GPL-2.0-only.txt",
    "GPL-3.0-only.txt",
    "LGPL-3.0-only.txt",
    "LicenseRef-Qt-Commercial.txt",
    "Qt-GPL-exception-1.0.txt",
)
QT_DOC_BASE = "https://doc.qt.io/qt-6.11/"
QT_DOCUMENTS = (
    "licensing.html",
    "licenses-used-in-qt.html",
    "sbom.html",
)
QT_WEBENGINE_LICENSE_PAGE = "qtwebengine-licensing.html"
QT_WEBENGINE_PAGE_PREFIX = "qtwebengine-3rdparty-"
MINIMUM_QT_WEBENGINE_NOTICE_PAGES = 100
QT_SOURCE_BASE = (
    f"https://download.qt.io/official_releases/qt/6.11/{QT_VERSION}/submodules/"
)
QT_SOURCE_MODULES = (
    "qtbase",
    "qtdeclarative",
    "qtimageformats",
    "qtpositioning",
    "qtwebchannel",
    "qtwebengine",
)
QT_RELEVANT_SECTIONS = {
    "qt-core",
    "qt-gui",
    "qt-image-formats",
    "qt-network",
    "qt-positioning",
    "qt-qml",
    "qt-quick",
    "qt-webengine",
}
MSVC_LICENSE_URL = "https://visualstudio.microsoft.com/license-terms/vs2022-cruntime/"
MSVC_LICENSE_DOCUMENT_URL = (
    "https://visualstudio.microsoft.com/wp-content/uploads/2021/09/"
    "Visual-C-Runtime-2015-2022-License-1.docx"
)
OPENSSL_VULNERABILITY_URL = (
    "https://www.openssl-library.org/news/vulnerabilities-3.0/index.html"
)
OPENVEX_SCHEMA_URL = (
    "https://raw.githubusercontent.com/openvex/spec/"
    "a68ccd19b15a9604d28ef66ebf33f27a772ba4ec/"
    "openvex_json_schema.json"
)
SPDX_SCHEMA_URL = (
    "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/"
    "schemas/spdx-schema.json"
)
OPENSSL_3022_CVES = (
    "CVE-2026-75803",
    "CVE-2026-54874",
    "CVE-2026-63072",
    "CVE-2026-63074",
    "CVE-2026-63076",
)

_LOCK_LINE_RE = re.compile(r"([A-Za-z0-9_.-]+)==([^\s;]+)")
_SAFE_OUTPUT_PART_RE = re.compile(r"[A-Za-z0-9_.+ -]+")
_NETWORK_PACKAGES = (
    "requests",
    "certifi",
    "charset-normalizer",
    "idna",
    "urllib3",
    "pysocks",
)
_PYSIDE_PACKAGES = (
    "pyside6",
    "pyside6-addons",
    "pyside6-essentials",
    "shiboken6",
)
_ALLOWED_SOURCE_HOSTS = {
    "code.qt.io",
    "doc.qt.io",
    "download.qt.io",
    "files.pythonhosted.org",
    "raw.githubusercontent.com",
    "visualstudio.microsoft.com",
    "www.openssl-library.org",
    "openssl-library.org",
    "www.python.org",
}

# PySocks 1.7.1 has no matching Git tag.  Extract its license from the exact
# official PyPI wheel that the portable lock uses instead of using mutable
# ``master``.  The archive digest is PyPI's published SHA-256.
_PYSOCKS_171_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/8d/59/"
    "b4572118e098ac8e46e399a1dd0f2d85403ce8bbaad9ec79373ed6badaf9/"
    "PySocks-1.7.1-py3-none-any.whl"
)
_PYSOCKS_171_WHEEL_SHA256 = (
    "2725bd0a9925919b9b51739eea5f9e2bae91e83288108a9ad338b2e3a4435ee5"
)
_PYSOCKS_171_LICENSE_MEMBER = "PySocks-1.7.1.dist-info/LICENSE"


class LicenseBundleError(RuntimeError):
    """Raised when inputs or collected license material are unsafe/invalid."""


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag.casefold() != "a":
            return
        for name, value in attrs:
            if name.casefold() == "href" and value:
                self.links.append(value)


class _SectionLinkCollector(HTMLParser):
    """Collect links while retaining the nearest preceding ``h2`` id."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.section: str | None = None
        self.links: list[tuple[str | None, str]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = {name.casefold(): value for name, value in attrs}
        if tag.casefold() == "h2":
            self.section = attributes.get("id")
        elif tag.casefold() == "a" and attributes.get("href"):
            self.links.append((self.section, str(attributes["href"])))


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def read_locked_versions(path: Path = LOCK_FILE) -> dict[str, tuple[str, str]]:
    """Read the deliberately simple exact-pin lock used by the portable app."""
    locked: dict[str, tuple[str, str]] = {}
    for line_number, raw_line in enumerate(path.read_text("utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _LOCK_LINE_RE.fullmatch(line)
        if match is None:
            raise LicenseBundleError(f"unsupported lock line {line_number}")
        display_name, version = match.groups()
        canonical = _canonical_name(display_name)
        if canonical in locked:
            raise LicenseBundleError(f"duplicate locked distribution: {display_name}")
        locked[canonical] = (display_name, version)

    required = set(_PYSIDE_PACKAGES)
    missing = sorted(required - set(locked))
    if missing:
        raise LicenseBundleError(
            "license bundle lock is missing: " + ", ".join(missing)
        )
    for canonical in _PYSIDE_PACKAGES:
        if locked[canonical][1] != PYSIDE_VERSION:
            raise LicenseBundleError(
                f"{locked[canonical][0]} must be {PYSIDE_VERSION} for this bundle"
            )
    unknown = sorted(set(locked) - set(_NETWORK_PACKAGES) - set(_PYSIDE_PACKAGES))
    if unknown:
        raise LicenseBundleError(
            "license source configuration is missing for: " + ", ".join(unknown)
        )
    return locked


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_url(url: str, *, maximum_bytes: int = 16 * 1024 * 1024) -> bytes:
    """Fetch one bounded HTTPS resource from its authoritative upstream."""
    split = urlsplit(url)
    if (
        split.scheme != "https"
        or split.hostname is None
        or split.hostname.casefold() not in _ALLOWED_SOURCE_HOSTS
    ):
        raise LicenseBundleError(f"non-HTTPS source URL: {url}")
    request = Request(
        url,
        headers={
            "Accept": "text/plain,text/html,application/octet-stream;q=0.8",
            "User-Agent": (
                "SankakuSyncer-license-collector/0.1 "
                "(+https://github.com/aaAarJimedes/SankakuSyncer_Portable)"
            ),
        },
    )
    last_error: Exception | None = None
    data: bytes | None = None
    for attempt in range(4):
        try:
            with urlopen(request, timeout=60) as response:
                final_url = response.geturl()
                final_split = urlsplit(final_url)
                if (
                    final_split.scheme != "https"
                    or final_split.hostname is None
                    or final_split.hostname.casefold() not in _ALLOWED_SOURCE_HOSTS
                ):
                    raise LicenseBundleError(
                        f"source redirected outside the allowlist: {url}"
                    )
                data = response.read(maximum_bytes + 1)
            break
        except LicenseBundleError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(0.5 * (2**attempt))
    if data is None:
        raise LicenseBundleError(
            f"download failed after retries: {url} ({type(last_error).__name__})"
        ) from last_error
    if not data:
        raise LicenseBundleError(f"empty upstream resource: {url}")
    if len(data) > maximum_bytes:
        raise LicenseBundleError(f"upstream resource is unexpectedly large: {url}")
    return data


def _fetch_locked_artifact(
    artifact: Mapping[str, object],
    fetcher: Callable[[str], bytes],
) -> bytes:
    expected_size = artifact.get("bytes")
    if type(expected_size) is not int or expected_size < 1:
        raise LicenseBundleError("locked artifact has invalid size")
    if fetcher is fetch_url:
        data = fetch_url(str(artifact["url"]), maximum_bytes=expected_size)
    else:
        data = fetcher(str(artifact["url"]))
    if len(data) != expected_size or _sha256(data) != artifact.get("sha256"):
        raise LicenseBundleError(
            f"locked artifact hash/size mismatch: {artifact.get('filename')}"
        )
    return data


def _validate_text_resource(path: str, url: str, data: bytes) -> None:
    if b"\x00" in data:
        raise LicenseBundleError(f"NUL byte in text resource: {url}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LicenseBundleError(f"non-UTF-8 text resource: {url}") from exc
    lowered = text[:512].casefold()
    if path.endswith(".html"):
        if "<html" not in lowered and "<!doctype html" not in lowered:
            raise LicenseBundleError(f"upstream HTML validation failed: {url}")
    elif "<html" in lowered or "<!doctype html" in lowered:
        raise LicenseBundleError(f"upstream license returned HTML: {url}")


def discover_qt_webengine_notice_urls(page: bytes) -> list[str]:
    """Return same-origin Qt WebEngine third-party pages from the index."""
    try:
        text = page.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LicenseBundleError("Qt WebEngine license index is not UTF-8") from exc
    if f"Qt {QT_VERSION}" not in text:
        raise LicenseBundleError(
            f"Qt WebEngine index is not the expected Qt {QT_VERSION} documentation"
        )
    parser = _LinkCollector()
    parser.feed(text)
    expected_origin = urlsplit(QT_DOC_BASE).netloc.casefold()
    urls: set[str] = set()
    for href in parser.links:
        joined = urljoin(QT_DOC_BASE + QT_WEBENGINE_LICENSE_PAGE, href)
        split = urlsplit(joined)
        filename = PurePosixPath(split.path).name
        if (
            split.scheme == "https"
            and split.netloc.casefold() == expected_origin
            and filename.startswith(QT_WEBENGINE_PAGE_PREFIX)
            and filename.endswith(".html")
            and split.query == ""
            and split.fragment == ""
        ):
            urls.add(urljoin(QT_DOC_BASE, filename))
    if len(urls) < MINIMUM_QT_WEBENGINE_NOTICE_PAGES:
        raise LicenseBundleError(
            "Qt WebEngine notice inventory is unexpectedly small: "
            f"expected at least {MINIMUM_QT_WEBENGINE_NOTICE_PAGES}, got {len(urls)}"
        )
    return sorted(urls)


def discover_qt_attribution_urls(page: bytes) -> list[str]:
    """Discover all third-party detail pages for actually shipped Qt modules."""
    try:
        text = page.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LicenseBundleError("Qt third-party index is not UTF-8") from exc
    if f"Qt {QT_VERSION}" not in text:
        raise LicenseBundleError(
            f"Qt third-party index is not the expected Qt {QT_VERSION} documentation"
        )
    parser = _SectionLinkCollector()
    parser.feed(text)
    expected_origin = urlsplit(QT_DOC_BASE).netloc.casefold()
    urls: set[str] = set()
    for section, href in parser.links:
        joined = urljoin(QT_DOC_BASE + "licenses-used-in-qt.html", href)
        split = urlsplit(joined)
        filename = PurePosixPath(split.path).name
        is_detail = "-attribution-" in filename or "-3rdparty-" in filename
        is_llvmpipe = filename == "qt-attribution-llvmpipe.html"
        if (
            split.scheme == "https"
            and split.netloc.casefold() == expected_origin
            and split.query == ""
            and split.fragment == ""
            and filename.endswith(".html")
            and is_detail
            and (section in QT_RELEVANT_SECTIONS or is_llvmpipe)
        ):
            urls.add(urljoin(QT_DOC_BASE, filename))
    webengine_count = sum(
        1
        for url in urls
        if PurePosixPath(urlsplit(url).path).name.startswith(QT_WEBENGINE_PAGE_PREFIX)
    )
    if webengine_count < MINIMUM_QT_WEBENGINE_NOTICE_PAGES:
        raise LicenseBundleError(
            "Qt WebEngine notice inventory is unexpectedly small: "
            f"expected at least {MINIMUM_QT_WEBENGINE_NOTICE_PAGES}, got {webengine_count}"
        )
    required = set(runtime_compliance.QT_NATIVE_ATTRIBUTIONS)
    discovered = {PurePosixPath(urlsplit(url).path).name for url in urls}
    missing = sorted(required - discovered)
    if missing:
        raise LicenseBundleError(
            "Qt attribution index is missing required runtime evidence: "
            + ", ".join(missing)
        )
    return sorted(urls)


def parse_qt_source_checksum(module: str, data: bytes) -> dict[str, str]:
    filename = f"{module}-everywhere-src-{QT_VERSION}.tar.xz"
    try:
        line = data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise LicenseBundleError(f"Qt source checksum is not ASCII: {module}") from exc
    match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?(.+)", line)
    if match is None or PurePosixPath(match.group(2)).name != filename:
        raise LicenseBundleError(f"Qt source checksum is malformed: {module}")
    return {
        "archive_url": urljoin(QT_SOURCE_BASE, filename),
        "checksum_url": urljoin(QT_SOURCE_BASE, filename + ".sha256"),
        "sha256": match.group(1).casefold(),
    }


def validate_cpython_artifact_sbom(data: bytes) -> dict[str, object]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LicenseBundleError("official CPython artifact SPDX is invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("spdxVersion") != "SPDX-2.3"
        or value.get("documentNamespace") != CPYTHON_ARTIFACT_SBOM_URL
    ):
        raise LicenseBundleError("official CPython artifact SPDX identity mismatch")
    packages = value.get("packages")
    if not isinstance(packages, list):
        raise LicenseBundleError("official CPython artifact SPDX has no packages")
    cpython = [
        package
        for package in packages
        if isinstance(package, dict) and package.get("name") == "CPython"
    ]
    if len(cpython) != 1 or cpython[0].get("versionInfo") != PYTHON_VERSION:
        raise LicenseBundleError("official CPython artifact SPDX version mismatch")
    return value


def validate_openssl_advisory(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LicenseBundleError("OpenSSL vulnerability page is not UTF-8") from exc
    for cve in OPENSSL_3022_CVES:
        position = text.find(cve)
        if position < 0:
            raise LicenseBundleError(f"OpenSSL advisory omits {cve}")
        excerpt = re.sub(r"<[^>]+>", " ", text[position : position + 20000])
        if "3.0.22" not in excerpt:
            raise LicenseBundleError(f"OpenSSL advisory range is not anchored for {cve}")


def validate_schema_resource(data: bytes, *, title: str) -> dict[str, object]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LicenseBundleError(f"{title} schema is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("title") != title:
        raise LicenseBundleError(f"{title} schema identity mismatch")
    return value


_POWERSHELL_SCHEMA_VALIDATOR = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json -AsHashtable
$document = $payload.document | ConvertTo-Json -Depth 100 -Compress
$schema = $payload.schema | ConvertTo-Json -Depth 100 -Compress
if (Test-Json -Json $document -Schema $schema -ErrorAction Stop) {
    [Console]::Out.Write('VALID')
    exit 0
}
exit 3
"""


def validate_against_frozen_schema(
    document: Mapping[str, object],
    schema: Mapping[str, object],
    *,
    title: str,
) -> None:
    """Run PowerShell 7's full JSON Schema validator with no network or files."""
    executable = shutil.which("pwsh")
    if executable is None:
        raise LicenseBundleError(
            f"PowerShell 7 is required for frozen {title} schema validation"
        )
    payload = json.dumps(
        {"document": document, "schema": schema},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    try:
        completed = subprocess.run(
            [
                executable,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _POWERSHELL_SCHEMA_VALIDATOR,
            ],
            input=payload,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LicenseBundleError(f"{title} schema validator failed to run") from exc
    if completed.returncode != 0 or completed.stdout.strip() != "VALID":
        detail = completed.stderr.strip().splitlines()
        suffix = f": {detail[-1][:300]}" if detail else ""
        raise LicenseBundleError(f"generated document fails frozen {title} schema{suffix}")


def validate_msvc_license_document(data: bytes) -> None:
    """Validate the official OOXML license payload without transforming it."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as document:
            xml = document.read("word/document.xml")
        root = ET.fromstring(xml)
    except (KeyError, OSError, ET.ParseError, zipfile.BadZipFile) as exc:
        raise LicenseBundleError("Microsoft VC Runtime license document is invalid") from exc
    text = re.sub(
        r"\s+",
        " ",
        " ".join(
            node.text or "" for node in root.iter() if node.tag.endswith("}t")
        ),
    ).strip()
    required = (
        "MICROSOFT SOFTWARE LICENSE TERMS",
        "MICROSOFT VISUAL C++ 2015 - 2022 RUNTIME",
        "SCOPE OF LICENSE",
        "EULA ID:",
    )
    if any(value.casefold() not in text.casefold() for value in required):
        raise LicenseBundleError("Microsoft VC Runtime license identity mismatch")


def validate_openvex_document(value: Mapping[str, object]) -> None:
    allowed_document = {
        "@context",
        "@id",
        "author",
        "role",
        "timestamp",
        "last_updated",
        "version",
        "tooling",
        "statements",
    }
    required_document = {
        "@context", "@id", "author", "role", "timestamp", "tooling", "version", "statements"
    }
    if set(value) - allowed_document or not required_document.issubset(value):
        raise LicenseBundleError("OpenVEX document fields are invalid")
    if (
        value.get("@context") != "https://openvex.dev/ns/v0.2.0"
        or not isinstance(value.get("@id"), str)
        or not str(value["@id"]).startswith("https://")
        or not isinstance(value.get("author"), str)
        or not value["author"]
        or not isinstance(value.get("role"), str)
        or not value["role"]
        or not isinstance(value.get("tooling"), str)
        or not value["tooling"]
        or type(value.get("version")) is not int
        or int(value["version"]) < 1
        or not isinstance(value.get("timestamp"), str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(value["timestamp"])) is None
    ):
        raise LicenseBundleError("OpenVEX context mismatch")
    statements = value.get("statements")
    if not isinstance(statements, list) or not statements:
        raise LicenseBundleError("OpenVEX must contain at least one statement")
    statuses = {"not_affected", "affected", "fixed", "under_investigation"}
    seen_vulnerabilities: set[str] = set()
    allowed_statement = {
        "action_statement",
        "impact_statement",
        "justification",
        "products",
        "status",
        "status_notes",
        "vulnerability",
    }
    for statement in statements:
        if (
            not isinstance(statement, dict)
            or set(statement) - allowed_statement
            or statement.get("status") not in statuses
            or not isinstance(statement.get("status_notes"), str)
            or not statement["status_notes"]
        ):
            raise LicenseBundleError("OpenVEX statement status is invalid")
        vulnerability = statement.get("vulnerability")
        products = statement.get("products")
        if (
            not isinstance(vulnerability, dict)
            or set(vulnerability) != {"@id", "name"}
            or not isinstance(vulnerability.get("name"), str)
            or re.fullmatch(r"CVE-\d{4}-\d{4,}", str(vulnerability["name"])) is None
            or not isinstance(vulnerability.get("@id"), str)
            or not str(vulnerability["@id"]).endswith(str(vulnerability["name"]))
            or not isinstance(products, list)
            or not products
            or not all(
                isinstance(item, dict)
                and set(item) == {"@id"}
                and isinstance(item.get("@id"), str)
                and str(item["@id"]).startswith("pkg:")
                for item in products
            )
        ):
            raise LicenseBundleError("OpenVEX statement identity is invalid")
        name = str(vulnerability["name"])
        if name in seen_vulnerabilities:
            raise LicenseBundleError("OpenVEX vulnerability statements are duplicated")
        seen_vulnerabilities.add(name)
        if statement["status"] == "not_affected" and statement.get(
            "justification"
        ) != "component_not_present":
            raise LicenseBundleError("OpenVEX not_affected statement has no justification")
        if statement["status"] == "affected" and not statement.get("action_statement"):
            raise LicenseBundleError("OpenVEX affected statement has no action")


def validate_spdx_document(value: Mapping[str, object]) -> None:
    required_document = {
        "SPDXID",
        "creationInfo",
        "dataLicense",
        "documentNamespace",
        "files",
        "name",
        "packages",
        "relationships",
        "spdxVersion",
    }
    if set(value) != required_document or (
        value.get("SPDXID") != "SPDXRef-DOCUMENT"
        or value.get("spdxVersion") != "SPDX-2.3"
        or value.get("dataLicense") != "CC0-1.0"
        or not isinstance(value.get("packages"), list)
        or not isinstance(value.get("files"), list)
        or not isinstance(value.get("relationships"), list)
        or not isinstance(value.get("name"), str)
        or not value["name"]
        or not isinstance(value.get("documentNamespace"), str)
        or not str(value["documentNamespace"]).startswith("https://")
    ):
        raise LicenseBundleError("generated SPDX 2.3 document structure is invalid")
    creation = value.get("creationInfo")
    if (
        not isinstance(creation, dict)
        or set(creation) != {"created", "creators"}
        or not isinstance(creation.get("created"), str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(creation["created"])) is None
        or not isinstance(creation.get("creators"), list)
        or not creation["creators"]
        or not all(isinstance(item, str) and item for item in creation["creators"])
    ):
        raise LicenseBundleError("generated SPDX creation info is invalid")

    id_pattern = re.compile(r"SPDXRef-[A-Za-z0-9.-]+")
    element_ids = {"SPDXRef-DOCUMENT"}
    package_allowed = {
        "SPDXID",
        "checksums",
        "comment",
        "copyrightText",
        "downloadLocation",
        "externalRefs",
        "filesAnalyzed",
        "licenseConcluded",
        "licenseDeclared",
        "name",
        "packageVerificationCode",
        "supplier",
        "versionInfo",
    }
    package_required = {
        "SPDXID",
        "copyrightText",
        "downloadLocation",
        "filesAnalyzed",
        "licenseConcluded",
        "licenseDeclared",
        "name",
        "supplier",
    }
    runtime_verification_code: str | None = None
    for package in value["packages"]:
        if (
            not isinstance(package, dict)
            or set(package) - package_allowed
            or not package_required.issubset(package)
            or not isinstance(package.get("SPDXID"), str)
            or id_pattern.fullmatch(str(package["SPDXID"])) is None
            or str(package["SPDXID"]) in element_ids
            or type(package.get("filesAnalyzed")) is not bool
            or not all(
                isinstance(package.get(key), str) and bool(package[key])
                for key in (
                    "copyrightText", "downloadLocation", "licenseConcluded",
                    "licenseDeclared", "name", "supplier",
                )
            )
        ):
            raise LicenseBundleError("generated SPDX package entry is invalid")
        element_ids.add(str(package["SPDXID"]))
        verification = package.get("packageVerificationCode")
        if package["filesAnalyzed"]:
            if (
                not isinstance(verification, dict)
                or set(verification) != {"packageVerificationCodeValue"}
                or re.fullmatch(
                    r"[0-9a-f]{40}", str(verification.get("packageVerificationCodeValue", ""))
                ) is None
            ):
                raise LicenseBundleError("generated SPDX package verification code is invalid")
            if package["SPDXID"] == "SPDXRef-Package-Portable-Runtime":
                runtime_verification_code = str(verification["packageVerificationCodeValue"])
        elif verification is not None:
            raise LicenseBundleError("unanalyzed SPDX package has a verification code")
        checksums = package.get("checksums", [])
        if not isinstance(checksums, list) or not all(
            isinstance(item, dict)
            and set(item) == {"algorithm", "checksumValue"}
            and item.get("algorithm") == "SHA256"
            and re.fullmatch(r"[0-9a-f]{64}", str(item.get("checksumValue", ""))) is not None
            for item in checksums
        ):
            raise LicenseBundleError("generated SPDX package checksum is invalid")

    file_sha1s: list[str] = []
    seen_file_names: set[str] = set()
    for file_entry in value["files"]:
        if (
            not isinstance(file_entry, dict)
            or set(file_entry) != {
                "SPDXID", "checksums", "copyrightText", "fileName",
                "licenseConcluded", "licenseInfoInFiles",
            }
            or not isinstance(file_entry.get("SPDXID"), str)
            or id_pattern.fullmatch(str(file_entry["SPDXID"])) is None
            or str(file_entry["SPDXID"]) in element_ids
            or not isinstance(file_entry.get("fileName"), str)
            or not str(file_entry["fileName"]).startswith("./Runtime/")
            or str(file_entry["fileName"]).casefold() in seen_file_names
            or not isinstance(file_entry.get("licenseConcluded"), str)
            or not isinstance(file_entry.get("copyrightText"), str)
            or not isinstance(file_entry.get("licenseInfoInFiles"), list)
            or file_entry["licenseInfoInFiles"] != ["NOASSERTION"]
            or not isinstance(file_entry.get("checksums"), list)
        ):
            raise LicenseBundleError("generated SPDX file entry is invalid")
        element_ids.add(str(file_entry["SPDXID"]))
        seen_file_names.add(str(file_entry["fileName"]).casefold())
        checksum_map = {
            str(item.get("algorithm")): str(item.get("checksumValue"))
            for item in file_entry["checksums"]
            if isinstance(item, dict) and set(item) == {"algorithm", "checksumValue"}
        }
        if (
            set(checksum_map) != {"SHA1", "SHA256"}
            or re.fullmatch(r"[0-9a-f]{40}", checksum_map["SHA1"]) is None
            or re.fullmatch(r"[0-9a-f]{64}", checksum_map["SHA256"]) is None
        ):
            raise LicenseBundleError("generated SPDX file checksum is invalid")
        file_sha1s.append(checksum_map["SHA1"])

    expected_verification_code = hashlib.sha1(
        "".join(sorted(file_sha1s)).encode("ascii")
    ).hexdigest()
    if runtime_verification_code != expected_verification_code:
        raise LicenseBundleError("generated SPDX Runtime verification code is invalid")

    seen_relationships: set[tuple[str, str, str]] = set()
    for relationship in value["relationships"]:
        if (
            not isinstance(relationship, dict)
            or set(relationship) != {
                "relatedSpdxElement", "relationshipType", "spdxElementId"
            }
            or relationship.get("relationshipType")
            not in {"CONTAINS", "DEPENDS_ON", "DESCRIBES", "GENERATED_FROM"}
            or relationship.get("spdxElementId") not in element_ids
            or relationship.get("relatedSpdxElement") not in element_ids
        ):
            raise LicenseBundleError("generated SPDX relationship is invalid")
        identity = (
            str(relationship["spdxElementId"]),
            str(relationship["relationshipType"]),
            str(relationship["relatedSpdxElement"]),
        )
        if identity in seen_relationships:
            raise LicenseBundleError("generated SPDX relationships are duplicated")
        seen_relationships.add(identity)


def _certifi_tag(version: str) -> str:
    parts = version.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise LicenseBundleError(f"unsupported certifi version format: {version}")
    return f"{int(parts[0]):04d}.{int(parts[1]):02d}.{int(parts[2]):02d}"


def dependency_license_source(canonical: str, version: str) -> tuple[str, str]:
    """Return the pinned upstream URL and output license filename."""
    if canonical == "requests":
        return (
            f"https://raw.githubusercontent.com/psf/requests/v{version}/LICENSE",
            "LICENSE",
        )
    if canonical == "certifi":
        return (
            "https://raw.githubusercontent.com/certifi/python-certifi/"
            f"{_certifi_tag(version)}/LICENSE",
            "LICENSE",
        )
    if canonical == "charset-normalizer":
        return (
            "https://raw.githubusercontent.com/Ousret/charset_normalizer/"
            f"{version}/LICENSE",
            "LICENSE",
        )
    if canonical == "idna":
        return (
            f"https://raw.githubusercontent.com/kjd/idna/v{version}/LICENSE.md",
            "LICENSE.md",
        )
    if canonical == "urllib3":
        return (
            f"https://raw.githubusercontent.com/urllib3/urllib3/{version}/LICENSE.txt",
            "LICENSE.txt",
        )
    if canonical == "pysocks" and version == "1.7.1":
        return _PYSOCKS_171_WHEEL_URL, "LICENSE"
    raise LicenseBundleError(
        f"no immutable official license source is configured for {canonical}=={version}"
    )


def _extract_pysocks_license(archive: bytes) -> bytes:
    actual = _sha256(archive)
    if actual != _PYSOCKS_171_WHEEL_SHA256:
        raise LicenseBundleError(
            "PySocks 1.7.1 wheel hash mismatch: "
            f"expected {_PYSOCKS_171_WHEEL_SHA256}, got {actual}"
        )
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as wheel:
            return wheel.read(_PYSOCKS_171_LICENSE_MEMBER)
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise LicenseBundleError("PySocks wheel license extraction failed") from exc


def _zip_member_inventory_value(
    artifact: Mapping[str, object], archive: bytes
) -> dict[str, object]:
    members: list[dict[str, object]] = []
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            for info in sorted(source.infolist(), key=lambda value: value.filename.casefold()):
                if info.is_dir():
                    continue
                path = PurePosixPath(info.filename.replace("\\", "/"))
                if path.is_absolute() or ".." in path.parts or not path.parts:
                    raise LicenseBundleError("unsafe CPython embeddable ZIP member")
                relative = path.as_posix()
                if relative.casefold() in seen:
                    raise LicenseBundleError("duplicate CPython embeddable ZIP member")
                seen.add(relative.casefold())
                data = source.read(info)
                members.append(
                    {"path": relative, "sha256": _sha256(data), "size": len(data)}
                )
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise LicenseBundleError("locked ZIP artifact inspection failed") from exc
    return {
        "members": members,
        "schema_version": 1,
        "source_artifact": {
            key: artifact[key] for key in ("bytes", "filename", "sha256", "url")
        },
    }


def build_cpython_member_inventory(
    artifact_lock: Mapping[str, object],
    fetcher: Callable[[str], bytes],
) -> tuple[bytes, str]:
    artifacts = artifact_lock.get("artifacts")
    if not isinstance(artifacts, list):
        raise LicenseBundleError("runtime artifact lock has no artifacts")
    candidates = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("canonical_name") == "cpython"
    ]
    if len(candidates) != 1:
        raise LicenseBundleError("runtime artifact lock has no unique CPython artifact")
    artifact = candidates[0]
    archive = _fetch_locked_artifact(artifact, fetcher)
    inventory = _json_bytes(_zip_member_inventory_value(artifact, archive))
    if _sha256(inventory) != artifact.get("member_inventory_sha256"):
        raise LicenseBundleError(
            "CPython member inventory does not match the artifact lock anchor"
        )
    return inventory, str(artifact["sha256"])


def build_wheel_member_inventories(
    artifact_lock: Mapping[str, object],
    fetcher: Callable[[str], bytes],
) -> dict[str, tuple[bytes, str, str]]:
    """Return exact wheel-member maps keyed by safe bundle-relative path."""
    artifacts = artifact_lock.get("artifacts")
    if not isinstance(artifacts, list):
        raise LicenseBundleError("runtime artifact lock has no artifacts")
    values: dict[str, tuple[bytes, str, str]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("kind") != "wheel":
            continue
        archive = _fetch_locked_artifact(artifact, fetcher)
        inventory = _json_bytes(_zip_member_inventory_value(artifact, archive))
        if _sha256(inventory) != artifact.get("member_inventory_sha256"):
            raise LicenseBundleError(
                f"wheel member inventory does not match the artifact lock anchor: "
                f"{artifact.get('filename')}"
            )
        relative = (
            "Artifact-Members/"
            f"{artifact['canonical_name']}-{artifact['version']}.wheel-members.json"
        )
        values[relative] = (
            inventory,
            str(artifact["url"]),
            str(artifact["sha256"]),
        )
    expected = sum(
        1
        for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("kind") == "wheel"
    )
    if len(values) != expected:
        raise LicenseBundleError("wheel member inventory paths collide")
    return values


def _entry(
    relative_path: str,
    source_url: str,
    data: bytes,
    *,
    source_sha256: str | None = None,
) -> dict[str, object]:
    _validate_relative_path(relative_path)
    if relative_path.casefold().endswith(".docx"):
        validate_msvc_license_document(data)
    else:
        _validate_text_resource(relative_path, source_url, data)
    value: dict[str, object] = {
        "path": relative_path,
        "sha256": _sha256(data),
        "size": len(data),
        "source_url": source_url,
    }
    if source_sha256 is not None:
        value["source_sha256"] = source_sha256
    return value


def collect_materials(
    locked: Mapping[str, tuple[str, str]],
    artifact_lock: Mapping[str, object],
    fetcher: Callable[[str], bytes] = fetch_url,
) -> tuple[dict[str, bytes], list[dict[str, object]]]:
    """Download and validate every license/notice in the pinned inventory."""
    files: dict[str, bytes] = {}
    entries: list[dict[str, object]] = []

    def add(
        relative_path: str,
        source_url: str,
        data: bytes,
        *,
        source_sha256: str | None = None,
    ) -> None:
        if relative_path in files:
            raise LicenseBundleError(f"duplicate output path: {relative_path}")
        files[relative_path] = data
        entries.append(
            _entry(
                relative_path,
                source_url,
                data,
                source_sha256=source_sha256,
            )
        )

    member_inventory, cpython_archive_sha256 = build_cpython_member_inventory(
        artifact_lock, fetcher
    )
    add(
        f"Python-{PYTHON_VERSION}/LICENSE.txt",
        CPYTHON_LICENSE_URL,
        fetcher(CPYTHON_LICENSE_URL),
    )
    python_sbom = fetcher(CPYTHON_ARTIFACT_SBOM_URL)
    validate_cpython_artifact_sbom(python_sbom)
    add(
        f"Python-{PYTHON_VERSION}/python-{PYTHON_VERSION}-embed-amd64.zip.spdx.json",
        CPYTHON_ARTIFACT_SBOM_URL,
        python_sbom,
    )
    add(
        f"Python-{PYTHON_VERSION}/embed-members.sha256.json",
        next(
            str(item["url"])
            for item in artifact_lock["artifacts"]
            if item["canonical_name"] == "cpython"
        ),
        member_inventory,
        source_sha256=cpython_archive_sha256,
    )
    for relative, (data, url, artifact_sha256) in sorted(
        build_wheel_member_inventories(artifact_lock, fetcher).items()
    ):
        add(
            relative,
            url,
            data,
            source_sha256=artifact_sha256,
        )
    for filename in PYSIDE_LICENSE_NAMES:
        url = f"{PYSIDE_LICENSE_BASE}{filename}?h=v{PYSIDE_VERSION}"
        add(f"PySide6-{PYSIDE_VERSION}/LICENSES/{filename}", url, fetcher(url))

    for canonical in _NETWORK_PACKAGES:
        if canonical not in locked:
            continue
        display_name, version = locked[canonical]
        url, filename = dependency_license_source(canonical, version)
        downloaded = fetcher(url)
        source_sha256: str | None = None
        if canonical == "pysocks":
            source_sha256 = _sha256(downloaded)
            downloaded = _extract_pysocks_license(downloaded)
        add(
            f"Python-Packages/{display_name}-{version}/{filename}",
            url,
            downloaded,
            source_sha256=source_sha256,
        )

    for filename in QT_DOCUMENTS:
        url = urljoin(QT_DOC_BASE, filename)
        data = fetcher(url)
        if filename == "licenses-used-in-qt.html":
            text = data.decode("utf-8", errors="replace")
            if f"Qt {QT_VERSION}" not in text:
                raise LicenseBundleError(
                    f"Qt third-party index is not the expected Qt {QT_VERSION} documentation"
                )
        add(f"Qt-{QT_VERSION}/{filename}", url, data)

    for module in QT_SOURCE_MODULES:
        checksum_filename = f"{module}-everywhere-src-{QT_VERSION}.tar.xz.sha256"
        url = urljoin(QT_SOURCE_BASE, checksum_filename)
        data = fetcher(url)
        parse_qt_source_checksum(module, data)
        add(f"Qt-{QT_VERSION}/source-archives/{checksum_filename}", url, data)

    index_url = urljoin(QT_DOC_BASE, QT_WEBENGINE_LICENSE_PAGE)
    index_data = fetcher(index_url)
    webengine_attribution_urls = discover_qt_webengine_notice_urls(index_data)
    add(
        f"Qt-{QT_VERSION}/{QT_WEBENGINE_LICENSE_PAGE}",
        index_url,
        index_data,
    )
    attribution_urls = sorted(
        set(webengine_attribution_urls)
        | set(
            discover_qt_attribution_urls(
                files[f"Qt-{QT_VERSION}/licenses-used-in-qt.html"]
            )
        )
    )

    # The exact set is discovered from the version-validated official index.
    # Fetch concurrently to keep a full refresh practical; output remains sorted.
    with ThreadPoolExecutor(max_workers=4) as executor:
        notice_data = list(executor.map(fetcher, attribution_urls))
    for url, data in zip(attribution_urls, notice_data, strict=True):
        filename = PurePosixPath(urlsplit(url).path).name
        runtime_compliance.parse_attribution_page(filename, data)
        add(f"Qt-{QT_VERSION}/attributions/{filename}", url, data)

    msvc_data = fetcher(MSVC_LICENSE_URL)
    add("Microsoft/VS2022-CRuntime-License.html", MSVC_LICENSE_URL, msvc_data)
    msvc_document = fetcher(MSVC_LICENSE_DOCUMENT_URL)
    validate_msvc_license_document(msvc_document)
    add(
        "Microsoft/Visual-C-Runtime-2015-2022-License.docx",
        MSVC_LICENSE_DOCUMENT_URL,
        msvc_document,
    )

    openssl_data = fetcher(OPENSSL_VULNERABILITY_URL)
    validate_openssl_advisory(openssl_data)
    add(
        "Security/OpenSSL-3.0-vulnerabilities.html",
        OPENSSL_VULNERABILITY_URL,
        openssl_data,
    )

    for relative, url, title in (
        ("Schemas/OpenVEX-0.2.0.schema.json", OPENVEX_SCHEMA_URL, "OpenVEX"),
        ("Schemas/SPDX-2.3.schema.json", SPDX_SCHEMA_URL, "SPDX 2.3"),
    ):
        data = fetcher(url)
        validate_schema_resource(data, title=title)
        add(relative, url, data)

    entries.sort(key=lambda value: str(value["path"]).casefold())
    return files, entries


def qt_source_archives_from_files(
    files: Mapping[str, bytes],
) -> dict[str, dict[str, str]]:
    sources: dict[str, dict[str, str]] = {}
    for module in QT_SOURCE_MODULES:
        relative = (
            f"Qt-{QT_VERSION}/source-archives/"
            f"{module}-everywhere-src-{QT_VERSION}.tar.xz.sha256"
        )
        try:
            data = files[relative]
        except KeyError as exc:
            raise LicenseBundleError(f"Qt source checksum is missing: {module}") from exc
        sources[module] = parse_qt_source_checksum(module, data)
    return sources


def qt_attributions_from_files(
    files: Mapping[str, bytes],
) -> dict[str, dict[str, object]]:
    prefix = f"Qt-{QT_VERSION}/attributions/"
    values: dict[str, dict[str, object]] = {}
    for relative, data in files.items():
        if relative.startswith(prefix) and relative.endswith(".html"):
            filename = relative[len(prefix) :]
            values[filename] = runtime_compliance.parse_attribution_page(filename, data)
    return dict(sorted(values.items()))


def wheel_member_inventories_from_files(
    files: Mapping[str, bytes],
) -> list[dict[str, object]]:
    values: list[dict[str, object]] = []
    for relative in sorted(files):
        if not relative.startswith("Artifact-Members/") or not relative.endswith(
            ".wheel-members.json"
        ):
            continue
        try:
            value = json.loads(files[relative].decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LicenseBundleError(
                f"wheel member inventory is invalid: {relative}"
            ) from exc
        if not isinstance(value, dict):
            raise LicenseBundleError(f"wheel member inventory is invalid: {relative}")
        values.append(value)
    return values


def expected_material_sources(
    locked: Mapping[str, tuple[str, str]],
    artifact_lock: Mapping[str, object],
    files: Mapping[str, bytes],
) -> dict[str, tuple[str, str | None]]:
    """Rebuild the exact path -> upstream URL/artifact-hash contract offline."""
    sources: dict[str, tuple[str, str | None]] = {}

    def add(path: str, url: str, source_sha256: str | None = None) -> None:
        if path in sources:
            raise LicenseBundleError(f"duplicate expected material path: {path}")
        sources[path] = (url, source_sha256)

    artifacts = artifact_lock.get("artifacts")
    if not isinstance(artifacts, list):
        raise LicenseBundleError("runtime artifact lock has no artifacts")
    cpython = [
        item
        for item in artifacts
        if isinstance(item, dict) and item.get("canonical_name") == "cpython"
    ]
    if len(cpython) != 1:
        raise LicenseBundleError("runtime artifact lock has no unique CPython artifact")
    add(f"Python-{PYTHON_VERSION}/LICENSE.txt", CPYTHON_LICENSE_URL)
    add(
        f"Python-{PYTHON_VERSION}/python-{PYTHON_VERSION}-embed-amd64.zip.spdx.json",
        CPYTHON_ARTIFACT_SBOM_URL,
    )
    add(
        f"Python-{PYTHON_VERSION}/embed-members.sha256.json",
        str(cpython[0]["url"]),
        str(cpython[0]["sha256"]),
    )
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("kind") != "wheel":
            continue
        add(
            "Artifact-Members/"
            f"{artifact['canonical_name']}-{artifact['version']}.wheel-members.json",
            str(artifact["url"]),
            str(artifact["sha256"]),
        )
    for filename in PYSIDE_LICENSE_NAMES:
        add(
            f"PySide6-{PYSIDE_VERSION}/LICENSES/{filename}",
            f"{PYSIDE_LICENSE_BASE}{filename}?h=v{PYSIDE_VERSION}",
        )
    for canonical in _NETWORK_PACKAGES:
        if canonical not in locked:
            continue
        display_name, version = locked[canonical]
        url, filename = dependency_license_source(canonical, version)
        add(
            f"Python-Packages/{display_name}-{version}/{filename}",
            url,
            _PYSOCKS_171_WHEEL_SHA256 if canonical == "pysocks" else None,
        )
    for filename in QT_DOCUMENTS:
        add(f"Qt-{QT_VERSION}/{filename}", urljoin(QT_DOC_BASE, filename))
    for module in QT_SOURCE_MODULES:
        filename = f"{module}-everywhere-src-{QT_VERSION}.tar.xz.sha256"
        add(
            f"Qt-{QT_VERSION}/source-archives/{filename}",
            urljoin(QT_SOURCE_BASE, filename),
        )
    webengine_path = f"Qt-{QT_VERSION}/{QT_WEBENGINE_LICENSE_PAGE}"
    add(webengine_path, urljoin(QT_DOC_BASE, QT_WEBENGINE_LICENSE_PAGE))
    try:
        attribution_urls = set(
            discover_qt_webengine_notice_urls(files[webengine_path])
        ) | set(
            discover_qt_attribution_urls(
                files[f"Qt-{QT_VERSION}/licenses-used-in-qt.html"]
            )
        )
    except KeyError as exc:
        raise LicenseBundleError("Qt attribution index is missing") from exc
    for url in sorted(attribution_urls):
        filename = PurePosixPath(urlsplit(url).path).name
        add(f"Qt-{QT_VERSION}/attributions/{filename}", url)
    add("Microsoft/VS2022-CRuntime-License.html", MSVC_LICENSE_URL)
    add(
        "Microsoft/Visual-C-Runtime-2015-2022-License.docx",
        MSVC_LICENSE_DOCUMENT_URL,
    )
    add(
        "Security/OpenSSL-3.0-vulnerabilities.html",
        OPENSSL_VULNERABILITY_URL,
    )
    add("Schemas/OpenVEX-0.2.0.schema.json", OPENVEX_SCHEMA_URL)
    add("Schemas/SPDX-2.3.schema.json", SPDX_SCHEMA_URL)
    return dict(sorted(sources.items(), key=lambda item: item[0].casefold()))


_CRYPTO_REACHABILITY_TOKENS = ("EVP_Cipher", "CMS_", "CMP_", "DTLS")


def scan_direct_crypto_calls(app_dir: Path = APP_DIR) -> list[dict[str, object]]:
    """Record bounded source evidence; absence is not an affectedness verdict."""
    findings: list[dict[str, object]] = []
    for path in sorted(app_dir.glob("*.py"), key=lambda value: value.name.casefold()):
        if path.name.startswith("test_") or path.name == "run_tests.py":
            continue
        try:
            lines = path.read_text("utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise LicenseBundleError(f"application source is unreadable: {path.name}") from exc
        for line_number, line in enumerate(lines, 1):
            folded = line.casefold()
            for token in _CRYPTO_REACHABILITY_TOKENS:
                if token.casefold() in folded:
                    findings.append(
                        {"path": f"App/{path.name}", "line": line_number, "token": token}
                    )
    return findings


def _runtime_openssl_version(inventory: Mapping[str, object]) -> str | None:
    components = inventory.get("components")
    if not isinstance(components, dict):
        raise LicenseBundleError("runtime inventory has no probed components")
    value = components.get("openssl")
    if not isinstance(value, str) or value == "not-present":
        return None
    match = re.search(r"\b(\d+\.\d+\.\d+)\b", value)
    if match is None:
        raise LicenseBundleError("Runtime OpenSSL version is not parseable")
    return match.group(1)


def build_vex(
    runtime_inventory: Mapping[str, object],
    source_findings: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    openssl_version = _runtime_openssl_version(runtime_inventory)
    findings = list(source_findings)
    runtime_files = runtime_inventory.get("files", [])
    if not isinstance(runtime_files, list):
        raise LicenseBundleError("runtime inventory has no files for VEX evidence")
    def is_openssl_payload(path: str) -> bool:
        name = PurePosixPath(path).name.casefold()
        return name in {"_hashlib.pyd", "_ssl.pyd", "qopensslbackend.dll"} or name.startswith(
            ("libcrypto-", "libssl-")
        )

    openssl_payload_evidence = sorted(
        str(item.get("path"))
        for item in runtime_files
        if isinstance(item, dict)
        and is_openssl_payload(str(item.get("path", "")))
    )
    if openssl_version is None and openssl_payload_evidence:
        raise LicenseBundleError(
            "OpenSSL probe says not-present but OpenSSL payload evidence exists"
        )
    target = runtime_inventory.get("target")
    if openssl_version is None and (
        not isinstance(target, dict)
        or target.get("transport") != "winhttp-schannel"
    ):
        raise LicenseBundleError(
            "OpenSSL component-not-present VEX requires the Schannel Runtime target"
        )
    if openssl_version is not None and not openssl_payload_evidence:
        raise LicenseBundleError(
            "OpenSSL probe reports a version but no OpenSSL payload evidence exists"
        )
    runtime_product = (
        f"pkg:generic/sankakusyncer-portable-runtime@{APP_VERSION}"
        "?arch=x86_64&os=windows"
    )
    statements: list[dict[str, object]] = []
    if openssl_version is None:
        status = "not_affected"
        notes = (
            "The complete final Runtime inventory contains no Python _ssl/_hashlib, "
            "OpenSSL libcrypto/libssl, or Qt qopensslbackend payload. Networking uses "
            "Windows WinHTTP/Schannel and the required python_hashlib_winhttp builder "
            "verification passed. This component-not-present conclusion is recomputed "
            "from runtime_subset_manifest.sha256 and every Runtime file."
        )
        for cve in OPENSSL_3022_CVES:
            statements.append(
                {
                    "justification": "component_not_present",
                    "products": [{"@id": runtime_product}],
                    "status": status,
                    "status_notes": notes,
                    "vulnerability": {
                        "@id": f"https://www.cve.org/CVERecord?id={cve}",
                        "name": cve,
                    },
                }
            )
    else:
        version_tuple = tuple(int(part) for part in openssl_version.split("."))
        fixed = version_tuple >= (3, 0, 22) and version_tuple < (3, 1, 0)
        if fixed:
            status = "fixed"
            notes = (
                f"The final Runtime probe reports OpenSSL {openssl_version}, which is "
                "outside the official OpenSSL 3.0.0-before-3.0.22 affected range."
            )
        else:
            status = "under_investigation"
            evidence = (
                "The bounded App/*.py production-source scan found no direct "
                "EVP_Cipher/CMS/CMP/DTLS tokens. "
                if not findings
                else "The bounded source scan found potential direct crypto tokens. "
            )
            notes = (
                f"The final Runtime contains OpenSSL {openssl_version}, within or not "
                "proven outside the official affected range. " + evidence
                + "The application-level path remains under investigation because "
                "absence of direct calls does not prove transitive TLS reachability. "
                + f"Evidence source: {OPENSSL_VULNERABILITY_URL}"
            )
        for cve in OPENSSL_3022_CVES:
            statements.append(
                {
                    "products": [{"@id": runtime_product}],
                    "status": status,
                    "status_notes": notes,
                    "vulnerability": {
                        "@id": f"https://www.cve.org/CVERecord?id={cve}",
                        "name": cve,
                    },
                }
            )
    fingerprint = _sha256(
        json.dumps(
            {
                "openssl": openssl_version,
                "payload": runtime_inventory.get("payload_sha256"),
                "statements": statements,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )[:24]
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": (
            "https://github.com/aaAarJimedes/SankakuSyncer_Portable/"
            f"vex/{APP_VERSION}/{fingerprint}"
        ),
        "author": "SankakuSyncer maintainers",
        "role": "Document Creator",
        "statements": statements,
        "timestamp": "2026-08-29T00:00:00Z",
        "tooling": "SankakuSyncer Runtime Compliance Collector",
        "version": 1,
    }


def build_runtime_spdx(
    artifact_lock: Mapping[str, object],
    runtime_inventory: Mapping[str, object],
    files: Mapping[str, bytes],
) -> dict[str, object]:
    python_relative = (
        f"Python-{PYTHON_VERSION}/python-{PYTHON_VERSION}-embed-amd64.zip.spdx.json"
    )
    try:
        python_sbom = validate_cpython_artifact_sbom(files[python_relative])
    except KeyError as exc:
        raise LicenseBundleError("official CPython artifact SPDX is missing") from exc
    return runtime_compliance.build_spdx(
        artifact_lock,
        runtime_inventory,
        python_sbom,
        qt_source_archives_from_files(files),
        qt_attributions_from_files(files),
    )


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def build_manifest(
    locked: Mapping[str, tuple[str, str]],
    entries: Iterable[Mapping[str, object]],
    artifact_lock_bytes: bytes,
    runtime_inventory_bytes: bytes,
    sbom_bytes: bytes,
    vex_bytes: bytes,
) -> dict[str, object]:
    def document(path: str, data: bytes) -> dict[str, object]:
        return {"path": path, "sha256": _sha256(data), "size": len(data)}

    return {
        "components": {
            "application": APP_VERSION,
            "python": PYTHON_VERSION,
            "pyside6": PYSIDE_VERSION,
            "qt": QT_VERSION,
            "transport": "winhttp-schannel",
            "python_packages": {
                locked[name][0]: locked[name][1] for name in sorted(locked)
            },
        },
        "documents": {
            "runtime_artifact_lock": document(
                "App/runtime_artifacts.lock.json", artifact_lock_bytes
            ),
            "runtime_inventory": document(
                "RUNTIME_INVENTORY.json", runtime_inventory_bytes
            ),
            "sbom": document("SBOM.spdx.json", sbom_bytes),
            "vex": document("VEX.openvex.json", vex_bytes),
        },
        "files": list(entries),
        "schema_version": BUNDLE_SCHEMA_VERSION,
    }


def _validate_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or value != path.as_posix()
        or ".." in path.parts
        or any(not _SAFE_OUTPUT_PART_RE.fullmatch(part) for part in path.parts)
    ):
        raise LicenseBundleError(f"unsafe bundle path: {value!r}")
    return path


def _safe_output_path(output: Path, relative: str) -> Path:
    pure = _validate_relative_path(relative)
    candidate = output.joinpath(*pure.parts)
    try:
        candidate.resolve(strict=False).relative_to(output.resolve(strict=False))
    except (OSError, ValueError) as exc:
        raise LicenseBundleError(f"bundle path escapes output: {relative!r}") from exc
    return candidate


def _read_manifest(output: Path) -> dict[str, object]:
    try:
        value = json.loads((output / "SOURCES.json").read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LicenseBundleError("SOURCES.json is missing or invalid") from exc
    if not isinstance(value, dict) or value.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise LicenseBundleError("unsupported SOURCES.json schema")
    return value


def verify_bundle(
    output: Path = DEFAULT_OUTPUT,
    sbom_path: Path = DEFAULT_SBOM,
    lock_path: Path = LOCK_FILE,
    *,
    runtime: Path = DEFAULT_RUNTIME,
    artifact_lock_path: Path = ARTIFACT_LOCK_FILE,
    inventory_path: Path = DEFAULT_INVENTORY,
    vex_path: Path = DEFAULT_VEX,
    full_schema_validation: bool = False,
) -> list[str]:
    """Recompute the complete Runtime and verify every frozen output offline."""
    failures: list[str] = []
    try:
        locked = read_locked_versions(lock_path)
        manifest = _read_manifest(output)
        artifact_lock_bytes = artifact_lock_path.read_bytes()
        artifact_lock = runtime_compliance.read_artifact_lock(
            artifact_lock_path, locked
        )
    except (
        OSError,
        UnicodeError,
        LicenseBundleError,
        runtime_compliance.RuntimeComplianceError,
    ) as exc:
        return [str(exc)]

    expected_components = {
        "application": APP_VERSION,
        "python": PYTHON_VERSION,
        "pyside6": PYSIDE_VERSION,
        "qt": QT_VERSION,
        "transport": "winhttp-schannel",
        "python_packages": {
            locked[name][0]: locked[name][1] for name in sorted(locked)
        },
    }
    if manifest.get("components") != expected_components:
        failures.append("SOURCES.json component versions do not match the locks")

    raw_entries = manifest.get("files")
    if not isinstance(raw_entries, list):
        failures.append("SOURCES.json files is not a list")
        raw_entries = []
    file_bytes: dict[str, bytes] = {}
    entry_metadata: dict[str, Mapping[str, object]] = {}
    previous_sort_key = ""
    seen_casefolded: set[str] = set()
    for index, raw_entry in enumerate(raw_entries):
        if not isinstance(raw_entry, dict):
            failures.append(f"SOURCES.json file entry {index} is invalid")
            continue
        relative = raw_entry.get("path")
        if not isinstance(relative, str):
            failures.append(f"SOURCES.json file entry {index} has no path")
            continue
        try:
            path = _safe_output_path(output, relative)
        except LicenseBundleError as exc:
            failures.append(str(exc))
            continue
        if relative.casefold() < previous_sort_key:
            failures.append("SOURCES.json file entries are not sorted")
        previous_sort_key = relative.casefold()
        if relative.casefold() in seen_casefolded:
            failures.append(f"duplicate SOURCES.json path: {relative}")
            continue
        seen_casefolded.add(relative.casefold())
        entry_metadata[relative] = raw_entry
        digest = raw_entry.get("sha256")
        size = raw_entry.get("size")
        source_url = raw_entry.get("source_url")
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or type(size) is not int
            or size < 1
            or not isinstance(source_url, str)
            or urlsplit(source_url).scheme != "https"
        ):
            failures.append(f"invalid SOURCES.json metadata: {relative}")
            continue
        source_digest = raw_entry.get("source_sha256")
        if source_digest is not None and (
            not isinstance(source_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", source_digest)
        ):
            failures.append(f"invalid source artifact hash: {relative}")
        try:
            data = path.read_bytes()
        except OSError:
            failures.append(f"license file missing or unreadable: {relative}")
            continue
        if len(data) != size or _sha256(data) != digest:
            failures.append(f"license file hash/size mismatch: {relative}")
        else:
            file_bytes[relative] = data

    actual_bundle_files: set[str] = set()
    if output.is_dir():
        try:
            for path in output.rglob("*"):
                if path.is_symlink():
                    failures.append(
                        "symbolic link is not allowed in license bundle: "
                        + path.relative_to(output).as_posix()
                    )
                elif path.is_file():
                    actual_bundle_files.add(path.relative_to(output).as_posix())
        except OSError:
            failures.append("license bundle tree is unreadable")
    actual_bundle_files.discard("SOURCES.json")
    for relative in sorted(actual_bundle_files - set(file_bytes)):
        failures.append(f"unmanifested license file: {relative}")

    required_paths = {
        f"Python-{PYTHON_VERSION}/LICENSE.txt",
        f"Python-{PYTHON_VERSION}/embed-members.sha256.json",
        (
            f"Python-{PYTHON_VERSION}/"
            f"python-{PYTHON_VERSION}-embed-amd64.zip.spdx.json"
        ),
        f"Qt-{QT_VERSION}/{QT_WEBENGINE_LICENSE_PAGE}",
        "Microsoft/VS2022-CRuntime-License.html",
        "Microsoft/Visual-C-Runtime-2015-2022-License.docx",
        "Schemas/OpenVEX-0.2.0.schema.json",
        "Schemas/SPDX-2.3.schema.json",
        "Security/OpenSSL-3.0-vulnerabilities.html",
    }
    required_paths.update(
        f"PySide6-{PYSIDE_VERSION}/LICENSES/{filename}"
        for filename in PYSIDE_LICENSE_NAMES
    )
    required_paths.update(f"Qt-{QT_VERSION}/{filename}" for filename in QT_DOCUMENTS)
    required_paths.update(
        (
            f"Qt-{QT_VERSION}/source-archives/"
            f"{module}-everywhere-src-{QT_VERSION}.tar.xz.sha256"
        )
        for module in QT_SOURCE_MODULES
    )
    for artifact in artifact_lock["artifacts"]:
        if artifact.get("kind") == "wheel":
            required_paths.add(
                "Artifact-Members/"
                f"{artifact['canonical_name']}-{artifact['version']}.wheel-members.json"
            )
    for canonical in _NETWORK_PACKAGES:
        if canonical not in locked:
            continue
        display_name, version = locked[canonical]
        _url, filename = dependency_license_source(canonical, version)
        required_paths.add(f"Python-Packages/{display_name}-{version}/{filename}")
    for relative in sorted(required_paths - set(file_bytes)):
        failures.append(f"required license material missing from manifest: {relative}")

    try:
        index = file_bytes[f"Qt-{QT_VERSION}/licenses-used-in-qt.html"]
        webengine_urls = discover_qt_webengine_notice_urls(
            file_bytes[f"Qt-{QT_VERSION}/{QT_WEBENGINE_LICENSE_PAGE}"]
        )
        expected_attributions = {
            f"Qt-{QT_VERSION}/attributions/"
            + PurePosixPath(urlsplit(url).path).name
            for url in set(discover_qt_attribution_urls(index)) | set(webengine_urls)
        }
        actual_attributions = {
            relative
            for relative in file_bytes
            if relative.startswith(f"Qt-{QT_VERSION}/attributions/")
        }
        if actual_attributions != expected_attributions:
            failures.append("Qt module third-party attribution inventory is incomplete")
        qt_source_archives_from_files(file_bytes)
        validate_cpython_artifact_sbom(
            file_bytes[
                f"Python-{PYTHON_VERSION}/"
                f"python-{PYTHON_VERSION}-embed-amd64.zip.spdx.json"
            ]
        )
        validate_openssl_advisory(
            file_bytes["Security/OpenSSL-3.0-vulnerabilities.html"]
        )
        validate_schema_resource(
            file_bytes["Schemas/OpenVEX-0.2.0.schema.json"], title="OpenVEX"
        )
        validate_schema_resource(
            file_bytes["Schemas/SPDX-2.3.schema.json"], title="SPDX 2.3"
        )
        validate_msvc_license_document(
            file_bytes["Microsoft/Visual-C-Runtime-2015-2022-License.docx"]
        )
    except (KeyError, LicenseBundleError, runtime_compliance.RuntimeComplianceError) as exc:
        failures.append(str(exc))

    try:
        expected_sources = expected_material_sources(locked, artifact_lock, file_bytes)
    except LicenseBundleError as exc:
        failures.append(str(exc))
    else:
        if set(entry_metadata) != set(expected_sources):
            failures.append("SOURCES.json path inventory does not match pinned sources")
        for relative, (expected_url, expected_source_sha256) in expected_sources.items():
            metadata = entry_metadata.get(relative)
            if metadata is None:
                continue
            if metadata.get("source_url") != expected_url:
                failures.append(f"source URL is not pinned: {relative}")
            actual_source_sha256 = metadata.get("source_sha256")
            if actual_source_sha256 != expected_source_sha256:
                failures.append(f"source artifact SHA-256 is not pinned: {relative}")

    try:
        member_inventory = json.loads(
            file_bytes[f"Python-{PYTHON_VERSION}/embed-members.sha256.json"]
        )
        expected_inventory = runtime_compliance.build_runtime_inventory(
            runtime,
            artifact_lock,
            _sha256(artifact_lock_bytes),
            member_inventory,
            wheel_member_inventories_from_files(file_bytes),
        )
        expected_inventory_bytes = _json_bytes(expected_inventory)
    except (
        KeyError,
        UnicodeError,
        json.JSONDecodeError,
        runtime_compliance.RuntimeComplianceError,
    ) as exc:
        failures.append(f"Runtime inventory recomputation failed: {exc}")
        expected_inventory = None
        expected_inventory_bytes = None

    document_bytes: dict[str, bytes] = {"runtime_artifact_lock": artifact_lock_bytes}
    for key, path, label in (
        ("runtime_inventory", inventory_path, "RUNTIME_INVENTORY.json"),
        ("sbom", sbom_path, "SBOM.spdx.json"),
        ("vex", vex_path, "VEX.openvex.json"),
    ):
        try:
            document_bytes[key] = path.read_bytes()
        except OSError:
            failures.append(f"{label} is missing or unreadable")

    raw_documents = manifest.get("documents")
    if not isinstance(raw_documents, dict):
        failures.append("SOURCES.json documents is invalid")
        raw_documents = {}
    expected_document_paths = {
        "runtime_artifact_lock": "App/runtime_artifacts.lock.json",
        "runtime_inventory": "RUNTIME_INVENTORY.json",
        "sbom": "SBOM.spdx.json",
        "vex": "VEX.openvex.json",
    }
    for key, expected_path in expected_document_paths.items():
        data = document_bytes.get(key)
        metadata = raw_documents.get(key)
        if (
            data is None
            or not isinstance(metadata, dict)
            or metadata.get("path") != expected_path
            or metadata.get("sha256") != _sha256(data)
            or metadata.get("size") != len(data)
        ):
            failures.append(f"{expected_path} does not match SOURCES.json")

    if expected_inventory_bytes is not None:
        if document_bytes.get("runtime_inventory") != expected_inventory_bytes:
            failures.append("RUNTIME_INVENTORY.json does not match the complete Runtime")
        assert expected_inventory is not None
        runtime_paths = {
            str(entry["path"]).casefold() for entry in expected_inventory["files"]
        }
        if any(
            path.endswith("/qsvg.dll") or path.endswith("/qt6svg.dll")
            for path in runtime_paths
        ):
            failures.append("QtSVG payload is present but has no configured source provenance")
        try:
            expected_sbom_bytes = _json_bytes(
                build_runtime_spdx(artifact_lock, expected_inventory, file_bytes)
            )
            expected_sbom = json.loads(expected_sbom_bytes)
            validate_spdx_document(expected_sbom)
            if full_schema_validation:
                validate_against_frozen_schema(
                    expected_sbom,
                    validate_schema_resource(
                        file_bytes["Schemas/SPDX-2.3.schema.json"], title="SPDX 2.3"
                    ),
                    title="SPDX 2.3",
                )
            if document_bytes.get("sbom") != expected_sbom_bytes:
                failures.append("SBOM.spdx.json is not the deterministic Runtime SBOM")
            expected_vex = build_vex(expected_inventory, scan_direct_crypto_calls())
            validate_openvex_document(expected_vex)
            if full_schema_validation:
                validate_against_frozen_schema(
                    expected_vex,
                    validate_schema_resource(
                        file_bytes["Schemas/OpenVEX-0.2.0.schema.json"], title="OpenVEX"
                    ),
                    title="OpenVEX",
                )
            expected_vex_bytes = _json_bytes(expected_vex)
            if document_bytes.get("vex") != expected_vex_bytes:
                failures.append("VEX.openvex.json is not the deterministic Runtime VEX")
            unresolved = [
                statement
                for statement in expected_vex["statements"]
                if statement.get("status") in {"affected", "under_investigation"}
            ]
            if unresolved:
                failures.append(
                    "release blocked: Runtime has unresolved OpenSSL 3.0 vulnerability statements"
                )
        except (LicenseBundleError, runtime_compliance.RuntimeComplianceError) as exc:
            failures.append(f"Runtime SBOM/VEX generation failed: {exc}")
    return failures


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
    try:
        temporary.replace(path)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _old_managed_paths(output: Path) -> set[str]:
    if not output.exists():
        return set()
    manifest = _read_manifest(output)
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise LicenseBundleError("existing SOURCES.json files is invalid")
    paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise LicenseBundleError("existing SOURCES.json file entry is invalid")
        relative = str(entry["path"])
        _safe_output_path(output, relative)
        paths.add(relative)
    return paths


def _is_link_like(path: Path) -> bool:
    try:
        return path.is_symlink() or path.is_junction()
    except (AttributeError, OSError):
        return path.is_symlink()


def _preflight_existing_outputs(output: Path, documents: Iterable[Path]) -> None:
    """Reject links and unknown license files before any formal output changes."""
    if output.exists():
        if _is_link_like(output) or not output.is_dir():
            raise LicenseBundleError("existing license bundle is not a plain directory")
        managed = _old_managed_paths(output) | {"SOURCES.json"}
        actual: set[str] = set()
        for path in output.rglob("*"):
            relative = path.relative_to(output).as_posix()
            if _is_link_like(path):
                raise LicenseBundleError(
                    f"link/reparse point in existing license bundle: {relative}"
                )
            if path.is_file():
                actual.add(relative)
        unknown = sorted(actual - managed, key=str.casefold)
        if unknown:
            raise LicenseBundleError(
                "existing license bundle has unmanaged files: " + ", ".join(unknown)
            )
    for path in documents:
        if path.exists() and (_is_link_like(path) or not path.is_file()):
            raise LicenseBundleError(f"formal output is not a plain file: {path.name}")


def _remove_installed_target(path: Path) -> None:
    """Remove only one exact just-installed transaction target during rollback."""
    if path.is_dir() and not _is_link_like(path):
        shutil.rmtree(path)
    elif path.exists() or _is_link_like(path):
        path.unlink()


def write_bundle(
    output: Path,
    sbom_path: Path,
    inventory_path: Path,
    vex_path: Path,
    files: Mapping[str, bytes],
    manifest: Mapping[str, object],
    inventory_bytes: bytes,
    sbom_bytes: bytes,
    vex_bytes: bytes,
) -> None:
    """Install a prepared bundle while preserving unknown files safely."""
    output = output.resolve(strict=False)
    sbom_path = sbom_path.resolve(strict=False)
    inventory_path = inventory_path.resolve(strict=False)
    vex_path = vex_path.resolve(strict=False)
    old_paths = _old_managed_paths(output)
    output.mkdir(parents=True, exist_ok=True)

    for relative in sorted(files, key=str.casefold):
        _atomic_write(_safe_output_path(output, relative), files[relative])
    _atomic_write(inventory_path, inventory_bytes)
    _atomic_write(sbom_path, sbom_bytes)
    _atomic_write(vex_path, vex_bytes)
    _atomic_write(output / "SOURCES.json", _json_bytes(manifest))

    # Delete only files explicitly owned by the prior validated manifest.
    stale = old_paths - set(files)
    for relative in sorted(stale, key=lambda value: (value.count("/"), value), reverse=True):
        path = _safe_output_path(output, relative)
        try:
            if path.is_file() and not path.is_symlink():
                path.unlink()
        except OSError as exc:
            raise LicenseBundleError(f"could not remove stale managed file: {relative}") from exc
    for path in sorted(
        (item for item in output.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        try:
            path.rmdir()
        except OSError:
            pass


def refresh_bundle(
    output: Path = DEFAULT_OUTPUT,
    sbom_path: Path = DEFAULT_SBOM,
    lock_path: Path = LOCK_FILE,
    *,
    runtime: Path = DEFAULT_RUNTIME,
    artifact_lock_path: Path = ARTIFACT_LOCK_FILE,
    inventory_path: Path = DEFAULT_INVENTORY,
    vex_path: Path = DEFAULT_VEX,
    fetcher: Callable[[str], bytes] = fetch_url,
) -> int:
    locked = read_locked_versions(lock_path)
    artifact_lock_bytes = artifact_lock_path.read_bytes()
    artifact_lock = runtime_compliance.read_artifact_lock(artifact_lock_path, locked)
    files, entries = collect_materials(locked, artifact_lock, fetcher)
    member_inventory = json.loads(
        files[f"Python-{PYTHON_VERSION}/embed-members.sha256.json"]
    )
    inventory = runtime_compliance.build_runtime_inventory(
        runtime,
        artifact_lock,
        _sha256(artifact_lock_bytes),
        member_inventory,
        wheel_member_inventories_from_files(files),
    )
    inventory_bytes = _json_bytes(inventory)
    sbom = build_runtime_spdx(artifact_lock, inventory, files)
    validate_spdx_document(sbom)
    validate_against_frozen_schema(
        sbom,
        validate_schema_resource(
            files["Schemas/SPDX-2.3.schema.json"], title="SPDX 2.3"
        ),
        title="SPDX 2.3",
    )
    sbom_bytes = _json_bytes(sbom)
    vex = build_vex(inventory, scan_direct_crypto_calls())
    validate_openvex_document(vex)
    validate_against_frozen_schema(
        vex,
        validate_schema_resource(
            files["Schemas/OpenVEX-0.2.0.schema.json"], title="OpenVEX"
        ),
        title="OpenVEX",
    )
    unresolved = [
        statement
        for statement in vex["statements"]
        if statement.get("status") in {"affected", "under_investigation"}
    ]
    if unresolved:
        raise LicenseBundleError(
            "release blocked: Runtime has unresolved OpenSSL vulnerability statements"
        )
    vex_bytes = _json_bytes(vex)
    manifest = build_manifest(
        locked,
        entries,
        artifact_lock_bytes,
        inventory_bytes,
        sbom_bytes,
        vex_bytes,
    )
    output = output.resolve(strict=False)
    sbom_path = sbom_path.resolve(strict=False)
    inventory_path = inventory_path.resolve(strict=False)
    vex_path = vex_path.resolve(strict=False)
    targets = (output, sbom_path, inventory_path, vex_path)
    parents = {path.parent for path in targets}
    if len(parents) != 1:
        raise LicenseBundleError(
            "formal output targets must share one directory for atomic installation"
        )
    parent = next(iter(parents))
    if not parent.is_dir():
        raise LicenseBundleError("formal output parent directory is missing")
    _preflight_existing_outputs(output, targets[1:])

    with tempfile.TemporaryDirectory(prefix=".license-bundle-transaction-", dir=parent) as temporary:
        transaction = Path(temporary)
        stage_output = transaction / output.name
        stage_sbom = transaction / sbom_path.name
        stage_inventory = transaction / inventory_path.name
        stage_vex = transaction / vex_path.name
        write_bundle(
            stage_output,
            stage_sbom,
            stage_inventory,
            stage_vex,
            files,
            manifest,
            inventory_bytes,
            sbom_bytes,
            vex_bytes,
        )
        stage_failures = verify_bundle(
            stage_output,
            stage_sbom,
            lock_path,
            runtime=runtime,
            artifact_lock_path=artifact_lock_path,
            inventory_path=stage_inventory,
            vex_path=stage_vex,
            full_schema_validation=True,
        )
        if stage_failures:
            raise LicenseBundleError(
                "staged bundle failed verification: " + "; ".join(stage_failures)
            )

        backup = transaction / "previous"
        backup.mkdir()
        staged_targets = (stage_output, stage_sbom, stage_inventory, stage_vex)
        backed_up: list[tuple[Path, Path]] = []
        installed: list[Path] = []
        try:
            for target in targets:
                if target.exists():
                    saved = backup / target.name
                    target.replace(saved)
                    backed_up.append((target, saved))
            for staged, target in zip(staged_targets, targets, strict=True):
                staged.replace(target)
                installed.append(target)
            failures = verify_bundle(
                output,
                sbom_path,
                lock_path,
                runtime=runtime,
                artifact_lock_path=artifact_lock_path,
                inventory_path=inventory_path,
                vex_path=vex_path,
                full_schema_validation=True,
            )
            if failures:
                raise LicenseBundleError(
                    "installed bundle failed verification: " + "; ".join(failures)
                )
        except Exception:
            rollback_failures: list[str] = []
            for target in reversed(installed):
                try:
                    _remove_installed_target(target)
                except OSError as exc:
                    rollback_failures.append(f"remove {target.name}: {type(exc).__name__}")
            for target, saved in reversed(backed_up):
                try:
                    saved.replace(target)
                except OSError as exc:
                    rollback_failures.append(f"restore {target.name}: {type(exc).__name__}")
            if rollback_failures:
                raise LicenseBundleError(
                    "formal output transaction rollback failed: "
                    + "; ".join(rollback_failures)
                )
            raise
    return len(files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect or verify pinned third-party license and SBOM material."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the existing bundle offline without writing files",
    )
    parser.add_argument(
        "--full-schema-check",
        action="store_true",
        help=(
            "also validate against the frozen official JSON Schemas using "
            "PowerShell 7; intended for the build host/CI"
        ),
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--sbom", type=Path, default=DEFAULT_SBOM)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--vex", type=Path, default=DEFAULT_VEX)
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--artifact-lock", type=Path, default=ARTIFACT_LOCK_FILE)
    parser.add_argument("--lock", type=Path, default=LOCK_FILE)
    arguments = parser.parse_args(argv)
    if arguments.check:
        failures = verify_bundle(
            arguments.output,
            arguments.sbom,
            arguments.lock,
            runtime=arguments.runtime,
            artifact_lock_path=arguments.artifact_lock,
            inventory_path=arguments.inventory,
            vex_path=arguments.vex,
            full_schema_validation=arguments.full_schema_check,
        )
        if failures:
            print("[FAIL] third-party license/SBOM bundle")
            for failure in failures:
                print(" -", failure)
            return 1
        print("[OK] third-party license/SBOM bundle")
        return 0
    try:
        count = refresh_bundle(
            arguments.output,
            arguments.sbom,
            arguments.lock,
            runtime=arguments.runtime,
            artifact_lock_path=arguments.artifact_lock,
            inventory_path=arguments.inventory,
            vex_path=arguments.vex,
            fetcher=fetch_url,
        )
    except (
        OSError,
        UnicodeError,
        LicenseBundleError,
        runtime_compliance.RuntimeComplianceError,
    ) as exc:
        print(f"[FAIL] third-party license/SBOM collection: {exc}")
        return 1
    print(f"[OK] collected {count} pinned license/notice files")
    print("Bundle:", arguments.output.resolve())
    print("Runtime inventory:", arguments.inventory.resolve())
    print("SBOM:", arguments.sbom.resolve())
    print("VEX:", arguments.vex.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
