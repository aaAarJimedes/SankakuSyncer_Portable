# -*- coding: utf-8 -*-
"""Pure URL policy for Sankaku Channel pages and signed media links."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit


MAX_URL_CHARS = 8192
MAX_POST_ID_CHARS = 64
MAX_TAG_QUERY_CHARS = 500
MAX_TAG_QUERY_BYTES = 2000

_POST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_POST_PATH_RE = re.compile(
    r"(?:^|/)(?:post/show|posts|post)/([A-Za-z0-9][A-Za-z0-9_-]{0,63})(?:/|$)",
    re.IGNORECASE,
)
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_PAGE_HOSTS = frozenset(
    {
        "chan.sankakucomplex.com",
        "www.sankakucomplex.com",
        "beta.sankakucomplex.com",
        "black.sankakucomplex.com",
        "white.sankakucomplex.com",
        "login.sankakucomplex.com",
        "sankaku.app",
    }
)
_MEDIA_HOSTS = frozenset(
    {
        "v.sankakucomplex.com",
        "s.sankakucomplex.com",
        "cs.sankakucomplex.com",
        "media.sankaku.app",
    }
)
_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "access_token",
        "accesstoken",
        "authorization",
        "auth",
        "code",
        "id_token",
        "password",
        "passwd",
        "refresh_token",
        "refreshtoken",
        "session_state",
        "token",
    }
)


def _clean_host(host: object) -> str | None:
    if not isinstance(host, str):
        return None
    value = host.strip().lower().rstrip(".")
    if not value or not value.isascii() or _HOST_RE.fullmatch(value) is None:
        return None
    return value


def is_allowed_page_host(host: object) -> bool:
    """Return whether *host* is an exact official browsing/login host."""
    return _clean_host(host) in _PAGE_HOSTS


def is_allowed_media_host(host: object) -> bool:
    """Return whether *host* is one of the known Sankaku media CDNs."""
    return _clean_host(host) in _MEDIA_HOSTS


def _contains_sensitive_parameters(value: str) -> bool:
    """Check form-style URL parameters without changing their raw encoding."""
    try:
        # Some servers still accept semicolons as query separators.  Treat
        # them as boundaries for the security check even though urlencode()
        # always emits ampersands.
        pairs = parse_qsl(
            value.replace(";", "&"), keep_blank_values=True, strict_parsing=False
        )
    except (TypeError, ValueError):
        return True
    return any(key.strip().casefold() in _SENSITIVE_QUERY_KEYS for key, _ in pairs)


def normalize_page_url(value: object, *, keep_fragment: bool = False) -> str | None:
    """Normalize one credential-free official HTTPS page URL."""
    if not isinstance(value, str):
        to_encoded = getattr(value, "toEncoded", None)
        try:
            value = bytes(to_encoded()).decode("ascii") if callable(to_encoded) else None
        except (RuntimeError, TypeError, UnicodeDecodeError, ValueError):
            return None
    if not value or len(value) > MAX_URL_CHARS:
        return None
    if "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None

    candidate = value.strip()
    if not candidate:
        return None
    if candidate.startswith("/") and not candidate.startswith("//"):
        candidate = "https://chan.sankakucomplex.com" + candidate
    elif "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parts = urlsplit(candidate)
        port = parts.port
        query_pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=False)
    except (TypeError, ValueError):
        return None
    if parts.scheme.lower() != "https":
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if port not in (None, 443):
        return None
    host = _clean_host(parts.hostname or "")
    if host not in _PAGE_HOSTS:
        return None
    if _contains_sensitive_parameters(parts.query):
        return None
    if _contains_sensitive_parameters(parts.fragment):
        return None

    return urlunsplit(
        (
            "https",
            host,
            parts.path or "/",
            urlencode(query_pairs, doseq=True),
            parts.fragment if keep_fragment else "",
        )
    )


def normalize_media_url(value: object) -> str | None:
    """Validate an official signed media URL without rewriting its query."""
    if not isinstance(value, str) or not value or len(value) > MAX_URL_CHARS:
        return None
    if "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except (TypeError, ValueError):
        return None
    if parts.scheme.lower() != "https" or parts.username is not None or parts.password is not None:
        return None
    if port not in (None, 443) or not is_allowed_media_host(parts.hostname or ""):
        return None
    if _contains_sensitive_parameters(parts.query) or _contains_sensitive_parameters(parts.fragment):
        return None
    return value.strip()


def is_allowed_browser_resource_url(value: object) -> bool:
    """Return whether a WebEngine resource URL may leave the renderer.

    HTTPS requests are restricted to exact page and media hosts.  The local
    schemes below do not create an outbound request; blob URLs must still be
    rooted in an approved page origin.
    """
    if not isinstance(value, str):
        to_encoded = getattr(value, "toEncoded", None)
        try:
            value = bytes(to_encoded()).decode("ascii") if callable(to_encoded) else None
        except (RuntimeError, TypeError, UnicodeDecodeError, ValueError):
            return False
    if not value or len(value) > MAX_URL_CHARS:
        return False
    if "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False

    candidate = value.strip()
    try:
        scheme = urlsplit(candidate).scheme.lower()
    except (TypeError, ValueError):
        return False
    if scheme == "https":
        return bool(
            normalize_page_url(candidate, keep_fragment=True)
            or normalize_media_url(candidate)
        )
    if scheme == "about":
        return candidate.casefold() in {"about:blank", "about:srcdoc"}
    if scheme == "data":
        return True
    if scheme == "blob":
        return normalize_page_url(candidate[5:], keep_fragment=True) is not None
    return False


def normalize_post_id(value: object) -> str | None:
    """Return one bounded canonical post ID."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if len(candidate) > MAX_POST_ID_CHARS or _POST_ID_RE.fullmatch(candidate) is None:
        return None
    return candidate


def post_id_from_url(value: object) -> str | None:
    """Extract a post ID from one trusted official page URL."""
    normalized = normalize_page_url(value)
    if normalized is None:
        return None
    match = _POST_PATH_RE.search(urlsplit(normalized).path)
    return normalize_post_id(match.group(1)) if match else None


def canonical_post_url(value: object, locale: str = "cn") -> str | None:
    """Build the canonical Channel URL for a post ID or post URL."""
    post_id = normalize_post_id(value)
    if post_id is None:
        post_id = post_id_from_url(value)
    if post_id is None:
        return None
    safe_locale = locale if locale in {"cn", "en", "ja"} else "cn"
    return f"https://chan.sankakucomplex.com/{safe_locale}/posts/{post_id}"


def normalize_tag_query(value: object) -> str | None:
    """Normalize a bounded, printable Sankaku tag expression."""
    if not isinstance(value, str):
        return None
    candidate = unicodedata.normalize("NFKC", value).strip()
    if len(candidate) > MAX_TAG_QUERY_CHARS:
        return None
    if any(unicodedata.category(char).startswith("C") for char in candidate):
        return None
    try:
        encoded = candidate.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(encoded) > MAX_TAG_QUERY_BYTES:
        return None
    return candidate


def tag_search_url(value: object, locale: str = "cn") -> str | None:
    """Build an official Channel search URL from a tag expression."""
    tags = normalize_tag_query(value)
    if tags is None:
        return None
    safe_locale = locale if locale in {"cn", "en", "ja"} else "cn"
    return f"https://chan.sankakucomplex.com/{safe_locale}/?tags={quote_plus(tags)}"


__all__ = [
    "MAX_POST_ID_CHARS",
    "MAX_TAG_QUERY_BYTES",
    "MAX_TAG_QUERY_CHARS",
    "MAX_URL_CHARS",
    "canonical_post_url",
    "is_allowed_browser_resource_url",
    "is_allowed_media_host",
    "is_allowed_page_host",
    "normalize_media_url",
    "normalize_page_url",
    "normalize_post_id",
    "normalize_tag_query",
    "post_id_from_url",
    "tag_search_url",
]
