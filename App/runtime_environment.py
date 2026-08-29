# -*- coding: utf-8 -*-
"""Sanitize inherited process state before importing Qt WebEngine."""

from __future__ import annotations

import os


UNSAFE_INHERITED_ENVIRONMENT = (
    "ALL_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "QTWEBENGINE_CHROMIUM_FLAGS",
    "QTWEBENGINE_DISABLE_SANDBOX",
    "QTWEBENGINE_REMOTE_DEBUGGING",
    "QTWEBENGINE_REMOTE_DEBUGGING_PORT",
    "SSLKEYLOGFILE",
)


def sanitize_runtime_environment(environment: dict[str, str] | None = None) -> None:
    """Remove inherited Chromium weakening/proxy knobs and select Schannel.

    Windows environment keys are case-insensitive, while a plain test mapping
    may not be.  Remove every case variant found instead of assuming the
    canonical spelling.
    """

    target = os.environ if environment is None else environment
    forbidden = {name.casefold() for name in UNSAFE_INHERITED_ENVIRONMENT}
    for name in list(target):
        if name.casefold() in forbidden:
            target.pop(name, None)
    target["QT_SSL_BACKEND"] = "schannel"


__all__ = ["UNSAFE_INHERITED_ENVIRONMENT", "sanitize_runtime_environment"]
