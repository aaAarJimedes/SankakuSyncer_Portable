# -*- coding: utf-8 -*-
"""Probe the bundled Qt WebEngine codec surface without network access."""

from __future__ import annotations

import argparse
import json
from typing import Iterable


def probe_codecs(timeout_ms: int = 15_000) -> dict[str, str]:
    # This helper is also a production-environment smoke test: inherited
    # Chromium debug/no-sandbox flags are removed before Qt is imported.
    from runtime_environment import sanitize_runtime_environment

    sanitize_runtime_environment()
    from PySide6.QtCore import QCoreApplication, QTimer, Qt

    QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
    from PySide6.QtWidgets import QApplication
    from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile

    app = QApplication.instance() or QApplication([])
    profile = QWebEngineProfile()
    page = QWebEnginePage(profile)
    result: dict[str, str] = {}
    failure: list[str] = []
    script = r"""
        JSON.stringify({
          h264: document.createElement('video').canPlayType(
              'video/mp4; codecs="avc1.42E01E"'),
          hevc: document.createElement('video').canPlayType(
              'video/mp4; codecs="hvc1"'),
          mp4: document.createElement('video').canPlayType('video/mp4'),
          mp3: document.createElement('audio').canPlayType('audio/mpeg'),
          webm: document.createElement('video').canPlayType(
              'video/webm; codecs="vp9,opus"')
        })
    """

    def finish(value=None) -> None:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = None
        if isinstance(value, dict):
            for key in ("h264", "hevc", "mp4", "mp3", "webm"):
                candidate = value.get(key, "")
                result[key] = candidate if isinstance(candidate, str) else ""
        elif value is not None:
            failure.append(f"unexpected JavaScript result: {type(value).__name__}")
        app.quit()

    def loaded(ok: bool) -> None:
        if not ok:
            failure.append("local data document failed to load")
            finish()
            return
        page.runJavaScript(script, finish)

    page.loadFinished.connect(loaded)
    QTimer.singleShot(timeout_ms, finish)
    page.setHtml("<!doctype html><meta charset=utf-8><title>codec probe</title>")
    app.exec()
    page.deleteLater()
    profile.deleteLater()
    app.processEvents()
    if not result:
        detail = "; ".join(failure) or "timed out before JavaScript completed"
        raise RuntimeError(f"Qt WebEngine codec probe failed: {detail}")
    return result


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-no-patented-video",
        action="store_true",
        help="fail if the build advertises H.264 or HEVC decoding",
    )
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    try:
        result = probe_codecs()
    except Exception as exc:
        print(f"[FAIL] Qt WebEngine codec probe ({type(exc).__name__}): {exc}")
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if arguments.require_no_patented_video and (result["h264"] or result["hevc"]):
        print("[FAIL] Qt WebEngine advertises H.264/HEVC decoding")
        return 1
    print("[OK] Qt WebEngine codec surface")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
