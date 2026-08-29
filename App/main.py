# -*- coding: utf-8 -*-
"""SankakuSyncer portable application entry point."""

from __future__ import annotations

import os
import sys

from runtime_environment import sanitize_runtime_environment


# This must run before *any* PySide6/QtWebEngine import.  The launchers perform
# the same cleanup, but direct ``python App/main.py`` execution is also safe.
sanitize_runtime_environment()

from PySide6.QtCore import QCoreApplication, QLockFile, Qt
from PySide6.QtNetwork import QSslSocket


QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)

from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from ui_main_window import MainWindow  # noqa: E402
from ui_theme import APP_STYLESHEET  # noqa: E402
from version import APP_DISPLAY_NAME, APP_NAME, APP_VERSION  # noqa: E402


def enforce_qt_schannel() -> None:
    """Fail startup unless Qt's active TLS plugin is exactly Schannel."""

    available = {str(name).casefold() for name in QSslSocket.availableBackends()}
    if "schannel" not in available:
        raise RuntimeError("Qt Schannel TLS backend is unavailable")
    QSslSocket.setActiveBackend("schannel")
    if str(QSslSocket.activeBackend()).casefold() != "schannel":
        raise RuntimeError("Qt refused the Schannel TLS backend")


def portable_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


def main() -> int:
    enforce_qt_schannel()
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_DISPLAY_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("SankakuSyncer")
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLESHEET)
    data_dir = os.path.join(portable_root(), "Data")
    os.makedirs(data_dir, exist_ok=True)
    instance_lock = QLockFile(os.path.join(data_dir, ".app.lock"))
    instance_lock.setStaleLockTime(0)
    if not instance_lock.tryLock(250):
        QMessageBox.information(
            None,
            "SankakuSyncer 已在运行",
            "为保护任务篮和下载终态，本便携目录一次只允许运行一个实例。",
        )
        return 2
    try:
        window = MainWindow(portable_root())
    except Exception as exc:
        QMessageBox.critical(
            None,
            "启动失败",
            f"程序未能安全启动（{type(exc).__name__}）。请运行便携自检或调试启动器查看原因。",
        )
        instance_lock.unlock()
        return 1
    window.show()
    exit_code = app.exec()
    instance_lock.unlock()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
