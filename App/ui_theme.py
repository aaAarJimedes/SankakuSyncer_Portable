# -*- coding: utf-8 -*-
"""Shared modern light theme for the SankakuSyncer desktop UI."""

from __future__ import annotations

from typing import Any


LIGHT_STYLESHEET = r"""
/* Application surface --------------------------------------------------- */
QWidget {
    background-color: #f6f8fb;
    color: #1f2937;
    font-family: "Segoe UI", "Microsoft YaHei UI", sans-serif;
    font-size: 13px;
    selection-background-color: #cfe0ff;
    selection-color: #102a56;
}

QMainWindow, QDialog {
    background-color: #f6f8fb;
}

QFrame#card, QFrame[card="true"] {
    background-color: #ffffff;
    border: 1px solid #dfe5ee;
    border-radius: 10px;
}

QLabel {
    background: transparent;
}

QLabel[heading="true"] {
    color: #111827;
    font-size: 20px;
    font-weight: 650;
}

QLabel[muted="true"], QLabel#browserStatus {
    color: #667085;
}

QLabel[status="error"] {
    color: #b42318;
}

/* Navigation and buttons ----------------------------------------------- */
QToolBar, QFrame#browserToolbar {
    background-color: #ffffff;
    border: 0;
    border-bottom: 1px solid #dfe5ee;
    spacing: 6px;
}

QPushButton, QToolButton {
    min-height: 22px;
    padding: 6px 12px;
    background-color: #ffffff;
    color: #344054;
    border: 1px solid #cfd7e3;
    border-radius: 7px;
}

QToolButton {
    padding: 5px 9px;
}

QPushButton:hover, QToolButton:hover {
    background-color: #f0f4fa;
    border-color: #aab7c8;
}

QPushButton:pressed, QToolButton:pressed {
    background-color: #e5ebf3;
}

QPushButton:focus, QToolButton:focus {
    border: 1px solid #4f7fcf;
}

QPushButton:disabled, QToolButton:disabled {
    background-color: #f2f4f7;
    color: #98a2b3;
    border-color: #e4e7ec;
}

QPushButton[role="primary"], QToolButton[role="primary"] {
    background-color: #2f6fc6;
    color: #ffffff;
    border-color: #2f6fc6;
    font-weight: 600;
}

QPushButton[role="primary"]:hover, QToolButton[role="primary"]:hover {
    background-color: #245eae;
    border-color: #245eae;
}

QPushButton[role="danger"] {
    color: #b42318;
    border-color: #f2b8b5;
}

QPushButton[role="danger"]:hover {
    background-color: #fff1f0;
    border-color: #e58b86;
}

/* Inputs ---------------------------------------------------------------- */
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox,
QDateEdit, QDateTimeEdit {
    min-height: 22px;
    padding: 6px 8px;
    background-color: #ffffff;
    color: #1f2937;
    border: 1px solid #cfd7e3;
    border-radius: 7px;
}

QPlainTextEdit, QTextEdit {
    padding: 8px;
}

QLineEdit:hover, QPlainTextEdit:hover, QTextEdit:hover, QComboBox:hover,
QSpinBox:hover, QDoubleSpinBox:hover {
    border-color: #aab7c8;
}

QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus,
QSpinBox:focus, QDoubleSpinBox:focus {
    border: 1px solid #4f7fcf;
}

QLineEdit:disabled, QPlainTextEdit:disabled, QTextEdit:disabled,
QComboBox:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled {
    background-color: #f2f4f7;
    color: #98a2b3;
}

QComboBox::drop-down {
    width: 26px;
    border: 0;
}

QComboBox QAbstractItemView {
    background-color: #ffffff;
    border: 1px solid #cfd7e3;
    selection-background-color: #e8f0fc;
    selection-color: #1f2937;
    outline: 0;
}

QCheckBox, QRadioButton {
    spacing: 7px;
    background: transparent;
}

QCheckBox::indicator, QRadioButton::indicator {
    width: 16px;
    height: 16px;
}

/* Collections ----------------------------------------------------------- */
QListView, QListWidget, QTreeView, QTreeWidget, QTableView, QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f8fafc;
    border: 1px solid #dfe5ee;
    border-radius: 8px;
    outline: 0;
    gridline-color: #edf1f6;
}

QListView::item, QListWidget::item, QTreeView::item, QTreeWidget::item {
    padding: 6px;
    border-radius: 5px;
}

QListView::item:hover, QListWidget::item:hover, QTreeView::item:hover,
QTreeWidget::item:hover {
    background-color: #f0f4fa;
}

QAbstractItemView::item:selected {
    background-color: #dce9fb;
    color: #173a69;
}

QHeaderView::section {
    padding: 7px 8px;
    background-color: #f2f5f9;
    color: #475467;
    border: 0;
    border-right: 1px solid #e4e9f0;
    border-bottom: 1px solid #dfe5ee;
    font-weight: 600;
}

/* Tabs, progress, menus ------------------------------------------------- */
QTabWidget::pane {
    background-color: #ffffff;
    border: 1px solid #dfe5ee;
    border-radius: 8px;
}

QTabBar::tab {
    padding: 8px 14px;
    margin-right: 3px;
    background-color: #edf1f6;
    color: #667085;
    border: 1px solid #dfe5ee;
    border-bottom: 0;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    color: #1f2937;
    font-weight: 600;
}

QProgressBar {
    min-height: 12px;
    background-color: #e9eef5;
    border: 0;
    border-radius: 6px;
    text-align: center;
    color: #344054;
}

QProgressBar::chunk {
    background-color: #4f7fcf;
    border-radius: 6px;
}

QMenu {
    padding: 5px;
    background-color: #ffffff;
    border: 1px solid #d7dee8;
    border-radius: 8px;
}

QMenu::item {
    padding: 7px 26px 7px 10px;
    border-radius: 5px;
}

QMenu::item:selected {
    background-color: #e8f0fc;
    color: #173a69;
}

QToolTip {
    padding: 5px 7px;
    background-color: #253347;
    color: #ffffff;
    border: 0;
    border-radius: 4px;
}

/* Scroll bars ----------------------------------------------------------- */
QScrollBar:vertical {
    width: 12px;
    margin: 2px;
    background: transparent;
}

QScrollBar::handle:vertical {
    min-height: 28px;
    background-color: #c3ccd8;
    border: 3px solid #f6f8fb;
    border-radius: 6px;
}

QScrollBar::handle:vertical:hover {
    background-color: #9eabba;
}

QScrollBar:horizontal {
    height: 12px;
    margin: 2px;
    background: transparent;
}

QScrollBar::handle:horizontal {
    min-width: 28px;
    background-color: #c3ccd8;
    border: 3px solid #f6f8fb;
    border-radius: 6px;
}

QScrollBar::add-line, QScrollBar::sub-line,
QScrollBar::add-page, QScrollBar::sub-page {
    width: 0;
    height: 0;
    background: transparent;
}

/* Browser fallback ------------------------------------------------------ */
QFrame#browserPlaceholder {
    background-color: #ffffff;
    border: 1px dashed #b8c3d1;
    border-radius: 12px;
}

QFrame#browserPlaceholder QLabel[placeholderTitle="true"] {
    color: #182230;
    font-size: 18px;
    font-weight: 650;
}
"""

# Friendly aliases for callers that use a project-wide stylesheet name.
APP_STYLESHEET = LIGHT_STYLESHEET
STYLE_SHEET = LIGHT_STYLESHEET


def apply_light_theme(application: Any) -> None:
    """Apply the light stylesheet to a QApplication-compatible object."""
    if application is None or not callable(getattr(application, "setStyleSheet", None)):
        raise TypeError("application must provide setStyleSheet()")
    application.setStyleSheet(LIGHT_STYLESHEET)


__all__ = [
    "APP_STYLESHEET",
    "LIGHT_STYLESHEET",
    "STYLE_SHEET",
    "apply_light_theme",
]
