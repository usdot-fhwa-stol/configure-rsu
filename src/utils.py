from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import QAbstractSpinBox, QLineEdit, QSpinBox

from src.constants import HEX_REGEX


def _hex_validator() -> QRegularExpressionValidator:
    return QRegularExpressionValidator(HEX_REGEX)


def _make_spinbox(value: int, lo: int, hi: int, readonly: bool = False) -> QSpinBox:
    sb = QSpinBox()
    sb.setRange(lo, hi)
    sb.setValue(value)
    if readonly:
        sb.setReadOnly(True)
        sb.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
    return sb


def _make_hex_edit(value: str = "") -> QLineEdit:
    le = QLineEdit(value)
    le.setValidator(_hex_validator())
    return le


def _normalise_hex(value: str) -> str:
    return value.strip().replace(" ", "").upper()
