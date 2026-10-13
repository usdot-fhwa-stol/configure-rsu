"""Shared pytest fixtures."""

import os

# Run Qt without a display (CI, SSH sessions). Set before any test imports PyQt.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def qapp():
    """QApplication that Qt widget tests need."""
    return QApplication.instance() or QApplication([])
