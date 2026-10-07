"""Unit tests for configure_rsu."""

import pytest
from PyQt6.QtCore import QEvent, Qt
from PyQt6.QtGui import QKeyEvent, QPalette
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QHeaderView, QStyledItemDelegate,
    QStyleOptionViewItem, QTableWidget, QTableWidgetItem,
)

from configure_rsu import (
    PAYLOAD_CELL_LINES, RSUConfigurationApp, _PayloadCell, _WrapAnywhereDelegate,
    _make_results_table, _set_payload_cell,
)

ZWSP = "\u200b"  # zero-width space
LONG_HEX = "0011223344556677889900AABBCCDDEEFF" * 6
PAYLOAD = "DEADBEEF" * 250
TABLE_WIDTH = 500


def _make_table(qapp, values, delegate_cls=None, payload_cells=False, width=TABLE_WIDTH) -> QTableWidget:
    """Results table with one ["#", value, "OK"] row per value."""
    table = _make_results_table(["#", "Value", "Status"])
    if delegate_cls is not None:
        table.setItemDelegate(delegate_cls(table))
    table.resize(width, 600)
    table.setRowCount(len(values))
    for row, value in enumerate(values):
        table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        if payload_cells:
            _set_payload_cell(table, row, 1, value)
        else:
            table.setItem(row, 1, QTableWidgetItem(value))
        table.setItem(row, 2, QTableWidgetItem("OK"))
    table.show()
    table.activateWindow()
    qapp.processEvents()
    return table


def _line_spacing(table: QTableWidget) -> int:
    return table.fontMetrics().lineSpacing()


def _click_cell(table: QTableWidget, row: int, col: int, modifier=Qt.KeyboardModifier.NoModifier):
    pos = table.visualRect(table.model().index(row, col)).center()
    QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, modifier, pos)


def _cell_center(table: QTableWidget, row: int, col: int):
    return table.visualRect(table.model().index(row, col)).center()


def _press_paste(widget, key, modifier) -> None:
    QApplication.clipboard().setText("PASTED")
    QTest.keyClick(widget, key, modifier)


# Every key sequence Qt treats as paste on Linux
_PASTE_KEYS = pytest.mark.parametrize("key,modifier", [
    (Qt.Key.Key_V, Qt.KeyboardModifier.ControlModifier),
    (Qt.Key.Key_Insert, Qt.KeyboardModifier.ShiftModifier),
], ids=["ctrl-v", "shift-insert"])


def _press_copy(widget) -> str:
    QApplication.clipboard().clear()
    QTest.keyClick(widget, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    return QApplication.clipboard().text()


def _current_cell(table: QTableWidget) -> tuple:
    return table.currentRow(), table.currentColumn()


def _colors_close(a, b, tolerance: int = 8) -> bool:
    return all(abs(x - y) <= tolerance for x, y in
               zip((a.red(), a.green(), a.blue()), (b.red(), b.green(), b.blue())))


def _layout_lines(cell: _PayloadCell) -> int:
    """Lines the payload wraps onto at the cell's current width."""
    return int(cell.document().documentLayout().documentSize().height())


def _shown_lines(cell: _PayloadCell) -> int:
    """Whole lines that fit in the cell's current height."""
    margin = int(cell.document().documentMargin())
    return (cell.height() - 2 * margin - 1) // cell.fontMetrics().lineSpacing()


class TestWrapAnywhereDelegateStyleOption:
    """_WrapAnywhereDelegate: a zero-width space goes between every displayed character."""

    @pytest.mark.parametrize("text,expected", [
        ("", ""),
        ("A", "A"),
        ("AB", f"A{ZWSP}B"),
        ("0011", f"0{ZWSP}0{ZWSP}1{ZWSP}1"),
        ("a b", f"a{ZWSP} {ZWSP}b"),
    ], ids=["empty", "single", "pair", "hex", "spaced"])
    def test_inserts_zero_width_spaces(self, qapp, text, expected):
        table = _make_table(qapp, [text])
        index = table.model().index(0, 1)
        option = QStyleOptionViewItem()
        table.itemDelegate().initStyleOption(option, index)
        assert option.text == expected

    @pytest.mark.parametrize("text", ["", "A", LONG_HEX, "a b"],
                             ids=["empty", "single", "long-hex", "spaced"])
    def test_model_data_is_unchanged(self, qapp, text):
        table = _make_table(qapp, [text])
        index = table.model().index(0, 1)
        table.itemDelegate().initStyleOption(QStyleOptionViewItem(), index)
        assert index.data() == text

    @pytest.mark.parametrize("payload_cells,expected", [
        (True, ""),
        (False, f"A{ZWSP}B"),
    ], ids=["under-widget", "plain-item"])
    def test_cell_under_a_widget_draws_no_text(self, qapp, payload_cells, expected):
        table = _make_table(qapp, ["AB"], payload_cells=payload_cells)
        index = table.model().index(0, 1)
        option = QStyleOptionViewItem()
        option.widget = table
        table.itemDelegate().initStyleOption(option, index)
        assert option.text == expected


class TestWrapAnywhereDelegateWrapping:
    """_WrapAnywhereDelegate: row heights in a results table."""

    @pytest.mark.parametrize("text", [
        "",
        "short",
        "0011AABB",
        "two words",
    ], ids=["empty", "word", "hex", "spaced"])
    def test_short_text_stays_on_one_line(self, qapp, text):
        table = _make_table(qapp, [text])
        assert table.rowHeight(0) < 2 * _line_spacing(table)

    @pytest.mark.parametrize("text,min_lines", [
        (LONG_HEX, 3),                      # no spaces at all
        ("A" * 150, 2),
        ("word " * 40, 2),                  # ordinary spaced text still wraps
        ("ab " + "F" * 150, 2),             # long token after a space
    ], ids=["long-hex", "repeated-char", "spaced-words", "long-token-after-space"])
    def test_long_text_wraps(self, qapp, text, min_lines):
        table = _make_table(qapp, [text])
        assert table.rowHeight(0) >= min_lines * _line_spacing(table)

    def test_stock_delegate_does_not_wrap_unbroken_text(self, qapp):
        # Guards the reason the custom delegate exists: if Qt ever wraps
        # unbroken text itself, the delegate may no longer be needed.
        table = _make_table(qapp, [LONG_HEX], delegate_cls=QStyledItemDelegate)
        assert table.rowHeight(0) < 2 * _line_spacing(table)

    def test_rows_rewrap_when_table_narrows(self, qapp):
        table = _make_table(qapp, [LONG_HEX])
        wide_height = table.rowHeight(0)
        table.resize(TABLE_WIDTH // 2, 400)
        qapp.processEvents()
        assert table.rowHeight(0) > wide_height


class TestResultsTableSetup:
    """_make_results_table: table configuration."""

    def test_installs_wrap_anywhere_delegate(self, qapp):
        table = _make_results_table(["Index", "PSID", ""])
        assert isinstance(table.itemDelegate(), _WrapAnywhereDelegate)

    @pytest.mark.parametrize("headers,stretched", [
        (["Index", "PSID", ""], [1]),
        (["Index", "PSID", "Dest IP", "Dest Port", ""], [1, 2, 3]),
        (["Index", "PSID", "Payload", ""], [1, 2]),
    ], ids=["immediate-forward", "forward", "store-and-repeat"])
    def test_first_and_last_columns_fit_contents_and_the_rest_stretch(self, qapp, headers, stretched):
        table = _make_results_table(headers)
        header = table.horizontalHeader()
        for col in range(len(headers)):
            expected = (QHeaderView.ResizeMode.Stretch if col in stretched
                        else QHeaderView.ResizeMode.ResizeToContents)
            assert header.sectionResizeMode(col) == expected

    def test_cells_are_read_only(self, qapp):
        table = _make_table(qapp, ["short"])
        assert table.editTriggers() == QAbstractItemView.EditTrigger.NoEditTriggers

    def test_only_one_cell_can_be_selected(self, qapp):
        table = _make_table(qapp, [LONG_HEX, "short"])
        _click_cell(table, 0, 1)
        _click_cell(table, 1, 1, Qt.KeyboardModifier.ControlModifier)
        assert [(ix.row(), ix.column()) for ix in table.selectedIndexes()] == [(1, 1)]


class TestResultsTableCopy:
    """Ctrl+C copies one cell's original text, without the zero-width spaces."""

    @pytest.mark.parametrize("row,col,expected", [
        (0, 0, "1"),
        (0, 1, LONG_HEX),
        (1, 1, "short"),
        (1, 2, "OK"),
    ], ids=["index", "long-hex", "short", "status"])
    def test_ctrl_c_copies_clicked_cell(self, qapp, row, col, expected):
        table = _make_table(qapp, [LONG_HEX, "short"])
        _click_cell(table, row, col)
        assert _press_copy(table) == expected

    def test_ctrl_c_copies_cell_reached_with_arrow_key(self, qapp):
        table = _make_table(qapp, [LONG_HEX, "short"])
        _click_cell(table, 1, 1)
        QTest.keyClick(table, Qt.Key.Key_Up)
        assert _press_copy(table) == LONG_HEX


class TestResultsTableRejectsInput:
    """Results cells are never edited, pasted or dropped into."""

    @_PASTE_KEYS
    @pytest.mark.parametrize("payload_cells", [False, True], ids=["plain-item", "payload-cell"])
    def test_paste_leaves_cell_unchanged(self, qapp, key, modifier, payload_cells):
        table = _make_table(qapp, [LONG_HEX], payload_cells=payload_cells)
        _click_cell(table, 0, 1)
        _press_paste(QApplication.focusWidget() or table, key, modifier)
        assert table.item(0, 1).text() == LONG_HEX
        if payload_cells:
            assert table.cellWidget(0, 1).toPlainText() == LONG_HEX
        assert table.state() != QAbstractItemView.State.EditingState

    def test_paste_is_swallowed_not_passed_on(self, qapp):
        table = _make_table(qapp, ["short"])
        event = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_V, Qt.KeyboardModifier.ControlModifier)
        event.ignore()
        QApplication.sendEvent(table, event)
        assert event.isAccepted()

    @pytest.mark.parametrize("request_edit", [
        lambda t: QTest.mouseDClick(t.viewport(), Qt.MouseButton.LeftButton, pos=_cell_center(t, 0, 1)),
        lambda t: QTest.keyClick(t, Qt.Key.Key_F2),
        lambda t: QTest.keyClicks(t, "typed"),
        lambda t: t.editItem(t.item(0, 1)),
    ], ids=["double-click", "f2", "typing", "edit-item"])
    def test_no_editor_ever_opens(self, qapp, request_edit):
        table = _make_table(qapp, ["short"])
        _click_cell(table, 0, 1)
        request_edit(table)
        assert table.state() != QAbstractItemView.State.EditingState
        assert table.item(0, 1).text() == "short"

    @pytest.mark.parametrize("payload_cells", [False, True], ids=["plain-item", "payload-cell"])
    def test_drops_are_refused(self, qapp, payload_cells):
        table = _make_table(qapp, ["DEADBEEF"], payload_cells=payload_cells)
        widgets = [table, table.viewport()]
        if payload_cells:
            cell = table.cellWidget(0, 1)
            widgets += [cell, cell.viewport()]
        assert not any(w.acceptDrops() for w in widgets)


@pytest.fixture
def results_log(qapp):
    """The main window's Results log, holding one logged line."""
    window = RSUConfigurationApp()
    window._on_result_logged("Connection OK")
    window.show()
    window.activateWindow()
    window.results_text.setFocus()
    qapp.processEvents()
    yield window.results_text
    window.close()


class TestResultsLog:
    """The Results log can be copied from but never typed, pasted or dropped into."""

    @_PASTE_KEYS
    def test_paste_leaves_log_unchanged(self, results_log, key, modifier):
        before = results_log.toPlainText()
        _press_paste(results_log, key, modifier)
        assert results_log.toPlainText() == before

    def test_typing_leaves_log_unchanged(self, results_log):
        before = results_log.toPlainText()
        QTest.keyClicks(results_log, "typed")
        assert results_log.toPlainText() == before

    def test_drops_are_refused(self, results_log):
        assert not results_log.acceptDrops()
        assert not results_log.viewport().acceptDrops()

    def test_ctrl_c_copies_selected_text(self, results_log):
        results_log.selectAll()
        assert _press_copy(results_log).strip() == "Connection OK"


class TestPayloadCellHeight:
    """_PayloadCell: grows with its payload up to PAYLOAD_CELL_LINES lines, then scrolls."""

    @pytest.mark.parametrize("width", [400, 1000], ids=["narrow", "wide"])
    @pytest.mark.parametrize("length", [0, 8, 60, 120, 240, 2000],
                             ids=["empty", "8", "60", "120", "240", "2000"])
    def test_shows_whole_payload_up_to_the_line_limit(self, qapp, length, width):
        table = _make_table(qapp, [PAYLOAD[:length]], payload_cells=True, width=width)
        cell = table.cellWidget(0, 1)
        lines = _layout_lines(cell)
        assert _shown_lines(cell) == min(lines, PAYLOAD_CELL_LINES)
        assert (cell.verticalScrollBar().maximum() > 0) == (lines > PAYLOAD_CELL_LINES)

    def test_cell_gets_the_height_it_asks_for(self, qapp):
        table = _make_table(qapp, ["short", PAYLOAD[:120], PAYLOAD], payload_cells=True)
        for row in range(3):
            cell = table.cellWidget(row, 1)
            assert cell.height() == cell.sizeHint().height()

    def test_short_payload_row_is_shorter_than_the_limit(self, qapp):
        table = _make_table(qapp, ["DEADBEEF", PAYLOAD], payload_cells=True)
        assert table.rowHeight(0) < table.rowHeight(1)

    @pytest.mark.parametrize("width", [300, 1000, 450], ids=["narrow", "wide", "medium"])
    def test_height_follows_table_width(self, qapp, width):
        table = _make_table(qapp, [PAYLOAD[:150]], payload_cells=True, width=650)
        table.resize(width, 600)
        qapp.processEvents()
        cell = table.cellWidget(0, 1)
        assert _shown_lines(cell) == min(_layout_lines(cell), PAYLOAD_CELL_LINES)


class TestPayloadCellInteraction:
    """The table underneath a _PayloadCell handles clicks, arrow keys and Ctrl+C."""

    def test_click_selects_the_payload_cell_and_ctrl_c_copies_it(self, qapp):
        table = _make_table(qapp, [PAYLOAD], payload_cells=True)
        cell = table.cellWidget(0, 1)
        QTest.mouseClick(cell.viewport(), Qt.MouseButton.LeftButton,
                         pos=cell.viewport().rect().center())
        assert _current_cell(table) == (0, 1)
        assert _press_copy(table) == PAYLOAD

    def test_arrow_keys_move_through_the_payload_cell(self, qapp):
        table = _make_table(qapp, [PAYLOAD], payload_cells=True)
        _click_cell(table, 0, 0)
        visited = []
        for key in (Qt.Key.Key_Right, Qt.Key.Key_Right, Qt.Key.Key_Left):
            QTest.keyClick(QApplication.focusWidget() or table, key)
            visited.append(_current_cell(table))
        assert visited == [(0, 1), (0, 2), (0, 1)]
        assert QApplication.focusWidget() is table

    def test_ctrl_c_after_arrowing_onto_payload_copies_it(self, qapp):
        table = _make_table(qapp, [PAYLOAD], payload_cells=True)
        _click_cell(table, 0, 0)
        QTest.keyClick(table, Qt.Key.Key_Right)
        assert _press_copy(QApplication.focusWidget() or table) == PAYLOAD

    def test_selection_highlight_shows_through(self, qapp):
        table = _make_table(qapp, ["DEADBEEF"], payload_cells=True)
        _click_cell(table, 0, 1)
        qapp.processEvents()
        # Sample the empty right-hand end of the cell, away from the text.
        rect = table.visualRect(table.model().index(0, 1))
        pixel = table.viewport().grab().toImage().pixelColor(rect.right() - 3, rect.center().y())
        highlights = [table.palette().color(group, QPalette.ColorRole.Highlight)
                      for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive)]
        # Styles may shade the highlight slightly, so allow a small difference.
        assert any(_colors_close(pixel, color) for color in highlights)
