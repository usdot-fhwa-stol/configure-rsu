#!/usr/bin/env python3
import os
import socket
import sys
from binascii import unhexlify
from typing import Any, Callable, Dict, List, Optional

from PyQt6.QtCore import (
    QObject, QRegularExpression, QRunnable, Qt, QThreadPool, pyqtSignal, pyqtSlot,
)
from PyQt6.QtGui import QBrush, QColor, QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QAbstractItemView, QAbstractSpinBox, QApplication, QButtonGroup, QComboBox,
    QDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QScrollArea,
    QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget,
)

from dotenv import load_dotenv
from snmp import Engine, Timeout, ErrorResponse
from snmp.security.usm.auth import HmacMd5, HmacSha, HmacSha256, HmacSha512
from snmp.security.usm.priv import DesCbc, AesCfb128
from snmp.smi import OctetString, Integer32

import cr_helper

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# Initialize SNMP Engine
snmp_engine = Engine()

# Load SNMP credentials from environment variables
IP_ADDRESS = os.getenv('IP_ADDRESS')
SNMP_PORT = int(os.getenv('SNMP_PORT', 161))
SNMP_USER = os.getenv('SNMP_USER')
AUTH_PASSWORD = os.getenv('AUTH_PASSWORD')
PRIV_PASSWORD = os.getenv('PRIV_PASSWORD')

ALIGN_RIGHT = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
HEX_REGEX = QRegularExpression(r'^[0-9A-Fa-f]*$')


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


# ---------- Async worker plumbing ----------

class _TaskSignals(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(object)


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], Any]):
        super().__init__()
        self._fn = fn
        self.signals = _TaskSignals()

    @pyqtSlot()
    def run(self) -> None:
        try:
            result = self._fn()
        except BaseException as e:
            self.signals.error.emit(e)
            return
        self.signals.finished.emit(result)


class RSUConfigurationApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RSU Configuration")
        self.resize(900, 700)

        # RSU Mode MIB selection ("ntcip1218" or "rsu41")
        self.mode_mib = "ntcip1218"
        self._mode_mib_callbacks: List[Callable[[], None]] = []

        # Serialize SNMP ops on a single background worker thread so the
        # UI stays responsive and SNMP state transitions don't interleave.
        self._snmp_pool = QThreadPool()
        self._snmp_pool.setMaxThreadCount(1)

        # Tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._create_credentials_tab()
        self._create_immediate_forward_tab()
        self._create_received_message_forward_tab()
        self._create_store_and_repeat_tab()
        self._create_active_message_tab()

    # ---------- Mode MIB helpers ----------
    def _set_mode_mib(self, value: str) -> None:
        self.mode_mib = value
        self.btn_mode_ntcip.setChecked(value == "ntcip1218")
        self.btn_mode_rsu41.setChecked(value == "rsu41")
        for cb in self._mode_mib_callbacks:
            try:
                cb()
            except Exception:
                pass

    def _register_mode_mib_callback(self, cb: Callable[[], None]) -> None:
        self._mode_mib_callbacks.append(cb)

    # ---------- Async helper ----------
    def _run_async(
        self,
        fn: Callable[[], Any],
        on_success: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[BaseException], None]] = None,
    ) -> None:
        task = _Task(fn)
        if on_success is not None:
            task.signals.finished.connect(on_success)
        if on_error is not None:
            task.signals.error.connect(on_error)
        self._snmp_pool.start(task)

    # ---------- Credentials tab ----------
    def _create_credentials_tab(self) -> None:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(12, 12, 12, 12)

        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        outer.addLayout(form)

        self.hostname_edit = QLineEdit(IP_ADDRESS if IP_ADDRESS else "192.168.55.20")
        form.addRow("RSU IP Address:", self.hostname_edit)

        self.port_spin = _make_spinbox(SNMP_PORT if SNMP_PORT else 161, 1, 65535)
        form.addRow("RSU SNMP Port:", self.port_spin)

        self.snmpv3_user_edit = QLineEdit(SNMP_USER if SNMP_USER else "snmpuser")
        form.addRow("SNMPv3 Username:", self.snmpv3_user_edit)

        self.security_level_combo = QComboBox()
        self.security_level_combo.setEditable(True)
        self.security_level_combo.addItems(["noAuthNoPriv", "authNoPriv", "authPriv"])
        self.security_level_combo.setCurrentText("authPriv")
        form.addRow("Security Level:", self.security_level_combo)

        self.auth_protocol_combo = QComboBox()
        self.auth_protocol_combo.setEditable(True)
        self.auth_protocol_combo.addItems(["MD5", "SHA", "SHA256", "SHA512"])
        self.auth_protocol_combo.setCurrentText("SHA")
        form.addRow("Auth Protocol:", self.auth_protocol_combo)

        self.auth_password_edit = QLineEdit(AUTH_PASSWORD if AUTH_PASSWORD else "authpass")
        self.auth_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Auth Password:", self.auth_password_edit)

        self.privacy_protocol_combo = QComboBox()
        self.privacy_protocol_combo.setEditable(True)
        self.privacy_protocol_combo.addItems(["DES", "AES"])
        self.privacy_protocol_combo.setCurrentText("AES")
        form.addRow("Privacy Protocol:", self.privacy_protocol_combo)

        self.privacy_password_edit = QLineEdit(PRIV_PASSWORD if PRIV_PASSWORD else "privpass")
        self.privacy_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Privacy Password:", self.privacy_password_edit)

        # MIB version toggle for RSU mode OIDs
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("RSU Mode MIB:"))
        self.btn_mode_ntcip = QPushButton("NTCIP 1218")
        self.btn_mode_ntcip.setCheckable(True)
        self.btn_mode_ntcip.setChecked(True)
        self.btn_mode_rsu41 = QPushButton("RSU 4.1")
        self.btn_mode_rsu41.setCheckable(True)
        mode_row.addWidget(self.btn_mode_ntcip)
        mode_row.addWidget(self.btn_mode_rsu41)
        mode_row.addStretch(1)
        mode_group = QButtonGroup(self)
        mode_group.setExclusive(True)
        mode_group.addButton(self.btn_mode_ntcip)
        mode_group.addButton(self.btn_mode_rsu41)
        self.btn_mode_ntcip.clicked.connect(lambda: self._set_mode_mib("ntcip1218"))
        self.btn_mode_rsu41.clicked.connect(lambda: self._set_mode_mib("rsu41"))
        outer.addLayout(mode_row)

        # Buttons
        button_row = QHBoxLayout()
        test_btn = QPushButton("Test Connection")
        test_btn.clicked.connect(self._test_connection)
        button_row.addWidget(test_btn)
        mode_status_btn = QPushButton("Get RSU Mode Status")
        mode_status_btn.clicked.connect(self._get_rsu_mode_status)
        button_row.addWidget(mode_status_btn)
        button_row.addStretch(1)
        help_btn = QPushButton("Help")
        help_btn.clicked.connect(lambda: self._show_help("SNMP Credentials", ""))
        button_row.addWidget(help_btn)
        quit_btn = QPushButton("Quit")
        quit_btn.clicked.connect(QApplication.instance().quit)
        button_row.addWidget(quit_btn)
        outer.addLayout(button_row)

        # Results section
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        results_layout.addWidget(self.results_text)
        outer.addWidget(results_group, 1)

        self.tabs.addTab(tab, "SNMP Credentials")

    # ---------- Results table helper ----------
    @staticmethod
    def _make_results_table(headers: List[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        header = table.horizontalHeader()
        for i in range(len(headers)):
            if i == 0 or i == len(headers) - 1:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
            else:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        return table

    @staticmethod
    def _fill_error_row(table: QTableWidget, row: int, err: str, data_cols: int) -> None:
        item = QTableWidgetItem(f"error retrieving info: {err}")
        item.setForeground(QBrush(QColor("#b00020")))
        table.setItem(row, 1, item)
        if data_cols > 1:
            table.setSpan(row, 1, 1, data_cols)

    # ---------- Immediate Forward tab ----------
    def _create_immediate_forward_tab(self) -> None:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(12, 12, 12, 12)

        controls = QHBoxLayout()
        outer.addLayout(controls)

        # Configuration section (scrollable container for entries)
        config_group = QGroupBox("Configure IFM Entries")
        config_vbox = QVBoxLayout(config_group)
        config_scroll = QScrollArea()
        config_scroll.setWidgetResizable(True)
        config_inner = QWidget()
        config_inner_layout = QVBoxLayout(config_inner)
        config_inner_layout.addStretch(1)
        config_scroll.setWidget(config_inner)
        config_vbox.addWidget(config_scroll)
        outer.addWidget(config_group)

        # Results table
        results_group = QGroupBox("IFM Results")
        results_layout = QVBoxLayout(results_group)
        ifm_table = self._make_results_table(["Index", "PSID", ""])
        results_layout.addWidget(ifm_table)
        outer.addWidget(results_group, 1)

        ifm_entries: List[dict] = []

        def update_field_states() -> None:
            is_ntcip = self.mode_mib == "ntcip1218"
            for entry in ifm_entries:
                for w in entry.get('ntcip_widgets', []):
                    w.setEnabled(is_ntcip)
                for w in entry.get('rsu41_widgets', []):
                    w.setEnabled(not is_ntcip)

        def set_single_ifm_entry(entry_vars: dict) -> None:
            ifm_index = entry_vars['index_spin'].value()
            psid = entry_vars['psid_edit'].text().strip()
            channel = entry_vars['channel_spin'].value()
            enable = entry_vars['enable_spin'].value()
            if not psid:
                QMessageBox.critical(self, "Validation Error", f"Entry {ifm_index}: PSID cannot be empty")
                return

            if self.mode_mib == "ntcip1218":
                priority = entry_vars['priority_spin'].value()
                options = entry_vars['options_edit'].text().strip()
                payload = entry_vars['payload_edit'].text().strip()
                mode_mib = "ntcip1218"
            else:
                dsrc_msg_id = entry_vars['dsrc_msg_id_spin'].value()
                tx_mode = entry_vars['tx_mode_spin'].value()
                mode_mib = "rsu41"

            def work():
                self._set_standby()
                session = self._get_session()
                if mode_mib == "ntcip1218":
                    base_oid = "1.3.6.1.4.1.1206.4.2.18.4.2.1"
                    session.set(
                        (f"{base_oid}.2.{ifm_index}", OctetString(unhexlify(psid))),
                        (f"{base_oid}.3.{ifm_index}", Integer32(channel)),
                        (f"{base_oid}.4.{ifm_index}", Integer32(enable)),
                        (f"{base_oid}.5.{ifm_index}", Integer32(4)),
                        (f"{base_oid}.6.{ifm_index}", Integer32(priority)),
                        (f"{base_oid}.7.{ifm_index}", OctetString(unhexlify(options))),
                        (f"{base_oid}.8.{ifm_index}", OctetString(unhexlify(payload))),
                    )
                else:
                    base_oid = "1.0.15628.4.1.5.1"
                    session.set(
                        (f"{base_oid}.2.{ifm_index}", OctetString(unhexlify(psid))),
                        (f"{base_oid}.3.{ifm_index}", Integer32(dsrc_msg_id)),
                        (f"{base_oid}.4.{ifm_index}", Integer32(tx_mode)),
                        (f"{base_oid}.5.{ifm_index}", Integer32(channel)),
                        (f"{base_oid}.6.{ifm_index}", Integer32(enable)),
                        (f"{base_oid}.7.{ifm_index}", Integer32(4)),
                    )
                self._set_operate()

            def on_ok(_):
                QMessageBox.information(self, "Success", f"Successfully configured IFM entry {ifm_index} with PSID {psid}")
                get_ifm_info()

            def on_err(e):
                QMessageBox.critical(self, "SNMP Error", f"Failed to set IFM entry {ifm_index}: {e}")

            self._run_async(work, on_ok, on_err)

        def remove_ifm_entry(entry_vars: dict) -> None:
            frame = entry_vars['frame']
            config_inner_layout.removeWidget(frame)
            frame.setParent(None)
            frame.deleteLater()
            ifm_entries.remove(entry_vars)
            for entry in ifm_entries:
                entry['frame'].setTitle(f"IFM Entry {entry['index_spin'].value()}")

        def add_ifm_entry() -> None:
            default_index = (ifm_entries[-1]['index_spin'].value() + 1) if ifm_entries else 1
            default_psid = (
                '8002' if default_index == 1 else
                '8003' if default_index == 2 else
                '8010' if default_index == 3 else
                '0027' if default_index == 4 else 'E0000017'
            )
            default_channel = 180 if self.mode_mib == "rsu41" else 183

            frame = QGroupBox(f"IFM Entry {default_index}")
            grid = QGridLayout(frame)
            grid.setHorizontalSpacing(6)
            grid.setVerticalSpacing(4)

            # Row 0: Index and PSID
            grid.addWidget(QLabel("IFM Index:"), 0, 0, ALIGN_RIGHT)
            index_spin = _make_spinbox(default_index, 1, 32)
            grid.addWidget(index_spin, 0, 1)
            grid.addWidget(QLabel("PSID (hex):"), 0, 2, ALIGN_RIGHT)
            psid_edit = _make_hex_edit(default_psid)
            grid.addWidget(psid_edit, 0, 3)

            # Row 1: Channel and Enable (readonly)
            grid.addWidget(QLabel("Channel:"), 1, 0, ALIGN_RIGHT)
            channel_spin = _make_spinbox(default_channel, 1, 255, readonly=True)
            grid.addWidget(channel_spin, 1, 1)
            grid.addWidget(QLabel("Enable:"), 1, 2, ALIGN_RIGHT)
            enable_spin = _make_spinbox(1, 0, 1, readonly=True)
            grid.addWidget(enable_spin, 1, 3)

            # Row 2: DSRC Msg ID and TX Mode (RSU 4.1 only)
            grid.addWidget(QLabel("DSRC Msg ID:"), 2, 0, ALIGN_RIGHT)
            dsrc_spin = _make_spinbox(31, 0, 255)
            grid.addWidget(dsrc_spin, 2, 1)
            grid.addWidget(QLabel("TX Mode:"), 2, 2, ALIGN_RIGHT)
            txmode_spin = _make_spinbox(0, 0, 1)
            grid.addWidget(txmode_spin, 2, 3)

            # Row 3: Priority and Options (NTCIP 1218 only)
            grid.addWidget(QLabel("Priority:"), 3, 0, ALIGN_RIGHT)
            priority_spin = _make_spinbox(5, 0, 63)
            grid.addWidget(priority_spin, 3, 1)
            grid.addWidget(QLabel("Options (hex):"), 3, 2, ALIGN_RIGHT)
            options_edit = _make_hex_edit("00")
            grid.addWidget(options_edit, 3, 3)

            # Row 4: Payload (NTCIP 1218 only)
            grid.addWidget(QLabel("Payload (hex):"), 4, 0, ALIGN_RIGHT)
            payload_edit = _make_hex_edit("")
            grid.addWidget(payload_edit, 4, 1, 1, 3)

            # Row 5: Set/Remove buttons
            btn_row = QHBoxLayout()
            btn_row.addStretch(1)
            set_btn = QPushButton("Set Entry")
            remove_btn = QPushButton("Remove Entry")
            btn_row.addWidget(set_btn)
            btn_row.addWidget(remove_btn)
            btn_row.addStretch(1)
            grid.addLayout(btn_row, 5, 0, 1, 4)

            grid.setColumnStretch(1, 1)
            grid.setColumnStretch(3, 1)

            entry_vars = {
                'frame': frame,
                'index_spin': index_spin,
                'psid_edit': psid_edit,
                'channel_spin': channel_spin,
                'enable_spin': enable_spin,
                'dsrc_msg_id_spin': dsrc_spin,
                'tx_mode_spin': txmode_spin,
                'priority_spin': priority_spin,
                'options_edit': options_edit,
                'payload_edit': payload_edit,
                'ntcip_widgets': [priority_spin, options_edit, payload_edit],
                'rsu41_widgets': [dsrc_spin, txmode_spin],
            }

            index_spin.valueChanged.connect(
                lambda v: frame.setTitle(f"IFM Entry {v}")
            )
            set_btn.clicked.connect(lambda: set_single_ifm_entry(entry_vars))
            remove_btn.clicked.connect(lambda: remove_ifm_entry(entry_vars))

            config_inner_layout.insertWidget(config_inner_layout.count() - 1, frame)
            ifm_entries.append(entry_vars)
            update_field_states()

        def destroy_ifm_entry(idx: int) -> None:
            if self.mode_mib == "ntcip1218":
                delete_oid = f"1.3.6.1.4.1.1206.4.2.18.4.2.1.5.{idx}"
            else:
                delete_oid = f"1.0.15628.4.1.5.1.7.{idx}"
            self._destroy_entry(delete_oid, on_done=get_ifm_info)

        def get_ifm_info() -> None:
            add_ifm_btn.setEnabled(True)
            base_oid = (
                "1.3.6.1.4.1.1206.4.2.18.4.2.1"
                if self.mode_mib == "ntcip1218" else "1.0.15628.4.1.5.1"
            )

            def work():
                session = self._get_session()
                results = []
                for i in range(1, 7):
                    try:
                        handle = session.get(f"{base_oid}.2.{i}")
                        varbind_list = handle.wait() if hasattr(handle, 'wait') else handle
                        value = cr_helper.format_snmp_value(varbind_list[0])
                        results.append((i, value, None))
                    except (Timeout, ErrorResponse) as e:
                        results.append((i, None, str(e)))
                return results

            def on_ok(results):
                ifm_table.setRowCount(0)
                for i, value, err in results:
                    row = ifm_table.rowCount()
                    ifm_table.insertRow(row)
                    ifm_table.setItem(row, 0, QTableWidgetItem(str(i)))
                    if err is None:
                        ifm_table.setItem(row, 1, QTableWidgetItem(value))
                        btn = QPushButton("Destroy")
                        btn.clicked.connect(lambda _c=False, ii=i: destroy_ifm_entry(ii))
                        ifm_table.setCellWidget(row, 2, btn)
                    else:
                        self._fill_error_row(ifm_table, row, err, data_cols=1)

            def on_err(e):
                QMessageBox.critical(self, "SNMP Error", str(e))

            self._run_async(work, on_ok, on_err)

        self._register_mode_mib_callback(update_field_states)

        add_ifm_btn = QPushButton("Add IFM Entry")
        add_ifm_btn.setEnabled(False)
        add_ifm_btn.clicked.connect(add_ifm_entry)
        controls.addWidget(add_ifm_btn)
        get_btn = QPushButton("Get IFM Info")
        get_btn.clicked.connect(get_ifm_info)
        controls.addWidget(get_btn)
        help_btn = QPushButton("Help")
        help_btn.clicked.connect(lambda: self._show_help("Immediate Forward", cr_helper.get_ifm_help_content()))
        controls.addWidget(help_btn)
        controls.addStretch(1)

        self.tabs.addTab(tab, "Immediate Forward")

    # ---------- Received Message Forward tab ----------
    def _create_received_message_forward_tab(self) -> None:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(12, 12, 12, 12)

        controls = QHBoxLayout()
        outer.addLayout(controls)

        config_group = QGroupBox("Configure RFM Entries")
        config_vbox = QVBoxLayout(config_group)
        config_scroll = QScrollArea()
        config_scroll.setWidgetResizable(True)
        config_inner = QWidget()
        config_inner_layout = QVBoxLayout(config_inner)
        config_inner_layout.addStretch(1)
        config_scroll.setWidget(config_inner)
        config_vbox.addWidget(config_scroll)
        outer.addWidget(config_group)

        results_group = QGroupBox("RFM Results")
        results_layout = QVBoxLayout(results_group)
        rfm_table = self._make_results_table(["Index", "PSID", "Dest IP", "Dest Port", ""])
        results_layout.addWidget(rfm_table)
        outer.addWidget(results_group, 1)

        rfm_entries: List[dict] = []

        def set_single_rfm_entry(entry_vars: dict) -> None:
            rfm_index = entry_vars['index_spin'].value()
            psid = entry_vars['psid_edit'].text().strip()
            dest_ip = entry_vars['dest_ip_edit'].text().strip()
            dest_port = entry_vars['dest_port_spin'].value()
            protocol = int(entry_vars['protocol_combo'].currentText())
            rssi = entry_vars['rssi_spin'].value()
            interval = entry_vars['interval_spin'].value()
            start_date = entry_vars['start_date_edit'].text().strip()
            stop_date = entry_vars['stop_date_edit'].text().strip()
            secure = entry_vars['secure_spin'].value()
            auth_interval = entry_vars['auth_interval_spin'].value()

            if not psid:
                QMessageBox.critical(self, "Validation Error", f"Entry {rfm_index}: PSID cannot be empty")
                return
            if not dest_ip:
                QMessageBox.critical(self, "Validation Error", f"Entry {rfm_index}: Destination IP cannot be empty")
                return

            try:
                start_date_bytes = cr_helper.convert_datetime_to_snmp(start_date)
                stop_date_bytes = cr_helper.convert_datetime_to_snmp(stop_date)
            except ValueError as e:
                QMessageBox.critical(self, "Validation Error", f"Entry {rfm_index}: {e}")
                return

            def work():
                self._set_standby()
                session = self._get_session()
                base_oid = "1.3.6.1.4.1.1206.4.2.18.5.2.1"
                session.set(
                    (f"{base_oid}.2.{rfm_index}", OctetString(unhexlify(psid))),
                    (f"{base_oid}.3.{rfm_index}", OctetString(dest_ip.encode())),
                    (f"{base_oid}.4.{rfm_index}", Integer32(dest_port)),
                    (f"{base_oid}.5.{rfm_index}", Integer32(protocol)),
                    (f"{base_oid}.6.{rfm_index}", Integer32(rssi)),
                    (f"{base_oid}.7.{rfm_index}", Integer32(interval)),
                    (f"{base_oid}.8.{rfm_index}", OctetString(start_date_bytes)),
                    (f"{base_oid}.9.{rfm_index}", OctetString(stop_date_bytes)),
                    (f"{base_oid}.10.{rfm_index}", Integer32(4)),
                    (f"{base_oid}.11.{rfm_index}", Integer32(secure)),
                    (f"{base_oid}.12.{rfm_index}", Integer32(auth_interval)),
                )
                self._set_operate()

            def on_ok(_):
                QMessageBox.information(self, "Success", f"Successfully configured RFM entry {rfm_index} with PSID {psid}")
                get_rfm_info()

            def on_err(e):
                QMessageBox.critical(self, "SNMP Error", f"Failed to set RFM entry {rfm_index}: {e}")

            self._run_async(work, on_ok, on_err)

        def remove_rfm_entry(entry_vars: dict) -> None:
            frame = entry_vars['frame']
            config_inner_layout.removeWidget(frame)
            frame.setParent(None)
            frame.deleteLater()
            rfm_entries.remove(entry_vars)
            for entry in rfm_entries:
                entry['frame'].setTitle(f"RFM Entry {entry['index_spin'].value()}")

        def add_rfm_entry() -> None:
            default_index = (rfm_entries[-1]['index_spin'].value() + 1) if rfm_entries else 1
            default_psid = '8002' if default_index == 1 else '8003'

            frame = QGroupBox(f"RFM Entry {default_index}")
            grid = QGridLayout(frame)
            grid.setHorizontalSpacing(6)
            grid.setVerticalSpacing(4)

            grid.addWidget(QLabel("RFM Index:"), 0, 0, ALIGN_RIGHT)
            index_spin = _make_spinbox(default_index, 1, 32)
            grid.addWidget(index_spin, 0, 1)
            grid.addWidget(QLabel("PSID (hex):"), 0, 2, ALIGN_RIGHT)
            psid_edit = _make_hex_edit(default_psid)
            grid.addWidget(psid_edit, 0, 3)

            grid.addWidget(QLabel("Dest IP:"), 1, 0, ALIGN_RIGHT)
            dest_ip_edit = QLineEdit("192.168.55.152")
            grid.addWidget(dest_ip_edit, 1, 1)
            grid.addWidget(QLabel("Dest Port:"), 1, 2, ALIGN_RIGHT)
            dest_port_spin = _make_spinbox(5398, 1, 65535)
            grid.addWidget(dest_port_spin, 1, 3)

            grid.addWidget(QLabel("Protocol:"), 2, 0, ALIGN_RIGHT)
            protocol_combo = QComboBox()
            protocol_combo.addItems(["2"])
            protocol_combo.setCurrentText("2")
            grid.addWidget(protocol_combo, 2, 1)
            grid.addWidget(QLabel("RSSI (dBm):"), 2, 2, ALIGN_RIGHT)
            rssi_spin = _make_spinbox(-100, -200, 0, readonly=True)
            grid.addWidget(rssi_spin, 2, 3)

            grid.addWidget(QLabel("Interval:"), 3, 0, ALIGN_RIGHT)
            interval_spin = _make_spinbox(1, 0, 1_000_000)
            grid.addWidget(interval_spin, 3, 1)
            grid.addWidget(QLabel("Secure:"), 3, 2, ALIGN_RIGHT)
            secure_spin = _make_spinbox(0, 0, 1)
            grid.addWidget(secure_spin, 3, 3)

            grid.addWidget(QLabel("Start Date:"), 4, 0, ALIGN_RIGHT)
            start_date_edit = QLineEdit("2025-01-01,00:00:00.0")
            grid.addWidget(start_date_edit, 4, 1, 1, 3)

            grid.addWidget(QLabel("Stop Date:"), 5, 0, ALIGN_RIGHT)
            stop_date_edit = QLineEdit("2030-01-01,00:00:00.0")
            grid.addWidget(stop_date_edit, 5, 1, 1, 3)

            grid.addWidget(QLabel("Auth Msg Interval:"), 6, 0, ALIGN_RIGHT)
            auth_interval_spin = _make_spinbox(0, 0, 1_000_000)
            grid.addWidget(auth_interval_spin, 6, 1)

            btn_row = QHBoxLayout()
            btn_row.addStretch(1)
            set_btn = QPushButton("Set Entry")
            remove_btn = QPushButton("Remove Entry")
            btn_row.addWidget(set_btn)
            btn_row.addWidget(remove_btn)
            btn_row.addStretch(1)
            grid.addLayout(btn_row, 7, 0, 1, 4)

            grid.setColumnStretch(1, 1)
            grid.setColumnStretch(3, 1)

            entry_vars = {
                'frame': frame,
                'index_spin': index_spin,
                'psid_edit': psid_edit,
                'dest_ip_edit': dest_ip_edit,
                'dest_port_spin': dest_port_spin,
                'protocol_combo': protocol_combo,
                'rssi_spin': rssi_spin,
                'interval_spin': interval_spin,
                'secure_spin': secure_spin,
                'start_date_edit': start_date_edit,
                'stop_date_edit': stop_date_edit,
                'auth_interval_spin': auth_interval_spin,
            }

            index_spin.valueChanged.connect(
                lambda v: frame.setTitle(f"RFM Entry {v}")
            )
            set_btn.clicked.connect(lambda: set_single_rfm_entry(entry_vars))
            remove_btn.clicked.connect(lambda: remove_rfm_entry(entry_vars))

            config_inner_layout.insertWidget(config_inner_layout.count() - 1, frame)
            rfm_entries.append(entry_vars)

        def destroy_rfm_entry(idx: int) -> None:
            delete_oid = f"1.3.6.1.4.1.1206.4.2.18.5.2.1.10.{idx}"
            self._destroy_entry(delete_oid, on_done=get_rfm_info)

        def get_rfm_info() -> None:
            add_rfm_btn.setEnabled(True)

            def work():
                session = self._get_session()
                results = []
                for i in range(1, 7):
                    try:
                        values = []
                        for j in (2, 3, 4):
                            handle = session.get(f"1.3.6.1.4.1.1206.4.2.18.5.2.1.{j}.{i}")
                            varbind_list = handle.wait() if hasattr(handle, 'wait') else handle
                            values.append(cr_helper.format_snmp_value(varbind_list[0]))
                        results.append((i, values, None))
                    except (Timeout, ErrorResponse) as e:
                        results.append((i, None, str(e)))
                return results

            def on_ok(results):
                rfm_table.setRowCount(0)
                for i, values, err in results:
                    row = rfm_table.rowCount()
                    rfm_table.insertRow(row)
                    rfm_table.setItem(row, 0, QTableWidgetItem(str(i)))
                    if err is None:
                        for col, v in enumerate(values, start=1):
                            rfm_table.setItem(row, col, QTableWidgetItem(v))
                        btn = QPushButton("Destroy")
                        btn.clicked.connect(lambda _c=False, ii=i: destroy_rfm_entry(ii))
                        rfm_table.setCellWidget(row, 4, btn)
                    else:
                        self._fill_error_row(rfm_table, row, err, data_cols=3)

            def on_err(e):
                QMessageBox.critical(self, "SNMP Error", str(e))

            self._run_async(work, on_ok, on_err)

        add_rfm_btn = QPushButton("Add RFM Entry")
        add_rfm_btn.setEnabled(False)
        add_rfm_btn.clicked.connect(add_rfm_entry)
        controls.addWidget(add_rfm_btn)
        get_btn = QPushButton("Get RFM Info")
        get_btn.clicked.connect(get_rfm_info)
        controls.addWidget(get_btn)
        help_btn = QPushButton("Help")
        help_btn.clicked.connect(lambda: self._show_help("Received Message Forward", cr_helper.get_rfm_help_content()))
        controls.addWidget(help_btn)
        controls.addStretch(1)

        self.tabs.addTab(tab, "Received Message Forward")


    # ---------- Store-and-Repeat tab ----------
    def _create_store_and_repeat_tab(self) -> None:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(12, 12, 12, 12)

        controls = QHBoxLayout()
        outer.addLayout(controls)

        config_group = QGroupBox("Configure SRM Entries")
        config_vbox = QVBoxLayout(config_group)
        config_scroll = QScrollArea()
        config_scroll.setWidgetResizable(True)
        config_inner = QWidget()
        config_inner_layout = QVBoxLayout(config_inner)
        config_inner_layout.addStretch(1)
        config_scroll.setWidget(config_inner)
        config_vbox.addWidget(config_scroll)
        outer.addWidget(config_group)

        results_group = QGroupBox("SRM Results")
        results_layout = QVBoxLayout(results_group)
        srm_table = self._make_results_table(["Index", "PSID", "Payload", ""])
        results_layout.addWidget(srm_table)
        outer.addWidget(results_group, 1)

        srm_entries: List[dict] = []

        def destroy_srm_entry(idx: int) -> None:
            delete_oid = f"1.3.6.1.4.1.1206.4.2.18.3.2.1.9.{idx}"
            self._destroy_entry(delete_oid, on_done=get_srm_info)

        def get_srm_info() -> None:
            add_srm_btn.setEnabled(True)

            def work():
                session = self._get_session()
                results = []
                for i in range(1, 7):
                    try:
                        values = []
                        for j in (2, 7):  # psid and payload
                            handle = session.get(f"1.3.6.1.4.1.1206.4.2.18.3.2.1.{j}.{i}")
                            varbind_list = handle.wait() if hasattr(handle, 'wait') else handle
                            values.append(cr_helper.format_snmp_value(varbind_list[0]))
                        results.append((i, values, None))
                    except (Timeout, ErrorResponse) as e:
                        results.append((i, None, str(e)))
                return results

            def on_ok(results):
                srm_table.setRowCount(0)
                for i, values, err in results:
                    row = srm_table.rowCount()
                    srm_table.insertRow(row)
                    srm_table.setItem(row, 0, QTableWidgetItem(str(i)))
                    if err is None:
                        for col, v in enumerate(values, start=1):
                            srm_table.setItem(row, col, QTableWidgetItem(v))
                        btn = QPushButton("Destroy")
                        btn.clicked.connect(lambda _c=False, ii=i: destroy_srm_entry(ii))
                        srm_table.setCellWidget(row, 3, btn)
                    else:
                        self._fill_error_row(srm_table, row, err, data_cols=2)

            def on_err(e):
                QMessageBox.critical(self, "SNMP Error", str(e))

            self._run_async(work, on_ok, on_err)

        def set_single_srm_entry(entry_vars: dict) -> None:
            srm_index = entry_vars['index_spin'].value()
            psid = entry_vars['psid_edit'].text().strip()
            channel = entry_vars['channel_spin'].value()
            interval = entry_vars['interval_spin'].value()
            start_date = entry_vars['start_date_edit'].text().strip()
            stop_date = entry_vars['stop_date_edit'].text().strip()
            payload = entry_vars['payload_edit'].text().strip()
            enable = entry_vars['enable_spin'].value()
            priority = entry_vars['priority_spin'].value()
            options = entry_vars['options_edit'].text().strip()

            if not psid:
                QMessageBox.critical(self, "Validation Error", f"Entry {srm_index}: PSID cannot be empty")
                return
            if not payload:
                QMessageBox.critical(self, "Validation Error", f"Entry {srm_index}: Payload cannot be empty")
                return

            try:
                start_date_bytes = cr_helper.convert_datetime_to_snmp(start_date)
                stop_date_bytes = cr_helper.convert_datetime_to_snmp(stop_date)
            except ValueError as e:
                QMessageBox.critical(self, "Validation Error", f"Entry {srm_index}: {e}")
                return

            def work():
                self._set_standby()
                session = self._get_session()
                base_oid = "1.3.6.1.4.1.1206.4.2.18.3.2.1"
                session.set(
                    (f"{base_oid}.2.{srm_index}", OctetString(unhexlify(psid))),
                    (f"{base_oid}.3.{srm_index}", Integer32(channel)),
                    (f"{base_oid}.4.{srm_index}", Integer32(interval)),
                    (f"{base_oid}.5.{srm_index}", OctetString(start_date_bytes)),
                    (f"{base_oid}.6.{srm_index}", OctetString(stop_date_bytes)),
                    (f"{base_oid}.7.{srm_index}", OctetString(unhexlify(payload))),
                    (f"{base_oid}.8.{srm_index}", Integer32(enable)),
                    (f"{base_oid}.9.{srm_index}", Integer32(4)),
                    (f"{base_oid}.10.{srm_index}", Integer32(priority)),
                    (f"{base_oid}.11.{srm_index}", OctetString(unhexlify(options))),
                )
                self._set_operate()

            def on_ok(_):
                QMessageBox.information(self, "Success", f"Successfully configured SRM entry {srm_index} with PSID {psid}")
                get_srm_info()

            def on_err(e):
                QMessageBox.critical(self, "SNMP Error", f"Failed to set SRM entry {srm_index}: {e}")

            self._run_async(work, on_ok, on_err)

        def remove_srm_entry(entry_vars: dict) -> None:
            frame = entry_vars['frame']
            config_inner_layout.removeWidget(frame)
            frame.setParent(None)
            frame.deleteLater()
            srm_entries.remove(entry_vars)
            for entry in srm_entries:
                entry['frame'].setTitle(f"SRM Entry {entry['index_spin'].value()}")

        def add_srm_entry() -> None:
            default_index = (srm_entries[-1]['index_spin'].value() + 1) if srm_entries else 1
            default_channel = 180 if self.mode_mib == "rsu41" else 183

            frame = QGroupBox(f"SRM Entry {default_index}")
            grid = QGridLayout(frame)
            grid.setHorizontalSpacing(6)
            grid.setVerticalSpacing(4)

            grid.addWidget(QLabel("SRM Index:"), 0, 0, ALIGN_RIGHT)
            index_spin = _make_spinbox(default_index, 1, 32)
            grid.addWidget(index_spin, 0, 1)
            grid.addWidget(QLabel("PSID (hex):"), 0, 2, ALIGN_RIGHT)
            psid_edit = _make_hex_edit("8002")
            grid.addWidget(psid_edit, 0, 3)

            grid.addWidget(QLabel("TX Channel:"), 1, 0, ALIGN_RIGHT)
            channel_spin = _make_spinbox(default_channel, 1, 255, readonly=True)
            grid.addWidget(channel_spin, 1, 1)
            grid.addWidget(QLabel("TX Interval (ms):"), 1, 2, ALIGN_RIGHT)
            interval_spin = _make_spinbox(1000, 0, 1_000_000)
            grid.addWidget(interval_spin, 1, 3)

            grid.addWidget(QLabel("Start Date:"), 2, 0, ALIGN_RIGHT)
            start_date_edit = QLineEdit("2025-01-01,00:00:00.0")
            grid.addWidget(start_date_edit, 2, 1, 1, 3)

            grid.addWidget(QLabel("Stop Date:"), 3, 0, ALIGN_RIGHT)
            stop_date_edit = QLineEdit("2030-01-01,00:00:00.0")
            grid.addWidget(stop_date_edit, 3, 1, 1, 3)

            grid.addWidget(QLabel("Payload (hex):"), 4, 0, ALIGN_RIGHT)
            payload_edit = _make_hex_edit("")
            grid.addWidget(payload_edit, 4, 1, 1, 3)

            grid.addWidget(QLabel("Enable:"), 5, 0, ALIGN_RIGHT)
            enable_spin = _make_spinbox(1, 0, 1)
            grid.addWidget(enable_spin, 5, 1)
            grid.addWidget(QLabel("Priority:"), 5, 2, ALIGN_RIGHT)
            priority_spin = _make_spinbox(6, 0, 63)
            grid.addWidget(priority_spin, 5, 3)

            grid.addWidget(QLabel("Options (hex):"), 6, 0, ALIGN_RIGHT)
            options_edit = _make_hex_edit("01")
            grid.addWidget(options_edit, 6, 1, 1, 3)

            btn_row = QHBoxLayout()
            btn_row.addStretch(1)
            set_btn = QPushButton("Set Entry")
            remove_btn = QPushButton("Remove Entry")
            btn_row.addWidget(set_btn)
            btn_row.addWidget(remove_btn)
            btn_row.addStretch(1)
            grid.addLayout(btn_row, 7, 0, 1, 4)

            grid.setColumnStretch(1, 1)
            grid.setColumnStretch(3, 1)

            entry_vars = {
                'frame': frame,
                'index_spin': index_spin,
                'psid_edit': psid_edit,
                'channel_spin': channel_spin,
                'interval_spin': interval_spin,
                'start_date_edit': start_date_edit,
                'stop_date_edit': stop_date_edit,
                'payload_edit': payload_edit,
                'enable_spin': enable_spin,
                'priority_spin': priority_spin,
                'options_edit': options_edit,
            }

            index_spin.valueChanged.connect(
                lambda v: frame.setTitle(f"SRM Entry {v}")
            )
            set_btn.clicked.connect(lambda: set_single_srm_entry(entry_vars))
            remove_btn.clicked.connect(lambda: remove_srm_entry(entry_vars))

            config_inner_layout.insertWidget(config_inner_layout.count() - 1, frame)
            srm_entries.append(entry_vars)

        add_srm_btn = QPushButton("Add SRM Entry")
        add_srm_btn.setEnabled(False)
        add_srm_btn.clicked.connect(add_srm_entry)
        controls.addWidget(add_srm_btn)
        get_btn = QPushButton("Get SRM Info")
        get_btn.clicked.connect(get_srm_info)
        controls.addWidget(get_btn)
        help_btn = QPushButton("Help")
        help_btn.clicked.connect(lambda: self._show_help("Store-and-Repeat", cr_helper.get_srm_help_content()))
        controls.addWidget(help_btn)
        controls.addStretch(1)

        self.tabs.addTab(tab, "Store-and-Repeat")

    # ---------- Send Active Message tab ----------
    def _create_active_message_tab(self) -> None:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(12, 12, 12, 12)

        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        outer.addLayout(form)

        self.amf_rsu_edit = QLineEdit("192.168.55.20")
        form.addRow("RSU IP Address:", self.amf_rsu_edit)

        self.amf_port_spin = _make_spinbox(1516, 1, 65535)
        form.addRow("RSU IFM Port:", self.amf_port_spin)

        self.msg_type_combo = QComboBox()
        self.msg_type_combo.setEditable(True)
        self.msg_type_combo.addItems(["MAP", "SPAT", "BSM", "SRM", "SSM", "TIM", "PSM", "RSM", "SDSM"])
        self.msg_type_combo.setCurrentText("MAP")
        form.addRow("Message Type:", self.msg_type_combo)

        self.psid_edit = _make_hex_edit("8002")
        form.addRow("PSID:", self.psid_edit)

        self.priority_spin = _make_spinbox(3, 0, 7)
        form.addRow("Priority:", self.priority_spin)

        self.tx_mode_combo = QComboBox()
        self.tx_mode_combo.setEditable(True)
        self.tx_mode_combo.addItems(["CONT", "ALT"])
        self.tx_mode_combo.setCurrentText("CONT")
        form.addRow("Tx Mode:", self.tx_mode_combo)

        self.tx_channel_spin = _make_spinbox(183, 1, 255, readonly=True)
        form.addRow("Tx Channel:", self.tx_channel_spin)

        self.tx_interval_spin = _make_spinbox(0, 0, 1_000_000, readonly=True)
        form.addRow("Tx Interval:", self.tx_interval_spin)

        self.signature_combo = QComboBox()
        self.signature_combo.setEditable(True)
        self.signature_combo.addItems(["True", "False"])
        self.signature_combo.setCurrentText("False")
        form.addRow("Signature:", self.signature_combo)

        self.encryption_combo = QComboBox()
        self.encryption_combo.setEditable(True)
        self.encryption_combo.addItems(["True", "False"])
        self.encryption_combo.setCurrentText("False")
        form.addRow("Encryption:", self.encryption_combo)

        self.payload_edit = QLineEdit("")
        form.addRow("Payload:", self.payload_edit)

        def send_amf() -> None:
            try:
                amf = (
                    f"Version=0.7\n"
                    f"Type={self.msg_type_combo.currentText()}\n"
                    f"PSID={self.psid_edit.text()}\n"
                    f"Priority={self.priority_spin.value()}\n"
                    f"TxMode={self.tx_mode_combo.currentText()}\n"
                    f"TxChannel={self.tx_channel_spin.value()}\n"
                    f"TxInterval={self.tx_interval_spin.value()}\n"
                    f"DeliveryStart=\n"
                    f"DeliveryStop=\n"
                    f"Signature={self.signature_combo.currentText()}\n"
                    f"Encryption={self.encryption_combo.currentText()}\n"
                    f"Payload={self.payload_edit.text()}"
                )
                hex_data = amf.encode('utf-8')
                sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sk.sendto(hex_data, (self.amf_rsu_edit.text(), self.amf_port_spin.value()))
                QMessageBox.information(self, "AMF Sent", "Active Message File has been sent to the RSU.")
            except Exception as e:
                QMessageBox.critical(self, "Error Sending AMF", f"Failed to send Active Message File:\n{e}")

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        help_btn = QPushButton("Help")
        help_btn.clicked.connect(lambda: self._show_help("Send Active Message", cr_helper.get_amf_help_content()))
        button_row.addWidget(help_btn)
        send_btn = QPushButton("Send Message")
        send_btn.clicked.connect(send_amf)
        button_row.addWidget(send_btn)
        outer.addLayout(button_row)
        outer.addStretch(1)

        self.tabs.addTab(tab, "Send Active Message")

    # ---------- SNMP sync helpers (run on worker thread) ----------
    def _get_rsu_mode(self) -> int:
        if self.mode_mib == "ntcip1218":
            mode_oid = "1.3.6.1.4.1.1206.4.2.18.16.2.0"
        else:
            mode_oid = "1.0.15628.4.1.99.0"
        session = self._get_session()
        handle = session.get(mode_oid)
        varbind_list = handle.wait() if hasattr(handle, 'wait') else handle
        value_obj = varbind_list[0].value
        return value_obj.value if hasattr(value_obj, 'value') else value_obj

    def _set_rsu_mode(self, target: Dict[str, int]) -> None:
        if self.mode_mib == "ntcip1218":
            mode_oid = "1.3.6.1.4.1.1206.4.2.18.16.2.0"
        else:
            mode_oid = "1.0.15628.4.1.99.0"
        target_name = list(target.keys())[0]
        target_mode = list(target.values())[0]

        current_mode = self._get_rsu_mode()
        if current_mode == target_mode:
            return

        session = self._get_session()
        session.set((mode_oid, Integer32(target_mode)))
        try:
            verified_mode = self._get_rsu_mode()
            if verified_mode != target_mode:
                print(f"Warning: Mode verification failed. Expected {target_mode}, got {verified_mode}")
        except Exception as verify_error:
            print(f"Note: Could not verify mode change: {verify_error}")

    def _set_standby(self) -> None:
        self._set_rsu_mode({"standby": 2})

    def _set_operate(self) -> None:
        if self.mode_mib == "ntcip1218":
            self._set_rsu_mode({"operate": 3})
        else:
            self._set_rsu_mode({"operate": 4})

    # ---------- Top-level SNMP actions (async entry points) ----------
    def _test_connection(self) -> None:
        def work():
            session = self._get_session()
            handle = session.get('1.3.6.1.2.1.1.1.0')
            varbind_list = handle.wait() if hasattr(handle, 'wait') else handle
            return cr_helper.format_snmp_value(varbind_list[0])

        def on_ok(value):
            self._append_result(f"Connection OK: {value}")

        def on_err(e):
            if isinstance(e, (Timeout, ErrorResponse)):
                self._append_result(f"Connection test failed: {e}")
                self._append_result("Check your credentials and device accessibility.")
                QMessageBox.critical(self, "Connection Error", f"Failed to connect to device:\n{e}")
            else:
                QMessageBox.critical(self, "Error", str(e))

        self._run_async(work, on_ok, on_err)

    def _get_rsu_mode_status(self) -> None:
        mode_status_oid = "1.3.6.1.4.1.1206.4.2.18.16.3.0"
        status_modes = {1: "other", 2: "standby", 3: "operate", 4: "fault"}

        def work():
            session = self._get_session()
            handle = session.get(mode_status_oid)
            varbind_list = handle.wait() if hasattr(handle, 'wait') else handle
            value_obj = varbind_list[0].value
            return value_obj.value if hasattr(value_obj, 'value') else value_obj

        def on_ok(mode_status):
            self._append_result(
                f"RSU Mode Status: {status_modes.get(mode_status, 'unknown')} ({mode_status})"
            )

        def on_err(e):
            self._append_result(f"ERROR getting RSU mode status: {e}")

        self._run_async(work, on_ok, on_err)

    def _destroy_entry(self, delete_oid: str, on_done: Optional[Callable[[], None]] = None) -> None:
        def work():
            self._set_standby()
            session = self._get_session()
            session.set((delete_oid, Integer32(6)))  # 6 = destroy
            self._set_operate()

        def on_ok(_):
            if on_done is not None:
                on_done()

        def on_err(e):
            QMessageBox.critical(self, "Error", f"Failed to destroy entry: {e}")

        self._run_async(work, on_ok, on_err)

    # ---------- Help dialog ----------
    def _show_help(self, tab_name: str, content: str) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{tab_name} Help")
        dialog.resize(600, 400)

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(12, 12, 12, 12)

        text_widget = QTextEdit()
        text_widget.setReadOnly(True)
        text_widget.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        if content:
            text_widget.setPlainText(content)
        else:
            text_widget.setPlainText(f"Help content for {tab_name} will be added here.")
        layout.addWidget(text_widget)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        dialog.exec()

    # ---------- SNMP session ----------
    def _get_session(self):
        auth_protocol_map = {
            "MD5": HmacMd5,
            "SHA": HmacSha,
            "SHA256": HmacSha256,
            "SHA512": HmacSha512,
        }
        priv_protocol_map = {
            "DES": DesCbc,
            "AES": AesCfb128,
        }

        auth_protocol = auth_protocol_map.get(self.auth_protocol_combo.currentText(), HmacSha)
        priv_protocol = priv_protocol_map.get(self.privacy_protocol_combo.currentText(), AesCfb128)

        username = self.snmpv3_user_edit.text()
        auth_password = self.auth_password_edit.text()
        priv_password = self.privacy_password_edit.text()

        try:
            snmp_engine.addUser(
                username,
                authProtocol=auth_protocol,
                authSecret=auth_password.encode() if isinstance(auth_password, str) else auth_password,
                privProtocol=priv_protocol,
                privSecret=priv_password.encode() if isinstance(priv_password, str) else priv_password,
            )
        except Exception:
            pass

        hostname = self.hostname_edit.text()
        port = self.port_spin.value()
        manager = snmp_engine.Manager((hostname, port), defaultUser=username)
        return manager

    def _append_result(self, text: str) -> None:
        self.results_text.append(text)
        self.results_text.append("")


def main() -> None:
    app = QApplication(sys.argv)
    window = RSUConfigurationApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
