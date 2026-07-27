#!/usr/bin/env python3
import datetime
import os
import socket
import sys
import time
from typing import Dict, List, Optional

from PyQt6.QtCore import (
    QObject,
    QRegularExpression,
    QRunnable,
    Qt,
    QThread,
    QThreadPool,
    pyqtSignal,
)
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QAbstractSpinBox,
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# Safe fallback import for PAYLOAD_DICT
try:
    from sample_hex_payloads import PAYLOAD_DICT
except ImportError:
    PAYLOAD_DICT = {
        "Default Sample": "00112233445566778899AABBCCDDEEFF",
        "MAP Test": "001420000000000000",
        "SPAT Test": "001320000000000000",
    }

HEX_REGEX = QRegularExpression(r"^[0-9A-Fa-f]*$")


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


# ---------- Worker Signals & Thread for Automated Broadcast ----------
class _BroadcastWorkerSignals(QObject):
    log = pyqtSignal(str)
    metrics_updated = pyqtSignal(str, dict)  # msg_type, metrics_dict
    finished = pyqtSignal()


class _BroadcastWorker(QThread):
    """
    Background worker thread that cycles through selected message types,
    sends payloads at configured frequency and period per message, and collects metrics.
    """

    def __init__(
        self,
        target_ip: str,
        target_port: int,
        selected_msgs: List[str],
        frequency_hz: float,
        period_sec: int,
        psid: str,
        payload_hex: str,
        security: str,
        is_signed: bool,
        rsu_sign: bool,
        dump_filepath: str,
    ):
        super().__init__()
        self.target_ip = target_ip
        self.target_port = target_port
        self.selected_msgs = selected_msgs
        self.frequency_hz = frequency_hz
        self.period_sec = period_sec
        self.psid = psid
        self.payload_hex = payload_hex
        self.security = security
        self.is_signed = is_signed
        self.rsu_sign = rsu_sign
        self.dump_filepath = dump_filepath
        self.signals = _BroadcastWorkerSignals()
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:
        interval = 1.0 / self.frequency_hz if self.frequency_hz > 0 else 0.1
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        # Ensure write destination for pcap / raw dump file
        dump_file = open(self.dump_filepath, "a")

        self.signals.log.emit(
            f"Starting broadcast sequence to {self.target_ip}:{self.target_port}..."
        )
        self.signals.log.emit(f"Dumping traffic records to: {self.dump_filepath}")

        for msg_type in self.selected_msgs:
            if self._stop_requested:
                break

            self.signals.log.emit(
                f"\n--- Broadcasting [{msg_type}] for {self.period_sec}s ---"
            )

            start_time = time.time()
            total_sent_bytes = 0
            latencies: List[float] = []
            failed_sends = 0
            failure_dist: Dict[str, int] = {}

            while (time.time() - start_time) < self.period_sec:
                if self._stop_requested:
                    break

                # Frame AMF payload format as per RSU 4.1 specification
                amf_content = (
                    f"Version=0.7\n"
                    f"Type={msg_type}\n"
                    f"PSID={self.psid}\n"
                    f"Priority={7}\n"
                    f"TxMode=CONT\n"
                    f"TxChannel={172}\n"
                    f"TxInterval={0}\n"
                    f"DeliveryStart=\n"
                    f"DeliveryStop=\n"
                    f"Signature={self.rsu_sign and self.is_signed}\n"
                    f"Encryption={self.security}\n"
                    f"Payload={self.payload_hex}\n"
                )
                data = amf_content.encode("utf-8")

                send_start = time.time()
                try:
                    sock.sendto(data, (self.target_ip, self.target_port))
                    latency = (time.time() - send_start) * 1000.0  # in milliseconds
                    latencies.append(latency)
                    total_sent_bytes += len(data)

                    # Log dump to file
                    dump_file.write(
                        f"[{datetime.datetime.now().isoformat()}] DEST={self.target_ip}:{self.target_port} "
                        f"TYPE={msg_type} SIZE={len(data)}B LATENCY={latency:.2f}ms\n"
                    )
                    dump_file.flush()

                except socket.error as e:
                    failed_sends += 1
                    err_type = type(e).__name__
                    failure_dist[err_type] = failure_dist.get(err_type, 0) + 1
                    self.signals.log.emit(f"[{msg_type}] Send failed: {e}")

                time.sleep(interval)

            elapsed = max(time.time() - start_time, 0.001)
            avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0
            throughput_kbps = (total_sent_bytes * 8 / 1024) / elapsed

            metrics = {
                "avg_latency_ms": avg_latency,
                "failed_send_count": failed_sends,
                "failure_distribution": failure_dist,
                "total_bytes_sent": total_sent_bytes,
                "throughput_kbps": throughput_kbps,
            }

            self.signals.metrics_updated.emit(msg_type, metrics)

        sock.close()
        dump_file.close()
        self.signals.log.emit("\nSequence Complete.")
        self.signals.finished.emit()


# ---------- Fake RSU Listener ----------
class _FakeRsuListenerSignals(QObject):
    received = pyqtSignal(bytes, str, int)
    error = pyqtSignal(str)
    started = pyqtSignal(int)


class _FakeRsuListenerTask(QRunnable):
    """Background UDP listener that stands in for a real OBU/RSU."""

    def __init__(self, bind_ip: str, bind_port: int):
        super().__init__()
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.signals = _FakeRsuListenerSignals()
        self._sock: Optional[socket.socket] = None
        self._stop = False

    def stop(self) -> None:
        self._stop = True
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def run(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.bind_port))
            self._sock.settimeout(0.5)
            self.signals.started.emit(self.bind_port)
        except OSError as e:
            self.signals.error.emit(
                f"Fake RSU could not bind {self.bind_ip}:{self.bind_port} - {e}"
            )
            return

        while not self._stop:
            try:
                data, addr = self._sock.recvfrom(65535)
                self.signals.received.emit(data, addr[0], addr[1])
            except socket.timeout:
                continue
            except OSError:
                break


# ---------- Standalone Window App Class ----------
class MockRsuApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mock RSU 4.1 Broadcast Simulator")
        self.resize(1000, 700)

        # Tab container required by _create_mock_rsu_41_tab expectation
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Initialize the interface tab
        _create_mock_rsu_41_tab(self)

    def closeEvent(self, event):
        # Gracefully shut down background threads upon window exit
        if hasattr(self, "_stop_fake_rsu_listener"):
            self._stop_fake_rsu_listener()
        if hasattr(self, "_broadcast_thread") and self._broadcast_thread:
            self._broadcast_thread.stop()
            self._broadcast_thread.wait()
        event.accept()


# ---------- Tab Construction ----------
def _create_mock_rsu_41_tab(self) -> None:
    tab = QWidget()
    main_layout = QVBoxLayout(tab)

    splitter = QSplitter()
    main_layout.addWidget(splitter)

    # --- Left Pane: Configurations ---
    left_widget = QWidget()
    left_layout = QVBoxLayout(left_widget)
    form = QFormLayout()

    self.target_mode_combo = QComboBox()
    self.target_mode_combo.addItems(["Real RSU", "Fake RSU (local loopback)"])
    form.addRow("Target Mode:", self.target_mode_combo)

    ip_validator = QRegularExpressionValidator(
        QRegularExpression(r"^(\d{1,3}\.){3}\d{1,3}$")
    )

    self.amf_rsu_edit = QLineEdit("127.0.0.1")
    self.amf_rsu_edit.setValidator(ip_validator)
    form.addRow("RSU IP Address:", self.amf_rsu_edit)

    self.amf_port_spin = _make_spinbox(1516, 1, 65535)
    form.addRow("RSU Port:", self.amf_port_spin)

    # Automated Settings Required by Jira
    self.freq_spin = QDoubleSpinBox()
    self.freq_spin.setRange(0.1, 100.0)
    self.freq_spin.setValue(10.0)
    self.freq_spin.setSuffix(" Hz")
    form.addRow("Frequency:", self.freq_spin)

    self.period_spin = _make_spinbox(60, 1, 3600)  # Default 60 seconds
    self.period_spin.setSuffix(" sec")
    form.addRow("Period (Duration/Msg):", self.period_spin)

    self.psid_edit = _make_hex_edit("8002")
    form.addRow("PSID:", self.psid_edit)

    
    self.chk_is_signed = QCheckBox("Is Message Signed")
    self.chk_rsu_sign = QCheckBox("Should RSU Sign Message")
    form.addRow("Signature:", self.chk_is_signed, self.chk_rsu_sign)
    
    self.security_edit = QCheckBox("")
    form.addRow("Security:", self.security_edit)

    self.payload_dict_combo = QComboBox()
    self.payload_dict_combo.addItems(sorted(PAYLOAD_DICT.keys()))

    initial_payload = (
        PAYLOAD_DICT[self.payload_dict_combo.currentText()]
        if self.payload_dict_combo.currentText() in PAYLOAD_DICT
        else ""
    )
    self.payload_edit = _make_hex_edit(initial_payload)
    self.payload_edit.setPlaceholderText("Hex payload bytes")
    form.addRow("Message Payload:", self.payload_edit)

    def _load_selected_payload(name: str) -> None:
        self.payload_edit.setText(PAYLOAD_DICT.get(name, ""))

    self.payload_dict_combo.currentTextChanged.connect(_load_selected_payload)

    self.dump_file_edit = QLineEdit("rsu_broadcast_capture.dump")
    form.addRow("Capture Dump File:", self.dump_file_edit)

    left_layout.addLayout(form)

    # Message Type Selector
    msg_box = QGroupBox("Select Message Types to Broadcast")
    msg_box_layout = QVBoxLayout(msg_box)
    self.msg_list_widget = QListWidget()
    msg_types = ["MAP", "SPAT", "BSM", "SDSM"]
    for m in msg_types:
        item = QListWidgetItem(m)
        item.setCheckState(
            Qt.CheckState.Checked if m in ["MAP", "SPAT"] else Qt.CheckState.Unchecked
        )
        self.msg_list_widget.addItem(item)
    msg_box_layout.addWidget(self.msg_list_widget)
    left_layout.addWidget(msg_box)

    splitter.addWidget(left_widget)

    # --- Right Pane: Output Logs & Metrics ---
    right_widget = QWidget()
    right_layout = QVBoxLayout(right_widget)

    self.amf_log = QTextEdit()
    self.amf_log.setReadOnly(True)
    self.amf_log.setPlaceholderText(
        "Broadcast updates and capture dumps will print here..."
    )
    right_layout.addWidget(self.amf_log)

    self.metrics_display = QTextEdit()
    self.metrics_display.setReadOnly(True)
    self.metrics_display.setPlaceholderText(
        "Metrics per message type will be reported here..."
    )
    right_layout.addWidget(self.metrics_display)

    splitter.addWidget(right_widget)

    # --- Controls & Execution ---
    self._broadcast_thread: Optional[_BroadcastWorker] = None
    self._fake_rsu_task: Optional[_FakeRsuListenerTask] = None

    def log(msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.amf_log.append(f"[{ts}] {msg}")

    def update_metrics(msg_type: str, metrics: dict) -> None:
        res = (
            f"=== Metrics for [{msg_type}] ===\n"
            f"Rolling Avg Latency : {metrics['avg_latency_ms']:.3f} ms\n"
            f"Failed Send Count   : {metrics['failed_send_count']}\n"
            f"Failure Types       : {metrics['failure_distribution']}\n"
            f"Total Data Sent     : {metrics['total_bytes_sent']} Bytes\n"
            f"Throughput          : {metrics['throughput_kbps']:.2f} kbps\n"
            f"----------------------------------------\n"
        )
        self.metrics_display.append(res)

    def start_fake_listener() -> None:
        if self._fake_rsu_task is not None:
            return
        task = _FakeRsuListenerTask("127.0.0.1", self.amf_port_spin.value())
        task.signals.started.connect(
            lambda port: log(f"Fake RSU listening on loopback port {port}")
        )
        task.signals.received.connect(
            lambda data, ip, port: log(
                f"Fake RSU Received {len(data)} B from {ip}:{port}"
            )
        )
        self._fake_rsu_task = task
        QThreadPool.globalInstance().start(task)

    def stop_fake_listener() -> None:
        if self._fake_rsu_task is not None:
            self._fake_rsu_task.stop()
            self._fake_rsu_task = None

    self._stop_fake_rsu_listener = stop_fake_listener

    def toggle_broadcast() -> None:
        if self._broadcast_thread and self._broadcast_thread.isRunning():
            self._broadcast_thread.stop()
            send_btn.setText("Start Automated Broadcast")
            return

        is_fake = "Fake" in self.target_mode_combo.currentText()
        if is_fake:
            start_fake_listener()

        selected_msgs = []
        for idx in range(self.msg_list_widget.count()):
            item = self.msg_list_widget.item(idx)
            if item.checkState() == Qt.CheckState.Checked:
                selected_msgs.append(item.text())

        if not selected_msgs:
            QMessageBox.warning(
                self, "No Message Selected", "Please select at least one message type."
            )
            return

        self._broadcast_thread = _BroadcastWorker(
            target_ip=self.amf_rsu_edit.text(),
            target_port=self.amf_port_spin.value(),
            selected_msgs=selected_msgs,
            frequency_hz=self.freq_spin.value(),
            period_sec=self.period_spin.value(),
            psid=self.psid_edit.text(),
            payload_hex=self.payload_edit.text(),
            security=self.security_edit.isChecked(),
            is_signed=self.chk_is_signed.isChecked(),
            rsu_sign=self.chk_rsu_sign.isChecked(),
            dump_filepath=self.dump_file_edit.text(),
        )

        self._broadcast_thread.signals.log.connect(log)
        self._broadcast_thread.signals.metrics_updated.connect(update_metrics)
        self._broadcast_thread.signals.finished.connect(
            lambda: send_btn.setText("Start Automated Broadcast")
        )

        self._broadcast_thread.start()
        send_btn.setText("Stop Broadcast")

    button_row = QHBoxLayout()
    button_row.addStretch(1)
    send_btn = QPushButton("Start Automated Broadcast")
    send_btn.clicked.connect(toggle_broadcast)
    button_row.addWidget(send_btn)
    main_layout.addLayout(button_row)

    self.tabs.addTab(tab, "Send Active Message (RSU 4.1)")


# Standard Application Entry Point
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MockRsuApp()
    window.show()
    sys.exit(app.exec())
