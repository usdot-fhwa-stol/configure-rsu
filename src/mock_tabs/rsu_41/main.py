import datetime
import sys

from PyQt6.QtCore import (
    Qt,
)
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from constants import PAYLOAD_DICT, PCAP_DIRECTORY
from utils import _make_hex_edit, _make_spinbox, _normalise_hex

from .workers import (
    _BroadcastWorker,
)


class Rsu41Tab(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self._broadcast_thread: _BroadcastWorker | None = None

        self._build_ui()

    def shutdown(self) -> None:
        """Stop any in-flight broadcast. Call this before the tab is destroyed."""
        if self._broadcast_thread is not None:
            self._broadcast_thread.stop()
            self._broadcast_thread.wait(3000)

    def _on_target_mode_changed(self, selected_mode: str) -> None:
        if selected_mode == "Using RSU":
            self.amf_rsu_edit.setText("192.168.55.20")
            self.prio = 3
            self.tx_channel = 183
            self.recording_interface_edit.setText("enp60s0")
        else:
            self.amf_rsu_edit.setText("127.0.0.1")
            self.prio = 7
            self.tx_channel = 172
            self.recording_interface_edit.setText("lo")

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter, 1)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        left_layout.addLayout(form)

        self.target_mode_combo = QComboBox()
        self.target_mode_combo.addItems(["No RSU", "Using RSU"])
        form.addRow("Target Mode:", self.target_mode_combo)

        self.amf_rsu_edit = QLineEdit("")
        form.addRow("RSU IP Address:", self.amf_rsu_edit)

        self.amf_port_spin = _make_spinbox(1516, 1, 65535)
        form.addRow("RSU IFM Port:", self.amf_port_spin)

        self.freq_spin = QDoubleSpinBox()
        self.freq_spin.setRange(0.1, 100.0)
        self.freq_spin.setDecimals(2)
        self.freq_spin.setValue(10.0)
        self.freq_spin.setSuffix(" Hz")
        form.addRow("Frequency:", self.freq_spin)

        self.period_spin = _make_spinbox(60, 1, 3600)
        self.period_spin.setSuffix(" sec")
        form.addRow("Period:", self.period_spin)

        self.psid_edit = _make_hex_edit("8002")
        self.psid_edit.setPlaceholderText("Example: 8002")
        form.addRow("PSID:", self.psid_edit)

        self.signature_check = QCheckBox()
        form.addRow("Signature:", self.signature_check)

        self.encryption_check = QCheckBox()
        form.addRow("Encryption:", self.encryption_check)

        self.payload_dict_combo = QComboBox()
        self.payload_dict_combo.addItems(sorted(PAYLOAD_DICT.keys()))

        initial_payload = PAYLOAD_DICT.get(self.payload_dict_combo.currentText(), "")
        self.payload_edit = _make_hex_edit(initial_payload)
        self.payload_edit.setPlaceholderText("Hex payload bytes")
        form.addRow("Message Payload:", self.payload_edit)

        self.payload_dict_combo.currentTextChanged.connect(
            lambda name: self.payload_edit.setText(PAYLOAD_DICT.get(name, ""))
        )

        recording_group = QGroupBox("PCAP Recording")
        recording_form = QFormLayout(recording_group)

        self.recording_enabled_check = QCheckBox()
        self.recording_enabled_check.setChecked(True)
        recording_form.addRow("Recording Packets:", self.recording_enabled_check)

        self.recording_interface_edit = QLineEdit("lo")
        self.recording_interface_edit.setPlaceholderText("Linux loopback is usually lo")
        recording_form.addRow("Interface:", self.recording_interface_edit)

        self.pcap_output_label = QLabel(f"Output directory: {PCAP_DIRECTORY}")
        self.pcap_output_label.setWordWrap(True)
        recording_form.addRow(self.pcap_output_label)

        left_layout.addWidget(recording_group)

        message_group = QGroupBox("Select Message Types to Broadcast")
        message_layout = QVBoxLayout(message_group)

        self.msg_list_widget = QListWidget()
        for message_type in ["MAP", "SPAT", "BSM", "SDSM"]:
            item = QListWidgetItem(message_type)
            item.setCheckState(
                Qt.CheckState.Checked
                if message_type in {"BSM"}
                else Qt.CheckState.Unchecked
            )
            self.msg_list_widget.addItem(item)

        message_layout.addWidget(self.msg_list_widget)
        left_layout.addWidget(message_group, 1)

        splitter.addWidget(left_widget)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        log_group = QGroupBox("Logs")
        log_group.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        log_layout = QVBoxLayout(log_group)

        self.amf_log = QTextEdit()
        self.amf_log.setReadOnly(True)
        log_layout.addWidget(self.amf_log)

        right_layout.addWidget(log_group, 1)

        metric_group = QGroupBox("Metrics")
        metric_group.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        metric_layout = QVBoxLayout(metric_group)

        self.metrics_display = QTextEdit()
        self.metrics_display.setReadOnly(True)
        self.metrics_display.setPlaceholderText(
            "Metrics are reported after each selected message type completes."
        )
        metric_layout.addWidget(self.metrics_display)

        right_layout.addWidget(metric_group, 1)

        splitter.addWidget(right_widget)
        splitter.setSizes([480, 640])

        button_row = QHBoxLayout()

        self.start_stop_button = QPushButton("Start Automated Broadcast")
        self.start_stop_button.clicked.connect(self._toggle_broadcast)

        clear_log_button = QPushButton("Clear Output")
        clear_log_button.clicked.connect(self._clear_output)

        button_row.addWidget(self.start_stop_button)
        button_row.addWidget(clear_log_button)
        button_row.addStretch(1)

        main_layout.addLayout(button_row)

        self.target_mode_combo.currentTextChanged.connect(self._on_target_mode_changed)
        self._on_target_mode_changed(self.target_mode_combo.currentText())

    def _log(self, message: str) -> None:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.amf_log.append(f"[{timestamp}] {message}")

    def _clear_output(self) -> None:
        self.amf_log.clear()
        self.metrics_display.clear()

    def _selected_message_types(self) -> list[str]:
        selected: list[str] = []
        for index in range(self.msg_list_widget.count()):
            item = self.msg_list_widget.item(index)
            if item.checkState() == Qt.CheckState.Checked:
                selected.append(item.text())
        return selected

    def _validate_input(self) -> str | None:
        psid = _normalise_hex(self.psid_edit.text())
        payload = _normalise_hex(self.payload_edit.text())

        if not psid:
            return "PSID cannot be empty."

        if len(psid) % 2 != 0:
            return "PSID must contain an even number of hex characters."

        if len(payload) % 2 != 0:
            return "Payload must contain an even number of hex characters."

        try:
            bytes.fromhex(psid)
            bytes.fromhex(payload)
        except ValueError:
            return "PSID and payload must contain valid hexadecimal values."

        if not self._selected_message_types():
            return "Select at least one message type."

        if self.recording_enabled_check.isChecked():
            interface = self.recording_interface_edit.text().strip()
            if not interface:
                return "Enter a PCAP recording interface or disable packet recording."

        return None

    def _toggle_broadcast(self) -> None:
        if self._broadcast_thread is not None and self._broadcast_thread.isRunning():
            self._log("Stop requested.")
            self._broadcast_thread.stop()
            self.start_stop_button.setEnabled(False)
            return

        validation_error = self._validate_input()
        if validation_error is not None:
            QMessageBox.warning(self, "Validation Error", validation_error)
            return

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_path = PCAP_DIRECTORY / f"mock_rsu_41_{timestamp}.pcap"

        self.metrics_display.clear()

        self._broadcast_thread = _BroadcastWorker(
            target_ip=self.amf_rsu_edit.text().strip(),
            target_port=self.amf_port_spin.value(),
            selected_messages=self._selected_message_types(),
            frequency_hz=self.freq_spin.value(),
            period_seconds=self.period_spin.value(),
            psid=_normalise_hex(self.psid_edit.text()),
            payload_hex=_normalise_hex(self.payload_edit.text()),
            signature=self.signature_check.isChecked(),
            encryption=self.encryption_check.isChecked(),
            recording_enabled=self.recording_enabled_check.isChecked(),
            recording_interface=self.recording_interface_edit.text().strip(),
            pcap_path=pcap_path,
        )

        self._broadcast_thread.signals.log.connect(self._log)
        self._broadcast_thread.signals.error.connect(self._on_broadcast_error)
        self._broadcast_thread.signals.metrics_updated.connect(self._update_metrics)
        self._broadcast_thread.signals.pcap_finished.connect(
            lambda path: self._log(f"Recording complete: {path}")
        )
        self._broadcast_thread.signals.finished.connect(self._on_broadcast_finished)

        self.start_stop_button.setText("Stop Broadcast")
        self.start_stop_button.setEnabled(True)
        self._broadcast_thread.start()

    def _on_broadcast_error(self, message: str) -> None:
        self._log(f"ERROR: {message}")
        QMessageBox.warning(self, "Broadcast Error", message)

    def _on_broadcast_finished(self) -> None:
        self.start_stop_button.setText("Start Automated Broadcast")
        self.start_stop_button.setEnabled(True)
        self._broadcast_thread = None

    def _update_metrics(self, message_type: str, metrics: dict) -> None:
        """Format and append one message type's metrics to the metrics pane."""
        errors = metrics["error_types"]
        errors_text = (
            "None"
            if not errors
            else "\n".join(
                f"  {error_type}: {count}"
                for error_type, count in sorted(errors.items())
            )
        )

        text = (
            f"=== Metrics for [{message_type}] ===\n"
            f"Throughput        : {metrics['throughput_kbps']:.2f} kbps\n"
            f"Total Bytes Sent  : {metrics['total_bytes_sent']} bytes\n"
            f"Total Messages Sent: {metrics['total_messages_sent']}\n"
            f"Error Type Counts :\n{errors_text}\n"
            f"{'-' * 48}"
        )

        self.metrics_display.append(text)


class _StandaloneWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mock RSU 4.1 Broadcast Simulator")
        self.resize(1120, 760)

        self.tab_widget = Rsu41Tab()

        tabs = QTabWidget()
        tabs.addTab(self.tab_widget, "RSU 4.1 Mock Messages")
        self.setCentralWidget(tabs)

    def closeEvent(self, event) -> None:
        self.tab_widget.shutdown()
        event.accept()


def main() -> None:
    """Launch the Mock RSU 4.1 GUI standalone (for local testing only)."""
    app = QApplication(sys.argv)
    window = _StandaloneWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()