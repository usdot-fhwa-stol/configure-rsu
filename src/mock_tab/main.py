"""Combined RSU 4.1 and NTCIP 1218 mock-message tab."""

from __future__ import annotations

import datetime
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
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
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from constants import PAYLOAD_DICT, PCAP_DIRECTORY
from utils import _make_hex_edit, _make_spinbox, _normalise_hex

from .broadcaster_external import ExternalBroadcastWorke
from .broadcaster_local import LocalBroadcastWorker


class MockMessagesTab(QWidget):
    """Configure RSU 4.1 or NTCIP 1218 mock-message broadcasts."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self._session_factory = session_factory
        self._broadcast_thread: (
            LocalBroadcastWorker | ExternalBroadcastWorke | None
        ) = None

        self._build_ui()

    def shutdown(self) -> None:
        """Stop the active worker before the application exits."""
        worker = self._broadcast_thread

        if worker is None:
            return

        if worker.isRunning():
            worker.stop()

            if not worker.wait(5000):
                self._log("Worker did not stop within five seconds.")

    def _build_ui(self) -> None:
        """Build the combined mock-message interface."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter, 1)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        configuration_group = QGroupBox("Broadcast Configuration")
        form = QFormLayout(configuration_group)
        form.setFieldGrowthPolicy(
            QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
        )
        left_layout.addWidget(configuration_group)

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem("RSU 4.1 AMF", "rsu41")
        self.protocol_combo.addItem(
            "NTCIP 1218 Immediate Forward",
            "ntcip1218",
        )
        form.addRow("Protocol:", self.protocol_combo)

        self.target_mode_combo = QComboBox()
        self.target_mode_combo.addItem("No RSU", "local")
        self.target_mode_combo.addItem("Using RSU", "rsu")
        form.addRow("Target Mode:", self.target_mode_combo)

        self.amf_rsu_edit = QLineEdit()
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

        self.priority_spin = _make_spinbox(7, 0, 255)
        form.addRow("Priority:", self.priority_spin)

        self.tx_channel_spin = _make_spinbox(172, 0, 255)
        form.addRow("Tx Channel:", self.tx_channel_spin)

        self.signature_check = QCheckBox()
        form.addRow("Signature:", self.signature_check)

        self.encryption_check = QCheckBox()
        form.addRow("Encryption:", self.encryption_check)

        self.payload_dict_combo = QComboBox()
        self.payload_dict_combo.addItems(sorted(PAYLOAD_DICT.keys()))
        form.addRow("Payload Template:", self.payload_dict_combo)

        initial_payload = PAYLOAD_DICT.get(
            self.payload_dict_combo.currentText(),
            "",
        )
        self.payload_edit = _make_hex_edit(initial_payload)
        self.payload_edit.setPlaceholderText("Hex payload bytes")
        form.addRow("Custom Payload:", self.payload_edit)

        self.use_matching_payloads_check = QCheckBox()
        self.use_matching_payloads_check.setChecked(True)
        self.use_matching_payloads_check.setToolTip(
            "Use PAYLOAD_DICT to select the correct payload for each "
            "checked message type."
        )
        form.addRow(
            "Match Payload to Message:",
            self.use_matching_payloads_check,
        )

        self.ntcip_index_spin = _make_spinbox(1, 1, 32)
        form.addRow("First IFM Index:", self.ntcip_index_spin)

        self.ntcip_enable_spin = _make_spinbox(1, 0, 1)
        form.addRow("NTCIP Enable:", self.ntcip_enable_spin)

        self.ntcip_options_edit = _make_hex_edit("00")
        self.ntcip_options_edit.setPlaceholderText("Example: 00")
        form.addRow("NTCIP Options:", self.ntcip_options_edit)

        self.ntcip_destroy_check = QCheckBox()
        self.ntcip_destroy_check.setChecked(True)
        form.addRow(
            "Destroy IFM Rows on Stop:",
            self.ntcip_destroy_check,
        )

        recording_group = QGroupBox("PCAP Recording")
        recording_form = QFormLayout(recording_group)

        self.recording_enabled_check = QCheckBox()
        self.recording_enabled_check.setChecked(True)
        recording_form.addRow(
            "Record Packets:",
            self.recording_enabled_check,
        )

        self.recording_interface_edit = QLineEdit("lo")
        self.recording_interface_edit.setPlaceholderText(
            "Examples: lo, eth0, enp60s0"
        )
        recording_form.addRow(
            "Local Interface:",
            self.recording_interface_edit,
        )

        self.pcap_output_label = QLabel(
            f"Output directory: {PCAP_DIRECTORY}"
        )
        self.pcap_output_label.setWordWrap(True)
        recording_form.addRow(self.pcap_output_label)

        left_layout.addWidget(recording_group)

        message_group = QGroupBox("Message Types")
        message_layout = QVBoxLayout(message_group)

        self.msg_list_widget = QListWidget()

        preferred_order = ["MAP", "SPAT", "SPaT", "BSM", "SDSM"]
        added_messages: set[str] = set()

        for message_type in preferred_order:
            if message_type not in PAYLOAD_DICT:
                continue

            self._add_message_item(message_type)
            added_messages.add(message_type)

        for message_type in sorted(PAYLOAD_DICT):
            if message_type not in added_messages:
                self._add_message_item(message_type)

        message_layout.addWidget(self.msg_list_widget)
        left_layout.addWidget(message_group, 1)

        splitter.addWidget(left_widget)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        log_group = QGroupBox("Logs")
        log_group.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        log_layout = QVBoxLayout(log_group)

        self.broadcast_log = QTextEdit()
        self.broadcast_log.setReadOnly(True)
        log_layout.addWidget(self.broadcast_log)

        right_layout.addWidget(log_group, 1)

        metrics_group = QGroupBox("Metrics")
        metrics_group.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        metrics_layout = QVBoxLayout(metrics_group)

        self.metrics_display = QTextEdit()
        self.metrics_display.setReadOnly(True)
        self.metrics_display.setPlaceholderText(
            "Metrics are displayed during or after the broadcast."
        )
        metrics_layout.addWidget(self.metrics_display)

        right_layout.addWidget(metrics_group, 1)

        splitter.addWidget(right_widget)
        splitter.setSizes([500, 640])

        button_row = QHBoxLayout()

        self.start_stop_button = QPushButton(
            "Start Automated Broadcast"
        )
        self.start_stop_button.clicked.connect(self._toggle_broadcast)

        clear_button = QPushButton("Clear Output")
        clear_button.clicked.connect(self._clear_output)

        button_row.addWidget(self.start_stop_button)
        button_row.addWidget(clear_button)
        button_row.addStretch(1)

        main_layout.addLayout(button_row)

        self.protocol_combo.currentIndexChanged.connect(
            self._on_protocol_changed
        )
        self.target_mode_combo.currentIndexChanged.connect(
            self._on_target_mode_changed
        )
        self.payload_dict_combo.currentTextChanged.connect(
            self._on_payload_template_changed
        )
        self.use_matching_payloads_check.toggled.connect(
            self._on_payload_mode_changed
        )
        self.recording_enabled_check.toggled.connect(
            self._on_recording_changed
        )

        self._on_target_mode_changed()
        self._on_protocol_changed()
        self._on_payload_mode_changed()
        self._on_recording_changed()

    def _add_message_item(self, message_type: str) -> None:
        """Add a checkable message type to the list."""
        item = QListWidgetItem(message_type)
        item.setCheckState(
            Qt.CheckState.Checked
            if message_type == "BSM"
            else Qt.CheckState.Unchecked
        )
        self.msg_list_widget.addItem(item)

    def _on_target_mode_changed(self) -> None:
        """Apply defaults for local simulation or a real RSU."""
        using_rsu = self.target_mode_combo.currentData() == "rsu"

        if using_rsu:
            self.amf_rsu_edit.setText("192.168.55.20")
            self.recording_interface_edit.setText("enp60s0")
            self.priority_spin.setValue(3)
            self.tx_channel_spin.setValue(183)
        else:
            self.amf_rsu_edit.setText("127.0.0.1")
            self.recording_interface_edit.setText("lo")
            self.priority_spin.setValue(7)
            self.tx_channel_spin.setValue(172)

        self._on_protocol_changed()

    def _on_protocol_changed(self) -> None:
        """Enable controls appropriate for the selected protocol."""
        is_ntcip = self._is_ntcip()
        using_rsu = self.target_mode_combo.currentData() == "rsu"

        self.ntcip_index_spin.setEnabled(is_ntcip)
        self.ntcip_enable_spin.setEnabled(is_ntcip)
        self.ntcip_options_edit.setEnabled(is_ntcip)
        self.ntcip_destroy_check.setEnabled(is_ntcip)

        self.signature_check.setEnabled(not is_ntcip)
        self.encryption_check.setEnabled(not is_ntcip)
        self.freq_spin.setEnabled(not is_ntcip)

        if is_ntcip:
            self.target_mode_combo.setCurrentIndex(1)
            self.target_mode_combo.setEnabled(False)
            self.amf_rsu_edit.setEnabled(False)
            self.amf_port_spin.setEnabled(False)

            self.priority_spin.setValue(5)
            self.tx_channel_spin.setValue(183)
        else:
            self.target_mode_combo.setEnabled(True)
            self.amf_rsu_edit.setEnabled(True)
            self.amf_port_spin.setEnabled(True)

            if using_rsu:
                self.priority_spin.setValue(3)
                self.tx_channel_spin.setValue(183)
            else:
                self.priority_spin.setValue(7)
                self.tx_channel_spin.setValue(172)

    def _on_payload_template_changed(self, name: str) -> None:
        """Load the selected payload template."""
        self.payload_edit.setText(PAYLOAD_DICT.get(name, ""))

    def _on_payload_mode_changed(self) -> None:
        """Enable custom payload controls when matching is disabled."""
        use_matching_payloads = (
            self.use_matching_payloads_check.isChecked()
        )
        self.payload_dict_combo.setEnabled(not use_matching_payloads)
        self.payload_edit.setEnabled(not use_matching_payloads)

    def _on_recording_changed(self) -> None:
        """Enable the recording interface when recording is selected."""
        self.recording_interface_edit.setEnabled(
            self.recording_enabled_check.isChecked()
        )

    def _is_ntcip(self) -> bool:
        """Return whether NTCIP 1218 is selected."""
        return self.protocol_combo.currentData() == "ntcip1218"

    def _selected_message_types(self) -> list[str]:
        """Return all checked message types."""
        selected: list[str] = []

        for index in range(self.msg_list_widget.count()):
            item = self.msg_list_widget.item(index)

            if item.checkState() == Qt.CheckState.Checked:
                selected.append(item.text())

        return selected

    def _message_payloads(self) -> dict[str, str]:
        """Build the selected message-to-payload mapping."""
        selected_messages = self._selected_message_types()

        if self.use_matching_payloads_check.isChecked():
            return {
                message_type: _normalise_hex(
                    PAYLOAD_DICT.get(message_type, "")
                )
                for message_type in selected_messages
            }

        payload = _normalise_hex(self.payload_edit.text())
        return {
            message_type: payload
            for message_type in selected_messages
        }

    def _validate_hex(
        self,
        value: str,
        field_name: str,
        *,
        allow_empty: bool = False,
    ) -> str | None:
        """Validate one normalized hexadecimal value."""
        if not value:
            if allow_empty:
                return None
            return f"{field_name} cannot be empty."

        if len(value) % 2 != 0:
            return (
                f"{field_name} must contain an even number of "
                "hexadecimal characters."
            )

        try:
            bytes.fromhex(value)
        except ValueError:
            return f"{field_name} must contain valid hexadecimal data."

        return None

    def _validate_input(self) -> str | None:
        """Validate all selected broadcast settings."""
        selected_messages = self._selected_message_types()

        if not selected_messages:
            return "Select at least one message type."

        psid_error = self._validate_hex(
            _normalise_hex(self.psid_edit.text()),
            "PSID",
        )
        if psid_error:
            return psid_error

        message_payloads = self._message_payloads()

        for message_type, payload in message_payloads.items():
            payload_error = self._validate_hex(
                payload,
                f"{message_type} payload",
            )
            if payload_error:
                return payload_error

        if self._is_ntcip():
            options_error = self._validate_hex(
                _normalise_hex(self.ntcip_options_edit.text()),
                "NTCIP options",
            )
            if options_error:
                return options_error

            final_index = (
                self.ntcip_index_spin.value()
                + len(selected_messages)
                - 1
            )
            if final_index > 32:
                return (
                    "The selected messages exceed IFM row 32. "
                    "Choose a lower first IFM index."
                )
        else:
            target_ip = self.amf_rsu_edit.text().strip()
            if not target_ip:
                return "RSU IP address cannot be empty."

        if self.recording_enabled_check.isChecked():
            interface = self.recording_interface_edit.text().strip()
            if not interface:
                return (
                    "Enter a local PCAP interface or disable recording."
                )

        return None

    def _toggle_broadcast(self) -> None:
        """Start a worker or request that the current worker stop."""
        worker = self._broadcast_thread

        if worker is not None and worker.isRunning():
            self._log("Stop requested.")
            worker.stop()
            self.start_stop_button.setEnabled(False)
            return

        validation_error = self._validate_input()
        if validation_error is not None:
            QMessageBox.warning(
                self,
                "Validation Error",
                validation_error,
            )
            return

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.metrics_display.clear()

        if self._is_ntcip():
            self._start_ntcip_worker(timestamp)
        else:
            self._start_rsu41_worker(timestamp)

        worker = self._broadcast_thread
        if worker is None:
            return

        worker.signals.log.connect(self._log)
        worker.signals.error.connect(self._on_broadcast_error)
        worker.signals.metrics_updated.connect(self._update_metrics)
        worker.signals.finished.connect(self._on_broadcast_finished)

        self._set_running_state(True)
        worker.start()

    def _start_rsu41_worker(self, timestamp: str) -> None:
        """Construct the RSU 4.1 local/UDP worker."""
        pcap_path = (
            Path(PCAP_DIRECTORY)
            / f"mock_rsu_4_1_{timestamp}.pcap"
        )

        message_payloads = self._message_payloads()

        # The existing RSU 4.1 worker accepts one payload for the run.
        # When matching mode is used, use the first selected payload.
        payload_hex = next(iter(message_payloads.values()))

        self._broadcast_thread = LocalBroadcastWorker(
            target_ip=self.amf_rsu_edit.text().strip(),
            target_port=self.amf_port_spin.value(),
            selected_messages=self._selected_message_types(),
            frequency_hz=self.freq_spin.value(),
            period_seconds=self.period_spin.value(),
            psid=_normalise_hex(self.psid_edit.text()),
            priority=self.priority_spin.value(),
            tx_channel=self.tx_channel_spin.value(),
            payload_hex=payload_hex,
            signature=self.signature_check.isChecked(),
            encryption=self.encryption_check.isChecked(),
            recording_enabled=(
                self.recording_enabled_check.isChecked()
            ),
            recording_interface=(
                self.recording_interface_edit.text().strip()
            ),
            pcap_path=pcap_path,
        )

    def _start_ntcip_worker(self, timestamp: str) -> None:
        """Construct the NTCIP 1218 Immediate Forward worker."""
        pcap_path = (
            Path(PCAP_DIRECTORY)
            / f"mock_ntcip_1218_{timestamp}.pcap"
        )

        self._broadcast_thread = ExternalBroadcastWorke(
            session_factory=self._session_factory,
            message_payloads=self._message_payloads(),
            first_index=self.ntcip_index_spin.value(),
            psid=_normalise_hex(self.psid_edit.text()),
            channel=self.tx_channel_spin.value(),
            enable=self.ntcip_enable_spin.value(),
            priority=self.priority_spin.value(),
            options=_normalise_hex(
                self.ntcip_options_edit.text()
            ),
            period_seconds=self.period_spin.value(),
            destroy_on_stop=self.ntcip_destroy_check.isChecked(),
            recording_enabled=(
                self.recording_enabled_check.isChecked()
            ),
            recording_interface=(
                self.recording_interface_edit.text().strip()
            ),
            recording_port=self.amf_port_spin.value(),
            pcap_path=pcap_path,
        )

    def _set_running_state(self, running: bool) -> None:
        """Update controls for running or stopped state."""
        self.start_stop_button.setText(
            "Stop Broadcast"
            if running
            else "Start Automated Broadcast"
        )
        self.start_stop_button.setEnabled(True)

        self.protocol_combo.setEnabled(not running)

        if running:
            self.target_mode_combo.setEnabled(False)
        else:
            self._on_protocol_changed()

    def _log(self, message: str) -> None:
        """Append a timestamped message to the log."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.broadcast_log.append(f"[{timestamp}] {message}")

    def _clear_output(self) -> None:
        """Clear logs and metrics."""
        self.broadcast_log.clear()
        self.metrics_display.clear()

    def _on_broadcast_error(self, message: str) -> None:
        """Display an error reported by the worker."""
        self._log(f"ERROR: {message}")
        QMessageBox.warning(
            self,
            "Broadcast Error",
            message,
        )

    def _on_broadcast_finished(self) -> None:
        """Reset the UI after the worker exits."""
        self._set_running_state(False)
        self._broadcast_thread = None

    def _update_metrics(
        self,
        message_type: str,
        metrics: dict[str, Any],
    ) -> None:
        """Display metrics emitted by either worker."""
        errors = metrics.get("error_types", {})
        errors_text = (
            "None"
            if not errors
            else "\n".join(
                f"  {error_type}: {count}"
                for error_type, count in sorted(errors.items())
            )
        )

        throughput = float(metrics.get("throughput_kbps", 0.0))
        total_bytes = int(metrics.get("total_bytes_sent", 0))
        total_messages = int(metrics.get("total_messages_sent", 0))

        text = (
            f"=== Metrics for [{message_type}] ===\n"
            f"Throughput         : {throughput:.2f} kbps\n"
            f"Total Bytes Sent   : {total_bytes} bytes\n"
            f"Total Messages Sent: {total_messages}\n"
            f"Error Type Counts  :\n{errors_text}\n"
            f"{'-' * 48}"
        )

        self.metrics_display.append(text)