import datetime
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
    QLabel,
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

from sample_hex_payloads import PAYLOAD_DICT

HEX_REGEX = QRegularExpression(r"^[0-9A-Fa-f]*$")
AMF_MESSAGE_TYPES = {"MAP", "SPAT", "BSM", "SDSM"}
REPO_ROOT = Path(__file__).resolve().parent
PCAP_DIRECTORY = REPO_ROOT / "pcaps"


def _hex_validator() -> QRegularExpressionValidator:
    return QRegularExpressionValidator(HEX_REGEX)


def _make_spinbox(
    value: int,
    minimum: int,
    maximum: int,
    readonly: bool = False,
) -> QSpinBox:
    spinbox = QSpinBox()
    spinbox.setRange(minimum, maximum)
    spinbox.setValue(value)

    if readonly:
        spinbox.setReadOnly(True)
        spinbox.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)

    return spinbox


def _make_hex_edit(value: str = "") -> QLineEdit:
    line_edit = QLineEdit(value)
    line_edit.setValidator(_hex_validator())
    return line_edit


def _normalise_hex(value: str) -> str:
    return value.strip().replace(" ", "").upper()


def _parse_amf(data: bytes) -> Dict[str, str]:
    """
    Parse the text AMF representation used by the existing active-message tab.

    This validates transport-format fields only. Payload semantic validation,
    such as J2735 ASN.1 decoding, is out of scope for the mock listener.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("AMF data is not UTF-8 text") from exc

    fields: Dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        key, separator, value = line.partition("=")

        if not separator or not key.strip():
            raise ValueError(f"Malformed AMF line: {raw_line!r}")

        fields[key.strip()] = value.strip()

    required_fields = {
        "Version",
        "Type",
        "Sequence",
        "PSID",
        "Priority",
        "TxMode",
        "TxChannel",
        "TxInterval",
        "DeliveryStart",
        "DeliveryStop",
        "Signature",
        "Encryption",
        "Payload",
    }

    missing = sorted(required_fields.difference(fields))

    if missing:
        raise ValueError(f"Missing AMF fields: {', '.join(missing)}")

    if fields["Version"] != "0.7":
        raise ValueError(f"Unsupported AMF version: {fields['Version']}")

    if fields["Type"] not in AMF_MESSAGE_TYPES:
        raise ValueError(f"Unsupported message type: {fields['Type']}")

    if fields["TxMode"] not in {"CONT", "ALT"}:
        raise ValueError(f"Unsupported TxMode: {fields['TxMode']}")

    if fields["Signature"] not in {"True", "False"}:
        raise ValueError("Signature must be True or False")

    if fields["Encryption"] not in {"True", "False"}:
        raise ValueError("Encryption must be True or False")

    try:
        int(fields["Sequence"])
        int(fields["Priority"])
        int(fields["TxChannel"])
        int(fields["TxInterval"])
    except ValueError as exc:
        raise ValueError(
            "Sequence, Priority, TxChannel, or TxInterval is invalid"
        ) from exc

    psid = _normalise_hex(fields["PSID"])
    payload = _normalise_hex(fields["Payload"])

    if not psid:
        raise ValueError("PSID cannot be empty")

    if len(psid) % 2 != 0:
        raise ValueError("PSID must have an even number of hex characters")

    if len(payload) % 2 != 0:
        raise ValueError("Payload must have an even number of hex characters")

    try:
        bytes.fromhex(psid)
        bytes.fromhex(payload)
    except ValueError as exc:
        raise ValueError("PSID or Payload contains invalid hex characters") from exc

    return fields


class _PacketCapture:
    """
    Manages a real PCAP process using dumpcap when available, falling back to
    tcpdump. The process captures UDP traffic for the configured RSU port.
    """

    def __init__(self, interface: str, udp_port: int, output_path: Path):
        self.interface = interface
        self.udp_port = udp_port
        self.output_path = output_path
        self.process: Optional[subprocess.Popen[str]] = None
        self.tool_name = ""

    def start(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        dumpcap = shutil.which("dumpcap")
        tcpdump = shutil.which("tcpdump")
        capture_filter = f"udp port {self.udp_port}"

        if dumpcap:
            command = [
                dumpcap,
                "-i",
                self.interface,
                "-f",
                capture_filter,
                "-w",
                str(self.output_path),
            ]
            self.tool_name = "dumpcap"
        elif tcpdump:
            command = [
                tcpdump,
                "-i",
                self.interface,
                "-n",
                capture_filter,
                "-w",
                str(self.output_path),
            ]
            self.tool_name = "tcpdump"
        else:
            raise RuntimeError(
                "PCAP capture requires dumpcap or tcpdump in PATH. "
                "Install Wireshark/dumpcap or tcpdump, then try again."
            )

        self.process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        time.sleep(0.4)

        if self.process.poll() is not None:
            stderr = ""

            if self.process.stderr is not None:
                stderr = self.process.stderr.read().strip()

            self.process = None

            raise RuntimeError(
                "PCAP capture did not start. "
                f"{stderr or 'Check capture permissions and interface name.'}"
            )

    def stop(self) -> None:
        if self.process is None:
            return

        if self.process.poll() is None:
            self.process.terminate()

            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)

        self.process = None


class _FakeRsuListenerSignals(QObject):
    started = pyqtSignal(int)
    received = pyqtSignal(str, int, str, int)
    rejected = pyqtSignal(str, str, int)
    error = pyqtSignal(str)
    stopped = pyqtSignal()


class _FakeRsuListenerTask(QRunnable):
    """
    UDP fake RSU listener.

    It accepts the existing text AMF format, validates the fields, and sends a
    mock acknowledgement back to the sending socket.

    The ACK protocol is local-test-only and is not an RSU 4.1 wire protocol.
    """

    def __init__(self, bind_ip: str, bind_port: int):
        super().__init__()
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.signals = _FakeRsuListenerSignals()
        self._socket: Optional[socket.socket] = None
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass

    def run(self) -> None:
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self.bind_ip, self.bind_port))
            self._socket.settimeout(0.25)
            self.signals.started.emit(self.bind_port)
        except OSError as exc:
            self.signals.error.emit(
                f"Fake RSU could not bind {self.bind_ip}:{self.bind_port}: {exc}"
            )
            return

        try:
            while not self._stop_requested:
                try:
                    data, address = self._socket.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break

                sender_ip, sender_port = address

                try:
                    fields = _parse_amf(data)
                    message_type = fields["Type"]
                    sequence = int(fields["Sequence"])

                    acknowledgement = (
                        f"ACK\nType={message_type}\nSequence={sequence}\nStatus=OK\n"
                    ).encode("utf-8")

                    self._socket.sendto(acknowledgement, address)

                    self.signals.received.emit(
                        message_type,
                        sequence,
                        sender_ip,
                        sender_port,
                    )
                except (OSError, ValueError) as exc:
                    reason = str(exc)

                    try:
                        rejection = (
                            "ACK\n"
                            "Type=UNKNOWN\n"
                            "Sequence=-1\n"
                            "Status=ERROR\n"
                            f"Reason={reason}\n"
                        ).encode("utf-8")

                        self._socket.sendto(rejection, address)
                    except OSError:
                        pass

                    self.signals.rejected.emit(reason, sender_ip, sender_port)
        finally:
            if self._socket is not None:
                try:
                    self._socket.close()
                except OSError:
                    pass

            self._socket = None
            self.signals.stopped.emit()


class _BroadcastWorkerSignals(QObject):
    log = pyqtSignal(str)
    metrics_updated = pyqtSignal(str, dict)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    pcap_started = pyqtSignal(str)
    pcap_finished = pyqtSignal(str)


class _BroadcastWorker(QThread):
    """
    Sends each selected AMF type for the configured period.

    In fake mode, waits for matching UDP ACK messages from the mock listener
    and calculates round-trip latency. In real mode, ACKs are optional:
    a non-ACKing real RSU produces no latency/drop measurement.
    """

    def __init__(
        self,
        target_ip: str,
        target_port: int,
        selected_messages: List[str],
        frequency_hz: float,
        period_seconds: int,
        psid: str,
        payload_hex: str,
        priority: int,
        tx_mode: str,
        tx_channel: int,
        tx_interval: int,
        signature: bool,
        encryption: bool,
        use_fake_rsu: bool,
        ack_timeout_seconds: float,
        capture_enabled: bool,
        capture_interface: str,
        pcap_path: Path,
    ):
        super().__init__()
        self.target_ip = target_ip
        self.target_port = target_port
        self.selected_messages = selected_messages
        self.frequency_hz = frequency_hz
        self.period_seconds = period_seconds
        self.psid = psid
        self.payload_hex = payload_hex
        self.priority = priority
        self.tx_mode = tx_mode
        self.tx_channel = tx_channel
        self.tx_interval = tx_interval
        self.signature = signature
        self.encryption = encryption
        self.use_fake_rsu = use_fake_rsu
        self.ack_timeout_seconds = ack_timeout_seconds
        self.capture_enabled = capture_enabled
        self.capture_interface = capture_interface
        self.pcap_path = pcap_path
        self.signals = _BroadcastWorkerSignals()
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    @staticmethod
    def _parse_ack(data: bytes) -> Dict[str, str]:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("ACK was not UTF-8 text") from exc

        lines = [line.strip() for line in text.splitlines() if line.strip()]

        if not lines or lines[0] != "ACK":
            raise ValueError("Received non-ACK UDP payload")

        fields: Dict[str, str] = {}

        for line in lines[1:]:
            key, separator, value = line.partition("=")

            if separator:
                fields[key.strip()] = value.strip()

        if "Sequence" not in fields or "Status" not in fields:
            raise ValueError("ACK is missing Sequence or Status")

        return fields

    def _build_amf(self, message_type: str, sequence: int) -> bytes:
        amf = (
            "Version=0.7\n"
            f"Type={message_type}\n"
            f"Sequence={sequence}\n"
            f"PSID={self.psid}\n"
            f"Priority={self.priority}\n"
            f"TxMode={self.tx_mode}\n"
            f"TxChannel={self.tx_channel}\n"
            f"TxInterval={self.tx_interval}\n"
            "DeliveryStart=\n"
            "DeliveryStop=\n"
            f"Signature={str(self.signature)}\n"
            f"Encryption={str(self.encryption)}\n"
            f"Payload={self.payload_hex}\n"
        )
        return amf.encode("utf-8")

    def _wait_for_matching_ack(
        self,
        sock: socket.socket,
        expected_sequence: int,
    ) -> Tuple[Optional[float], Optional[str]]:
        """
        Returns (latency_ms, error_type).

        A None error means a matching successful ACK was received.
        """
        deadline = time.monotonic() + self.ack_timeout_seconds

        while not self._stop_requested:
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                return None, "AckTimeout"

            sock.settimeout(min(remaining, 0.2))

            try:
                data, _address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                return None, type(exc).__name__

            try:
                ack = self._parse_ack(data)
                received_sequence = int(ack["Sequence"])
            except (ValueError, KeyError):
                return None, "MalformedAck"

            if received_sequence != expected_sequence:
                continue

            if ack["Status"] != "OK":
                return None, "RejectedAck"

            return time.monotonic(), None

        return None, "Stopped"

    def run(self) -> None:
        capture: Optional[_PacketCapture] = None
        sock: Optional[socket.socket] = None

        try:
            if self.capture_enabled:
                capture = _PacketCapture(
                    interface=self.capture_interface,
                    udp_port=self.target_port,
                    output_path=self.pcap_path,
                )
                capture.start()
                self.signals.pcap_started.emit(str(self.pcap_path))
                self.signals.log.emit(
                    f"PCAP capture started using {capture.tool_name}: {self.pcap_path}"
                )

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            interval_seconds = 1.0 / max(self.frequency_hz, 0.1)
            self.signals.log.emit(
                f"Starting broadcast to {self.target_ip}:{self.target_port} "
                f"at {self.frequency_hz:.2f} Hz."
            )

            if self.use_fake_rsu:
                self.signals.log.emit(
                    "Fake RSU acknowledgements are enabled; "
                    "latency and dropped-message metrics are active."
                )
            else:
                self.signals.log.emit(
                    "Real RSU mode is selected. Latency and dropped-message "
                    "metrics require a compatible UDP acknowledgement."
                )

            global_sequence = 1

            for message_type in self.selected_messages:
                if self._stop_requested:
                    break

                attempted_count = 0
                sent_count = 0
                dropped_count = 0
                total_bytes_sent = 0
                latencies_ms: List[float] = []
                error_types: Dict[str, int] = {}

                message_start = time.monotonic()
                message_end = message_start + self.period_seconds
                next_send = message_start

                self.signals.log.emit(
                    f"Broadcasting {message_type} for {self.period_seconds} second(s)."
                )

                while not self._stop_requested and time.monotonic() < message_end:
                    now = time.monotonic()

                    if now < next_send:
                        time.sleep(min(next_send - now, 0.025))
                        continue

                    attempted_count += 1
                    sequence = global_sequence
                    global_sequence += 1
                    data = self._build_amf(message_type, sequence)

                    send_started = time.monotonic()

                    try:
                        sock.sendto(data, (self.target_ip, self.target_port))
                        sent_count += 1
                        total_bytes_sent += len(data)
                    except OSError as exc:
                        error_name = type(exc).__name__
                        error_types[error_name] = error_types.get(error_name, 0) + 1
                        self.signals.log.emit(
                            f"[{message_type}] send error for sequence "
                            f"{sequence}: {exc}"
                        )
                        next_send += interval_seconds
                        continue

                    if self.use_fake_rsu:
                        ack_time, ack_error = self._wait_for_matching_ack(
                            sock,
                            sequence,
                        )

                        if ack_error is None and ack_time is not None:
                            latencies_ms.append((ack_time - send_started) * 1000.0)
                        elif ack_error != "Stopped":
                            dropped_count += 1
                            error_types[ack_error] = error_types.get(ack_error, 0) + 1

                    next_send += interval_seconds

                    if next_send < time.monotonic() - interval_seconds:
                        next_send = time.monotonic()

                elapsed_seconds = max(time.monotonic() - message_start, 0.001)
                average_latency = (
                    sum(latencies_ms) / len(latencies_ms) if latencies_ms else None
                )
                throughput_kbps = (total_bytes_sent * 8.0 / 1024.0) / elapsed_seconds

                metrics = {
                    "attempted_count": attempted_count,
                    "total_messages_sent": sent_count,
                    "messages_dropped": dropped_count,
                    "total_bytes_sent": total_bytes_sent,
                    "throughput_kbps": throughput_kbps,
                    "average_latency_ms": average_latency,
                    "ack_count": len(latencies_ms),
                    "error_types": error_types,
                    "elapsed_seconds": elapsed_seconds,
                }

                self.signals.metrics_updated.emit(message_type, metrics)

            if self._stop_requested:
                self.signals.log.emit("Broadcast stopped by user.")
            else:
                self.signals.log.emit("Broadcast sequence complete.")

        except Exception as exc:
            self.signals.error.emit(str(exc))
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

            if capture is not None:
                try:
                    capture.stop()
                    self.signals.pcap_finished.emit(str(self.pcap_path))
                    self.signals.log.emit(f"PCAP saved: {self.pcap_path}")
                except Exception as exc:
                    self.signals.error.emit(f"Could not stop PCAP capture: {exc}")

            self.signals.finished.emit()


class MockRsuApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mock RSU 4.1 Broadcast Simulator")
        self.resize(1120, 760)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._broadcast_thread: Optional[_BroadcastWorker] = None
        self._fake_rsu_task: Optional[_FakeRsuListenerTask] = None

        self._create_mock_rsu_41_tab()

    def closeEvent(self, event) -> None:
        if self._broadcast_thread is not None:
            self._broadcast_thread.stop()
            self._broadcast_thread.wait(3000)

        self._stop_fake_listener()
        event.accept()

    def _create_mock_rsu_41_tab(self) -> None:
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
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
        self.target_mode_combo.addItems(
            [
                "Fake RSU (local loopback)",
                "Real RSU",
            ]
        )
        form.addRow("Target Mode:", self.target_mode_combo)

        self.amf_rsu_edit = QLineEdit("127.0.0.1")
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
        form.addRow("Period per Message:", self.period_spin)

        self.ack_timeout_spin = QDoubleSpinBox()
        self.ack_timeout_spin.setRange(0.01, 10.0)
        self.ack_timeout_spin.setDecimals(2)
        self.ack_timeout_spin.setValue(0.50)
        self.ack_timeout_spin.setSuffix(" sec")
        form.addRow("Fake ACK Timeout:", self.ack_timeout_spin)

        self.psid_edit = _make_hex_edit("8002")
        self.psid_edit.setPlaceholderText("Example: 8002")
        form.addRow("PSID:", self.psid_edit)

        self.priority_spin = _make_spinbox(3, 0, 7)
        self.priority_spin.setValue(7)
        form.addRow("Priority:", self.priority_spin)

        self.tx_mode_combo = QComboBox()
        self.tx_mode_combo.addItems(["CONT", "ALT"])
        self.tx_mode_combo.setCurrentText("CONT")
        form.addRow("Tx Mode:", self.tx_mode_combo)

        self.tx_channel_spin = _make_spinbox(183, 1, 255, readonly=True)
        self.tx_channel_spin.setValue(172)
        form.addRow("Tx Channel:", self.tx_channel_spin)

        self.tx_interval_spin = _make_spinbox(0, 0, 1_000_000, readonly=True)
        self.tx_interval_spin.setValue(0)
        form.addRow("Tx Interval:", self.tx_interval_spin)

        self.signature_check = QCheckBox()
        form.addRow("Signature:", self.signature_check)

        self.encryption_check = QCheckBox()
        form.addRow("Encryption:", self.encryption_check)

        self.payload_dict_combo = QComboBox()
        self.payload_dict_combo.addItems(sorted(PAYLOAD_DICT.keys()))
        form.addRow("Payload Preset:", self.payload_dict_combo)

        initial_payload = PAYLOAD_DICT.get(
            self.payload_dict_combo.currentText(),
            "",
        )
        self.payload_edit = _make_hex_edit(initial_payload)
        self.payload_edit.setPlaceholderText("Hex payload bytes")
        form.addRow("Message Payload:", self.payload_edit)

        self.payload_dict_combo.currentTextChanged.connect(
            lambda name: self.payload_edit.setText(PAYLOAD_DICT.get(name, ""))
        )

        capture_group = QGroupBox("PCAP Capture")
        capture_form = QFormLayout(capture_group)

        self.capture_enabled_check = QCheckBox()
        self.capture_enabled_check.setChecked(True)
        capture_form.addRow("Capture Packets:", self.capture_enabled_check)

        self.capture_interface_edit = QLineEdit("lo")
        self.capture_interface_edit.setPlaceholderText("Linux loopback is usually lo")
        capture_form.addRow("Interface:", self.capture_interface_edit)

        self.pcap_output_label = QLabel(f"Output directory: {PCAP_DIRECTORY}")
        self.pcap_output_label.setWordWrap(True)
        capture_form.addRow(self.pcap_output_label)

        left_layout.addWidget(capture_group)

        message_group = QGroupBox("Select Message Types to Broadcast")
        message_layout = QVBoxLayout(message_group)

        self.msg_list_widget = QListWidget()

        for message_type in ["MAP", "SPAT", "BSM", "SDSM"]:
            item = QListWidgetItem(message_type)
            item.setCheckState(
                Qt.CheckState.Checked
                if message_type in {"MAP", "SPAT"}
                else Qt.CheckState.Unchecked
            )
            self.msg_list_widget.addItem(item)

        message_layout.addWidget(self.msg_list_widget)
        left_layout.addWidget(message_group, 1)

        splitter.addWidget(left_widget)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        log_group = QGroupBox("Broadcast and Fake RSU Log")
        log_layout = QVBoxLayout(log_group)

        self.amf_log = QTextEdit()
        self.amf_log.setReadOnly(True)
        self.amf_log.setPlaceholderText(
            "Broadcast status, Fake RSU validation, and PCAP events appear here."
        )
        log_layout.addWidget(self.amf_log)

        right_layout.addWidget(log_group, 1)

        metric_group = QGroupBox("Per-Message Metrics")
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

        self.tabs.addTab(tab, "Send Active Message (RSU 4.1)")

    def _log(self, message: str) -> None:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.amf_log.append(f"[{timestamp}] {message}")

    def _clear_output(self) -> None:
        self.amf_log.clear()
        self.metrics_display.clear()

    def _on_target_mode_changed(self, selected_mode: str) -> None:
        is_fake = selected_mode.startswith("Fake")

        if is_fake:
            self.amf_rsu_edit.setText("127.0.0.1")
            self.amf_rsu_edit.setReadOnly(True)
            self.capture_interface_edit.setText("lo")
            self.ack_timeout_spin.setEnabled(True)
        else:
            self.amf_rsu_edit.setReadOnly(False)
            self.ack_timeout_spin.setEnabled(False)

    def _start_fake_listener(self) -> bool:
        if self._fake_rsu_task is not None:
            return True

        task = _FakeRsuListenerTask(
            bind_ip="127.0.0.1",
            bind_port=self.amf_port_spin.value(),
        )

        task.signals.started.connect(
            lambda port: self._log(f"Fake RSU listening on 127.0.0.1:{port}")
        )
        task.signals.received.connect(
            lambda message_type, sequence, ip, port: self._log(
                f"Fake RSU accepted {message_type} sequence {sequence} "
                f"from {ip}:{port}."
            )
        )
        task.signals.rejected.connect(
            lambda reason, ip, port: self._log(
                f"Fake RSU rejected AMF from {ip}:{port}: {reason}"
            )
        )
        task.signals.error.connect(self._log)
        task.signals.stopped.connect(lambda: self._log("Fake RSU listener stopped."))

        self._fake_rsu_task = task
        QThreadPool.globalInstance().start(task)
        time.sleep(0.1)

        return True

    def _stop_fake_listener(self) -> None:
        if self._fake_rsu_task is not None:
            self._fake_rsu_task.stop()
            self._fake_rsu_task = None

    def _selected_message_types(self) -> List[str]:
        selected: List[str] = []

        for index in range(self.msg_list_widget.count()):
            item = self.msg_list_widget.item(index)

            if item.checkState() == Qt.CheckState.Checked:
                selected.append(item.text())

        return selected

    def _validate_input(self) -> Optional[str]:
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

        if self.capture_enabled_check.isChecked():
            interface = self.capture_interface_edit.text().strip()

            if not interface:
                return "Enter a PCAP capture interface or disable packet capture."

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

        is_fake = self.target_mode_combo.currentText().startswith("Fake")

        if is_fake and not self._start_fake_listener():
            QMessageBox.critical(
                self,
                "Fake RSU Error",
                "Unable to start the fake RSU listener.",
            )
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
            priority=self.priority_spin.value(),
            tx_mode=self.tx_mode_combo.currentText(),
            tx_channel=self.tx_channel_spin.value(),
            tx_interval=self.tx_interval_spin.value(),
            signature=self.signature_check.isChecked(),
            encryption=self.encryption_check.isChecked(),
            use_fake_rsu=is_fake,
            ack_timeout_seconds=self.ack_timeout_spin.value(),
            capture_enabled=self.capture_enabled_check.isChecked(),
            capture_interface=self.capture_interface_edit.text().strip(),
            pcap_path=pcap_path,
        )

        self._broadcast_thread.signals.log.connect(self._log)
        self._broadcast_thread.signals.error.connect(self._on_broadcast_error)
        self._broadcast_thread.signals.metrics_updated.connect(self._update_metrics)
        self._broadcast_thread.signals.pcap_started.connect(
            lambda path: self._log(f"Capturing UDP traffic to: {path}")
        )
        self._broadcast_thread.signals.pcap_finished.connect(
            lambda path: self._log(f"Capture complete: {path}")
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
        latency = metrics["average_latency_ms"]

        if latency is None:
            latency_text = "N/A (no matching acknowledgements)"
        else:
            latency_text = f"{latency:.3f} ms"

        errors = metrics["error_types"]

        if not errors:
            errors_text = "None"
        else:
            errors_text = "\n".join(
                f"  {error_type}: {count}"
                for error_type, count in sorted(errors.items())
            )

        text = (
            f"=== Metrics for [{message_type}] ===\n"
            f"Latency (average) : {latency_text}\n"
            f"Throughput        : {metrics['throughput_kbps']:.2f} kbps\n"
            f"Total Bytes Sent  : {metrics['total_bytes_sent']} bytes\n"
            f"Total Messages Sent: {metrics['total_messages_sent']}\n"
            f"Messages Dropped  : {metrics['messages_dropped']}\n"
            f"ACKs Received     : {metrics['ack_count']}\n"
            f"Elapsed Time      : {metrics['elapsed_seconds']:.2f} sec\n"
            f"Error Type Counts :\n{errors_text}\n"
            f"{'-' * 48}"
        )

        self.metrics_display.append(text)


def main() -> None:
    app = QApplication(sys.argv)
    window = MockRsuApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
