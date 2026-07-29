import socket
import time
from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from .recorder import Recorder


class _BroadcastWorkerSignals(QObject):
    log = pyqtSignal(str)
    metrics_updated = pyqtSignal(str, dict)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    pcap_started = pyqtSignal(str)
    pcap_finished = pyqtSignal(str)


class _BroadcastWorker(QThread):
    def __init__(
        self,
        target_ip: str,
        target_port: int,
        selected_messages: list[str],
        frequency_hz: float,
        period_seconds: int,
        psid: str,
        payload_hex: str,
        signature: bool,
        encryption: bool,
        recording_enabled: bool,
        recording_interface: str,
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
        self.prio = 7
        self.tx_mode = "CONT"
        self.tx_channel = 172
        self.tx_interval = 0
        self.signature = signature
        self.encryption = encryption
        self.recording_enabled = recording_enabled
        self.recording_interface = recording_interface
        self.pcap_path = pcap_path
        self.signals = _BroadcastWorkerSignals()
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def _build_amf(self, message_type: str) -> bytes:
        amf = (
            "Version=0.7\n"
            f"Type={message_type}\n"
            f"PSID={self.psid}\n"
            f"Priority={self.prio}\n"
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

    def run(self) -> None:
        recorder: Recorder | None = None
        sock: socket.socket | None = None

        try:
            if self.recording_enabled:
                recorder = Recorder(
                    interface=self.recording_interface,
                    udp_port=self.target_port,
                    output_path=self.pcap_path,
                )
                recorder.start()
                self.signals.pcap_started.emit(str(self.pcap_path))

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            interval_seconds = 1.0 / max(self.frequency_hz, 0.1)
            self.signals.log.emit(
                f"Starting broadcast to {self.target_ip}:{self.target_port} "
                f"at {self.frequency_hz:.2f} Hz."
            )

            for message_type in self.selected_messages:
                if self._stop_requested:
                    break

                attempted_count = sent_count = total_bytes_sent = 0
                error_types: dict[str, int] = {}

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
                    data = self._build_amf(message_type)

                    try:
                        sock.sendto(data, (self.target_ip, self.target_port))
                        sent_count += 1
                        total_bytes_sent += len(data)
                    except OSError as exc:
                        error_name = type(exc).__name__
                        error_types[error_name] = error_types.get(error_name, 0) + 1
                        self.signals.log.emit(f"[{message_type}] send error: {exc}")

                    next_send += interval_seconds

                    if next_send < time.monotonic() - interval_seconds:
                        next_send = time.monotonic()

                elapsed_seconds = max(time.monotonic() - message_start, 0.001)
                throughput_kbps = (total_bytes_sent * 8.0 / 1024.0) / elapsed_seconds

                metrics = {
                    "attempted_count": attempted_count,
                    "total_messages_sent": sent_count,
                    "total_bytes_sent": total_bytes_sent,
                    "throughput_kbps": throughput_kbps,
                    "error_types": error_types,
                }

                self.signals.metrics_updated.emit(message_type, metrics)

            if self._stop_requested:
                self.signals.log.emit("Broadcast stopped by user.")
            else:
                self.signals.log.emit("Broadcast complete.")

        except Exception as exc:
            self.signals.error.emit(str(exc))
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

            if recorder is not None:
                try:
                    recorder.stop()
                    self.signals.pcap_finished.emit(str(self.pcap_path))
                except Exception as exc:
                    self.signals.error.emit(f"Could not stop PCAP recording: {exc}")

            self.signals.finished.emit()
