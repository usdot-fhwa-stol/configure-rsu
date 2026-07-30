import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .recorder import Recorder

LogCallback = Callable[[str], None]
MetricsCallback = Callable[[str, dict[str, Any]], None]


class BroadcastRunner:
    def __init__(
        self,
        target_ip: str,
        target_port: int,
        selected_messages: list[str],
        frequency_hz: float,
        period_seconds: int,
        psid: str,
        payload_hex: str,
        priority: int,
        tx_channel: int,
        signature: bool,
        encryption: bool,
        recording_enabled: bool,
        recording_interface: str,
        pcap_path: Path,
        log_callback: LogCallback | None = None,
        metrics_callback: MetricsCallback | None = None,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.selected_messages = selected_messages
        self.frequency_hz = frequency_hz
        self.period_seconds = period_seconds
        self.psid = psid
        self.payload_hex = payload_hex
        self.priority = priority
        self.tx_mode = "CONT"
        self.tx_channel = tx_channel
        self.tx_interval = 0
        self.signature = signature
        self.encryption = encryption
        self.recording_enabled = recording_enabled
        self.recording_interface = recording_interface
        self.pcap_path = pcap_path

        self.log_callback = log_callback
        self.metrics_callback = metrics_callback
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def log(self, message: str) -> None:
        if self.log_callback is not None:
            self.log_callback(message)

    def report_metrics(
        self,
        message_type: str,
        metrics: dict[str, Any],
    ) -> None:
        if self.metrics_callback is not None:
            self.metrics_callback(message_type, metrics)

    def _build_amf(self, message_type: str) -> bytes:
        amf = (
            "Version=0.7\n"
            f"Type={message_type}\n"
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
                self.log(f"Recording packets to {self.pcap_path}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            interval_seconds = 1.0 / max(self.frequency_hz, 0.1)

            self.log(
                f"Starting broadcast to {self.target_ip}:{self.target_port} "
                f"at {self.frequency_hz:.2f} Hz."
            )

            for message_type in self.selected_messages:
                if self._stop_requested:
                    break

                self._broadcast_message_type(
                    sock=sock,
                    message_type=message_type,
                    interval_seconds=interval_seconds,
                )

            if self._stop_requested:
                self.log("Broadcast stopped by user.")
            else:
                self.log("Broadcast complete.")
        finally:
            if sock is not None:
                sock.close()

            if recorder is not None:
                recorder.stop()
                self.log(f"Recording complete: {self.pcap_path}")

    def _broadcast_message_type(
        self,
        sock: socket.socket,
        message_type: str,
        interval_seconds: float,
    ) -> None:
        attempted_count = 0
        sent_count = 0
        total_bytes_sent = 0
        error_types: dict[str, int] = {}

        message_start = time.monotonic()
        message_end = message_start + self.period_seconds
        next_send = message_start
        data = self._build_amf(message_type)

        self.log(
            f"Broadcasting {message_type} for "
            f"{self.period_seconds} second(s)."
        )

        while not self._stop_requested and time.monotonic() < message_end:
            now = time.monotonic()

            if now < next_send:
                time.sleep(min(next_send - now, 0.025))
                continue

            attempted_count += 1

            try:
                sock.sendto(
                    data,
                    (self.target_ip, self.target_port),
                )
                sent_count += 1
                total_bytes_sent += len(data)
            except OSError as exc:
                error_name = type(exc).__name__
                error_types[error_name] = (
                    error_types.get(error_name, 0) + 1
                )
                self.log(f"[{message_type}] send error: {exc}")

            next_send += interval_seconds

            if next_send < time.monotonic() - interval_seconds:
                next_send = time.monotonic()

        elapsed_seconds = max(time.monotonic() - message_start, 0.001)
        throughput_kbps = (
            total_bytes_sent * 8.0 / 1024.0
        ) / elapsed_seconds

        metrics: dict[str, Any] = {
            "attempted_count": attempted_count,
            "total_messages_sent": sent_count,
            "total_bytes_sent": total_bytes_sent,
            "throughput_kbps": throughput_kbps,
            "error_types": error_types,
        }

        self.report_metrics(message_type, metrics)