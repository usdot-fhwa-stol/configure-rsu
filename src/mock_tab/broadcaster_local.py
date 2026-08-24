from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from mock_common.runner import BroadcastRunner


class LocalBroadcastWorkerSignals(QObject):
    """Signals emitted by `BroadcastWorker`."""
    log = pyqtSignal(str)
    metrics_updated = pyqtSignal(str, dict)
    finished = pyqtSignal()
    error = pyqtSignal(str)


class LocalBroadcastWorker(QThread):
    """Send mock RSU 4.1 AMF messages without blocking the UI thread."""

    def __init__(
        self,
        *,
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
    ):
        """Set up the broadcast worker.

        Args:
            target_ip: IP address of the target RSU.
            target_port: UDP port used by the target.
            selected_messages: AMF message types to send.
            frequency_hz: Messages sent per second.
            period_seconds: How long to send each message type.
            psid: PSID value for outgoing messages.
            payload_hex: Hex payload included in outgoing messages.
            signature: Whether to mark messages as signed.
            encryption: Whether to mark messages as encrypted.
            recording_enabled: Whether to record traffic to a PCAP file.
            recording_interface: Interface used for packet capture.
            pcap_path: Path for the PCAP output file.
        """
        super().__init__()

        self.signals = BroadcastWorkerSignals()

        self.runner = BroadcastRunner(
            target_ip=target_ip,
            target_port=target_port,
            selected_messages=selected_messages,
            frequency_hz=frequency_hz,
            period_seconds=period_seconds,
            psid=psid,
            payload_hex=payload_hex,
            priority=priority,
            tx_channel=tx_channel,
            signature=signature,
            encryption=encryption,
            recording_enabled=recording_enabled,
            recording_interface=recording_interface,
            pcap_path=pcap_path,
            log_callback=self.signals.log.emit,
            metrics_callback=self.signals.metrics_updated.emit,
        )

    def stop(self) -> None:
        self.runner.stop()

    def run(self) -> None:
        try:
            self.runner.run()
        except Exception as exc:
            self.signals.error.emit(str(exc))
        finally:
            self.signals.finished.emit()
