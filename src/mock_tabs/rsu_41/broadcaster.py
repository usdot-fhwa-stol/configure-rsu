from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from mock_common.runner import BroadcastRunner


class BroadcastWorkerSignals(QObject):
    log = pyqtSignal(str)
    metrics_updated = pyqtSignal(str, dict)
    finished = pyqtSignal()
    error = pyqtSignal(str)


class BroadcastWorker(QThread):
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