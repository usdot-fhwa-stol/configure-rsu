"""NTCIP 1218 Immediate Forward mock broadcast worker."""

from __future__ import annotations

import threading
import time
from binascii import unhexlify
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from snmp.smi import Integer32, OctetString

from mock_common.recorder import Recorder


def _wait(result: Any) -> Any:
    """Wait for an asynchronous SNMP result when necessary."""
    return result.wait() if hasattr(result, "wait") else result


class ExternalBroadcastSignals(QObject):
    log = pyqtSignal(str)
    metrics_updated = pyqtSignal(str, dict)
    finished = pyqtSignal()
    error = pyqtSignal(str)


class ExternalBroadcastWorker(QThread):
    """Configure NTCIP 1218 IFM rows for selected mock messages."""

    IFM_BASE_OID = "1.3.6.1.4.1.1206.4.2.18.4.2.1"
    MODE_OID = "1.3.6.1.4.1.1206.4.2.18.16.2.0"

    STANDBY_MODE = 2
    OPERATE_MODE = 3
    ACTIVE_ROW_STATUS = 4
    DESTROY_ROW_STATUS = 6

    def __init__(
        self,
        *,
        session_factory: Callable[[], Any],
        message_payloads: dict[str, str],
        first_index: int,
        psid: str,
        channel: int,
        enable: int,
        priority: int,
        options: str,
        period_seconds: int,
        destroy_on_stop: bool,
        recording_enabled: bool,
        recording_interface: str,
        recording_port: int,
        pcap_path: Path,
    ) -> None:
        super().__init__()

        self.signals = NtcipBroadcastSignals()
        self._session_factory = session_factory
        self._message_payloads = message_payloads
        self._first_index = first_index
        self._psid = psid
        self._channel = channel
        self._enable = enable
        self._priority = priority
        self._options = options
        self._period_seconds = period_seconds
        self._destroy_on_stop = destroy_on_stop
        self._recording_enabled = recording_enabled
        self._recording_interface = recording_interface
        self._recording_port = recording_port
        self._pcap_path = pcap_path

        self._stop_event = threading.Event()
        self._configured_indices: list[int] = []

    def stop(self) -> None:
        """Request worker shutdown."""
        self._stop_event.set()

    def run(self) -> None:
        recorder: Recorder | None = None
        started_at = time.monotonic()

        try:
            if self._recording_enabled:
                recorder = Recorder(
                    interface=self._recording_interface,
                    udp_port=self._recording_port,
                    output_path=self._pcap_path,
                )
                recorder.start()
                self.signals.log.emit(
                    f"Recording packets to {self._pcap_path}"
                )

            self._set_mode(self.STANDBY_MODE)
            self.signals.log.emit("RSU placed in standby mode.")

            for offset, (message_type, payload) in enumerate(
                self._message_payloads.items()
            ):
                if self._stop_event.is_set():
                    break

                index = self._first_index + offset
                self._set_ifm_entry(index, payload)
                self._configured_indices.append(index)

                self.signals.log.emit(
                    f"Configured IFM row {index} for {message_type}."
                )

                self.signals.metrics_updated.emit(
                    message_type,
                    {
                        "attempted_count": 1,
                        "total_messages_sent": 1,
                        "total_bytes_sent": len(unhexlify(payload)),
                        "throughput_kbps": 0.0,
                        "error_types": {},
                    },
                )

            if self._configured_indices:
                self._set_mode(self.OPERATE_MODE)
                self.signals.log.emit(
                    "RSU placed in operate mode; IFM rows are active."
                )

                self._stop_event.wait(self._period_seconds)

            if self._destroy_on_stop and self._configured_indices:
                self._set_mode(self.STANDBY_MODE)

                for index in self._configured_indices:
                    self._destroy_ifm_entry(index)
                    self.signals.log.emit(f"Destroyed IFM row {index}.")

                self._set_mode(self.OPERATE_MODE)

            if self._stop_event.is_set():
                self.signals.log.emit("NTCIP 1218 mock broadcast stopped.")
            else:
                self.signals.log.emit("NTCIP 1218 mock broadcast complete.")

        except Exception as exc:
            self.signals.error.emit(str(exc))
        finally:
            if recorder is not None:
                try:
                    recorder.stop()
                    self.signals.log.emit(
                        f"Recording complete: {self._pcap_path}"
                    )
                except Exception as exc:
                    self.signals.error.emit(
                        f"Could not stop packet recording: {exc}"
                    )

            self.signals.finished.emit()

    def _set_mode(self, mode: int) -> None:
        session = self._session_factory()

        current_result = _wait(session.get(self.MODE_OID))
        current_value = current_result[0].value
        current_mode = getattr(current_value, "value", current_value)

        if current_mode == mode:
            return

        _wait(
            session.set(
                (self.MODE_OID, Integer32(mode)),
            )
        )

        verify_result = _wait(session.get(self.MODE_OID))
        verify_value = verify_result[0].value
        verified_mode = getattr(verify_value, "value", verify_value)

        if verified_mode != mode:
            raise RuntimeError(
                "RSU mode verification failed: "
                f"expected {mode}, got {verified_mode}."
            )

    def _set_ifm_entry(self, index: int, payload: str) -> None:
        base = self.IFM_BASE_OID
        session = self._session_factory()

        result = session.set(
            (
                f"{base}.2.{index}",
                OctetString(unhexlify(self._psid)),
            ),
            (f"{base}.3.{index}", Integer32(self._channel)),
            (f"{base}.4.{index}", Integer32(self._enable)),
            (
                f"{base}.5.{index}",
                Integer32(self.ACTIVE_ROW_STATUS),
            ),
            (f"{base}.6.{index}", Integer32(self._priority)),
            (
                f"{base}.7.{index}",
                OctetString(unhexlify(self._options)),
            ),
            (
                f"{base}.8.{index}",
                OctetString(unhexlify(payload)),
            ),
        )
        _wait(result)

    def _destroy_ifm_entry(self, index: int) -> None:
        oid = (
            f"{self.IFM_BASE_OID}.5.{index}"
        )
        session = self._session_factory()
        _wait(
            session.set(
                (oid, Integer32(self.DESTROY_ROW_STATUS)),
            )
        )