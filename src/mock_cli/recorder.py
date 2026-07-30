import select
import shutil
import signal
import subprocess
import time
from pathlib import Path


class Recorder:
    def __init__(
        self,
        interface: str,
        udp_port: int,
        output_path: Path,
    ):
        self.interface = interface
        self.udp_port = udp_port
        self.output_path = output_path
        self.process: subprocess.Popen[str] | None = None
        self.tool_name = ""

    def start(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        tcpdump = shutil.which("tcpdump")
        if tcpdump is None:
            raise RuntimeError(
                "tcpdump was not found. Install it with: "
                "sudo apt install tcpdump"
            )

        command = [
            tcpdump,
            "-i",
            self.interface,
            "-nn",
            "-s",
            "0",
            "-U",
            "-w",
            str(self.output_path),
            "udp",
            "port",
            str(self.udp_port),
        ]

        self.tool_name = "tcpdump"

        self.process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        self._wait_until_ready()

    def _wait_until_ready(self, timeout: float = 5.0) -> None:
        if self.process is None:
            raise RuntimeError("tcpdump process was not created.")

        if self.process.stderr is None:
            raise RuntimeError("Could not monitor tcpdump startup.")

        deadline = time.monotonic() + timeout
        startup_messages: list[str] = []

        while time.monotonic() < deadline:
            return_code = self.process.poll()

            if return_code is not None:
                remaining_output = self.process.stderr.read().strip()
                if remaining_output:
                    startup_messages.append(remaining_output)

                self.process = None
                details = "\n".join(startup_messages)

                raise RuntimeError(
                    "PCAP recording did not start. "
                    f"{details or f'tcpdump exited with code {return_code}.'}"
                )

            readable, _, _ = select.select(
                [self.process.stderr],
                [],
                [],
                0.1,
            )

            if not readable:
                continue

            line = self.process.stderr.readline()
            if not line:
                continue

            line = line.strip()
            startup_messages.append(line)

            if "listening on" in line.lower():
                return

        self.stop()

        details = "\n".join(startup_messages)
        raise RuntimeError(
            "Timed out waiting for tcpdump to begin listening. "
            f"{details or 'No startup output was received.'}"
        )

    def stop(self) -> str:
        if self.process is None:
            return ""

        process = self.process
        self.process = None

        try:
            if process.poll() is None:
                # SIGINT lets tcpdump flush packets and finalize the PCAP.
                process.send_signal(signal.SIGINT)

                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()

                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)

            stderr = (
                process.stderr.read().strip()
                if process.stderr is not None
                else ""
            )

            return stderr
        finally:
            if process.stderr is not None:
                process.stderr.close()