"""Capture UDP traffic to a PCAP file with tcpdump."""

import shutil
import subprocess
import time
from pathlib import Path


class Recorder:
    """Start and stop a tcpdump packet capture."""

    def __init__(self, interface: str, udp_port: int, output_path: Path):
        """Set up the packet capture.

        Args:
            interface: Network interface to capture.
            udp_port: UDP port to capture.
            output_path: Path for the PCAP file.
        """
        self.interface = interface
        self.udp_port = udp_port
        self.output_path = output_path
        self.process: subprocess.Popen[str] | None = None
        self.tool_name = ""

    def start(self) -> None:
        """Start tcpdump and check that it is still running."""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        tcpdump = shutil.which("tcpdump")
        filter = f"udp port {self.udp_port}"

        command = [
            tcpdump,
            "-i",
            self.interface,
            "-n",
            filter,
            "-w",
            str(self.output_path),
        ]
        self.tool_name = "tcpdump"

        self.process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        time.sleep(0.4)

        if self.process.poll() is not None:
            stderr = self.process.stderr.read().strip() if self.process.stderr else ""
            self.process = None
            raise RuntimeError(
                "PCAP record did not start. "
                f"{stderr or 'Check record permissions and interface name.'}"
            )

    def stop(self) -> None:
        """Stop tcpdump and wait for it to exit."""
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
