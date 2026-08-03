"""Command-line interface for sending mock RSU 4.1 AMF messages."""

import argparse
import datetime
import sys
from pathlib import Path
from typing import Any

from constants import PAYLOAD_DICT, PCAP_DIRECTORY
from utils import _normalise_hex

from .broadcaster import BroadcastRunner

MESSAGE_TYPES = ("MAP", "SPAT", "BSM", "SDSM")

MODE_NO_RSU = "no-rsu"
MODE_USING_RSU = "using-rsu"


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description="Mock RSU 4.1 UDP broadcast simulator.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--mode",
        choices=(MODE_NO_RSU, MODE_USING_RSU),
        default=MODE_NO_RSU,
        help="Select local No-RSU mode or an external RSU.",
    )
    parser.add_argument(
        "--target-ip",
        help="Override the IP address selected by --mode.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1516,
        help="RSU IFM UDP port.",
    )
    parser.add_argument(
        "--frequency",
        type=float,
        default=10.0,
        help="Broadcast frequency in Hz.",
    )
    parser.add_argument(
        "--period",
        type=int,
        default=60,
        help="Broadcast period for each message type in seconds.",
    )
    parser.add_argument(
        "--psid",
        default="8002",
        help="PSID as hexadecimal characters.",
    )
    parser.add_argument(
        "--message",
        dest="messages",
        action="append",
        choices=MESSAGE_TYPES,
        help="Message type to send. May be provided more than once.",
    )
    parser.add_argument(
        "--signature",
        action="store_true",
        help="Set Signature=True in the generated AMF message.",
    )
    parser.add_argument(
        "--encryption",
        action="store_true",
        help="Set Encryption=True in the generated AMF message.",
    )

    payload_group = parser.add_mutually_exclusive_group()
    payload_group.add_argument(
        "--payload",
        help="Raw payload as hexadecimal characters.",
    )
    payload_group.add_argument(
        "--payload-name",
        choices=sorted(PAYLOAD_DICT),
        help="Select a payload from PAYLOAD_DICT.",
    )

    parser.add_argument(
        "--no-record",
        action="store_true",
        help="Disable PCAP recording.",
    )
    parser.add_argument(
        "--interface",
        help="Override the recording interface selected by --mode.",
    )
    parser.add_argument(
        "--pcap-path",
        type=Path,
        help="Override the generated PCAP output path.",
    )

    return parser


def validate_args(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> None:
    """Validate arguments and normalize hexadecimal values."""

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535.")

    if not 0.1 <= args.frequency <= 100.0:
        parser.error("--frequency must be between 0.1 and 100.0 Hz.")

    if not 1 <= args.period <= 3600:
        parser.error("--period must be between 1 and 3600 seconds.")

    psid = _normalise_hex(args.psid)
    payload = _normalise_hex(args.payload)

    if not psid:
        parser.error("--psid cannot be empty.")

    if len(psid) % 2 != 0:
        parser.error("--psid must contain an even number of hex characters.")

    if len(payload) % 2 != 0:
        parser.error("--payload must contain an even number of hex characters.")

    try:
        bytes.fromhex(psid)
        bytes.fromhex(payload)
    except ValueError:
        parser.error("--psid and --payload must contain valid hexadecimal values.")

    if not args.messages:
        parser.error("Select at least one message type with --message.")

    if not args.no_record and not args.interface:
        parser.error(
            "A recording interface is required unless --no-record is used."
        )

    args.psid = psid
    args.payload = payload


def apply_mode_defaults(args: argparse.Namespace) -> None:
    """Apply target, interface, and radio defaults for the selected mode."""

    if args.mode == MODE_USING_RSU:
        default_ip = "192.168.55.20"
        default_interface = "enp60s0"
        args.priority = 3
        args.tx_channel = 183
    else:
        default_ip = "127.0.0.1"
        default_interface = "lo"
        args.priority = 7
        args.tx_channel = 172

    if args.target_ip is None:
        args.target_ip = default_ip

    if args.interface is None:
        args.interface = default_interface


def resolve_payload(args: argparse.Namespace) -> None:
    """Set the payload from the command line, a named payload, or a default."""

    if args.payload is not None:
        return

    if args.payload_name is not None:
        args.payload = PAYLOAD_DICT[args.payload_name]
        return

    if PAYLOAD_DICT:
        first_name = sorted(PAYLOAD_DICT)[0]
        args.payload = PAYLOAD_DICT[first_name]
        return

    args.payload = ""


def make_pcap_path(args: argparse.Namespace) -> Path:
    """Return the requested PCAP path or create a timestamped default path."""

    if args.pcap_path is not None:
        return args.pcap_path

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return PCAP_DIRECTORY / f"mock_rsu_4_1_{timestamp}.pcap"


def log(message: str) -> None:
    """Print a timestamped log message."""

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def print_metrics(
    message_type: str,
    metrics: dict[str, Any],
) -> None:
    """Print send metrics for a message type."""

    errors = metrics["error_types"]

    if errors:
        errors_text = "\n".join(
            f"  {error_type}: {count}"
            for error_type, count in sorted(errors.items())
        )
    else:
        errors_text = "None"

    print(
        f"\n=== Metrics for [{message_type}] ===\n"
        f"Throughput         : "
        f"{metrics['throughput_kbps']:.2f} kbps\n"
        f"Attempted Messages : {metrics['attempted_count']}\n"
        f"Total Bytes Sent   : {metrics['total_bytes_sent']} bytes\n"
        f"Total Messages Sent: {metrics['total_messages_sent']}\n"
        f"Error Type Counts  :\n{errors_text}\n"
        f"{'-' * 48}",
        flush=True,
    )


def main() -> int:
    """Parse arguments, run the broadcast, and return an exit code."""

    parser = build_parser()
    args = parser.parse_args()

    apply_mode_defaults(args)
    resolve_payload(args)
    validate_args(parser, args)

    pcap_path = make_pcap_path(args)

    runner = BroadcastRunner(
        target_ip=args.target_ip,
        target_port=args.port,
        selected_messages=args.messages,
        frequency_hz=args.frequency,
        period_seconds=args.period,
        psid=args.psid,
        payload_hex=args.payload,
        priority=args.priority,
        tx_channel=args.tx_channel,
        signature=args.signature,
        encryption=args.encryption,
        recording_enabled=not args.no_record,
        recording_interface=args.interface,
        pcap_path=pcap_path,
        log_callback=log,
        metrics_callback=print_metrics,
    )

    try:
        runner.run()
    except KeyboardInterrupt:
        runner.stop()
        log("Interrupted by user.")
        return 130
    except Exception as exc:
        log(f"ERROR: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
