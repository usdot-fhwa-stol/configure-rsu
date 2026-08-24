from dataclasses import dataclass

MODE_NO_RSU = "no-rsu"
MODE_USING_RSU = "using-rsu"


@dataclass(frozen=True)
class ModeDefaults:
    target_ip: str
    recording_interface: str
    priority: int
    tx_channel: int


MODE_DEFAULTS = {
    MODE_NO_RSU: ModeDefaults(
        target_ip="127.0.0.1",
        recording_interface="lo",
        priority=7,
        tx_channel=172,
    ),
    MODE_USING_RSU: ModeDefaults(
        target_ip="192.168.55.20",
        recording_interface="enp60s0",
        priority=3,
        tx_channel=183,
    ),
}


def get_mode_defaults(mode: str) -> ModeDefaults:
    try:
        return MODE_DEFAULTS[mode]
    except KeyError as exc:
        raise ValueError(f"Unknown mode: {mode}") from exc
