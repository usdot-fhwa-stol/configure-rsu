#!/usr/bin/env python3
"""Diagnostic probe for RSU 4.1 rsuDsrcForwardTable (RFM) writes on a Cohda RSU.

Run this against the live RSU. It answers two questions:

  1. How long does the RSU actually take to apply a mode change (standby/operate)?
  2. Which SET sequence does the agent accept for creating a DSRC forward row,
     and do the written values actually persist?

Usage (credentials default to src/.env):
    python3 src/diagnose_rfm.py --index 1
    python3 src/diagnose_rfm.py --host 192.168.55.1 --user rsu --index 3 \
        --auth-protocol SHA --priv-protocol AES

Nothing here is used by the GUI; it exists only to gather evidence.
"""
import argparse
import os
import time
from binascii import unhexlify

from dotenv import load_dotenv
from snmp import Engine, Timeout, ErrorResponse
from snmp.security.usm.auth import HmacMd5, HmacSha, HmacSha256, HmacSha512
from snmp.security.usm.priv import DesCbc, AesCfb128
from snmp.smi import OctetString, Integer32

import cr_helper

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

MODE_OID = "1.0.15628.4.1.99.0"
BASE_OID = "1.0.15628.4.1.7.1"

STANDBY = 2
OPERATE = 4

snmp_engine = None

AUTH_PROTOCOLS = {"MD5": HmacMd5, "SHA": HmacSha, "SHA256": HmacSha256, "SHA512": HmacSha512}
PRIV_PROTOCOLS = {"DES": DesCbc, "AES": AesCfb128}

# rsuDsrcForwardTable columns, in the order the GUI writes them.
COLUMN_NAMES = {
    2: "rsuDsrcFwdPsid",
    3: "rsuDsrcFwdDestIpAddr",
    4: "rsuDsrcFwdDestPort",
    5: "rsuDsrcFwdProtocol",
    6: "rsuDsrcFwdRssi",
    7: "rsuDsrcFwdMsgInterval",
    8: "rsuDsrcFwdDeliveryStart",
    9: "rsuDsrcFwdDeliveryStop",
    10: "rsuDsrcFwdEnable",
    11: "rsuDsrcFwdStatus",
}


def log(msg: str) -> None:
    print(msg, flush=True)


def connect(args):
    # Keep the Engine alive at module scope: if it is only referenced by a local,
    # it gets garbage-collected on return and closes the Manager's socket.
    global snmp_engine
    engine = snmp_engine = Engine()
    engine.addUser(
        args.user,
        authProtocol=AUTH_PROTOCOLS[args.auth_protocol],
        authSecret=args.auth_password.encode(),
        privProtocol=PRIV_PROTOCOLS[args.priv_protocol],
        privSecret=args.priv_password.encode(),
    )
    return engine.Manager((args.host, args.port), defaultUser=args.user)


def get_int(session, oid: str) -> int:
    value = session.get(oid)[0].value
    return value.value if hasattr(value, 'value') else value


def get_mode(session) -> int:
    return get_int(session, MODE_OID)


# --------------------------------------------------------------------------
# Part 1: how long does a mode change take to take effect?
# --------------------------------------------------------------------------
def time_mode_change(session, target: int, poll_interval=0.25, timeout=15.0) -> float:
    """SET the mode, then poll until it reads back as target. Returns settle seconds."""
    start_mode = get_mode(session)
    log(f"  current mode = {start_mode}, setting mode = {target}")
    if start_mode == target:
        log("  already at target; nothing to time")
        return 0.0

    t0 = time.monotonic()
    session.set((MODE_OID, Integer32(target)))
    log(f"  SET returned after {time.monotonic() - t0:.2f}s")

    while True:
        elapsed = time.monotonic() - t0
        mode = get_mode(session)
        log(f"    t={elapsed:6.2f}s  mode={mode}")
        if mode == target:
            log(f"  --> reached {target} after {elapsed:.2f}s")
            return elapsed
        if elapsed > timeout:
            log(f"  --> TIMED OUT after {elapsed:.2f}s, mode is still {mode}")
            return -1.0
        time.sleep(poll_interval)


def ensure_mode(session, target: int, timeout=15.0) -> bool:
    """Force the RSU into `target` mode and confirm it. Returns True on success."""
    if get_mode(session) == target:
        return True
    session.set((MODE_OID, Integer32(target)))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if get_mode(session) == target:
            return True
        time.sleep(0.25)
    return False


# --------------------------------------------------------------------------
# Part 2: which row-creation sequence does the agent accept?
# --------------------------------------------------------------------------
def data_varbinds(idx: int, args):
    """Columns 2..10 — the row's data, without the RowStatus column."""
    start = cr_helper.convert_datetime_to_rsu41(args.start_date)
    stop = cr_helper.convert_datetime_to_rsu41(args.stop_date)
    return [
        (f"{BASE_OID}.2.{idx}", OctetString(unhexlify(args.psid))),
        (f"{BASE_OID}.3.{idx}", OctetString(args.dest_ip.encode())),
        (f"{BASE_OID}.4.{idx}", Integer32(args.dest_port)),
        (f"{BASE_OID}.5.{idx}", Integer32(2)),          # protocol: UDP
        (f"{BASE_OID}.6.{idx}", Integer32(args.rssi)),
        (f"{BASE_OID}.7.{idx}", Integer32(args.interval)),
        (f"{BASE_OID}.8.{idx}", OctetString(start)),
        (f"{BASE_OID}.9.{idx}", OctetString(stop)),
        (f"{BASE_OID}.10.{idx}", Integer32(1)),         # enable
    ]


def read_row(session, idx: int) -> dict:
    """GET every column of the row; returns {column: value-or-error-string}."""
    row = {}
    for col in sorted(COLUMN_NAMES):
        oid = f"{BASE_OID}.{col}.{idx}"
        try:
            row[col] = cr_helper.format_snmp_value(session.get(oid)[0])
        except (Timeout, ErrorResponse) as e:
            row[col] = f"<{e}>"
    return row


def walk(session, root: str, limit: int = 200) -> list:
    """GETNEXT through a subtree; returns [(oid, formatted value)]."""
    results = []
    oid = root
    while len(results) < limit:
        try:
            varbind = session.getNext(oid)[0]
        except (Timeout, ErrorResponse) as e:
            log(f"    walk stopped at {oid}: {e}")
            break
        next_oid = str(varbind.name)
        if not next_oid.startswith(root + "."):
            break
        results.append((next_oid, cr_helper.format_snmp_value(varbind)))
        oid = next_oid
    return results


def show_walk(session, root: str, label: str) -> None:
    log(f"  walk of {label} ({root}):")
    rows = walk(session, root)
    if not rows:
        log("    <empty — the RSU exposes nothing under this subtree>")
    for oid, value in rows:
        log(f"    {oid} = {value}")


def probe_gets(session, idx: int) -> None:
    """Direct GETs of exact instance OIDs — the only access pattern the GUI uses.

    This agent may not answer GETNEXT (walk) even for objects it serves via GET,
    so a walk coming back empty proves nothing on its own.
    """
    targets = [
        ("sysDescr",                  "1.3.6.1.2.1.1.1.0"),
        ("rsuMode (4.1)",             "1.0.15628.4.1.99.0"),
        ("rsuMode (NTCIP 1218)",      "1.3.6.1.4.1.1206.4.2.18.16.2.0"),
        ("rsuModeStatus (NTCIP)",     "1.3.6.1.4.1.1206.4.2.18.16.3.0"),
        (f"IFM psid       [{idx}]",   f"1.0.15628.4.1.5.1.2.{idx}"),
        (f"IFM tx channel [{idx}]",   f"1.0.15628.4.1.5.1.3.{idx}"),
        (f"IFM status     [{idx}]",   f"1.0.15628.4.1.5.1.7.{idx}"),
        (f"RFM psid       [{idx}]",   f"{BASE_OID}.2.{idx}"),
        (f"RFM dest ip    [{idx}]",   f"{BASE_OID}.3.{idx}"),
        (f"RFM dest port  [{idx}]",   f"{BASE_OID}.4.{idx}"),
        (f"RFM status     [{idx}]",   f"{BASE_OID}.11.{idx}"),
    ]
    log("  direct GETs (no GETNEXT — this is what the GUI actually does):")
    for label, oid in targets:
        try:
            log(f"    {label:<24} {oid:<32} = {cr_helper.format_snmp_value(session.get(oid)[0])}")
        except (Timeout, ErrorResponse) as e:
            log(f"    {label:<24} {oid:<32} ! {e}")


def show_row(session, idx: int, label: str) -> dict:
    log(f"  read-back of row {idx} ({label}):")
    row = read_row(session, idx)
    for col, value in row.items():
        log(f"    .{col:<2} {COLUMN_NAMES[col]:<24} = {value}")
    return row


def row_matches(row: dict, idx: int, args) -> bool:
    """Did the data columns actually land? Compares the easily-checkable ones."""
    checks = {
        3: args.dest_ip,
        4: str(args.dest_port),
        5: "2",
        10: "1",
    }
    ok = all(row.get(col) == expected for col, expected in checks.items())
    psid_read = (row.get(2) or "").replace(" ", "").lower()
    ok = ok and psid_read == args.psid.lower()
    return ok


def destroy_row(session, idx: int) -> None:
    """Best-effort cleanup so each attempt starts from a known state."""
    try:
        session.set((f"{BASE_OID}.11.{idx}", Integer32(6)))  # destroy
        log(f"  (row {idx} destroyed)")
    except (Timeout, ErrorResponse) as e:
        log(f"  (destroy of row {idx} returned {e} — probably no such row, fine)")


def check_in_operate(session, idx: int, args, label: str) -> bool:
    """Some agents only materialize config once the RSU returns to operate."""
    log(f"  flipping to operate to see whether the row appears there...")
    if not ensure_mode(session, OPERATE):
        log("  could not reach operate mode")
        return False
    return row_matches(show_row(session, idx, f"in OPERATE, after {label}"), idx, args)


def attempt_single_pdu(session, idx: int, args) -> bool:
    """(a) What the GUI does today: all columns + createAndGo(4) in one PDU."""
    log("\n[attempt a] single PDU: columns 2..10 + rsuDsrcFwdStatus = createAndGo(4)")
    varbinds = data_varbinds(idx, args) + [(f"{BASE_OID}.11.{idx}", Integer32(4))]
    try:
        session.set(*varbinds)
        log("  SET succeeded")
    except (Timeout, ErrorResponse) as e:
        log(f"  SET FAILED: {e}")
        return False
    return row_matches(show_row(session, idx, "after single-PDU createAndGo"), idx, args)


def attempt_two_phase(session, idx: int, args) -> bool:
    """(b) createAndWait(5) -> data columns -> active(1), as three separate PDUs."""
    log("\n[attempt b] two-phase: createAndWait(5), then columns 2..10, then active(1)")
    try:
        session.set((f"{BASE_OID}.11.{idx}", Integer32(5)))
        log("  createAndWait(5) succeeded")
    except (Timeout, ErrorResponse) as e:
        log(f"  createAndWait(5) FAILED: {e}")
        return False

    show_row(session, idx, "after createAndWait, before writing columns")

    try:
        session.set(*data_varbinds(idx, args))
        log("  data column SET succeeded")
    except (Timeout, ErrorResponse) as e:
        log(f"  data column SET FAILED: {e}")
        return False

    try:
        session.set((f"{BASE_OID}.11.{idx}", Integer32(1)))
        log("  active(1) succeeded")
    except (Timeout, ErrorResponse) as e:
        log(f"  active(1) FAILED: {e}")
        return False

    return row_matches(show_row(session, idx, "after two-phase creation"), idx, args)


def attempt_per_column(session, idx: int, args) -> None:
    """(c) One column at a time, to isolate which value the agent rejects."""
    log("\n[attempt c] per-column SETs (isolates a bad value/type from a row-status problem)")
    log("  creating the row first with createAndWait(5)")
    try:
        session.set((f"{BASE_OID}.11.{idx}", Integer32(5)))
    except (Timeout, ErrorResponse) as e:
        log(f"  createAndWait(5) FAILED: {e} — writing columns into a nonexistent row")

    for oid, value in data_varbinds(idx, args):
        col = int(oid.split('.')[-2])
        try:
            session.set((oid, value))
            log(f"  OK   .{col:<2} {COLUMN_NAMES[col]:<24} {oid}")
        except (Timeout, ErrorResponse) as e:
            log(f"  FAIL .{col:<2} {COLUMN_NAMES[col]:<24} {oid}: {e}")

    show_row(session, idx, "after per-column SETs")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--host', default=os.getenv('IP_ADDRESS'))
    p.add_argument('--port', type=int, default=int(os.getenv('SNMP_PORT', 161)))
    p.add_argument('--user', default=os.getenv('SNMP_USER'))
    p.add_argument('--auth-password', default=os.getenv('AUTH_PASSWORD'))
    p.add_argument('--priv-password', default=os.getenv('PRIV_PASSWORD'))
    p.add_argument('--auth-protocol', default='SHA', choices=sorted(AUTH_PROTOCOLS))
    p.add_argument('--priv-protocol', default='AES', choices=sorted(PRIV_PROTOCOLS))
    p.add_argument('--index', type=int, default=1, help='RFM entry index to probe')
    p.add_argument('--psid', default='8002')
    p.add_argument('--dest-ip', default='192.168.55.152')
    p.add_argument('--dest-port', type=int, default=5398)
    p.add_argument('--rssi', type=int, default=-100)
    p.add_argument('--interval', type=int, default=1)
    p.add_argument('--start-date', default='2025-01-01,00:00:00.0')
    p.add_argument('--stop-date', default='2030-01-01,00:00:00.0')
    p.add_argument('--skip-mode-timing', action='store_true')
    p.add_argument('--walk-only', action='store_true',
                   help='only dump what the RSU exposes; do not write anything')
    args = p.parse_args()

    if not args.host or not args.user:
        p.error("host and user are required (set them in src/.env or pass --host/--user)")

    idx = args.index
    log(f"RSU {args.host}:{args.port} as {args.user} "
        f"({args.auth_protocol}/{args.priv_protocol}), RFM index {idx}\n")

    session = connect(args)

    mib_alive = False
    try:
        log("\n=== Part 0: what does this RSU actually expose? ===")
        try:
            log(f"  sysDescr = {cr_helper.format_snmp_value(session.get('1.3.6.1.2.1.1.1.0')[0])}")
        except (Timeout, ErrorResponse) as e:
            log(f"  sysDescr failed: {e}")

        probe_gets(session, idx)

        mode = get_mode(session)
        mib_alive = isinstance(mode, int)

        show_walk(session, "1.0.15628.4.1.7", "RSU 4.1 rsuDsrcForwardTable")
        show_walk(session, "1.3.6.1.4.1.1206.4.2.18.5.2", "NTCIP 1218 rsuReceivedMsgTable")
        show_walk(session, "1.0.15628.4.1.5", "RSU 4.1 rsuIFMTable (for comparison)")

        if not mib_alive:
            log(f"\nSTOP: rsuMode ({MODE_OID}) does not GET as an integer, so this run cannot "
                "put the RSU into standby and any config write would be meaningless. Compare "
                "the direct-GET results above: if the IFM OIDs answer but rsuMode does not, "
                "the RSU MIB is partly served and the mode object is the problem. If nothing "
                "under 1.0.15628 answers, the RSU's V2X application is not registered with "
                "the SNMP master agent — restart it on the device and re-run.")
            return

        if args.walk_only:
            return

        if not args.skip_mode_timing:
            log("\n=== Part 1: mode transition timing ===")
            log("\nstandby:")
            standby_secs = time_mode_change(session, STANDBY)
            log("\noperate:")
            operate_secs = time_mode_change(session, OPERATE)
            log(f"\nsettle times: standby {standby_secs:.2f}s, operate {operate_secs:.2f}s")

        log("\n=== Part 2: row creation probe (RSU held in standby) ===")
        if not ensure_mode(session, STANDBY):
            log("ERROR: could not get the RSU into standby; aborting the probe")
            return
        log("RSU confirmed in standby\n")

        show_row(session, idx, "before any writes")

        destroy_row(session, idx)
        persisted = attempt_single_pdu(session, idx, args)
        persisted = persisted or check_in_operate(session, idx, args, "single-PDU createAndGo")
        if persisted:
            log("\nRESULT: single-PDU createAndGo works and the values persist. "
                "The GUI's PDU shape is fine — the bug is purely the mode race.")
            return

        ensure_mode(session, STANDBY)
        destroy_row(session, idx)
        persisted = attempt_two_phase(session, idx, args)
        persisted = persisted or check_in_operate(session, idx, args, "two-phase creation")
        if persisted:
            log("\nRESULT: two-phase createAndWait -> columns -> active works and the "
                "values persist. The GUI should switch the RSU 4.1 path to this sequence.")
            return

        ensure_mode(session, STANDBY)
        destroy_row(session, idx)
        attempt_per_column(session, idx, args)
        check_in_operate(session, idx, args, "per-column SETs")
        log("\nRESULT: neither row-creation sequence persisted the values, in standby "
            "or in operate. See Part 0: if the RSU 4.1 subtree walks up empty, this RSU "
            "is not serving rsuDsrcForwardTable at all and the GUI must use the NTCIP "
            "1218 table instead.")
    finally:
        if mib_alive:
            log("\nrestoring operate mode...")
            try:
                if ensure_mode(session, OPERATE):
                    log("RSU is back in operate mode")
                else:
                    log("WARNING: could not restore operate mode — check the RSU")
            except (Timeout, ErrorResponse) as e:
                log(f"WARNING: could not restore operate mode: {e} — check the RSU")


if __name__ == '__main__':
    main()
