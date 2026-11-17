"""Unit tests for cr_helper."""

import pytest
from hypothesis import example, given, strategies as st

from cr_helper import (
    convert_date_range,
    convert_datetime,
    encode_ipv6_address,
    format_ipv6_address,
    format_snmp_hex,
    format_snmp_ipv6,
    format_snmp_text,
    format_snmp_value,
    parse_datetime_fields,
)

# @given: Property-based tests state a rule and check it against generated inputs
# @example: provides the inputs that must be checked on every run.

# Any valid date as (year, month, day, hour, minute, second, decisecond).
# Day stops at 28 so that it exists in every month of every year.
_valid_dates = st.tuples(
    st.integers(0, 65535), st.integers(1, 12), st.integers(1, 28),
    st.integers(0, 23), st.integers(0, 59), st.integers(0, 60), st.integers(0, 9),
)

_modes = st.sampled_from(["ntcip1218", "rsu41"])


def _date_str(fields) -> str:
    """Write date fields the way the UI takes them: yyyy-mm-dd,hh:mm:ss.ms"""
    year, month, day, hour, minute, second, decisecond = fields
    return f"{year:04d}-{month:02d}-{day:02d},{hour:02d}:{minute:02d}:{second:02d}.{decisecond}"


class TestConvertDatetimeRsu41Mode:
    """convert_datetime in "rsu41" mode (6-octet delivery time)."""

    @pytest.mark.parametrize("date_str,expected", [
        ("2025-01-01,00:00:00.0", b"\x07\xe9\x01\x01\x00\x00"),
        ("2025-12-31,23:59:59.9", b"\x07\xe9\x0c\x1f\x17\x3b"),
        ("1999-06-15,12:30:00.0", b"\x07\xcf\x06\x0f\x0c\x1e"),
        ("2000-02-29,01:02:03.4", b"\x07\xd0\x02\x1d\x01\x02"),
    ])
    def test_known_conversions(self, date_str, expected):
        assert convert_datetime(date_str, "rsu41") == expected

    def test_year_uses_network_byte_order(self):
        result = convert_datetime("2025-01-01,00:00:00.0", "rsu41")
        assert result[0] == (2025 >> 8) & 0xFF  # 0x07
        assert result[1] == 2025 & 0xFF         # 0xE9

    @given(fields=_valid_dates)
    @example(fields=(2025, 3, 4, 5, 6, 59, 9))
    def test_seconds_and_deciseconds_are_ignored(self, fields):
        # Only 6 octets in rsu41, so the seconds change nothing, even when omitted entirely
        without_seconds = _date_str(fields).rsplit(":", 1)[0]
        assert convert_datetime(without_seconds, "rsu41") == convert_datetime(_date_str(fields), "rsu41")

    @pytest.mark.parametrize("date_str", [
        "",
        "not-a-date",
        "2025-01-01",                # missing the time part
        "00:00:00.0",                # missing the date part
        "2025-01,00:00:00.0",        # incomplete date
        "2025-01-01,00",             # incomplete time
        "20xx-01-01,00:00:00.0",     # non-numeric year
        "2025-01-01,aa:00:00.0",     # non-numeric hour
        None,
    ])
    def test_invalid_input_raises_value_error(self, date_str):
        with pytest.raises(ValueError):
            convert_datetime(date_str, "rsu41")

    def test_error_message_includes_the_offending_input(self):
        with pytest.raises(ValueError, match="bad-input"):
            convert_datetime("bad-input", "rsu41")


class TestConvertDatetimeNtcip1218Mode:
    """convert_datetime in "ntcip1218" mode (8-octet DateAndTime)."""

    @pytest.mark.parametrize("date_str,expected", [
        ("2025-01-01,00:00:00.0", b"\x07\xe9\x01\x01\x00\x00\x00\x00"),
        ("2025-12-31,23:59:59.9", b"\x07\xe9\x0c\x1f\x17\x3b\x3b\x09"),
        ("2025-07-04,16:20:45.7", b"\x07\xe9\x07\x04\x10\x14\x2d\x07"),
    ])
    def test_known_conversions(self, date_str, expected):
        assert convert_datetime(date_str, "ntcip1218") == expected

    def test_deciseconds_default_to_zero_when_omitted(self):
        assert convert_datetime("2025-01-01,00:00:05", "ntcip1218")[7] == 0

    def test_seconds_are_required(self):
        # seconds required in ntcip1218, not rsu41
        with pytest.raises(ValueError):
            convert_datetime("2025-03-04,05:06", "ntcip1218")


class TestConvertDatetimeModeSelection:
    """Behavior of the mode_mib argument itself."""

    @given(fields=_valid_dates)
    @example(fields=(2025, 7, 4, 16, 20, 45, 7))
    def test_rsu41_is_ntcip_1218_truncated_to_six_octets(self, fields):
        ntcip1218 = convert_datetime(_date_str(fields), "ntcip1218")
        rsu41 = convert_datetime(_date_str(fields), "rsu41")
        assert len(ntcip1218) == 8
        assert len(rsu41) == 6
        assert rsu41 == ntcip1218[:6]

    @pytest.mark.parametrize("mode_mib", [
        "",
        "ntcip",
        "ntcip1218 ",     # trailing whitespace
        "NTCIP1218",      # wrong case
        "rsu_41",         # plausible typo
        "rsu4.1",
        "1218",
        None,
        0,
    ])
    def test_unknown_mode_raises_value_error(self, mode_mib):
        with pytest.raises(ValueError, match="Unknown RSU mode"):
            convert_datetime("2025-01-01,00:00:00.0", mode_mib)

    def test_unknown_mode_message_lists_the_valid_modes(self):
        with pytest.raises(ValueError, match="ntcip1218, rsu41"):
            convert_datetime("2025-01-01,00:00:00.0", "bogus")

    def test_mode_is_checked_before_the_date_is_parsed(self):
        # Both arguments are bad; the mode error is the more useful one.
        with pytest.raises(ValueError, match="Unknown RSU mode"):
            convert_datetime("not-a-date", "bogus")


class TestParseDatetimeFields:
    """Tests for parse_datetime_fields, the shared parse/validate helper."""

    def test_returns_all_seven_components(self):
        assert parse_datetime_fields("2025-07-04,16:20:45.7") == (2025, 7, 4, 16, 20, 45, 7)

    def test_deciseconds_default_to_zero_when_omitted(self):
        assert parse_datetime_fields("2025-07-04,16:20:45") == (2025, 7, 4, 16, 20, 45, 0)

    def test_seconds_are_required_by_default(self):
        with pytest.raises(ValueError):
            parse_datetime_fields("2025-07-04,16:20")

    def test_seconds_optional_when_not_required(self):
        result = parse_datetime_fields("2025-07-04,16:20", require_seconds=False)
        assert result == (2025, 7, 4, 16, 20, 0, 0)

    @pytest.mark.parametrize("date_str,field", [
        ("65536-01-01,00:00:00.0", "year"),        # RFC 2579 erratum 417: max is 65535
        ("2025-00-01,00:00:00.0", "month"),
        ("2025-13-01,00:00:00.0", "month"),
        ("2025-01-00,00:00:00.0", "day"),
        ("2025-01-32,00:00:00.0", "day"),
        ("2025-01-45,00:00:00.0", "day"),
        ("2025-01-01,24:00:00.0", "hour"),
        ("2025-01-01,00:60:00.0", "minute"),
        ("2025-01-01,00:00:61.0", "second"),
        ("2025-01-01,00:00:00.10", "decisecond"),
    ])
    def test_out_of_range_field_raises_naming_the_field(self, date_str, field):
        with pytest.raises(ValueError, match=field):
            parse_datetime_fields(date_str)

    @pytest.mark.parametrize("date_str,index,expected", [
        ("0000-01-01,00:00:00.0", 0, 0),        # year: RFC 2579 lower bound
        ("65535-01-01,00:00:00.0", 0, 65535),   # year: two-octet upper bound (erratum 417)
        ("2025-12-31,23:59:60.0", 5, 60),       # second: 60 is a leap second
    ])
    def test_rfc_2579_boundary_values_are_accepted(self, date_str, index, expected):
        assert parse_datetime_fields(date_str)[index] == expected

    def test_negative_year_is_rejected(self):
        with pytest.raises(ValueError):
            parse_datetime_fields("-1-01-01,00:00:00.0")

    @pytest.mark.parametrize("date_str", [
        "2024-02-29,00:00:00.0",   # 2024 is a leap year
        "2000-02-29,00:00:00.0",   # divisible by 400
        "2025-02-28,00:00:00.0",
        "2025-01-31,00:00:00.0",
    ])
    def test_valid_calendar_days_are_accepted(self, date_str):
        assert parse_datetime_fields(date_str) is not None

    @pytest.mark.parametrize("date_str", [
        "2025-02-29,00:00:00.0",   # 2025 is not a leap year
        "1900-02-29,00:00:00.0",   # divisible by 100 but not 400
        "2025-02-30,00:00:00.0",
        "2025-04-31,00:00:00.0",   # April has 30 days
        "2025-06-31,00:00:00.0",
    ])
    def test_nonexistent_calendar_days_are_rejected(self, date_str):
        with pytest.raises(ValueError):
            parse_datetime_fields(date_str)

    def test_error_message_includes_the_offending_input(self):
        with pytest.raises(ValueError, match="2025-13-01"):
            parse_datetime_fields("2025-13-01,00:00:00.0")


class TestValidationReachesBothModes:
    """Both encodings must reject values that were previously encoded silently."""

    @pytest.mark.parametrize("mode_mib", ["ntcip1218", "rsu41"])
    @pytest.mark.parametrize("date_str", [
        "2025-13-01,00:00:00.0",   # month 13
        "2025-01-45,00:00:00.0",   # day 45
        "2025-02-30,00:00:00.0",   # February 30th
        "2025-01-01,24:00:00.0",   # hour 24
        "2025-01-01,00:60:00.0",   # minute 60
    ])
    def test_out_of_range_values_are_rejected(self, mode_mib, date_str):
        with pytest.raises(ValueError):
            convert_datetime(date_str, mode_mib)

    @pytest.mark.parametrize("mode_mib,expected", [
        ("ntcip1218", b"\x07\xe9\x01\x01\x00\x00\x00\x00"),
        ("rsu41", b"\x07\xe9\x01\x01\x00\x00"),
    ])
    def test_valid_values_still_encode(self, mode_mib, expected):
        assert convert_datetime("2025-01-01,00:00:00.0", mode_mib) == expected

    @pytest.mark.parametrize("mode_mib", ["ntcip1218", "rsu41"])
    def test_largest_encodable_year_fills_both_octets(self, mode_mib):
        assert convert_datetime("65535-01-01,00:00:00.0", mode_mib)[:2] == b"\xff\xff"


class TestConvertDateRange:
    """convert_date_range pairs the two delivery times and orders them."""

    @pytest.mark.parametrize("mode_mib,start_bytes,stop_bytes", [
        ("ntcip1218", b"\x07\xe9\x01\x01\x00\x00\x00\x00", b"\x07\xee\x01\x01\x00\x00\x00\x00"),
        ("rsu41", b"\x07\xe9\x01\x01\x00\x00", b"\x07\xee\x01\x01\x00\x00"),
    ])
    def test_returns_both_encodings_in_order(self, mode_mib, start_bytes, stop_bytes):
        result = convert_date_range("2025-01-01,00:00:00.0", "2030-01-01,00:00:00.0", mode_mib)
        assert result == (start_bytes, stop_bytes)

    @given(start=_valid_dates, stop=_valid_dates, mode_mib=_modes)
    # Equal dates are allowed.
    @example(start=(2025, 6, 1, 12, 0, 0, 0), stop=(2025, 6, 1, 12, 0, 0, 0), mode_mib="ntcip1218")
    @example(start=(2025, 6, 1, 12, 0, 0, 0), stop=(2025, 6, 1, 12, 0, 0, 0), mode_mib="rsu41")
    # Reversed by a single decisecond.
    @example(start=(2025, 6, 1, 12, 0, 0, 5), stop=(2025, 6, 1, 12, 0, 0, 4), mode_mib="ntcip1218")
    # RSU 4.1 drops the seconds, so a pair that is reversed in real time but only
    # below the minute encodes to two identical values and is allowed.
    @example(start=(2025, 6, 1, 12, 0, 30, 0), stop=(2025, 6, 1, 12, 0, 29, 0), mode_mib="rsu41")
    # calendar/datetime cannot represent year 0, but the encoding permits it.
    @example(start=(0, 1, 1, 0, 0, 0, 0), stop=(1, 1, 1, 0, 0, 0, 0), mode_mib="ntcip1218")
    @example(start=(1, 1, 1, 0, 0, 0, 0), stop=(0, 1, 1, 0, 0, 0, 0), mode_mib="ntcip1218")
    def test_rejected_only_when_stop_precedes_start(self, start, stop, mode_mib):
        start_str, stop_str = _date_str(start), _date_str(stop)
        compared = 7 if mode_mib == "ntcip1218" else 5  # fields that reach the wire

        if stop[:compared] < start[:compared]:
            with pytest.raises(ValueError, match="earlier than start date"):
                convert_date_range(start_str, stop_str, mode_mib)
        else:
            # Otherwise each value converts exactly as it would alone.
            assert convert_date_range(start_str, stop_str, mode_mib) == (
                convert_datetime(start_str, mode_mib), convert_datetime(stop_str, mode_mib))

    def test_error_message_names_both_dates(self):
        with pytest.raises(ValueError) as excinfo:
            convert_date_range("2030-01-01,00:00:00.0", "2025-01-01,00:00:00.0", "ntcip1218")
        assert "2030-01-01,00:00:00.0" in str(excinfo.value)
        assert "2025-01-01,00:00:00.0" in str(excinfo.value)

    @pytest.mark.parametrize("start,stop", [
        ("not-a-date", "2030-01-01,00:00:00.0"),
        ("2025-01-01,00:00:00.0", "not-a-date"),
        ("2025-13-01,00:00:00.0", "2030-01-01,00:00:00.0"),
        ("2025-01-01,00:00:00.0", "2030-02-30,00:00:00.0"),
    ])
    def test_an_invalid_value_in_either_position_raises(self, start, stop):
        with pytest.raises(ValueError):
            convert_date_range(start, stop, "ntcip1218")

    def test_invalid_value_is_reported_rather_than_the_reversal(self):
        # Reversed and malformed (two errors), but per-value error wins.
        with pytest.raises(ValueError) as excinfo:
            convert_date_range("2030-01-01,00:00:00.0", "not-a-date", "ntcip1218")
        assert "not-a-date" in str(excinfo.value)
        assert "earlier than start date" not in str(excinfo.value)

    def test_unknown_mode_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown RSU mode"):
            convert_date_range("2025-01-01,00:00:00.0", "2030-01-01,00:00:00.0", "bogus")


class _FakeVarBind:
    """Minimal stand-in for an snmp VarBind: only .value is read."""
    def __init__(self, value):
        self.value = value

class _FakeOctetString:
    """Stand-in for snmp.smi.OctetString, which carries its payload in .data."""
    def __init__(self, data):
        self.data = data

class _FakeInteger32:
    """Stand-in for an INTEGER32, which carries a plain int in .value."""
    def __init__(self, value):
        self.value = value

def _format(value) -> str:
    return format_snmp_value(_FakeVarBind(value))

def _format_hex(value) -> str:
    return format_snmp_hex(_FakeVarBind(value))

def _format_text(value) -> str:
    return format_snmp_text(_FakeVarBind(value))


class TestPlainAndWrappedPayloads:
    """
    bytes and str payloads reach the formatters either plain or wrapped in an
    OctetString. Test both.
    """

    @given(payload=st.one_of(st.binary(max_size=64), st.text(max_size=32)),
           formatter=st.sampled_from(
               [format_snmp_value, format_snmp_hex, format_snmp_text, format_snmp_ipv6]))
    @example(payload=bytes.fromhex("07E9010100000000"), formatter=format_snmp_value)
    @example(payload=bytes.fromhex("00000000000000000000FFFFC0A837BF"), formatter=format_snmp_ipv6)
    @example(payload="rsu-config", formatter=format_snmp_value)
    def test_format_identically(self, payload, formatter):
        plain = formatter(_FakeVarBind(payload))
        wrapped = formatter(_FakeVarBind(_FakeOctetString(payload)))
        assert plain == wrapped


class TestFormatSnmpValueIntegers:
    """Integers arrive normally, or as an INTEGER32 wrapped in an object exposing .value."""

    @given(number=st.integers())
    @example(number=0)
    @example(number=-1)
    @example(number=65535)
    def test_integers_are_stringified(self, number):
        assert _format(number) == str(number)
        assert _format(_FakeInteger32(number)) == str(number)


class TestFormatSnmpValueBytes:
    """bytes payloads: shown as a DateAndTime if they are one, then printable ASCII, then hex."""

    @pytest.mark.parametrize("data,expected", [
        (bytes.fromhex("07E9010100000000"), "2025-01-01,00:00:00.0"),  # 8 octets read as DateAndTime
        (bytes.fromhex("07E90C1F173B3C09"), "2025-12-31,23:59:60.9"),  # every field at its upper limit
        (b"rsu-config", "rsu-config"),      # printable ASCII decodes to text
        (b"a\tb\nc", "61 09 62 0a 63"),     # control characters are never expected; hex makes them visible
        (b"\xff\xfe", "ff fe"),             # not valid UTF-8
        (b"\x01\x02\x03", "01 02 03"),      # decodable but unprintable
        (b"\x00\x0f\xff", "00 0f ff"),      # hex is space-separated and zero-padded
        (b"", ""),
    ])
    def test_bytes_are_formatted(self, data, expected):
        assert _format(_FakeOctetString(data)) == expected

    @pytest.mark.parametrize("data,expected", [
        (b"RSU-4100", "RSU-4100"),                                       # e.g. a device description
        (b"10.0.0.1", "10.0.0.1"),
        (bytes.fromhex("07E90D0100000000"), "07 e9 0d 01 00 00 00 00"),  # month 13
        (bytes.fromhex("07E9010118000000"), "07 e9 01 01 18 00 00 00"),  # hour 24
        (bytes(8), "00 00 00 00 00 00 00 00"),                           # month 0, day 0
    ], ids=["text", "ip", "month-13", "hour-24", "all-zeros"])
    def test_eight_octets_that_are_not_dates_are_not_shown_as_dates(self, data, expected):
        assert _format(_FakeOctetString(data)) == expected

    @given(text=st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
                        min_size=8, max_size=8))
    def test_eight_printable_characters_are_always_shown_as_text(self, text):
        assert _format(_FakeOctetString(text.encode("ascii"))) == text

    @given(fields=_valid_dates)
    def test_every_valid_date_is_shown_as_a_date(self, fields):
        encoded = convert_datetime(_date_str(fields), "ntcip1218")
        assert _format(_FakeOctetString(encoded)) == _date_str(fields)


class TestFormatSnmpValueText:
    """str payloads get the same printable-ASCII check as bytes."""

    @pytest.mark.parametrize("value,expected", [
        ("rsu-config", "rsu-config"),
        ("\x01\x02", "01 02"),
        ("a\tb", "61 09 62"),
    ])
    def test_text_is_formatted(self, value, expected):
        assert _format(_FakeOctetString(value)) == expected


class TestFormatSnmpValueFallbacks:
    """Anything not matched by a specific branch falls back to str()."""

    @pytest.mark.parametrize("value", [None, 3.5, [1, 2]])
    def test_unknown_type_is_stringified(self, value):
        assert _format(value) == str(value)

    def test_octet_string_holding_other_type_is_stringified(self):
        assert _format(_FakeOctetString(12345)) == "12345"


class TestFormatSnmpHex:
    """format_snmp_hex: OctetStrings always become unspaced, uppercase hex, never text or a date."""

    @given(data=st.binary(max_size=64))
    @example(data=bytes.fromhex("8002"))                # typical PSID
    @example(data=b"\x00\x0f\xff")                      # zero-padded, uppercase
    @example(data=b"Hello World")                       # printable ASCII is not decoded
    @example(data=bytes.fromhex("07E9010100000000"))    # a date is not shown as one
    @example(data=b"")
    def test_hex_decodes_back_to_the_same_bytes(self, data):
        result = _format_hex(_FakeOctetString(data))
        assert len(result) == 2 * len(data)             # two digits per octet, nothing between
        assert bytes.fromhex(result) == data
        assert result == result.upper()

    @pytest.mark.parametrize("value,expected", [
        ("rsu", "727375"),
        ("\x01\x02", "0102"),
    ], ids=["printable", "unprintable"])
    def test_text_becomes_hex(self, value, expected):
        assert _format_hex(_FakeOctetString(value)) == expected

    @pytest.mark.parametrize("value", [_FakeInteger32(32770), 42, None],
                             ids=["integer32", "int", "none"])
    def test_non_octet_values_match_format_snmp_value(self, value):
        assert _format_hex(value) == _format(value)


class TestFormatSnmpText:
    """format_snmp_text: OctetStrings become printable ASCII text, then hex, never a date."""

    @pytest.mark.parametrize("data,expected", [
        (b"192.168.1.10", "192.168.1.10"),
        (b"fe80::1", "fe80::1"),
        (bytes.fromhex("07E9010100000000"), "07 e9 01 01 00 00 00 00"),  # a date is not shown as one
        (bytes.fromhex("0011223344556677"), "00 11 22 33 44 55 66 77"),  # unprintable falls back to hex
        (b"", ""),
    ], ids=["ipv4", "ipv6", "date", "unprintable", "empty"])
    def test_bytes_become_text(self, data, expected):
        assert _format_text(_FakeOctetString(data)) == expected

    @pytest.mark.parametrize("value", ["10.0.0.1", "\x01\x02"], ids=["printable", "unprintable"])
    def test_text_matches_format_snmp_value(self, value):
        assert _format_text(_FakeOctetString(value)) == _format(_FakeOctetString(value))

    @pytest.mark.parametrize("value", [_FakeInteger32(5000), 42, None],
                             ids=["integer32", "int", "none"])
    def test_non_octet_values_match_format_snmp_value(self, value):
        assert _format_text(value) == _format(value)


class TestEncodeIpv6Address:
    """encode_ipv6_address: RSU 4.1 IP columns are a 16-octet Ipv6Address, never text."""

    # The exact octets on the wire. A round trip cannot check these: sending
    # the address as text and reading it back as text round-trips too.
    @pytest.mark.parametrize("ip,expected_hex", [
        ("192.168.55.191", "00000000000000000000FFFFC0A837BF"),  # IPv4 is sent IPv4-mapped
        (" 10.0.0.1 ", "00000000000000000000FFFF0A000001"),      # surrounding whitespace is ignored
        ("fe80::1", "FE800000000000000000000000000001"),
    ], ids=["ipv4", "whitespace", "ipv6"])
    def test_known_encodings(self, ip, expected_hex):
        assert encode_ipv6_address(ip) == bytes.fromhex(expected_hex)

    @given(ip=st.ip_addresses(v=4))
    def test_any_ipv4_address_is_sent_ipv4_mapped(self, ip):
        encoded = encode_ipv6_address(str(ip))
        assert encoded == bytes(10) + b"\xff\xff" + ip.packed
        assert format_ipv6_address(encoded) == str(ip)

    @pytest.mark.parametrize("ip", ["192.168.55.256", "rsu.local"], ids=["octet-256", "hostname"])
    def test_rejects_invalid_address(self, ip):
        with pytest.raises(ValueError, match="Invalid IP address"):
            encode_ipv6_address(ip)


class TestFormatIpv6Address:
    """format_ipv6_address: 16 octets render as an address, IPv4-mapped ones as dotted IPv4."""

    @given(data=st.binary(min_size=16, max_size=16))
    @example(data=bytes(16))
    @example(data=bytes.fromhex("00000000000000000000FFFFC0A837BF"))
    def test_any_sixteen_octets_survive_display_and_re_encoding(self, data):
        assert encode_ipv6_address(format_ipv6_address(data)) == data

    def test_all_zeros_is_the_unspecified_address(self):
        assert format_ipv6_address(bytes(16)) == "::"

    @pytest.mark.parametrize("data,expected", [
        (b"192.168.55.191", "192.168.55.191"),  # text, as older versions of this tool sent it
        (b"\xc0\xa8\x37\xbf", "c0 a8 37 bf"),   # 4 octets: shown as hex
    ], ids=["text", "four-octets"])
    def test_other_lengths_are_shown_as_text_or_hex(self, data, expected):
        assert format_ipv6_address(data) == expected


class TestFormatSnmpIpv6:
    """format_snmp_ipv6: unwraps the VarBind, then formats as format_ipv6_address."""

    def test_ipv4_mapped_is_dotted(self):
        data = bytes.fromhex("00000000000000000000FFFFC0A837BF")
        assert format_snmp_ipv6(_FakeVarBind(_FakeOctetString(data))) == "192.168.55.191"

    def test_non_octet_value_matches_format_snmp_value(self):
        assert format_snmp_ipv6(_FakeVarBind(_FakeInteger32(0))) == _format(_FakeInteger32(0))
