"""Unit tests for cr_helper."""

import pytest

from cr_helper import (
    convert_date_range,
    convert_datetime,
    format_snmp_value,
    get_rfm_help_content,
    get_srm_help_content,
    parse_datetime_fields,
)


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

    @pytest.mark.parametrize("date_str", [
        "2025-03-04,05:06:00.0",
        "2025-03-04,05:06:59.9",
        "2025-03-04,05:06:30.5",
        "2025-03-04,05:06",          # omitted entirely
    ])
    def test_seconds_and_deciseconds_are_ignored(self, date_str):
        # Only the minute field and coarser are encoded, so every value of
        # seconds/deciseconds, present or not, must produce the same 6 octets.
        assert convert_datetime(date_str, "rsu41") == b"\x07\xe9\x03\x04\x05\x06"

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

    @pytest.mark.parametrize("mode_mib,octets", [("ntcip1218", 8), ("rsu41", 6)])
    def test_octet_count_per_mode(self, mode_mib, octets):
        assert len(convert_datetime("2025-01-01,00:00:00.0", mode_mib)) == octets

    def test_rsu41_is_ntcip_1218_truncated_to_six_octets(self):
        date_str = "2025-07-04,16:20:45.7"
        assert convert_datetime(date_str, "rsu41") == convert_datetime(date_str, "ntcip1218")[:6]

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

    @pytest.mark.parametrize("mode_mib", ["ntcip1218", "rsu41"])
    def test_matches_converting_each_value_separately(self, mode_mib):
        start, stop = "2025-03-04,05:06:07.8", "2026-03-04,05:06:07.8"
        assert convert_date_range(start, stop, mode_mib) == (
            convert_datetime(start, mode_mib), convert_datetime(stop, mode_mib))

    @pytest.mark.parametrize("start,stop", [
        ("2030-01-01,00:00:00.0", "2025-01-01,00:00:00.0"),  # year
        ("2025-06-01,00:00:00.0", "2025-05-01,00:00:00.0"),  # month
        ("2025-06-02,00:00:00.0", "2025-06-01,00:00:00.0"),  # day
        ("2025-06-01,13:00:00.0", "2025-06-01,12:00:00.0"),  # hour
        ("2025-06-01,12:30:00.0", "2025-06-01,12:29:00.0"),  # minute
        ("2025-06-01,12:00:30.0", "2025-06-01,12:00:29.0"),  # second
        ("2025-06-01,12:00:00.5", "2025-06-01,12:00:00.4"),  # decisecond
    ])
    def test_stop_before_start_raises_value_error(self, start, stop):
        with pytest.raises(ValueError):
            convert_date_range(start, stop, "ntcip1218")

    def test_error_message_names_both_dates(self):
        with pytest.raises(ValueError) as excinfo:
            convert_date_range("2030-01-01,00:00:00.0", "2025-01-01,00:00:00.0", "ntcip1218")
        assert "2030-01-01,00:00:00.0" in str(excinfo.value)
        assert "2025-01-01,00:00:00.0" in str(excinfo.value)

    @pytest.mark.parametrize("mode_mib", ["ntcip1218", "rsu41"])
    def test_equal_dates_are_allowed(self, mode_mib):
        date_str = "2025-06-01,12:00:00.0"
        start, stop = convert_date_range(date_str, date_str, mode_mib)
        assert start == stop

    def test_rsu41_truncation_makes_sub_minute_reversal_compare_equal(self):
        # RSU 4.1 drops the seconds, so a pair that is reversed in real time but
        # only below the minute encodes to two identical values and is allowed.
        start, stop = convert_date_range(
            "2025-06-01,12:00:30.0", "2025-06-01,12:00:29.0", "rsu41")
        assert start == stop

    def test_year_zero_is_ordered_without_datetime(self):
        # calendar/datetime cannot represent year 0, but the encoding permits it.
        start, stop = convert_date_range(
            "0000-01-01,00:00:00.0", "0001-01-01,00:00:00.0", "ntcip1218")
        assert start < stop

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


class TestFormatSnmpValueIntegers:
    """INTEGER32 values arrive wrapped in an object exposing .value."""

    @pytest.mark.parametrize("number", [0, 1, -1, 63, 65535])
    def test_wrapped_integer_is_stringified(self, number):
        assert _format(_FakeInteger32(number)) == str(number)

    def test_bare_integer_is_stringified(self):
        assert _format(42) == "42"


# bytes and str payloads reach format_snmp_value either bare or wrapped in an
# OctetString (via .data); both routes must format identically.
_BARE_OR_WRAPPED = pytest.mark.parametrize(
    "wrap", [lambda v: v, _FakeOctetString], ids=["bare", "octetstring"])


class TestFormatSnmpValueBytes:
    """bytes payloads: tried as a DateAndTime, then printable ASCII, then hex."""

    @_BARE_OR_WRAPPED
    @pytest.mark.parametrize("data,expected", [
        (bytes.fromhex("07E9010100000000"), "2025-01-01,00:00:00.0"),  # 8 octets read as DateAndTime
        (b"rsu-config", "rsu-config"),      # printable ASCII decodes to text
        (b"a\tb\nc", "61 09 62 0a 63"),     # control characters are never expected; hex makes them visible
        (b"\xff\xfe", "ff fe"),             # not valid UTF-8
        (b"\x01\x02\x03", "01 02 03"),      # decodable but unprintable
        (b"\x00\x0f\xff", "00 0f ff"),      # hex is space-separated and zero-padded
        (b"", ""),
    ])
    def test_bytes_are_formatted(self, wrap, data, expected):
        assert _format(wrap(data)) == expected


class TestFormatSnmpValueText:
    """str payloads get the same printable-ASCII check as bytes."""

    @_BARE_OR_WRAPPED
    @pytest.mark.parametrize("value,expected", [
        ("rsu-config", "rsu-config"),
        ("\x01\x02", "01 02"),
        ("a\tb", "61 09 62"),
    ])
    def test_text_is_formatted(self, wrap, value, expected):
        assert _format(wrap(value)) == expected


class TestFormatSnmpValueFallbacks:
    """Anything not matched by a specific branch falls back to str()."""

    @pytest.mark.parametrize("value", [None, 3.5, [1, 2]])
    def test_unknown_type_is_stringified(self, value):
        assert _format(value) == str(value)

    def test_octet_string_holding_other_type_is_stringified(self):
        assert _format(_FakeOctetString(12345)) == "12345"


class TestRsuModeHelpContent:
    """Check RSU Mode help text differences."""

    @pytest.mark.parametrize("get_content,ntcip1218_oid,rsu41_oid", [
        (get_rfm_help_content, "1.3.6.1.4.1.1206.4.2.18.5.2.1", "1.0.15628.4.1.7.1"),  # rsuReceivedMsgTable / rsuDsrcForwardTable
        (get_srm_help_content, "1.3.6.1.4.1.1206.4.2.18.3.2.1", "1.0.15628.4.1.4.1"),  # rsuMsgRepeatStatusTable / rsuSRMStatusTable
    ])
    def test_help_documents_both_modes(self, get_content, ntcip1218_oid, rsu41_oid):
        content = get_content()
        assert "=== RSU Mode differences ===" in content
        assert ntcip1218_oid in content
        assert rsu41_oid in content
