import calendar
import struct

# Valid ranges for each field of a DateAndTime value, per RFC 2579, erratum 417.
_FIELD_RANGES = (
    ("year", 0, 65535),
    ("month", 1, 12),
    ("day", 1, 31),
    ("hour", 0, 23),
    ("minute", 0, 59),
    ("second", 0, 60),
    ("decisecond", 0, 9),
)

# Indicates datetime format for each RSU mode.
_MODE_FORMATS = {
    "ntcip1218": (8, True),
    "rsu41": (6, False),
}

# Wire layout of a DateAndTime value: big-endian two-octet year,
# one octet each for: month, day, hour, minute, second, and decisecond.
_DATETIME_STRUCT = struct.Struct('>HBBBBBB')

def _to_hex(data) -> str:
    """Render bytes, or a str's code points, as space-separated two-digit hex."""
    if isinstance(data, str):
        return ' '.join(f'{ord(c):02x}' for c in data)
    return data.hex(' ')

def _is_printable_ascii(text: str) -> bool:
    """
    Check whether every character is printable ASCII (0x20-0x7E).

    Control characters, including tab, newline and carriage return, are not
    printable. Make edit if ever needed, but probably not needed.
    """
    return text.isascii() and text.isprintable()

def parse_datetime_fields(date_str: str, require_seconds: bool = True) -> tuple:
    """
    Parse and validate input date string into its components.

    Args:
        date_str (str): yyyy-mm-dd,hh:mm:ss.ms

    Returns:
        tuple: year, month, day, hour, minute, second, decisecond

    Raises:
        ValueError: If any of the following validation checks fail:
            * The string cannot be parsed.
            * A field falls outside the range allowed by RFC 2579.
            * The day does not exist in the given month (e.g. 2025-02-30).
    """
    try:
        date_part, time_part = date_str.split(',')
        year, month, day = map(int, date_part.split('-'))

        time_components = time_part.split(':')
        hour = int(time_components[0])
        minute = int(time_components[1])

        if len(time_components) > 2:
            seconds_with_ds = time_components[2].split('.')
            second = int(seconds_with_ds[0])
            decisecond = int(seconds_with_ds[1]) if len(seconds_with_ds) > 1 else 0
        elif require_seconds:
            raise ValueError("missing seconds")
        else:
            second = 0
            decisecond = 0
    except Exception as e:
        raise ValueError(
            f"Invalid date format '{date_str}'. Expected format: yyyy-mm-dd,hh:mm:ss.ms. Error: {e}")

    fields = (year, month, day, hour, minute, second, decisecond)
    for value, (name, low, high) in zip(fields, _FIELD_RANGES):
        if not low <= value <= high:
            raise ValueError(f"Invalid date '{date_str}'. {name} must be {low}-{high}, got {value}")

    # Reject days that do not exist in the given month
    if year >= 1: # calendar.monthrange cannot handle year 0, which the encoding permits.
        days_in_month = calendar.monthrange(year, month)[1]
        if day > days_in_month:
            raise ValueError(f"Invalid date '{date_str}'. Day must be 1-{days_in_month} for month {month} of {year}, got {day}.")

    return fields

def convert_datetime(date_str: str, mode_mib: str) -> bytes:
    """
    Convert input date format to the delivery time encoding used by
    the given RSU mode.

    Args:
        date_str (str): yyyy-mm-dd,hh:mm:ss.ms
        mode_mib (str): "ntcip1218" or "rsu41"

    Returns:
        bytes:

    * octets 1-2: year
    * octet 3: month (1-12)
    * octet 4: day (1-31)
    * octet 5: hour (0-23)
    * octet 6: minutes (0-59)
    * octet 7: seconds (0-60) # 60 allows for leap seconds
    * octet 8: deciseconds (0-9)

    Examples:
        ("2025-01-01,00:00:00.0", "ntcip1218") -> 07 E9 01 01 00 00 00 00

        ("2025-01-01,00:00:00.0", "rsu41")     -> 07 E9 01 01 00 00

    Raises:
        ValueError: If mode_mib is not a known mode
    """
    if mode_mib not in _MODE_FORMATS:
        known = ", ".join(sorted(_MODE_FORMATS))
        raise ValueError(f"Unknown RSU mode '{mode_mib}'. Expected one of: {known}")

    octets, require_seconds = _MODE_FORMATS[mode_mib]
    fields = parse_datetime_fields(date_str, require_seconds=require_seconds)

    # Every field is already range-checked to what its octet(s) can hold.
    return _DATETIME_STRUCT.pack(*fields)[:octets]

def convert_date_range(start_str: str, stop_str: str, mode_mib: str) -> tuple:
    """
    Convert a start/stop pair, rejecting a stop that precedes the start.

    Args:
        start_str (str): yyyy-mm-dd,hh:mm:ss.ms
        stop_str (str): yyyy-mm-dd,hh:mm:ss.ms
        mode_mib (str): "ntcip1218" or "rsu41"

    Returns:
        tuple: (start_bytes, stop_bytes), encoded per convert_datetime.

    Raises:
        ValueError: If the stop date is earlier than the start date.
    """
    start_bytes = convert_datetime(start_str, mode_mib)
    stop_bytes = convert_datetime(stop_str, mode_mib)

    if stop_bytes < start_bytes:
        raise ValueError(
            f"Invalid date range. Stop date '{stop_str}' is earlier than start date '{start_str}'.")

    return start_bytes, stop_bytes

def convert_snmp_datetime_to_string(date_bytes: bytes) -> str:
    """
    Convert SNMP DateAndTime to human-readable format.

    Args:
        date_bytes (bytes): 8 bytes representing DateAndTime per RFC 2579:

    * octets 1-2: year
    * octet 3: month (1-12)
    * octet 4: day (1-31)
    * octet 5: hour (0-23)
    * octet 6: minutes (0-59)
    * octet 7: seconds (0-60) # 60 allows for leap seconds
    * octet 8: deciseconds (0-9)

    Returns:
        str: yyyy-mm-dd,hh:mm:ss.ms

    Example:
        07 E9 01 01 00 00 00 00 -> "2025-01-01,00:00:00.0"
    """
    try:
        if len(date_bytes) != _DATETIME_STRUCT.size:
            return _to_hex(date_bytes)  # Return as hex if not 8 bytes

        year, month, day, hour, minute, second, decisecond = _DATETIME_STRUCT.unpack(date_bytes)

        # Format as readable string
        return f"{year:04d}-{month:02d}-{day:02d},{hour:02d}:{minute:02d}:{second:02d}.{decisecond}"
    except Exception:
        # If conversion fails, return as hex string
        return _to_hex(date_bytes)

def _format_octet_bytes(data: bytes) -> str:
    """Format an OctetString payload for display."""
    if len(data) == 8:
        datetime_str = convert_snmp_datetime_to_string(data)
        # Only return as datetime if it looks valid (not all hex).
        if ',' in datetime_str and '-' in datetime_str:
            return datetime_str

    try:
        decoded_str = data.decode('utf-8')
        if _is_printable_ascii(decoded_str):
            return decoded_str
    except (UnicodeDecodeError, AttributeError):
        pass

    return _to_hex(data)

def _format_text(value: str) -> str:
    """Format a str payload, falling back to hex if it is not printable ASCII."""
    if not _is_printable_ascii(value):
        return _to_hex(value)
    return value

def format_snmp_value(varbind) -> str:
    """Format SNMP VarBind value, converting binary data to hex string if needed, and 8-byte octet strings to datetime."""
    value = varbind.value

    # Handle INTEGER32 types
    if hasattr(value, 'value') and isinstance(value.value, int):
        return str(value.value)

    # Handle different value types from snmp library
    if hasattr(value, 'data'):  # OctetString type
        data = value.data
        if isinstance(data, bytes):
            return _format_octet_bytes(data)
        if isinstance(data, str):
            return _format_text(data)
        return str(data)

    if isinstance(value, bytes):
        return _format_octet_bytes(value)
    if isinstance(value, str):
        return _format_text(value)
    if isinstance(value, int):
        return str(value)

    return str(value)

def get_ifm_help_content() -> str:
    """Return help content for Immediate Forward tab."""
    return """Immediate Forward Messages (IFM) Configuration Help

=== IFM Entry Fields ===
For more information on each field, refer to the RSU SNMP MIB documentation section 5.5 Immediate Forward Messages.
https://www.ntcip.org/file/2025/01/NTCIP-1218-v01A-2024-AsPublished.pdf

PSID: Provider Service Identifier (hex value)
      Identifies the type of message being transmitted.

Channel: Transmission channel number (typically 172-184)
         The radio channel on which the message will be broadcast.

Enable: 0 = Disabled, 1 = Enabled
        Controls whether this IFM entry is active.

Priority: Message priority (0-63, higher is more important)
          Determines transmission priority when multiple messages compete.

Payload: Hex value containing the message data to be transmitted.


Options: Bit-mapped options (BITS, hex):
    Bit 0: 0=Bypass1609.2, 1=Process1609.2
    Bit 1: 0=Secure,       1=Unsecure
    Bit 2: 0=ContXmit,     1=NoXmitShortTermXceeded
    Bit 3: 0=ContXmit,     1=NoXmitLongTermXceeded
"""
def get_tfm_help_content() -> str:
    """Return help content for Transmitted Message Forward tab."""
    return """Transmitted Message Forward (TFM) Configuration Help

=== TFM Entry Fields ===
For more information on each field, refer to the RSU SNMP MIB documentation section 5.2 Transmitted Messages.
https://www.ntcip.org/file/2025/01/NTCIP-1218-v01A-2024-AsPublished.pdf

PSID: Provider Service Identifier (hex value)
      Identifies the type of message to forward when received.

Destination IP: IP address where received messages will be forwarded.
                The IP address of the destination system.

Destination Port: Port number for forwarding.
                  The port on the destination system.

Protocol: Transport protocol for forwarding
          1 = Other (A SET to a value of 'other' shall return a badValue error.)
          2 = UDP (User Datagram Protocol)

Start Date: Message forwarding start date/time
            Format: yyyy-mm-dd,hh:mm:ss.ms
            Example: 2025-01-01,00:00:00.0
            This is converted to SNMP DateAndTime format (8 octets)
            Example: 2025-01-01,00:00:00.0 becomes 07 E9 01 01 00 00 00 00

Stop Date: Message forwarding stop date/time
           Format: yyyy-mm-dd,hh:mm:ss.ms
           Example: 2030-01-01,00:00:00.0
           This is converted to SNMP DateAndTime format (8 octets)

Secure: Security requirement for forwarded messages
        0 = Accept both secure and unsecure messages
        1 = Accept only secure messages
"""

def get_rfm_help_content() -> str:
    """Return help content for Received Message Forward tab."""
    return """Received Message Forward (RFM) Configuration Help

=== RFM Entry Fields ===
For more information on each field, refer to the RSU SNMP MIB documentation section 5.6 Received Messages.
https://www.ntcip.org/file/2025/01/NTCIP-1218-v01A-2024-AsPublished.pdf

PSID: Provider Service Identifier (hex value)
      Identifies the type of message to forward when received.

Destination IP: IP address where received messages will be forwarded.
                The IP address of the destination system.

Destination Port: Port number for forwarding.
                  The port on the destination system.

Protocol: Transport protocol for forwarding
          1 = Other (A SET to a value of 'other' shall return a badValue error.)
          2 = UDP (User Datagram Protocol)

RSSI: Received Signal Strength Indicator threshold (dBm)
      Minimum signal strength required to forward message.
      Typical value: -100 (dBm)

Interval: Forwarding interval in deciseconds (1/10 second)
          Controls how often messages are forwarded.
          1 = 100ms, 10 = 1 second

Start Date: Message forwarding start date/time
            Format: yyyy-mm-dd,hh:mm:ss.ms
            Example: 2025-01-01,00:00:00.0
            This is converted to SNMP DateAndTime format (8 octets)
            Example: 2025-01-01,00:00:00.0 becomes 07 E9 01 01 00 00 00 00

Stop Date: Message forwarding stop date/time
           Format: yyyy-mm-dd,hh:mm:ss.ms
           Example: 2030-01-01,00:00:00.0
           This is converted to SNMP DateAndTime format (8 octets)

Secure: Security requirement for forwarded messages
        0 = Accept both secure and unsecure messages
        1 = Accept only secure messages

Auth Msg Interval: Authentication message interval in deciseconds
                   0 = No authentication messages

=== RSU Mode differences ===
The active RSU Mode (set on the SNMP Credentials tab) selects the MIB used
and which fields apply. Fields that do not apply to the selected mode are
grayed out.

NTCIP 1218 (rsuReceivedMsgTable, 1.3.6.1.4.1.1206.4.2.18.5.2.1):
    Uses Secure and Auth Msg Interval. Start/Stop dates are 8-octet
    DateAndTime values (e.g. 2025-01-01,00:00:00.0 -> 07 E9 01 01 00 00 00 00).

RSU 4.1 (rsuDsrcForwardTable, 1.0.15628.4.1.7.1):
    DSRC Forwarding was renamed to Received Message Forwarding in NTCIP 1218.
    Uses Enable (0 = off, 1 = on) instead of Secure/Auth Msg Interval.
    Start/Stop dates are 6-octet values that drop the seconds/deciseconds
    (e.g. 2025-01-01,00:00 UTC -> 07 E9 01 01 00 00).
"""

def get_srm_help_content() -> str:
    """Return help content for Store and Repeat Messages tab."""
    return """Store and Repeat Messages (SRM) Configuration Help

=== SRM Entry Fields ===
For more information on each field, refer to the RSU SNMP MIB documentation section 5.4 Store and Repeat Messages.
https://www.ntcip.org/file/2025/01/NTCIP-1218-v01A-2024-AsPublished.pdf

PSID: Provider Service Identifier (hex value)
      Identifies the message type to store and repeat.

TX Channel: Transmission channel number (typically 172-184)
            The radio channel used when repeating the message.

TX Interval: Transmission interval in milliseconds
             How often the stored message is repeated. (rsuMsgRepeatTxInterval)

Start Date: Message forwarding start date/time
            Format: yyyy-mm-dd,hh:mm:ss.ms
            Example: 2025-01-01,00:00:00.0
            This is converted to SNMP DateAndTime format (8 octets)
            Example: 2025-01-01,00:00:00.0 becomes 07 E9 01 01 00 00 00 00

Stop Date: Message forwarding stop date/time
           Format: yyyy-mm-dd,hh:mm:ss.ms
           Example: 2030-01-01,00:00:00.0
           This is converted to SNMP DateAndTime format (8 octets)

Payload: Hex value containing the message data to be transmitted.

Enable: 0 = Disabled, 1 = Enabled
        Controls whether this SRM entry is active (rsuMsgRepeatEnable).

Priority: Message priority (0-63, higher is more important)
          Determines transmission priority when multiple messages compete.

Options: Bit-mapped options (BITS, hex):
    Bit 0: 0=Bypass1609.2, 1=Process1609.2
    Bit 1: 0=Secure,       1=Unsecure
    Bit 2: 0=ContXmit,     1=NoXmitShortTermXceeded
    Bit 3: 0=ContXmit,     1=NoXmitLongTermXceeded

=== RSU Mode differences ===
The active RSU Mode (set on the SNMP Credentials tab) selects the MIB used
and which fields apply. Fields that do not apply to the selected mode are
grayed out.

NTCIP 1218 (1.3.6.1.4.1.1206.4.2.18.3.2.1):
    Uses Priority and Options. Start/Stop dates are 8-octet DateAndTime
    values (e.g. 2025-01-01,00:00:00.0 -> 07 E9 01 01 00 00 00 00).

RSU 4.1 (rsuSRMStatusTable, 1.0.15628.4.1.4.1):
    Uses DSRC Msg ID and TX Mode (0=cont, 1=alt) instead of Priority/Options.
    Start/Stop dates are 6-octet values that drop the seconds/deciseconds
    (e.g. 2025-01-01,00:00 UTC -> 07 E9 01 01 00 00).
"""

def get_amf_help_content() -> str:
    """Return help content for Active Message File tab."""
    return """Active Message File (AMF) Configuration Help
=== AMF Entry Fields ===
# Message File Format
# Modified Date: 04/10/2014
# Version: 0.7
Version=0.7
#
# Message Dispatch Items
#
# All line beginning with # shall be removed in file sent to radio
#
# Message Type
# Values: SPAT, MAP, TIM, (other J2735 message types)
Type=<Type>
#
# Message PSID as a 2 Byte Hex value (e.g. 8003)
# List of PSIDs can be found here: https://standards.ieee.org/products-programs/regauth/psid/public/
# Use the P-encoded column.
PSID=<PSID>
#
# Message Priority in the range of 0 (lowest) through 7
Priority=<priority>
#
# Transmission Channel Mode
# Allowed values: CONT, ALT
TxMode=<txmode>
# Allowed values: 172-183, CCH, SCH (note: “CCH” refers to DSRC Channel 178 and SCH refers to
# the operator configured DSRC Service Channel. 183 is the only C-V2X channel.)
TxChannel=<channel>
#
# Transmission Broadcast Interval in Seconds
# Allowed values: 0 for Immediate-Forwarding, 1 to 5 for Store-and-Repeat
TxInterval=<txinterval>
#
# Message Delivery (broadcast) start time (UTC date and time) in the form:
# "mm/dd/yyyy, hh:mm”
# Leave value blank if Immediate Forward mode
DeliveryStart=<mm/dd/yyyy, hh:mm>
#
# Message Delivery (broadcast) stop time (UTC date and time) in the form:
# "mm/dd/yyyy, hh:mm”
# Leave value blank if Immediate Forward mode
DeliveryStop=<mm/dd/yyyy, hh:mm>
#
# Message Signature/Encryption
Signature=<True/False>
Encryption=<True/False>
# 
# Message Payload (encoded according to J2735 or other definition)
Payload=<V2X message payload>
"""
