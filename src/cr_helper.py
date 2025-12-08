def convert_datetime_to_snmp(date_str: str) -> bytes:
    """
    Convert human-readable date format to DateAndTime (8 octets).

    Input format: yyyy-mm-dd,hh:mm:ss.ms
    Example: "2025-01-01,00:00:00.0"

    Output: 8 bytes representing DateAndTime per RFC 2579:
    - octets 1-2: year (network byte order)
    - octet 3: month (1-12)
    - octet 4: day (1-31)
    - octet 5: hour (0-23)
    - octet 6: minutes (0-59)
    - octet 7: seconds (0-59)
    - octet 8: deciseconds (0-9)

    Example: "2025-01-01,00:00:00.0" -> 07 E9 01 01 00 00 00 00
    """
    try:
        # Parse the date string
        date_part, time_part = date_str.split(',')
        year, month, day = map(int, date_part.split('-'))

        # Parse time with deciseconds
        time_components = time_part.split(':')
        hour = int(time_components[0])
        minute = int(time_components[1])
        seconds_with_ds = time_components[2].split('.')
        second = int(seconds_with_ds[0])
        decisecond = int(seconds_with_ds[1]) if len(seconds_with_ds) > 1 else 0

        # Build the 8-byte DateAndTime structure
        year_high = (year >> 8) & 0xFF
        year_low = year & 0xFF

        date_time_bytes = bytes([
            year_high,      # octet 1: year high byte
            year_low,       # octet 2: year low byte
            month,          # octet 3: month
            day,            # octet 4: day
            hour,           # octet 5: hour
            minute,         # octet 6: minute
            second,         # octet 7: second
            decisecond      # octet 8: decisecond
        ])

        return date_time_bytes
    except Exception as e:
        raise ValueError(f"Invalid date format '{date_str}'. Expected format: yyyy-mm-dd,hh:mm:ss.ms (e.g., 2025-01-01,00:00:00.0). Error: {e}")

def convert_snmp_datetime_to_string(date_bytes: bytes) -> str:
    """
    Convert SNMP DateAndTime (8 octets) to human-readable format.

    Input: 8 bytes representing DateAndTime per RFC 2579:
    - octets 1-2: year (network byte order, big-endian)
    - octet 3: month (1-12)
    - octet 4: day (1-31)
    - octet 5: hour (0-23)
    - octet 6: minutes (0-59)
    - octet 7: seconds (0-59)
    - octet 8: deciseconds (0-9)

    Output format: yyyy-mm-dd,hh:mm:ss.ms
    Example: 07 E9 01 01 00 00 00 00 -> "2025-01-01,00:00:00.0"
    """
    try:
        if len(date_bytes) != 8:
            return ' '.join(f'{b:02x}' for b in date_bytes)  # Return as hex if not 8 bytes

        # Extract values from bytes
        year = (date_bytes[0] << 8) | date_bytes[1]  # Combine high and low bytes
        month = date_bytes[2]
        day = date_bytes[3]
        hour = date_bytes[4]
        minute = date_bytes[5]
        second = date_bytes[6]
        decisecond = date_bytes[7]

        # Format as readable string
        return f"{year:04d}-{month:02d}-{day:02d},{hour:02d}:{minute:02d}:{second:02d}.{decisecond}"
    except Exception:
        # If conversion fails, return as hex string
        return ' '.join(f'{b:02x}' for b in date_bytes)

def format_snmp_value(varbind) -> str:
    """Format SNMP VarBind value, converting binary data to hex string if needed, and 8-byte octet strings to datetime."""
    # varbind has .value attribute which is an snmp.smi.ObjectSyntax object
    value = varbind.value

    # Handle INTEGER32 types
    if hasattr(value, 'value') and isinstance(value.value, int):
        return str(value.value)

    # Handle different value types from snmp library
    if hasattr(value, 'data'):  # OctetString type
        data = value.data
        if isinstance(data, bytes):
            # Check if this is an 8-byte DateAndTime value
            if len(data) == 8:
                # Try to convert to datetime string
                datetime_str = convert_snmp_datetime_to_string(data)
                # Only return as datetime if it looks valid (not all hex)
                if ',' in datetime_str and '-' in datetime_str:
                    return datetime_str

            # Try to decode as UTF-8 string first
            try:
                decoded_str = data.decode('utf-8')
                # If it's printable, return as string
                if all(32 <= ord(c) <= 126 or c in '\t\n\r' for c in decoded_str):
                    return decoded_str
            except (UnicodeDecodeError, AttributeError):
                pass

            # Return as hex string if not printable
            return ' '.join(f'{b:02x}' for b in data)
        elif isinstance(data, str):
            return data
        return str(data)
    elif isinstance(value, bytes):
        # Check if this is an 8-byte DateAndTime value
        if len(value) == 8:
            datetime_str = convert_snmp_datetime_to_string(value)
            if ',' in datetime_str and '-' in datetime_str:
                return datetime_str

        # Try to decode as UTF-8 string first
        try:
            decoded_str = value.decode('utf-8')
            # If it's printable, return as string
            if all(32 <= ord(c) <= 126 or c in '\t\n\r' for c in decoded_str):
                return decoded_str
        except (UnicodeDecodeError, AttributeError):
            pass

        return ' '.join(f'{b:02x}' for b in value)
    elif isinstance(value, str):
        # Check if string contains non-printable characters
        if any(ord(c) < 32 or ord(c) > 126 for c in value):
            # Convert to hex
            return ' '.join(f'{ord(c):02x}' for c in value)
        return value
    elif isinstance(value, int):
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
"""
