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
