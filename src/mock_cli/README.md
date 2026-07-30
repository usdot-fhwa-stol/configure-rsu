# Mock Message RSU 4.1 CLI Tool

## Create a virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Install dependencies
```bash
pip install PyQt6
```

## Run the application
```bash
# Make sure directory is /src
python3 -m mock_cli.main --message BSM
```

### Arguments
`--mode {no-rsu,using-rsu}`
Select local No-RSU mode or use an external RSU. Defaults to no-rsu.

`--target-ip IP`
Override the IP address selected by --mode.

`--port PORT`
Set the RSU IFM UDP port. Defaults to 1516.

`--frequency HZ`
Set the broadcast frequency in hertz. Defaults to 10.0.

`--period SECONDS`
Set the broadcast period for each message type. Defaults to 60 seconds.

`--psid HEX`
Set the PSID as hexadecimal characters. Defaults to 8002.

`--message TYPE`
Select a message type to send. This option may be specified multiple times.

`--signature`
Set Signature=True in the generated AMF message.

`--encryption`
Set Encryption=True in the generated AMF message.

`--payload HEX`
Send a raw payload represented as hexadecimal characters. Mutually exclusive with
`--payload-name`.

`--payload-name NAME`
Select a predefined payload from PAYLOAD_DICT. Mutually exclusive with
`--payload`.

`--no-record`
Disable PCAP recording. Recording is enabled by default.

`--interface INTERFACE`
Override the recording network interface selected by `--mode`.

`--pcap-path PATH`
Override the generated PCAP output path.