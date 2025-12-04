# Configure RSU

## Prerequisites

- tkinter
- snmp

Run the [install.sh](/install/install.sh) script to install all dependencies. 
```bash
cd install
./install.sh
```

The install script will create a .env file in the [src](/src/) directory. You may update this file to contain your RSU's credentials, if repeated access will be needed.

## Usage

The UI for this tool contains four separate tabs. Each tab is used for specific RSU configurations. The initial SNMP credentials configuration must be set before continuing to use the other three tabs. 

1. Execute the script:
```bash
cd src
./configure-rsu.py
```
2. SNMP Configuration
    - Set and test your SNMP user credentials in this tab. 
    - An exit/quit option is also available here.

3. Immediate Forward
    - Get/Destroy/Set immediate forward rules in this tab.

4. Received Message Forward
    - Get/Destroy/Set received message forward rules in this tab.

5. Store-and-Repeat
    - Get/Destroy/Set store-and-repeat rules in this tab.

### Version

Version 1.0 – Dec 05, 2025
