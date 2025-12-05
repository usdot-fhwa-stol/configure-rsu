# Configure RSU

## Prerequisites

- tkinter
- snmp

Run the [install.sh](/install/install.sh) script to install all dependencies and a desktop app icon.
```bash
cd install
./install.sh
```

The install script will:
 - Create a .env file in the [src](/src/) directory. You may update this file to contain your RSU's credentials, if repeated access will be needed.
 - Create a desktop app on your Desktop. Right-click on the RSU icon and select "Allow Launching" to be able to run the App.

## Usage

The UI for this tool contains four separate tabs. Each tab is used for specific RSU configurations. The initial SNMP credentials configuration must be set before continuing to use the other three tabs. 

1. Run the application:
    - Double-click on the desktop app icon. 

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
