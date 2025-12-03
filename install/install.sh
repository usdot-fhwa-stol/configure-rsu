#!/bin/sh

set -e
sudo apt-get update 

# Dependencies
dependencies="python3 \
    python3-pip \
    python3-tk"

# Install dependencies, packages
sudo apt-get install -y $dependencies
python3 -m pip install -r requirements.txt

# Create .env file with SNMP credentials if it doesn't exist
SRC_ENV_FILE="$(dirname "$0")/../src/.env"
if [ ! -f "$SRC_ENV_FILE" ]; then
    cat << EOF > "$SRC_ENV_FILE"
# SNMP credentials
SNMP_USER=your_snmp_username
AUTH_PASSWORD=your_authentication_password
PRIV_PASSWORD=your_privacy_password
EOF
    echo "\n.env file created at $SRC_ENV_FILE"
else
    echo "\n.env file already exists at $SRC_ENV_FILE"
fi
