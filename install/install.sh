#!/bin/sh

set -e
sudo apt-get update

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN=${PYTHON:-python3}

# Dependencies
dependencies="python3 \
    python3-pip \
    python3-tk"

# Install dependencies, packages
sudo apt-get install -y $dependencies
$PYTHON_BIN -m pip install -r "$REPO_ROOT/install/requirements.txt"

# Create .env file with SNMP credentials if it doesn't exist
SRC_ENV_FILE="$REPO_ROOT/src/.env"
if [ ! -f "$SRC_ENV_FILE" ]; then
    cat << EOF > "$SRC_ENV_FILE"
# SNMP credentials
IP_ADDRESS=your_rsu_ip_address
SNMP_PORT=161
SNMP_USER=your_snmp_username
AUTH_PASSWORD=your_authentication_password
PRIV_PASSWORD=your_privacy_password
EOF
    echo "\n.env file created at $SRC_ENV_FILE"
else
    echo "\n.env file already exists at $SRC_ENV_FILE"
fi

# Declare desktop entry and icon paths
DESKTOP_SRC="$REPO_ROOT/src/desktop_app/configure_rsu.desktop"
ICON_SRC="$REPO_ROOT/src/desktop_app/rsu.png"
USER_DESKTOP="$HOME/Desktop"
LOCAL_ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
LOCAL_ICON_NAME="configure_rsu.png"

# Create necessary directories
mkdir -p "$USER_DESKTOP" "$LOCAL_ICON_DIR"

# If icon does not exist, create a placeholder minimal PNG (white rectangle)
if [ ! -f "$ICON_SRC" ]; then
  echo "Icon rsu.png not found. Creating placeholder icon." >&2
  mkdir -p "$(dirname "$ICON_SRC")"
  # 1x1 white PNG base64
  base64 -d > "$ICON_SRC" <<'EOF'
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==
EOF
fi

# Copy icon to local icon theme directory
cp "$ICON_SRC" "$LOCAL_ICON_DIR/$LOCAL_ICON_NAME"

# Update Icon line in a temp desktop file to point to absolute icon path
TEMP_DESKTOP="$(mktemp)"
sed "s|^Icon=.*|Icon=$LOCAL_ICON_DIR/$LOCAL_ICON_NAME|" "$DESKTOP_SRC" > "$TEMP_DESKTOP"

# Ensure Exec line points to the repo python script (absolute path)
sed -i "s|^Exec=.*|Exec=$PYTHON_BIN $REPO_ROOT/src/configure_rsu.py|" "$TEMP_DESKTOP"

# Copy to user Desktop
TARGET_DESKTOP="$USER_DESKTOP/configure_rsu.desktop"
cp "$TEMP_DESKTOP" "$TARGET_DESKTOP"
chmod +x "$TARGET_DESKTOP"
rm -f "$TEMP_DESKTOP"

# Try to update icon cache (ignore errors if tool absent)
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" || true
fi

echo "Installed desktop entry at $TARGET_DESKTOP"
echo "Icon installed at $LOCAL_ICON_DIR/$LOCAL_ICON_NAME"
