#!/bin/bash
set -e
INSTALL_DIR="/opt/smartcache"
USER="smartcache"

sudo useradd -r -s /bin/false $USER || true
sudo mkdir -p "$INSTALL_DIR"
sudo curl -L -o "$INSTALL_DIR/smartcache.zip" "https://github.com/Marcone1983/uacx-proxy-android3/releases/latest/download/smartcache.zip"
sudo unzip -o "$INSTALL_DIR/smartcache.zip" -d "$INSTALL_DIR"
sudo chown -R $USER:$USER "$INSTALL_DIR"

cat <<EOF | sudo tee /etc/systemd/system/smartcache.service
[Unit]
Description=SmartCache AI Interceptor
After=network.target

[Service]
ExecStart=/usr/bin/node $INSTALL_DIR/src/smartcache.js
Restart=always
User=$USER
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now smartcache

xdg-open "http://localhost:3000" 2>/dev/null || true