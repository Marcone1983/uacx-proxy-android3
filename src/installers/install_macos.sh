#!/bin/bash
set -e
INSTALL_DIR="/usr/local/smartcache"

mkdir -p "$INSTALL_DIR"
curl -L -o "$INSTALL_DIR/smartcache.zip" "https://github.com/Marcone1983/uacx-proxy-android3/releases/latest/download/smartcache.zip"
unzip -o "$INSTALL_DIR/smartcache.zip" -d "$INSTALL_DIR"

cat <<EOF >/Library/LaunchDaemons/com.smartcache.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.smartcache</string>
<key>ProgramArguments</key><array>
<string>/usr/local/bin/node</string>
<string>$INSTALL_DIR/src/smartcache.js</string>
</array>
<key>RunAtLoad</key><true/>
</dict></plist>
EOF

launchctl load /Library/LaunchDaemons/com.smartcache.plist

open "http://localhost:3000"