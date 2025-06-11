#!/bin/bash
set -euo pipefail

CONFIG_FILE="/app/config.toml"

# Extract tun_if and tun_ip from the config file
TUN_IF=$(grep -E '^interface *= *"' "$CONFIG_FILE" | sed -E 's/.*= *"(.*)"/\1/' || true)
TUN_IP=$(grep -E '^ip *= *"' "$CONFIG_FILE" | sed -E 's/.*= *"(.*)"/\1/' || true)

# Fail if either is empty
if [[ -z "$TUN_IF" ]]; then
    echo "[ERROR] Failed to extract 'interface' from $CONFIG_FILE"
    exit 1
fi

if [[ -z "$TUN_IP" ]]; then
    echo "[ERROR] Failed to extract 'ip' from $CONFIG_FILE"
    exit 1
fi

# Launch tinescale in the background
tinescale --config "$CONFIG_FILE" &
APP_PID=$!

# Wait for the TUN interface to appear
echo "[INFO] Waiting for interface $TUN_IF to be created by tinescale..."
for i in {1..10}; do
    if ip link show "$TUN_IF" >/dev/null 2>&1; then
        echo "[INFO] Interface $TUN_IF detected"
        break
    fi
    sleep 1
done

# Assign IP to the interface
echo "[INFO] Assigning $TUN_IP to $TUN_IF"
ip addr add "$TUN_IP" dev "$TUN_IF"
ip link set up dev "$TUN_IF"

# Wait for tinescale to exit
wait $APP_PID