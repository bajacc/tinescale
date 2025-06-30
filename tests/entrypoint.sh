#!/bin/bash
set -euo pipefail

IPC_FILE="/app/config.ipc"

# Fail if either is empty
if [[ -z "$IFACE" ]]; then
    echo "[ERROR] IFACE not defined as an env variable"
    exit 1
fi

if [[ -z "$ADDR" ]]; then
    echo "[ERROR] ADDR not defined as an env variable"
    exit 1
fi

# Launch tinescale in the background
tinescale --ipc "$IPC_FILE" &
APP_PID=$!

# Wait for the TUN interface to appear
echo "[INFO] Waiting for interface $IFACE to be created by tinescale..."
for i in {1..10}; do
    if ip link show "$IFACE" >/dev/null 2>&1; then
        echo "[INFO] Interface $IFACE detected"
        break
    fi
    sleep 1
done

# Assign IP to the interface
echo "[INFO] Assigning $ADDR to $IFACE"
ip addr add "$ADDR" dev "$IFACE"
ip link set up dev "$IFACE"

# Wait for tinescale to exit
wait $APP_PID