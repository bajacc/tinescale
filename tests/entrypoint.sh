#!/bin/bash
set -euo pipefail

ROUTE="${ROUTE:-}"

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
LOG_LEVEL=debug tinescale "$IFACE"

sleep 2

SOCKET_PATH="/var/run/wireguard/$IFACE.sock"
if [[ ! -S "$SOCKET_PATH" ]]; then
    echo "[ERROR] UAPI socket not found at $SOCKET_PATH"
    exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "[ERROR] Interface $IFACE not found"
    exit 1
fi

socat - UNIX-CONNECT:"$SOCKET_PATH" < /app/config.ipc
printf "get=1\n\n" | socat - UNIX-CONNECT:"$SOCKET_PATH"

# Assign IP to the interface
echo "[INFO] Assigning $ADDR to $IFACE"
ip addr add "$ADDR" dev "$IFACE"
ip link set up dev "$IFACE"

if [[ -n "$ROUTE" ]]; then
    ip route add $ROUTE
fi

ping "$PING_ADDR"