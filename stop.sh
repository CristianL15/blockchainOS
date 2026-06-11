#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
FABRIC_DIR="$ROOT/fabric"

echo "=== Stopping gateway ==="
GATEWAY_PID=$(lsof -ti :8443 2>/dev/null || true)
if [ -n "$GATEWAY_PID" ]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    echo "Gateway stopped (PID $GATEWAY_PID)"
else
    echo "Gateway not running"
fi

echo "=== Stopping Fabric network ==="
cd "$FABRIC_DIR"
sudo ./network.sh clean

echo "=== Done ==="
