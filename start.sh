#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
FABRIC_DIR="$ROOT/fabric"
GATEWAY_DIR="$ROOT/gateway"
CHAINCODE_DIR="$ROOT/chaincode"

export GATEWAY_URL="${GATEWAY_URL:-http://localhost:8443}"
export FABRIC_PEER_ENDPOINT="${FABRIC_PEER_ENDPOINT:-peer0.org1:7051}"

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# -------------------------------
# Step 1: Build C auditor
# -------------------------------
echo "=== Building C auditor ==="
cd "$ROOT"
make -s 2>&1

# -------------------------------
# Step 2: Start Fabric network
# -------------------------------
echo "=== Starting Fabric network ==="
cd "$FABRIC_DIR"

# Clean if already running (ignore errors)
sudo ./network.sh clean 2>/dev/null || true
sudo ./network.sh start

# Fix crypto file ownership (network.sh generates them as root)
echo "=== Fixing permissions ==="
sudo find "$FABRIC_DIR/crypto-config" -user root -exec chown "$(id -u):$(id -g)" {} \;
chmod 600 "$FABRIC_DIR/crypto-config/peerOrganizations/org1/users/Admin@org1/msp/keystore/priv_sk"

# Copy TLS cert for gateway
cp "$FABRIC_DIR/crypto-config/peerOrganizations/org1/tlsca/tlsca.org1-cert.pem" \
   "$FABRIC_DIR/tls_root_cert.pem"

# -------------------------------
# Step 3: Ensure peer0 hostname resolves
# -------------------------------
if ! grep -qs "peer0.org1" /etc/hosts; then
    echo "=== Adding peer0.org1 to /etc/hosts ==="
    echo "127.0.0.1 peer0 peer0.org1" | sudo tee -a /etc/hosts
fi

# -------------------------------
# Step 4: Start gateway
# -------------------------------
echo "=== Starting gateway ==="
cd "$GATEWAY_DIR"

export FABRIC_TLS_CERT_PATH="$FABRIC_DIR/crypto-config/peerOrganizations/org1/tlsca/tlsca.org1-cert.pem"
export FABRIC_CERT_PATH="$FABRIC_DIR/crypto-config/peerOrganizations/org1/users/Admin@org1/msp/signcerts/Admin@org1-cert.pem"
export FABRIC_KEY_PATH="$FABRIC_DIR/crypto-config/peerOrganizations/org1/users/Admin@org1/msp/keystore/priv_sk"

node src/index.js &
GATEWAY_PID=$!

# Wait for gateway to be ready
for i in $(seq 1 10); do
    if curl -s http://localhost:8443/api/status >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# -------------------------------
# Step 5: Verify
# -------------------------------
echo ""
echo "========================================"
echo "  All systems ready!"
echo "========================================"
echo ""
echo "  Gateway:  http://localhost:8443"
echo "  Auditor:  $ROOT/auditor"
echo ""
echo "  Quick test:"
echo "    curl -s http://localhost:8443/api/status"
echo "    $ROOT/auditor run ls"
echo "    curl -s http://localhost:8443/api/events | python3 -m json.tool"
echo ""

# Keep running until Ctrl+C
wait "$GATEWAY_PID"
