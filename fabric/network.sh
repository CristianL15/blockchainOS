#!/usr/bin/env bash
set -euo pipefail

command -v docker >/dev/null 2>&1 || { echo "docker is required"; exit 1; }

CHANNEL_NAME="auditchannel"
CHAINCODE_LANG="node"
CHAINCODE_NAME="audit"
CHAINCODE_VERSION="1.0"
ORDERER="orderer"
PEER="peer0"
FABRIC_CFG_PATH="${PWD}"

export FABRIC_CFG_PATH

pull_images() {
    echo "=== Pulling Fabric images ==="
    docker pull hyperledger/fabric-tools:2.5
    docker pull hyperledger/fabric-orderer:2.5
    docker pull hyperledger/fabric-peer:2.5
}

gen_crypto() {
    echo "=== Generating crypto material ==="
    rm -rf crypto-config
    mkdir -p crypto-config
    docker run --rm \
        -v "${PWD}/crypto-config.yaml:/crypto-config.yaml:ro" \
        -v "${PWD}/crypto-config:/crypto-config" \
        --entrypoint sh \
        hyperledger/fabric-tools:2.5 \
        -c "rm -rf /crypto-config/* && cryptogen generate --config=/crypto-config.yaml --output=/crypto-config"
    echo "=== Disabling NodeOUs and adding certs to admincerts ==="
    cp crypto-config/peerOrganizations/org1/users/Admin@org1/msp/signcerts/Admin@org1-cert.pem \
       crypto-config/peerOrganizations/org1/msp/admincerts/
    cp crypto-config/peerOrganizations/org1/peers/peer0.org1/msp/signcerts/peer0.org1-cert.pem \
       crypto-config/peerOrganizations/org1/msp/admincerts/
    # Disable NodeOUs in the MSP config (orderer doesn't seem to support it properly)
    cat > crypto-config/peerOrganizations/org1/msp/config.yaml << 'EOF'
NodeOUs:
  Enable: false
EOF
}

gen_channel_artifacts() {
    echo "=== Generating channel genesis block ==="
    mkdir -p channel-artifacts

    docker run --rm \
        -v "${PWD}:/workspace" \
        -w /workspace \
        -e FABRIC_CFG_PATH=/workspace \
        hyperledger/fabric-tools:2.5 \
        configtxgen -profile AuditChannel -outputBlock "./channel-artifacts/${CHANNEL_NAME}.block" -channelID "${CHANNEL_NAME}"
}

up() {
    echo "=== Starting Fabric network ==="
    docker compose -f docker-compose.yaml up -d
    echo "Waiting for peers..."
    sleep 5
}

create_channel() {
    echo "=== Creating channel ${CHANNEL_NAME} via osnadmin ==="
    docker exec cli osnadmin channel join \
        --channelID "${CHANNEL_NAME}" \
        --config-block "/etc/hyperledger/configtx/${CHANNEL_NAME}.block" \
        -o "${ORDERER}:9443" \
        --ca-file /var/hyperledger/orderer/tls/ca.crt \
        --client-cert /var/hyperledger/orderer/tls/server.crt \
        --client-key /var/hyperledger/orderer/tls/server.key

    echo "=== Joining peer to channel ${CHANNEL_NAME} ==="
    docker exec cli peer channel join \
        -b "/etc/hyperledger/configtx/${CHANNEL_NAME}.block"
}

install_chaincode() {
    echo "=== Installing chaincode ==="
    PACKAGE_LABEL="${CHAINCODE_NAME}_${CHAINCODE_VERSION}"

    docker exec cli peer lifecycle chaincode package ${PACKAGE_LABEL}.tar.gz \
        --path /opt/gopath/src/github.com/chaincode \
        --lang "${CHAINCODE_LANG}" \
        --label "${PACKAGE_LABEL}"

    docker exec cli peer lifecycle chaincode install ${PACKAGE_LABEL}.tar.gz

    local pkg_id
    pkg_id=$(docker exec cli peer lifecycle chaincode queryinstalled 2>/dev/null \
        | grep "${PACKAGE_LABEL}" \
        | awk '{print $3}' \
        | tr -d ',')

    echo "Package ID: ${pkg_id}"

    docker exec cli peer lifecycle chaincode approveformyorg \
        -o "${ORDERER}:7050" \
        --tls \
        --cafile /var/hyperledger/orderer/tls/ca.crt \
        --channelID "${CHANNEL_NAME}" \
        --name "${CHAINCODE_NAME}" \
        --version "${CHAINCODE_VERSION}" \
        --package-id "${pkg_id}" \
        --sequence 1

    docker exec cli peer lifecycle chaincode checkcommitreadiness \
        --channelID "${CHANNEL_NAME}" \
        --name "${CHAINCODE_NAME}" \
        --version "${CHAINCODE_VERSION}" \
        --sequence 1

    docker exec cli peer lifecycle chaincode commit \
        -o "${ORDERER}:7050" \
        --tls \
        --cafile /var/hyperledger/orderer/tls/ca.crt \
        --channelID "${CHANNEL_NAME}" \
        --name "${CHAINCODE_NAME}" \
        --version "${CHAINCODE_VERSION}" \
        --sequence 1
}

test_chaincode() {
    echo "=== Testing chaincode ==="
    docker exec cli peer chaincode invoke \
        -o "${ORDERER}:7050" \
        --tls \
        --cafile /var/hyperledger/orderer/tls/ca.crt \
        -C "${CHANNEL_NAME}" \
        -n "${CHAINCODE_NAME}" \
        -c '{"Args":["getTotalCount"]}'
}

down() {
    echo "=== Stopping network ==="
    docker compose -f docker-compose.yaml down -v
    rm -rf crypto-config channel-artifacts
}

case "${1:-help}" in
    pull)      pull_images ;;
    setup)     gen_crypto; gen_channel_artifacts ;;
    up)        up ;;
    channel)   create_channel ;;
    chaincode) install_chaincode ;;
    test)      test_chaincode ;;
    start)
        gen_crypto
        gen_channel_artifacts
        up
        create_channel
        echo "=== Waiting for Raft leader ==="
        sleep 5
        install_chaincode
        echo "=== Network ready ==="
        ;;
    clean)     down ;;
    restart)   down; start ;;
    *)
        echo "Usage: $0 {pull|setup|up|channel|chaincode|test|start|clean|restart}"
        echo ""
        echo "Steps (in order):"
        echo "  1. $0 pull       - download Fabric images"
        echo "  2. $0 setup      - generate crypto + channel artifacts"
        echo "  3. $0 up         - start containers"
        echo "  4. $0 channel    - create and join channel"
        echo "  5. $0 chaincode  - install and commit chaincode"
        echo "  6. $0 test       - invoke chaincode"
        echo ""
        echo "  $0 start         - all steps in one command"
        echo "  $0 clean         - stop and remove everything"
        exit 1
        ;;
esac
