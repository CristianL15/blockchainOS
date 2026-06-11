const grpc = require("@grpc/grpc-js");
const crypto = require("crypto");
const fs = require("fs");
const { connect, signers, hash } = require("@hyperledger/fabric-gateway");

const chaincodeName = "audit";
const channelName = "auditchannel";
const mspId = "Org1MSP";

class FabricClient {
  constructor() {
    this.healthy = false;

    const peerEndpoint = process.env.FABRIC_PEER_ENDPOINT;
    if (!peerEndpoint) {
      throw new Error("FABRIC_PEER_ENDPOINT not set");
    }

    const tlsCertPath = process.env.FABRIC_TLS_CERT_PATH;
    const keyPath = process.env.FABRIC_KEY_PATH;
    const certPath = process.env.FABRIC_CERT_PATH;

    const tlsCreds = this._newTls(tlsCertPath);
    const client = new grpc.Client(peerEndpoint, tlsCreds);

    const identity = {
      mspId,
      credentials: fs.readFileSync(certPath),
    };

    const privateKey = crypto.createPrivateKey(
      fs.readFileSync(keyPath, "utf8"),
    );
    const signer = signers.newPrivateKeySigner(privateKey);

    const gateway = connect({
      client,
      identity,
      signer,
      hash: hash.sha256,
      evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
      endorseOptions: () => ({ deadline: Date.now() + 15000 }),
      submitOptions: () => ({ deadline: Date.now() + 15000 }),
      commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
    });

    this._gateway = gateway;
    this._network = gateway.getNetwork(channelName);
    this._contract = this._network.getContract(chaincodeName);
    this.healthy = true;
  }

  async submitEvent(event) {
    const data = JSON.stringify(event);
    await this._contract.submitTransaction("CreateEvent", data);
  }

  async queryByHash(hash) {
    const result = await this._contract.evaluateTransaction(
      "QueryByHash",
      hash,
    );
    return JSON.parse(Buffer.from(result).toString());
  }

  async getAllEvents() {
    const result = await this._contract.evaluateTransaction("GetAllEvents");
    return JSON.parse(Buffer.from(result).toString());
  }

  async getTotalCount() {
    const result = await this._contract.evaluateTransaction("GetTotalCount");
    return JSON.parse(Buffer.from(result).toString());
  }

  close() {
    if (this._gateway) {
      this._gateway.close();
    }
  }

  _newTls(certPath) {
    if (!certPath) {
      return grpc.credentials.createInsecure();
    }
    const rootCert = fs.readFileSync(certPath);
    return grpc.credentials.createSsl(rootCert);
  }
}

module.exports = { FabricClient };
