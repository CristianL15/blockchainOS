"use strict";

const shim = require("fabric-shim");

class AuditChaincode extends shim.ChaincodeInterface {
  async Init(stub) {
    return shim.success(null);
  }

  async Invoke(stub) {
    const { fcn, params } = stub.getFunctionAndParameters();

    switch (fcn) {
      case "CreateEvent":
        return this.CreateEvent(stub, params[0]);
      case "QueryByHash":
        return this.QueryByHash(stub, params[0]);
      case "GetAllEvents":
        return this.GetAllEvents(stub);
      case "GetTotalCount":
        return this.GetTotalCount(stub);
      default:
        throw new Error(`unknown function: ${fcn}`);
    }
  }

  async CreateEvent(stub, eventJSON) {
    let event;
    try {
      event = JSON.parse(eventJSON);
    } catch {
      throw new Error("failed to parse event JSON");
    }

    if (!event.hash) {
      throw new Error("event hash is required");
    }

    await stub.putState(event.hash, Buffer.from(eventJSON));
    return shim.success(Buffer.from(event.hash));
  }

  async QueryByHash(stub, hash) {
    const eventBytes = await stub.getState(hash);
    if (!eventBytes || eventBytes.length === 0) {
      throw new Error(`event not found: ${hash}`);
    }

    return shim.success(eventBytes);
  }

  async GetAllEvents(stub) {
    const results = await stub.getStateByRange("", "");
    const events = [];

    while (true) {
      const res = await results.next();
      if (res.done) {
        break;
      }
      try {
        const event = JSON.parse(res.value.value.toString());
        events.push(event);
      } catch {
        continue;
      }
    }
    await results.close();

    return shim.success(Buffer.from(JSON.stringify(events)));
  }

  async GetTotalCount(stub) {
    const events = await this.GetAllEvents(stub);
    const count = JSON.parse(events.payload.toString()).length;
    return shim.success(Buffer.from(JSON.stringify({ count })));
  }
}

shim.start(new AuditChaincode());
