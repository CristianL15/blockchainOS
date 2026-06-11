const crypto = require("crypto");

class Handlers {
  constructor(fc) {
    this.fc = fc;
  }

  handleEvents(req, res) {
    switch (req.method) {
      case "POST":
        return this.createEvent(req, res);
      case "GET":
        return this.listEvents(req, res);
      default:
        return res.status(405).json({ error: "method not allowed" });
    }
  }

  async createEvent(req, res) {
    const event = req.body;
    if (!event || !event.hash) {
      return res
        .status(400)
        .json({ error: "invalid JSON or hash is required" });
    }

    if (!this.fc || !this.fc.healthy) {
      return res.status(422).json({
        error: "Fabric unavailable",
        message: "event stored locally but not submitted to blockchain",
      });
    }

    try {
      await this.fc.submitEvent(event);
      return res
        .status(201)
        .json({ message: "event created", hash: event.hash });
    } catch (err) {
      console.error("Fabric submit error:", err.message);
      return res.status(422).json({
        error: "Fabric submit failed",
        message: err.message,
      });
    }
  }

  async listEvents(req, res) {
    if (!this.fc || !this.fc.healthy) {
      return res.status(503).json({ error: "Fabric unavailable" });
    }

    try {
      const events = await this.fc.getAllEvents();
      return res.json(events || []);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  async handleEventByHash(req, res) {
    if (req.method !== "GET") {
      return res.status(405).json({ error: "method not allowed" });
    }

    const hash = req.params.hash;
    if (!hash) {
      return res.status(400).json({ error: "hash required" });
    }

    if (!this.fc || !this.fc.healthy) {
      return res.status(503).json({ error: "Fabric unavailable" });
    }

    try {
      const event = await this.fc.queryByHash(hash);
      return res.json(event);
    } catch (err) {
      return res.status(404).json({ error: "event not found" });
    }
  }

  async handleVerify(req, res) {
    if (req.method !== "GET") {
      return res.status(405).json({ error: "method not allowed" });
    }

    if (!this.fc || !this.fc.healthy) {
      return res.status(503).json({ error: "Fabric unavailable" });
    }

    try {
      const events = await this.fc.getAllEvents();
      let verified = true;
      const failed = [];

      for (const ev of events) {
        const expectedHash = computeSHA256(ev);
        if (ev.hash !== expectedHash) {
          verified = false;
          failed.push(ev.hash);
        }
      }

      return res.json({ verified, total: events.length, failed });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  async handleStatus(req, res) {
    const online = !!(this.fc && this.fc.healthy);
    let count = -1;

    if (online) {
      try {
        count = await this.fc.getTotalCount();
      } catch {
        count = -1;
      }
    }

    return res.json({ gateway: "running", fabric: online, events: count });
  }
}

function computeSHA256(ev) {
  const h = crypto.createHash("sha256");
  h.update(ev.event_type || "");
  h.update(ev.command || "");
  h.update(ev.user || "");
  h.update(String(ev.pid || 0));
  h.update(ev.cwd || "");
  h.update(ev.timestamp || "");
  h.update(String(ev.return_code || 0));
  return h.digest("hex");
}

module.exports = { Handlers, computeSHA256 };
