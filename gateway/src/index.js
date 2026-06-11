const express = require("express");
const { FabricClient } = require("./fabric-client");
const { Handlers } = require("./handlers");

const PORT = process.env.PORT || "8443";
const app = express();

app.use(express.json());

let fc;
try {
  fc = new FabricClient();
  console.log("Gateway running with Fabric connection");
} catch (err) {
  console.warn(`WARNING: Fabric unavailable: ${err.message}`);
  console.log("Gateway running in OFFLINE mode");
}

const h = new Handlers(fc);

app.post("/api/events", (req, res) => h.handleEvents(req, res));
app.get("/api/events", (req, res) => h.handleEvents(req, res));
app.get("/api/events/:hash", (req, res) => h.handleEventByHash(req, res));
app.get("/api/verify", (req, res) => h.handleVerify(req, res));
app.get("/api/status", (req, res) => h.handleStatus(req, res));

app.listen(PORT, () => {
  console.log(`Gateway listening on :${PORT}`);
});
