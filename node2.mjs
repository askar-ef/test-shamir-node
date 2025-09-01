import "dotenv/config";
import express from "express";
import fs from "fs/promises";
import crypto from "crypto";
import fetch from "node-fetch";
import https from "https";
import fsSync from "fs";
import { CryptoEnclave } from "./crypto-enclave.mjs";

const app = express();
app.use(express.json());

// HTTPS options
const httpsOptions = {
  key: fsSync.readFileSync("./certs/key.pem"),
  cert: fsSync.readFileSync("./certs/cert.pem"),
};

const API_KEY = process.env.API_KEY || "YOUR_COORDINATOR_API_KEY_HERE";
const ENCRYPTION_KEY_HEX =
  process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex");

// Initialize CryptoEnclave for this node (Node 2 acts as the enclave handler)
const nodeCrypto = new CryptoEnclave(ENCRYPTION_KEY_HEX);

console.log("Node 2 (Enclave) API Key:", API_KEY);
console.log("Node 2 (Enclave) Encryption Key:", ENCRYPTION_KEY_HEX);

// Middleware for API Key authentication
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== API_KEY) {
    return res.status(401).json({ error: "Unauthorized: Invalid API Key" });
  }
  next();
};

app.use(authenticateApiKey); // Apply authentication middleware to all routes

const SHARE_FILE = `./node_share_${process.argv[2] || 3002}.enc`;

// Node 2 is responsible for handling the enclave operations (storing shares and managing sign requests)

// Store share
app.post("/store", async (req, res) => {
  try {
    const share = req.body.share;
    if (!share) {
      return res.status(400).json({ error: "Share is required" });
    }
    const encryptedShare = nodeCrypto.encrypt(share);
    await fs.writeFile(SHARE_FILE, encryptedShare);
    console.log("Stored and encrypted share to file:", SHARE_FILE);
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Error storing share:", err);
    res.status(500).json({ error: err.message });
  }
});

// Return share
app.get("/get-share", async (req, res) => {
  try {
    const encryptedShare = await fs.readFile(SHARE_FILE, "utf8");
    const decryptedShare = nodeCrypto.decrypt(encryptedShare);
    res.json({ share: decryptedShare });
  } catch (err) {
    if (err.code === "ENOENT") {
      return res.status(400).json({ error: "No share stored" });
    }
    console.error("Error retrieving share:", err);
    res.status(500).json({ error: err.message });
  }
});

// Store pending sign requests
let pendingSignRequests = {};
const APPROVAL_TIMEOUT_MS = 60 * 1000; // 1 minute

const NODE1_URL = process.env.NODE1_URL || "https://localhost:3001";

// create https agent to ignore self-signed certs for local calls to node1
const agent = new https.Agent({
  rejectUnauthorized: false,
  secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
  ca: fsSync.readFileSync("./certs/cert.pem"),
});
const fetchAgent = (parsedURL) => {
  try {
    return parsedURL.protocol === "https:" ? agent : undefined;
  } catch (e) {
    return undefined;
  }
};

// Endpoint to request signing (now validates token by calling Node1)
app.post("/request-sign", async (req, res) => {
  try {
    const { message, requestId, token } = req.body;
    if (!message || !requestId || !token) {
      return res.status(400).json({ error: "Message, requestId and token are required" });
    }

    // Verify token by asking Node1
    try {
      const vres = await fetch(`${NODE1_URL}/validate-jwt`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
        },
        body: JSON.stringify({ token }),
        agent: fetchAgent,
      });
      const vjson = await vres.json();
      if (!vres.ok || vjson.status !== "valid") {
        console.error("Token validation at Node1 failed:", vjson);
        return res.status(401).json({ error: "Invalid token", details: vjson });
      }
      console.log("Node2: token validated for user:", vjson.userid);
    } catch (err) {
      console.error("Error validating token with Node1:", err);
      return res.status(500).json({ error: "Token validation error", details: err.message });
    }

    if (pendingSignRequests[requestId]) {
      return res.status(409).json({ error: "Request ID already exists" });
    }

    const timeoutId = setTimeout(() => {
      if (
        pendingSignRequests[requestId] &&
        pendingSignRequests[requestId].status === "pending"
      ) {
        pendingSignRequests[requestId].status = "cancelled";
        console.log(`Sign request ${requestId} cancelled due to timeout.`);
      }
    }, APPROVAL_TIMEOUT_MS);

    pendingSignRequests[requestId] = {
      message,
      status: "pending",
      timestamp: new Date(),
      timeoutId: timeoutId,
    };
    console.log(`Received sign request ${requestId} for message: "${message}". Waiting for manual approval.`);

    res.json({
      status: "pending_approval",
      requestId: requestId,
      message: message,
      expires_in_ms:
        APPROVAL_TIMEOUT_MS -
        (new Date() - pendingSignRequests[requestId].timestamp),
    });
  } catch (err) {
    console.error("Error in /request-sign:", err);
    res.status(500).json({ error: err.message });
  }
});

// Endpoint for manual approval
app.post("/approve/:requestId", (req, res) => {
  const { requestId } = req.params;
  if (!pendingSignRequests[requestId]) {
    return res
      .status(404)
      .json({ error: "Sign request not found or already processed" });
  }
  if (pendingSignRequests[requestId].status !== "pending") {
    return res.status(409).json({
      error: `Sign request already ${pendingSignRequests[requestId].status}`,
    });
  }

  clearTimeout(pendingSignRequests[requestId].timeoutId);
  pendingSignRequests[requestId].status = "approved";
  console.log(`Sign request ${requestId} approved manually.`);
  res.json({ status: "approved", requestId: requestId });
});

// Endpoint for manual rejection
app.post("/reject/:requestId", (req, res) => {
  const { requestId } = req.params;
  if (!pendingSignRequests[requestId]) {
    return res
      .status(404)
      .json({ error: "Sign request not found or already processed" });
  }
  if (pendingSignRequests[requestId].status !== "pending") {
    return res.status(409).json({
      error: `Sign request already ${pendingSignRequests[requestId].status}`,
    });
  }

  clearTimeout(pendingSignRequests[requestId].timeoutId);
  pendingSignRequests[requestId].status = "rejected";
  console.log(`Sign request ${requestId} rejected manually.`);
  res.json({ status: "rejected", requestId: requestId });
});

// Endpoint for coordinator to check request status
app.get("/status/:requestId", (req, res) => {
  const { requestId } = req.params;
  if (!pendingSignRequests[requestId]) {
    return res.status(404).json({ error: "Sign request not found" });
  }
  const { message, status, timestamp } = pendingSignRequests[requestId];
  res.json({
    requestId,
    message,
    status,
    timestamp,
    expires_in_ms: APPROVAL_TIMEOUT_MS - (new Date() - new Date(timestamp)),
  });
});

const port = process.argv[2] || 3002; // Changed port for node2
https
  .createServer(httpsOptions, app)
  .listen(port, () => console.log(`Node running on :${port} (HTTPS)`));
