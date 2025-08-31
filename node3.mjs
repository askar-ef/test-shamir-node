import "dotenv/config"; // Load environment variables from .env file
import express from "express";
import fs from "fs/promises"; // For file system operations
import crypto from "crypto"; // For encryption (still needed for randomBytes for API_KEY fallback)
import https from "https"; // Import https module
import fsSync from "fs"; // Import synchronous fs for reading certificate files
import { CryptoEnclave } from "./crypto-enclave.mjs"; // Import CryptoEnclave

const app = express();
app.use(express.json());

// HTTPS options
const httpsOptions = {
  key: fsSync.readFileSync("./certs/key.pem"),
  cert: fsSync.readFileSync("./certs/cert.pem"),
};

// For demonstration, use the same API_KEY as coordinator.
// In a real application, each node should have its own securely managed API key.
const API_KEY = process.env.API_KEY || "YOUR_COORDINATOR_API_KEY_HERE";
const ENCRYPTION_KEY_HEX =
  process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex"); // 256-bit key
// const IV_LENGTH = 16; // Moved to CryptoEnclave

// Initialize CryptoEnclave for this node
const nodeCrypto = new CryptoEnclave(ENCRYPTION_KEY_HEX);

console.log("Node API Key:", API_KEY);

// Middleware for API Key authentication
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== API_KEY) {
    return res.status(401).json({ error: "Unauthorized: Invalid API Key" });
  }
  next();
};

app.use(authenticateApiKey); // Apply authentication middleware to all routes

const SHARE_FILE = `./node_share_${process.argv[2] || 3003}.enc`; // Changed port for node3

// Encryption and Decryption functions are now handled by CryptoEnclave

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
// { requestId: { message: "...", status: "pending" | "approved" | "rejected" | "cancelled", timestamp: Date, timeoutId: Timeout } }
let pendingSignRequests = {};
const APPROVAL_TIMEOUT_MS = 60 * 1000; // 1 minute

// Endpoint to request signing
app.post("/request-sign", async (req, res) => {
  try {
    const { message, requestId } = req.body;
    if (!message || !requestId) {
      return res
        .status(400)
        .json({ error: "Message and requestId are required" });
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
        console.log(
          `Sign request ${requestId} for message: "${message}" cancelled due to timeout.`
        );
      }
    }, APPROVAL_TIMEOUT_MS);

    pendingSignRequests[requestId] = {
      message,
      status: "pending",
      timestamp: new Date(),
      timeoutId: timeoutId,
    };
    console.log(
      `Received sign request ${requestId} for message: "${message}". Waiting for manual approval.`
    );
    console.log(
      `Approve manually via: curl -k -X POST https://localhost:${
        process.argv[2] || 3003
      }/approve/${requestId} -H "X-API-Key: ${API_KEY}"`
    );
    console.log(
      `Reject manually via: curl -k -X POST https://localhost:${
        process.argv[2] || 3003
      }/reject/${requestId} -H "X-API-Key: ${API_KEY}"`
    );

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

const port = process.argv[2] || 3003; // Changed port for node3
https
  .createServer(httpsOptions, app)
  .listen(port, () => console.log(`Node running on :${port} (HTTPS)`));
