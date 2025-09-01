import "dotenv/config";
import express from "express";
import https from "https";
import fsSync from "fs";
import { OAuth2Client } from "google-auth-library"; // Import OAuth2Client for Google JWT verification

const app = express();
app.use(express.json());

// HTTPS options
const httpsOptions = {
  key: fsSync.readFileSync("./certs/key.pem"),
  cert: fsSync.readFileSync("./certs/cert.pem"),
};

const API_KEY = process.env.API_KEY || "YOUR_COORDINATOR_API_KEY_HERE"; // API Key for inter-service communication

// Accept one or more valid Google client IDs (audiences).
// This lets Node1 verify ID tokens issued for the Main App (GOOGLE_CLIENT_ID_MAIN_APP)
// as well as any other configured client ID.
const GOOGLE_CLIENT_IDS = [
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_ID_MAIN_APP,
].filter(Boolean);

if (GOOGLE_CLIENT_IDS.length === 0) {
  console.error("No GOOGLE_CLIENT_ID or GOOGLE_CLIENT_ID_MAIN_APP set in .env for Node 1.");
  process.exit(1);
}

// OAuth2Client can be instantiated without a client id; we'll pass the allowed
// audiences to verifyIdToken so multiple audiences are accepted.
const client = new OAuth2Client();

console.log("Node 1 API Key:", API_KEY);
console.log("Node 1 accepted Google client IDs (audiences):", GOOGLE_CLIENT_IDS);

// Middleware for API Key authentication
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== API_KEY) {
    return res.status(401).json({ error: "Unauthorized: Invalid API Key" });
  }
  next();
};

app.use(authenticateApiKey); // Apply authentication middleware to all routes

// Endpoint to validate Google JWT
app.post("/validate-jwt", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: "JWT token is required" });
    }

    // Pass the accepted audiences array so tokens issued to any of these
    // client IDs will validate.
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_IDS,
    });
    const payload = ticket.getPayload();
    console.log("Validated token payload audience:", payload.aud);
    const userid = payload["sub"];

    console.log(`JWT from user ${userid} validated successfully.`);
    res.json({ status: "valid", userid: userid, email: payload.email });
  } catch (error) {
    console.error("Error validating JWT:", error);
    res
      .status(401)
      .json({ error: "Invalid JWT token", details: error.message });
  }
});

const SHARE_FILE = `./node_share_${process.argv[2] || 3001}.enc`;

// Return share
app.get("/get-share", async (req, res) => {
  try {
    const encryptedShare = await fsSync.readFileSync(SHARE_FILE, "utf8");
    res.json({ share: encryptedShare });
  } catch (err) {
    if (err.code === "ENOENT") {
      return res.status(400).json({ error: "No share stored" });
    }
    console.error("Error retrieving share:", err);
    res.status(500).json({ error: err.message });
  }
});

// Store share
app.post("/store", async (req, res) => {
  try {
    const share = req.body.share;
    if (!share) {
      return res.status(400).json({ error: "Share is required" });
    }
    await fsSync.writeFileSync(SHARE_FILE, share);
    console.log("Stored share to file:", SHARE_FILE);
    res.json({ status: "ok" });
  } catch (err) {
    console.error("Error storing share:", err);
    res.status(500).json({ error: err.message });
  }
});

// --- New: request-sign / approve / reject / status on Node1 (with JWT verification) ---
let pendingSignRequests = {};
const APPROVAL_TIMEOUT_MS = 60 * 1000;

app.post("/request-sign", async (req, res) => {
  try {
    const { message, requestId, token } = req.body;
    if (!message || !requestId || !token) {
      return res
        .status(400)
        .json({ error: "message, requestId and token are required" });
    }

    // verify token locally
    try {
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: GOOGLE_CLIENT_IDS,
      });
      const payload = ticket.getPayload();
      console.log("Request-sign token valid for user:", payload.sub);
    } catch (err) {
      console.error("Request-sign token verification failed:", err.message);
      return res.status(401).json({ error: "Invalid token", details: err.message });
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
      timeoutId,
    };

    console.log(`Node1 received sign request ${requestId} for "${message}".`);
    console.log(
      `Approve via: curl -k -X POST https://localhost:${process.argv[2] ||
        3001}/approve/${requestId} -H "X-API-Key: ${API_KEY}"`
    );

    res.json({
      status: "pending_approval",
      requestId,
      expires_in_ms:
        APPROVAL_TIMEOUT_MS - (new Date() - pendingSignRequests[requestId].timestamp),
    });
  } catch (err) {
    console.error("Error in /request-sign (node1):", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/approve/:requestId", (req, res) => {
  const { requestId } = req.params;
  if (!pendingSignRequests[requestId]) {
    return res.status(404).json({ error: "Sign request not found" });
  }
  if (pendingSignRequests[requestId].status !== "pending") {
    return res.status(409).json({ error: `Sign request already ${pendingSignRequests[requestId].status}` });
  }
  clearTimeout(pendingSignRequests[requestId].timeoutId);
  pendingSignRequests[requestId].status = "approved";
  console.log(`Sign request ${requestId} approved on Node1.`);
  res.json({ status: "approved", requestId });
});

app.post("/reject/:requestId", (req, res) => {
  const { requestId } = req.params;
  if (!pendingSignRequests[requestId]) {
    return res.status(404).json({ error: "Sign request not found" });
  }
  if (pendingSignRequests[requestId].status !== "pending") {
    return res.status(409).json({ error: `Sign request already ${pendingSignRequests[requestId].status}` });
  }
  clearTimeout(pendingSignRequests[requestId].timeoutId);
  pendingSignRequests[requestId].status = "rejected";
  console.log(`Sign request ${requestId} rejected on Node1.`);
  res.json({ status: "rejected", requestId });
});

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

const port = process.argv[2] || 3001;
https.createServer(httpsOptions, app).listen(port, () => {
  console.log(`Node running on HTTPS :${port}`);
});
