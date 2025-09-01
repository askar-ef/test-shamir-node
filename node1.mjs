import "dotenv/config";
import express from "express";
import fs from "fs/promises";
import crypto from "crypto";
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
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID; // Google Client ID for JWT verification

if (!GOOGLE_CLIENT_ID) {
  console.error("GOOGLE_CLIENT_ID is not set in .env for Node 1.");
  process.exit(1);
}

const client = new OAuth2Client(GOOGLE_CLIENT_ID);

console.log("Node 1 API Key:", API_KEY);
console.log("Node 1 Google Client ID:", GOOGLE_CLIENT_ID);

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

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
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

const port = process.argv[2] || 3001;
https.createServer(httpsOptions, app).listen(port, () => {
  console.log(`Node running on HTTPS :${port}`);
});
