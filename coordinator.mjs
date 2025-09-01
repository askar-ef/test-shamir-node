import "dotenv/config";
import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import https from "https";
import fs from "fs";
import { CryptoEnclave } from "./crypto-enclave.mjs";

const app = express();
app.use(express.json());

const agent = new https.Agent({
  rejectUnauthorized: false,
  secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
  ca: fs.readFileSync("./certs/cert.pem"),
});

const fetchAgent = (parsedURL) => {
  try {
    return parsedURL.protocol === "https:" ? agent : undefined;
  } catch (e) {
    return undefined;
  }
};

const httpsOptions = {
  key: fs.readFileSync("./certs/key.pem"),
  cert: fs.readFileSync("./certs/cert.pem"),
};

const API_KEY = process.env.API_KEY || crypto.randomBytes(32).toString("hex");
console.log("Coordinator API Key:", API_KEY);

const nodes = ["https://localhost:3001", "https://localhost:3002"];

let currentWallet = null;

const coordinatorCrypto = new CryptoEnclave(
  process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex")
);

app.post("/generate", async (req, res) => {
  try {
    const { address, encryptedShares } =
      await coordinatorCrypto.generateAndSplitSecret(2, 2);

    await Promise.all(
      encryptedShares.map((share, i) =>
        fetch(`${nodes[i]}/store`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
          },
          body: JSON.stringify({ share }),
          agent: fetchAgent,
        })
      )
    );

    currentWallet = { address: address };
    res.json({ address, shares: encryptedShares });
  } catch (err) {
    console.error("Error in /generate:", err);
    res.status(500).json({ error: err.message });
  }
});

// Request signing
app.post("/sign", async (req, res) => {
  try {
    const { message, token } = req.body; // accept token from caller (Main App)
    if (!message) return res.status(400).json({ error: "Message is required" });
    if (!currentWallet || !currentWallet.address)
      return res.status(400).json({ error: "No wallet yet" });

    // 1) Validate token by asking Node1
    if (!token) return res.status(400).json({ error: "Token is required" });
    let vjson;
    try {
      const vresp = await fetch(`${nodes[0]}/validate-jwt`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
        },
        body: JSON.stringify({ token }),
        agent: fetchAgent,
      });
      const vtext = await vresp.text();
      try {
        vjson = JSON.parse(vtext);
      } catch (e) {
        console.error("Invalid JSON from Node1 validate-jwt:", vtext);
        return res.status(502).json({ error: "Invalid response from Node1", body: vtext });
      }
      if (!vresp.ok || vjson.status !== "valid") {
        console.log("Token validation failed at Node1:", vjson);
        return res.status(401).json({ error: "Invalid token", details: vjson });
      }
    } catch (err) {
      console.error("Error validating token with Node1:", err);
      return res.status(500).json({ error: "Token validation error", details: err.message });
    }

    // 2) Fetch shares from all nodes immediately
    const shareFetches = nodes.map((nodeUrl) =>
      fetch(`${nodeUrl}/get-share`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
        },
        agent: fetchAgent,
      })
        .then(async (r) => {
          const text = await r.text();
          if (!r.ok) {
            let body = text;
            try { body = JSON.parse(text); } catch(e) {}
            throw new Error(`${nodeUrl} returned ${r.status}: ${JSON.stringify(body)}`);
          }
          try {
            return JSON.parse(text);
          } catch (e) {
            throw new Error(`Invalid JSON from ${nodeUrl}: ${text}`);
          }
        })
        .catch((err) => ({ error: err.message, node: nodeUrl }))
    );

    const shareResults = await Promise.all(shareFetches);

    const encryptedShares = [];
    for (const r of shareResults) {
      if (r && r.error) {
        console.error("Failed to get share:", r);
        return res.status(502).json({ error: "Failed to fetch shares from nodes", details: r });
      }
      if (!r.share) {
        console.error("Node returned no share:", r);
        return res.status(502).json({ error: "Node did not return share", details: r });
      }
      encryptedShares.push(r.share);
    }

    // 3) Combine & sign in coordinator enclave
    let signature;
    try {
      signature = await coordinatorCrypto.signMessageWithShares(encryptedShares, message);
    } catch (err) {
      console.error("Error combining shares/signing:", err);
      return res.status(500).json({ error: "Signing error", details: err.message });
    }

    // 4) Return signature + wallet address
    res.json({
      signature,
      walletAddress: currentWallet.address,
    });
  } catch (err) {
    console.error("Error in /sign:", err);
    res.status(500).json({ error: err.message });
  }
});

https.createServer(httpsOptions, app).listen(3000, () => {
  console.log("Coordinator running on HTTPS :3000");
});
