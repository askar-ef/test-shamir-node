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
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required" });
    if (!currentWallet || !currentWallet.address)
      return res.status(400).json({ error: "No wallet yet" });

    const requestId = uuidv4();
    const requiredApprovals = 2;
    const COORDINATOR_TIMEOUT_MS = 70 * 1000;

    const requestSignPromises = nodes.map((nodeUrl) =>
      fetch(`${nodeUrl}/request-sign`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
        },
        body: JSON.stringify({ message, requestId }),
        agent: fetchAgent,
      })
        .then((response) => response.json())
        .then((data) => ({
          node: nodeUrl,
          status: data.status,
          requestId: data.requestId,
          expires_in_ms: data.expires_in_ms,
        }))
        .catch((error) => ({
          node: nodeUrl,
          status: "error",
          error: error.message,
        }))
    );

    const requestSignResults = await Promise.all(requestSignPromises);
    console.log("Request Sign Results:", requestSignResults);

    const nodesAwaitingApproval = requestSignResults.filter(
      (result) => result.status === "pending_approval"
    );

    if (nodesAwaitingApproval.length < requiredApprovals) {
      return res.status(400).json({
        error:
          "Not enough nodes available or willing to process signing request.",
      });
    }

    let approvedNodes = [];
    const startTime = Date.now();

    while (
      approvedNodes.length < requiredApprovals &&
      Date.now() - startTime < COORDINATOR_TIMEOUT_MS
    ) {
      const statusCheckPromises = nodesAwaitingApproval.map((node) =>
        fetch(`${node.node}/status/${requestId}`, {
          headers: { "X-API-Key": API_KEY },
          agent: fetchAgent, // Use the agent to ignore self-signed certs
        })
          .then((response) => response.json())
          .then((data) => ({
            node: node.node,
            status: data.status,
            requestId: data.requestId,
          }))
          .catch((error) => ({
            node: node.node,
            status: "error",
            error: error.message,
          }))
      );

      const statusResults = await Promise.all(statusCheckPromises);
      approvedNodes = statusResults.filter(
        (result) => result.status === "approved"
      );
      console.log(
        `Polling for approvals... Current approved: ${approvedNodes.length}/${requiredApprovals}`
      );

      if (approvedNodes.length < requiredApprovals) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
    }

    if (approvedNodes.length < requiredApprovals) {
      console.log(
        `Timeout: Not enough approvals (${
          approvedNodes.length
        }/${requiredApprovals}) received within ${
          COORDINATOR_TIMEOUT_MS / 1000
        } seconds.`
      );
      return res.status(408).json({
        error: `Timeout: Not enough approvals (${approvedNodes.length}/${requiredApprovals}) to sign the message.`,
      });
    }

    const encryptedSharesToCombine = [];
    for (const node of approvedNodes) {
      const shareResponse = await fetch(`${node.node}/get-share`, {
        headers: { "X-API-Key": API_KEY },
        agent: fetchAgent,
      });
      const shareData = await shareResponse.json();
      if (shareData.share) {
        encryptedSharesToCombine.push(shareData.share);
      } else {
        throw new Error(`Failed to get share from ${node.node}`);
      }
    }

    const signature = await coordinatorCrypto.signMessageWithShares(
      encryptedSharesToCombine,
      message
    );

    res.json({
      signature,
      requestId,
      approvedNodes: approvedNodes.map((r) => r.node),
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
