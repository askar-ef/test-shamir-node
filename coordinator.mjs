import "dotenv/config";
import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import https from "https";
import fs from "fs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { CryptoEnclave, CryptoError } from "./crypto-enclave.mjs";

class CoordinatorError extends Error {
  constructor(message, code = 'COORDINATOR_ERROR', details = {}, statusCode = 500) {
    super(message);
    this.code = code;
    this.details = details;
    this.statusCode = statusCode;
  }
}

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
}));

// HTTPS Configuration
const httpsOptions = {
  key: fs.readFileSync("./certs/key.pem"),
  cert: fs.readFileSync("./certs/cert.pem"),
};

const agent = new https.Agent({
  rejectUnauthorized: false,
  secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
  ca: fs.readFileSync("./certs/cert.pem"),
});

// Configuration
const API_KEY = process.env.API_KEY || crypto.randomBytes(32).toString("hex");
const nodes = ["https://localhost:3001", "https://localhost:3002"];
const coordinatorCrypto = new CryptoEnclave(
  process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex")
);

// State
let currentWallet = null;

// Middleware
const validateApiKey = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== API_KEY) {
    throw new CoordinatorError("Invalid API Key", "INVALID_API_KEY", {}, 401);
  }
  next();
};

const errorHandler = (err, req, res, next) => {
  console.error("Error:", {
    code: err.code,
    message: err.message,
    details: err.details,
    stack: err.stack
  });

  res.status(err.statusCode || 500).json({
    error: err.message,
    code: err.code,
    details: err.details
  });
};

app.use(validateApiKey);

// Utility functions
const fetchWithRetry = async (url, options, maxRetries = 3) => {
  let lastError;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, {
        ...options,
        agent: options.agent || ((new URL(url)).protocol === 'https:' ? agent : undefined)
      });
      
      const text = await response.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        throw new CoordinatorError(
          "Invalid JSON response", 
          "INVALID_RESPONSE",
          { url, responseText: text },
          502
        );
      }

      if (!response.ok) {
        throw new CoordinatorError(
          data.error || "Request failed",
          "NODE_ERROR",
          { url, response: data },
          response.status
        );
      }

      return data;
    } catch (error) {
      lastError = error;
      if (i < maxRetries - 1) {
        await new Promise(r => setTimeout(r, Math.pow(2, i) * 1000));
      }
    }
  }
  
  throw lastError;
};

// Routes
app.post("/generate", async (req, res, next) => {
  try {
    // Generate and split the secret
    const { address, encryptedShares } = await coordinatorCrypto.generateAndSplitSecret(2, 2);

    // Distribute shares to nodes
    await Promise.all(
      encryptedShares.map((share, i) =>
        fetchWithRetry(`${nodes[i]}/store`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
          },
          body: JSON.stringify({ share })
        })
      )
    );

    currentWallet = { address };
    res.json({ address, shares: encryptedShares });
  } catch (error) {
    if (error instanceof CryptoError) {
      next(new CoordinatorError(
        "Wallet generation failed",
        "GENERATION_ERROR",
        { cryptoError: error },
        500
      ));
    } else {
      next(error);
    }
  }
});

app.post("/sign", async (req, res, next) => {
  try {
    const { message, token } = req.body;
    
    // Input validation
    if (!message) {
      throw new CoordinatorError("Message is required", "MISSING_MESSAGE", {}, 400);
    }
    if (!token) {
      throw new CoordinatorError("Token is required", "MISSING_TOKEN", {}, 400);
    }
    if (!currentWallet?.address) {
      throw new CoordinatorError("No wallet initialized", "NO_WALLET", {}, 400);
    }

    // 1. Validate token with Node1
    const validationResult = await fetchWithRetry(
      `${nodes[0]}/validate-jwt`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
        },
        body: JSON.stringify({ token })
      }
    );

    if (validationResult.status !== "valid") {
      throw new CoordinatorError(
        "Token validation failed",
        "INVALID_TOKEN",
        { validation: validationResult },
        401
      );
    }

    // 2. Fetch shares from nodes
    const shareResults = await Promise.all(
      nodes.map(nodeUrl =>
        fetchWithRetry(
          `${nodeUrl}/get-share`,
          {
            method: "GET",
            headers: {
              "Content-Type": "application/json",
              "X-API-Key": API_KEY,
            }
          }
        )
      )
    );

    const encryptedShares = shareResults.map(result => {
      if (!result.share) {
        throw new CoordinatorError(
          "Node did not return share",
          "MISSING_SHARE",
          { result },
          502
        );
      }
      return result.share;
    });

    // 3. Sign message
    const signature = await coordinatorCrypto.signMessageWithShares(
      encryptedShares,
      message
    );

    res.json({
      signature,
      walletAddress: currentWallet.address,
    });
  } catch (error) {
    next(error);
  }
});

// Error handling middleware
app.use(errorHandler);

// Start server
https.createServer(httpsOptions, app).listen(3000, () => {
  console.log("Coordinator running on HTTPS :3000");
  console.log("API Key:", API_KEY);
});
