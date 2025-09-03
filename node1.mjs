import "dotenv/config";
import express from "express";
import https from "https";
import fsSync from "fs";
import { OAuth2Client } from "google-auth-library";

class NodeError extends Error {
  constructor(message, code = 'NODE_ERROR', details = {}, statusCode = 500) {
    super(message);
    this.code = code;
    this.details = details;
    this.statusCode = statusCode;
  }
}

const app = express();

app.use(express.json());

// Configuration
const httpsOptions = {
  key: fsSync.readFileSync("./certs/key.pem"),
  cert: fsSync.readFileSync("./certs/cert.pem"),
};

const API_KEY = process.env.API_KEY || "YOUR_COORDINATOR_API_KEY_HERE";
const GOOGLE_CLIENT_IDS = [
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_ID_MAIN_APP,
].filter(Boolean);

if (GOOGLE_CLIENT_IDS.length === 0) {
  console.error("No Google Client IDs configured");
  process.exit(1);
}

const client = new OAuth2Client();

// Utility function to get share file path for email
const getShareFilePath = (email, port = process.argv[2] || 3001) => {
  if (!email) {
    throw new NodeError("Email is required for share file", "MISSING_EMAIL", {}, 400);
  }
  // Sanitize email for filename
  const sanitizedEmail = email.replace(/[^a-zA-Z0-9@._-]/g, '_');
  return `./node_share_${port}_${sanitizedEmail}.enc`;
};

// Middleware
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== API_KEY) {
    throw new NodeError("Invalid API Key", "INVALID_API_KEY", {}, 401);
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

app.use(authenticateApiKey);

// Routes
app.post("/validate-jwt", async (req, res, next) => {
  try {
    const { token } = req.body;
    if (!token) {
      throw new NodeError("JWT token is required", "MISSING_TOKEN", {}, 400);
    }

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_IDS,
    });
    
    const payload = ticket.getPayload();
    console.log(`JWT validated for user ${payload.sub}`);
    
    res.json({ 
      status: "valid",
      userid: payload.sub,
      email: payload.email
    });
  } catch (error) {
    next(new NodeError(
      "JWT validation failed",
      "INVALID_TOKEN",
      { error: error.message },
      401
    ));
  }
});

app.get("/get-share", async (req, res, next) => {
  try {
    const { email } = req.query;
    if (!email) {
      throw new NodeError("Email parameter is required", "MISSING_EMAIL", {}, 400);
    }

    let shareFile;
    let encryptedShare;

    // Try email-specific file first (new format)
    shareFile = getShareFilePath(email);
    encryptedShare = await fsSync.readFileSync(shareFile, "utf8");
    console.log(`Found email-specific share file: ${shareFile}`);

    res.json({ share: encryptedShare });
  } catch (err) {
    if (err.code === "ENOENT") {
      next(new NodeError("No share stored for this email", "NO_SHARE", {}, 404));
    } else if (err instanceof NodeError) {
      next(err);
    } else {
      next(new NodeError(
        "Error retrieving share",
        "SHARE_READ_ERROR",
        { error: err.message },
        500
      ));
    }
  }
});

app.post("/store", async (req, res, next) => {
  try {
    const { share, email } = req.body;
    if (!share) {
      throw new NodeError("Share is required", "MISSING_SHARE", {}, 400);
    }

    let shareFile;

    if (email) {
      // New format: email-specific file
      shareFile = getShareFilePath(email);
      console.log(`Storing share in email-specific file: ${shareFile}`);
    } 

    await fsSync.writeFileSync(shareFile, share);
    console.log(`Share stored successfully for ${email}`);
    res.json({ status: "ok" });
  } catch (err) {
    if (err instanceof NodeError) {
      next(err);
    } else {
      next(new NodeError(
        "Error storing share",
        "SHARE_WRITE_ERROR",
        { error: err.message },
        500
      ));
    }
  }
});

app.use(errorHandler);

const port = process.argv[2] || 3001;
https.createServer(httpsOptions, app).listen(port, () => {
  console.log(`Node1 running on HTTPS :${port}`);
});
