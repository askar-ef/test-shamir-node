import "dotenv/config";
import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import fetch from "node-fetch";
import https from "https";
import fs from "fs";
import crypto from "crypto";

const app = express();
app.use(express.json());

// HTTPS agent to ignore self-signed certificates for local development
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

// Session configuration
app.use(
  session({
    secret:
      process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }, // Use secure cookies in production
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Google OAuth2 Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID_MAIN_APP,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET_MAIN_APP,
      callbackURL: "/auth/google/callback",
      scope: ["profile", "email"],
    },
    (accessToken, refreshToken, profile, done) => {
      // In a real app, you would save the user profile to your database
      // For this example, we'll just pass the profile
      return done(null, profile);
    }
  )
);

// Serialize and deserialize user for session management
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Routes
app.get("/", (req, res) => {
  res.send('<h1>Main App</h1><a href="/auth/google">Login with Google</a>');
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    // Successful authentication, redirect home or to a dashboard
    res.redirect("/dashboard");
  }
);

app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/");
  }
  res.send(
    `<h1>Welcome, ${req.user.displayName}!</h1><p>Email: ${req.user.emails[0].value}</p><a href="/sign-message">Sign a Message</a><br><a href="/logout">Logout</a>`
  );
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// --- New functionality for wallet generation and signing ---
const COORDINATOR_URL = "https://localhost:3000";
const NODE1_URL = "https://localhost:3001"; // Node for JWT validation
const NODE2_URL = "https://localhost:3002"; // Node for enclave operations (shares)
const API_KEY = process.env.API_KEY || "YOUR_COORDINATOR_API_KEY_HERE"; // Same API key for inter-service communication

// Middleware to ensure user is authenticated
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
};

app.get("/generate-wallet", ensureAuthenticated, async (req, res) => {
  try {
    // Simulate getting JWT from Google login (in a real app, this would be handled by the OAuth flow)
    // For this example, we'll assume req.user contains enough info to simulate a JWT.
    // In a real scenario, the JWT would be obtained directly from Google's OAuth response.
    // For simplicity, we'll just use a placeholder for the JWT for now.
    const googleJwt = "SIMULATED_GOOGLE_JWT_FROM_LOGIN"; // Replace with actual JWT from Google

    // 1. Validate JWT with Node 1
    const validationResponse = await fetch(`${NODE1_URL}/validate-jwt`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
      },
      body: JSON.stringify({ token: googleJwt }),
      agent: fetchAgent,
    });
    const validationResult = await validationResponse.json();

    if (validationResult.status !== "valid") {
      return res
        .status(401)
        .json({
          error: "JWT validation failed",
          details: validationResult.details,
        });
    }

    // 2. If JWT is valid, proceed to generate wallet via Coordinator
    const generateResponse = await fetch(`${COORDINATOR_URL}/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
      },
      agent: fetchAgent,
    });
    const generateResult = await generateResponse.json();

    if (generateResponse.ok) {
      res.json({
        message: "Wallet generated and shares distributed successfully!",
        walletAddress: generateResult.address,
      });
    } else {
      res.status(generateResponse.status).json({ error: generateResult.error });
    }
  } catch (error) {
    console.error("Error generating wallet:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/sign-message", ensureAuthenticated, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    // Simulate getting JWT from Google login
    const googleJwt = "SIMULATED_GOOGLE_JWT_FROM_LOGIN"; // Replace with actual JWT from Google

    // 1. Validate JWT with Node 1
    const validationResponse = await fetch(`${NODE1_URL}/validate-jwt`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
      },
      body: JSON.stringify({ token: googleJwt }),
      agent: fetchAgent,
    });
    const validationResult = await validationResponse.json();

    if (validationResult.status !== "valid") {
      return res
        .status(401)
        .json({
          error: "JWT validation failed",
          details: validationResult.details,
        });
    }

    // 2. If JWT is valid, proceed to sign message via Coordinator
    const signResponse = await fetch(`${COORDINATOR_URL}/sign`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
      },
      body: JSON.stringify({ message }),
      agent: fetchAgent,
    });
    const signResult = await signResponse.json();

    if (signResponse.ok) {
      res.json({
        message: "Message signed successfully!",
        signature: signResult.signature,
        walletAddress: signResult.walletAddress,
      });
    } else {
      res.status(signResponse.status).json({ error: signResult.error });
    }
  } catch (error) {
    console.error("Error signing message:", error);
    res.status(500).json({ error: error.message });
  }
});

const port = process.argv[2] || 3004; // Main app runs on a new port
https.createServer(httpsOptions, app).listen(port, () => {
  console.log(`Main App running on HTTPS :${port}`);
});
