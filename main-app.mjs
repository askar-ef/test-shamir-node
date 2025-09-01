import "dotenv/config";
import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import fetch from "node-fetch";
import https from "https";
import crypto from "crypto";
import fsSync from "fs";

const app = express();
app.use(express.json());

// HTTPS options
const httpsOptions = {
  key: fsSync.readFileSync("./certs/key.pem"),
  cert: fsSync.readFileSync("./certs/cert.pem"),
};

// HTTPS agent to ignore self-signed certificates for local development
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

// Session configuration
app.use(
  session({
    secret:
      process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: true,
    cookie: { 
      secure: false, // For local development (change to true in production)
      sameSite: 'lax',  // For local testing
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Google OAuth2 Strategy: request OpenID Connect id_token and store it when present
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID_MAIN_APP,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET_MAIN_APP,
      callbackURL: "/auth/google/callback",
      scope: ["openid", "profile", "email"], // request id_token
    },
    // Note: passport-google-oauth20 may pass an extra `params` argument that contains
    // the `id_token`. Use the 5-argument form to capture it when available.
    (accessToken, refreshToken, params, profile, done) => {
      // Prefer id_token (a JWT) if provided by Google; fallback to accessToken.
      const tokenToUse = (params && params.id_token) || accessToken;
      const user = {
        id: profile.id,
        displayName: profile.displayName,
        emails: profile.emails,
        photos: profile.photos,
        jwt: tokenToUse,
      };
      return done(null, user);
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
  async (req, res) => {
    // After successful Google login, immediately:
    // 1) send the JWT/token to Node 1 for validation
    // 2) if valid, request the stored shares from Node1 and Node2
    // 3) send both shares to the Coordinator to combine and sign in enclave
    console.log("DEBUG: Auth callback reached, session id:", req.sessionID);
    try {
      if (!req.user || !req.user.jwt) {
        console.error("No token found on user after auth");
        return res.redirect("/");
      }

      // Use the stored Google ID token (JWT)
      const googleJwt = req.user.jwt;
      // 1) Validate JWT with Node 1
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
        console.error("JWT validation failed:", validationResult);
        return res.redirect("/");
      }

      const userid = validationResult.userid || req.user.id;
      const email = validationResult.email || (req.user.emails && req.user.emails[0] && req.user.emails[0].value);

      // 2) Ask Coordinator to generate wallet & distribute shares to nodes if needed
      // This will cause Coordinator to create shares and POST them to Node1/Node2 `/store` endpoints.
      console.log("DEBUG: Requesting Coordinator to generate wallet for user:", userid);
      const generateResponse = await fetch(`${COORDINATOR_URL}/generate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
        },
        body: JSON.stringify({ userId: userid, email }),
        agent: fetchAgent,
      });
      const generateResult = await generateResponse.json();

      if (!generateResponse.ok) {
        console.error("Coordinator generate failed:", generateResult);
        return res.redirect("/");
      }

      // Coordinator has distributed encrypted shares to Node1 and Node2
      req.session.walletAddress = generateResult.address;
      req.session.combineSignature = null;

      // Redirect to dashboard where user can see wallet status
      res.redirect("/dashboard");
    } catch (err) {
      console.error("Error in auth callback flow:", err);
      res.redirect("/");
    }
  }
);

app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/");
  }
  const wallet = req.session.walletAddress || "Not generated yet";
  const signature = req.session.combineSignature || "Not signed yet";
  const email = req.user.emails && req.user.emails[0] && req.user.emails[0].value;
  res.send(
    `<h1>Welcome, ${req.user.displayName}!</h1>
     <p>Email: ${email}</p>
     <p>Wallet: ${wallet}</p>
     <p>Last signature: ${signature}</p>
     <a href="/sign-message">Sign a Message</a><br><a href="/logout">Logout</a>`
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
    // Kirim JWT aktual ke Node 1 untuk validasi
    // Asumsikan kita menyimpan JWT di sesi setelah login
    const googleJwt = req.user.jwt;

    // 1. Validasi JWT dengan Node 1
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
      return res.status(401).json({
        error: "JWT validation failed",
        details: validationResult.details
      });
    }

    // 2. Jika JWT valid, kirim permintaan generate wallet ke Coordinator
    const generateResponse = await fetch(`${COORDINATOR_URL}/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
      },
      body: JSON.stringify({
        userId: validationResult.userid,
        email: validationResult.email
      }),
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

// --- New: serve simple sign UI (GET)
app.get("/sign-message", ensureAuthenticated, (req, res) => {
  res.send(`
    <h1>Sign a Message</h1>
    <form id="signForm">
      <label>Message</label><br/>
      <textarea id="message" rows="4" cols="50"></textarea><br/>
      <button type="submit">Sign</button>
    </form>
    <pre id="out"></pre>
    <script>
      const out = document.getElementById('out');
      document.getElementById('signForm').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        out.textContent = 'Sending sign request...';
        const message = document.getElementById('message').value;
        try {
          const resp = await fetch('/sign-message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
          });
          const text = await resp.text();
          try {
            const json = JSON.parse(text);
            if (resp.ok) {
              out.textContent = 'Signed successfully:\\n' + JSON.stringify(json, null, 2);
            } else {
              out.textContent = 'Error:\\n' + JSON.stringify(json, null, 2);
            }
          } catch (e) {
            out.textContent = 'Non-JSON response:\\n' + text;
          }
        } catch (err) {
          out.textContent = 'Network error: ' + err.message;
        }
      });
    </script>
  `);
});

// Replace POST /sign-message with robust handling and session update
app.post("/sign-message", ensureAuthenticated, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    if (!req.user || !req.user.jwt) {
      return res.status(401).json({ error: "No JWT available on session/user" });
    }
    const googleJwt = req.user.jwt;

    // Validate JWT with Node1 first (optional, coordinator also validates)
    const vResp = await fetch(`${NODE1_URL}/validate-jwt`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
      body: JSON.stringify({ token: googleJwt }),
      agent: fetchAgent,
    });
    const vText = await vResp.text();
    let vJson;
    try {
      vJson = JSON.parse(vText);
    } catch (e) {
      return res.status(502).json({ error: "Invalid response from Node1", body: vText });
    }
    if (!vResp.ok || vJson.status !== "valid") {
      return res.status(401).json({ error: "JWT validation failed", details: vJson });
    }

    // Send sign request to Coordinator, include token so nodes can validate
    const signResp = await fetch(`${COORDINATOR_URL}/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
      body: JSON.stringify({ message, token: googleJwt }),
      agent: fetchAgent,
    });

    const signText = await signResp.text();
    let signJson;
    try {
      signJson = JSON.parse(signText);
    } catch (e) {
      // coordinator returned non-json (HTML/error page) — forward as error
      return res.status(502).json({ error: "Invalid response from Coordinator", body: signText });
    }

    if (!signResp.ok) {
      return res.status(signResp.status).json(signJson);
    }

    // success: coordinator returns { signature, walletAddress, ... }
    if (signJson.signature) {
      req.session.combineSignature = signJson.signature;
      req.session.walletAddress = signJson.walletAddress || req.session.walletAddress;
    }

    return res.json(signJson);
  } catch (error) {
    console.error("Error signing message:", error);
    return res.status(500).json({ error: error.message });
  }
});

const port = process.argv[2] || 3004; // Main app runs on a new port
https.createServer(httpsOptions, app).listen(port, () => {
  console.log(`Main App running on HTTPS :${port}`);
});
