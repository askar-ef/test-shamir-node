import "dotenv/config";
import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import fetch from "node-fetch";
import https from "https";
import crypto from "crypto";
import fsSync from "fs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

class AppError extends Error {
  constructor(message, code = 'APP_ERROR', details = {}, statusCode = 500) {
    super(message);
    this.code = code;
    this.details = details;
    this.statusCode = statusCode;
  }
}

// Configuration
const COORDINATOR_URL = "https://localhost:3000";
const NODE1_URL = "https://localhost:3001";
const NODE2_URL = "https://localhost:3002";
const API_KEY = process.env.API_KEY || "YOUR_COORDINATOR_API_KEY_HERE";

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'self'"]
    }
  }
}));
app.use(express.json());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

// HTTPS Configuration
const httpsOptions = {
  key: fsSync.readFileSync("./certs/key.pem"),
  cert: fsSync.readFileSync("./certs/cert.pem"),
};

const agent = new https.Agent({
  rejectUnauthorized: false,
  secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
  ca: fsSync.readFileSync("./certs/cert.pem"),
});

// Session Configuration
const sessionConfig = {
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  name: 'sessionId',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax'
  },
  resave: false,
  saveUninitialized: false
};

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
  sessionConfig.cookie.secure = true;
}

app.use(session(sessionConfig));

// Passport Configuration
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID_MAIN_APP,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET_MAIN_APP,
      callbackURL: "/auth/google/callback",
      scope: ["openid", "profile", "email"],
    },
    (accessToken, refreshToken, params, profile, done) => {
      try {
        const tokenToUse = (params && params.id_token) || accessToken;
        if (!tokenToUse) {
          return done(new AppError("No token received from Google", "NO_TOKEN"));
        }

        const user = {
          id: profile.id,
          displayName: profile.displayName,
          emails: profile.emails,
          photos: profile.photos,
          jwt: tokenToUse,
        };
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Middleware
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect("/");
};

const validateSession = (req, res, next) => {
  if (!req.user?.jwt) {
    throw new AppError("No JWT in session", "NO_JWT", {}, 401);
  }
  next();
};

// Error Handler
const errorHandler = (err, req, res, next) => {
  console.error("Error:", {
    code: err.code,
    message: err.message,
    details: err.details,
    stack: err.stack
  });

  if (err.statusCode === 401) {
    return res.redirect("/");
  }

  res.status(err.statusCode || 500).json({
    error: err.message,
    code: err.code,
    details: process.env.NODE_ENV === 'production' ? undefined : err.details
  });
};

// Routes
app.get("/", (req, res) => {
  res.send('<h1>Main App</h1><a href="/auth/google">Login with Google</a>');
});

app.get("/auth/google", passport.authenticate("google"));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  async (req, res, next) => {
    try {
      if (!req.user?.jwt) {
        throw new AppError("No token found after auth", "AUTH_ERROR");
      }

      // Validate JWT
      const validationResponse = await fetch(`${NODE1_URL}/validate-jwt`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
        },
        body: JSON.stringify({ token: req.user.jwt }),
        agent: agent
      });

      const text = await validationResponse.text();
      let validationResult;
      try {
        validationResult = JSON.parse(text);
      } catch (e) {
        throw new AppError(
          "Invalid JSON response from validation", 
          "INVALID_RESPONSE",
          { url: NODE1_URL, responseText: text },
          502
        );
      }

      if (!validationResponse.ok) {
        throw new AppError(
          validationResult.error || "JWT validation failed",
          "VALIDATION_ERROR",
          { response: validationResult },
          validationResponse.status
        );
      }

      // Generate wallet
      const generateResponse = await fetch(`${COORDINATOR_URL}/generate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": API_KEY,
        },
        body: JSON.stringify({
          userId: validationResult.userid || req.user.id,
          email: validationResult.email || req.user.emails?.[0]?.value
        }),
        agent: agent
      });

      const generateText = await generateResponse.text();
      let generateResult;
      try {
        generateResult = JSON.parse(generateText);
      } catch (e) {
        throw new AppError(
          "Invalid JSON response from coordinator", 
          "INVALID_RESPONSE",
          { url: COORDINATOR_URL, responseText: generateText },
          502
        );
      }

      if (!generateResponse.ok) {
        throw new AppError(
          generateResult.error || "Wallet generation failed",
          "GENERATION_ERROR",
          { response: generateResult },
          generateResponse.status
        );
      }

      req.session.walletAddress = generateResult.address;
      res.redirect("/dashboard");
    } catch (error) {
      next(error);
    }
  }
);

app.get("/dashboard", ensureAuthenticated, (req, res) => {
  const wallet = req.session.walletAddress || "Not generated yet";
  const signature = req.session.combineSignature || "Not signed yet";
  const email = req.user.emails?.[0]?.value;
  
  res.send(`
    <h1>Welcome, ${req.user.displayName}!</h1>
    <p>Email: ${email}</p>
    <p>Wallet: ${wallet}</p>
    <p>Last signature: ${signature}</p>
    <a href="/sign-message">Sign a Message</a><br>
    <a href="/logout">Logout</a>
  `);
});

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/sign-message", ensureAuthenticated, (req, res) => {
  res.send(`
    <h2>Sign Message</h2>
    <form id="signForm">
      <textarea id="message" placeholder="Enter message to sign" rows="3" cols="60"></textarea><br><br>
      <button type="submit" id="submitBtn">Sign</button>
    </form>
    <div id="status"></div>
    <div id="result"></div>

    <script>
      document.getElementById('signForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const message = document.getElementById('message').value.trim();
        const status = document.getElementById('status');
        const result = document.getElementById('result');
        const btn = document.getElementById('submitBtn');
        
        if (!message) {
          status.innerHTML = 'Please enter a message';
          return;
        }

        btn.disabled = true;
        result.innerHTML = '';
        status.innerHTML = 'Signing...';
        
        try {
          const res = await fetch('/sign-message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
          });
          
          const data = await res.json();
          
          if (res.ok && data.signature) {
            status.innerHTML = 'Successfully signed!';
            result.innerHTML = 
              '<p><b>Message:</b> ' + message + '</p>' +
              '<p><b>Signature:</b> ' + data.signature + '</p>' +
              (data.walletAddress ? '<p><b>Wallet:</b> ' + data.walletAddress + '</p>' : '');
            
            document.getElementById('message').value = '';
          } else {
            status.innerHTML = 'Error: ' + (data.error || 'Sign failed');
          }
        } catch (err) {
          status.innerHTML = 'Network error';
        }
        
        btn.disabled = false;
      });
    </script>
  `);
});

app.post("/sign-message", [ensureAuthenticated, validateSession], async (req, res, next) => {
  try {
    const { message } = req.body;
    
    if (!message?.trim()) {
      throw new AppError("Message is required", "MISSING_MESSAGE", {}, 400);
    }

    if (!req.user?.jwt) {
      throw new AppError("No JWT available", "NO_JWT", {}, 401);
    }

    // Sign message with coordinator
    const signResponse = await fetch(`${COORDINATOR_URL}/sign`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        "Accept": "application/json"
      },
      body: JSON.stringify({
        message: message.trim(),
        token: req.user.jwt
      }),
      agent: agent
    });

    const signText = await signResponse.text();
    let signResult;
    try {
      signResult = JSON.parse(signText);
    } catch (e) {
      throw new AppError(
        "Invalid JSON response from coordinator",
        "INVALID_RESPONSE",
        { url: COORDINATOR_URL, responseText: signText },
        502
      );
    }

    if (!signResponse.ok) {
      throw new AppError(
        signResult.error || "Message signing failed",
        "SIGN_ERROR",
        { response: signResult },
        signResponse.status
      );
    }

    // Validate signature response
    if (!signResult?.signature) {
      throw new AppError(
        "Invalid signature response from coordinator",
        "INVALID_SIGNATURE",
        { response: signResult },
        502
      );
    }

    // Update session
    req.session.combineSignature = signResult.signature;
    req.session.walletAddress = signResult.walletAddress || req.session.walletAddress;
    
    await new Promise((resolve, reject) => {
      req.session.save(err => {
        if (err) reject(new AppError("Failed to save session", "SESSION_ERROR", { error: err.message }, 500));
        else resolve();
      });
    });

    res.json({
      success: true,
      signature: signResult.signature,
      walletAddress: signResult.walletAddress
    });
  } catch (error) {
    console.error("[Sign] Error:", error);
    if (error instanceof AppError) {
      next(error);
    } else {
      next(new AppError(
        "Failed to sign message",
        "SIGN_ERROR",
        { error: error.message },
        500
      ));
    }
  }
});

// Error handling middleware
app.use(errorHandler);

// Start server
const port = process.argv[2] || 3004;
https.createServer(httpsOptions, app).listen(port, () => {
  console.log(`Main App running on HTTPS :${port}`);
});