import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import compression from "compression";
import morgan from "morgan";
import session from "express-session";
import passport from "passport";
import { env } from "./config/env.js";
import logger from "./utils/logger.js";

// Import routes
import authRoutes from "./routes/auth.routes.js";
import oauthRoutes from "./routes/oauth.routes.js";
import mfaRoutes from "./routes/mfa.routes.js";
import userRoutes from "./routes/user.routes.js";
import testRoutes from "./routes/test.routes.js";

// Import middlewares
import { errorHandler, notFoundHandler } from "./middlewares/errorHandler.js";
import { validateRequest } from "./middlewares/validation.js";

const app = express();

// Security & core middlewares
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({ 
  origin: env.security.corsOrigin, 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-ID']
}));

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: env.security.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: env.security.cookieSecure,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Rate limiting
const authLimiter = rateLimit({
  windowMs: env.security.rateLimitWindow,
  max: 5, // 5 requests per window for auth endpoints
  message: { 
    success: false,
    message: "Too many authentication attempts, please try again later" 
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true
});

const apiLimiter = rateLimit({
  windowMs: env.security.rateLimitWindow,
  max: env.security.rateLimitMax,
  message: { 
    success: false,
    message: "Too many requests, please try again later" 
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Logging middleware
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.http(message.trim())
  }
}));

// Health check
app.get("/health", async (req, res) => {
  try {
    const health = {
      status: "healthy",
      timestamp: new Date().toISOString(),
      service: env.app.name,
      version: env.app.version,
      environment: env.nodeEnv,
      uptime: process.uptime()
    };
    
    res.json(health);
  } catch (error) {
    res.status(503).json({
      status: "unhealthy",
      error: error.message
    });
  }
});

// API Documentation
app.get("/", (req, res) => {
  res.json({
    service: env.app.name,
    version: env.app.version,
    description: "Enterprise-grade authentication service with OAuth, MFA, and advanced security",
    endpoints: {
      auth: "/api/auth",
      oauth: "/api/oauth",
      mfa: "/api/mfa",
      users: "/api/users",
      test: "/api/test"
    },
    documentation: "https://github.com/yourusername/auth-service"
  });
});

// Apply rate limiting
app.use("/api/auth", authLimiter);
app.use("/api", apiLimiter);

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/oauth", oauthRoutes);
app.use("/api/mfa", mfaRoutes);
app.use("/api/users", userRoutes);
app.use("/api/test", testRoutes);

// Not found handler
app.use(notFoundHandler);

// Error handler
app.use(errorHandler);

export default app;
