import { Router } from "express";
import { requireAuth } from "../middlewares/auth.js";
import redis from "../config/redis.js";
import emailService from "../utils/email.js";

const router = Router();

// Test OAuth setup (no authentication required)
router.get("/oauth-setup", (req, res) => {
  res.json({
    success: true,
    message: "OAuth Test Endpoints",
    endpoints: {
      google: {
        login: "GET /api/oauth/google",
        callback: "GET /api/oauth/google/callback",
        description: "Google OAuth flow"
      },
      facebook: {
        login: "GET /api/oauth/facebook", 
        callback: "GET /api/oauth/facebook/callback",
        description: "Facebook OAuth flow"
      }
    },
    instructions: [
      "1. Visit /api/oauth/google in browser",
      "2. Complete Google login",
      "3. Check callback response",
      "4. Use returned tokens for authenticated requests"
    ]
  });
});

// Test protected endpoint
router.get("/protected", requireAuth, (req, res) => {
  res.json({
    success: true,
    message: "You are authenticated!",
    user: {
      id: req.user.id,
      email: req.user.email,
      role: req.user.role
    }
  });
});

// Test database connection
router.get("/db-test", async (req, res) => {
  try {
    const database = (await import("../config/db.js")).default;
    const health = await database.healthCheck();
    
    res.json({
      success: true,
      message: "Database connection test",
      database: health
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Database connection failed",
      error: error.message
    });
  }
});

// Test Redis connection
router.get("/redis-test", async (req, res) => {
  try {
    const health = await redis.healthCheck();
    
    res.json({
      success: true,
      message: "Redis connection test",
      redis: health
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Redis connection failed",
      error: error.message
    });
  }
});

// Test email service
router.get("/email-test", async (req, res) => {
  try {
    const health = await emailService.healthCheck();
    
    res.json({
      success: true,
      message: "Email service test",
      email: health
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Email service test failed",
      error: error.message
    });
  }
});

// Test Redis operations
router.post("/redis-test", async (req, res) => {
  try {
    const { key, value, ttl = 60 } = req.body;
    
    if (!key || !value) {
      return res.status(400).json({
        success: false,
        message: "Key and value are required"
      });
    }
    
    // Set value
    await redis.set(key, value, ttl);
    
    // Get value
    const retrieved = await redis.get(key);
    
    // Check if exists
    const exists = await redis.exists(key);
    
    res.json({
      success: true,
      message: "Redis operations test",
      operations: {
        set: { key, value, ttl },
        get: retrieved,
        exists: exists === 1
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Redis operations failed",
      error: error.message
    });
  }
});

// Test all services health
router.get("/health-all", async (req, res) => {
  try {
    const database = (await import("../config/db.js")).default;
    const dbHealth = await database.healthCheck();
    const redisHealth = await redis.healthCheck();
    const emailHealth = await emailService.healthCheck();
    
    res.json({
      success: true,
      message: "All services health check",
      services: {
        database: dbHealth,
        redis: redisHealth,
        email: emailHealth,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Health check failed",
      error: error.message
    });
  }
});

export default router;
