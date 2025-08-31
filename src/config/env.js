import dotenv from "dotenv";
dotenv.config();

export const env = {
  // Service Configuration
  nodeEnv: process.env.NODE_ENV || "development",
  port: Number(process.env.PORT || 5000),
  
  // Database Configuration
  postgres: {
    host: process.env.POSTGRES_HOST || "postgres",
    port: Number(process.env.POSTGRES_PORT || 5432),
    database: process.env.POSTGRES_DB || "bookmyshow",
    username: process.env.POSTGRES_USER || "admin",
    password: process.env.POSTGRES_PASSWORD || "secure_password",
    url: process.env.DATABASE_URL || `postgresql://${process.env.POSTGRES_USER || 'admin'}:${process.env.POSTGRES_PASSWORD || 'secure_password'}@${process.env.POSTGRES_HOST || 'postgres'}:${process.env.POSTGRES_PORT || 5432}/${process.env.POSTGRES_DB || 'bookmyshow'}`
  },
  
  // Redis Configuration
  redis: {
    host: process.env.REDIS_HOST || "redis",
    port: Number(process.env.REDIS_PORT || 6379),
    password: process.env.REDIS_PASSWORD,
    url: process.env.REDIS_URL || `redis://${process.env.REDIS_HOST || 'redis'}:${process.env.REDIS_PORT || 6379}`
  },
  
  // JWT Configuration
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET || "your-super-secret-access-key-change-in-production",
    refreshSecret: process.env.JWT_REFRESH_SECRET || "your-super-secret-refresh-key-change-in-production",
    accessTokenTtl: process.env.ACCESS_TOKEN_TTL || "15m",
    refreshTokenTtl: process.env.REFRESH_TOKEN_TTL || "7d"
  },
  
  // OAuth Configuration
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      callbackUrl: process.env.GOOGLE_CALLBACK_URL || "http://localhost:5000/api/auth/google/callback"
    },
    facebook: {
      appId: process.env.FACEBOOK_APP_ID || "",
      appSecret: process.env.FACEBOOK_APP_SECRET || "",
      callbackUrl: process.env.FACEBOOK_CALLBACK_URL || "http://localhost:5000/api/auth/facebook/callback"
    },
    apple: {
      clientId: process.env.APPLE_CLIENT_ID || "",
      teamId: process.env.APPLE_TEAM_ID || "",
      keyId: process.env.APPLE_KEY_ID || "",
      privateKey: process.env.APPLE_PRIVATE_KEY || ""
    }
  },
  
  // Email Configuration
  email: {
    host: process.env.EMAIL_HOST || "smtp.gmail.com",
    port: Number(process.env.EMAIL_PORT || 587),
    secure: process.env.EMAIL_SECURE === "true",
    user: process.env.EMAIL_USER || "",
    pass: process.env.EMAIL_PASS || "",
    from: process.env.EMAIL_FROM || "noreply@bookmyshow.com"
  },
  
  // Security Configuration
  security: {
    bcryptRounds: Number(process.env.BCRYPT_ROUNDS || 12),
    sessionSecret: process.env.SESSION_SECRET || "your-session-secret-change-in-production",
    corsOrigin: (process.env.CORS_ORIGIN || "http://localhost:3000").split(",").map((s) => s.trim()),
    cookieSecure: (process.env.COOKIE_SECURE || "false").toLowerCase() === "true",
    cookieDomain: process.env.COOKIE_DOMAIN || undefined,
    rateLimitWindow: Number(process.env.RATE_LIMIT_WINDOW || 15 * 60 * 1000), // 15 minutes
    rateLimitMax: Number(process.env.RATE_LIMIT_MAX || 100),
    mfaIssuer: process.env.MFA_ISSUER || "BookMyShow",
    passwordMinLength: Number(process.env.PASSWORD_MIN_LENGTH || 8),
    passwordRequireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE !== "false",
    passwordRequireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE !== "false",
    passwordRequireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS !== "false",
    passwordRequireSpecialChars: process.env.PASSWORD_REQUIRE_SPECIAL_CHARS !== "false"
  },
  
  // Application Configuration
  app: {
    name: process.env.APP_NAME || "BookMyShow Auth Service",
    version: process.env.APP_VERSION || "1.0.0",
    baseUrl: process.env.BASE_URL || "http://localhost:5000",
    frontendUrl: process.env.FRONTEND_URL || "http://localhost:3000"
  }
};

