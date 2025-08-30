import dotenv from "dotenv";
dotenv.config();

export const env = {
  nodeEnv: process.env.NODE_ENV || "development",
  port: Number(process.env.PORT || 5000),
  mongoUri: process.env.MONGODB_URI || "mongodb://localhost:27017/authDB",
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET || "change_me_access",
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || "change_me_refresh",
  accessTokenTtl: process.env.ACCESS_TOKEN_TTL || "15m",
  refreshTokenTtl: process.env.REFRESH_TOKEN_TTL || "7d",
  corsOrigin: (process.env.CORS_ORIGIN || "*").split(",").map((s) => s.trim()),
  cookieDomain: process.env.COOKIE_DOMAIN || undefined,
  cookieSecure: (process.env.COOKIE_SECURE || "false").toLowerCase() === "true",
};

