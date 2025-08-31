import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { env } from "../config/env.js";
import logger from "./logger.js";

export const signAccessToken = (payload) => {
  try {
    return jwt.sign(payload, env.jwt.accessSecret, { 
      expiresIn: env.jwt.accessTokenTtl,
      issuer: env.app.name,
      audience: env.app.name
    });
  } catch (error) {
    logger.error('Error signing access token:', error);
    throw error;
  }
};

export const signRefreshToken = (payload) => {
  try {
    return jwt.sign(payload, env.jwt.refreshSecret, { 
      expiresIn: env.jwt.refreshTokenTtl,
      issuer: env.app.name,
      audience: env.app.name,
      jti: uuidv4() // Unique identifier for refresh token
    });
  } catch (error) {
    logger.error('Error signing refresh token:', error);
    throw error;
  }
};

export const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, env.jwt.accessSecret, {
      issuer: env.app.name,
      audience: env.app.name
    });
  } catch (error) {
    logger.warn('Invalid access token:', error.message);
    throw error;
  }
};

export const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, env.jwt.refreshSecret, {
      issuer: env.app.name,
      audience: env.app.name
    });
  } catch (error) {
    logger.warn('Invalid refresh token:', error.message);
    throw error;
  }
};

export const decodeToken = (token) => {
  try {
    return jwt.decode(token);
  } catch (error) {
    logger.warn('Error decoding token:', error.message);
    return null;
  }
};

export const generateTokenPair = (payload) => {
  const accessToken = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);
  
  return {
    accessToken,
    refreshToken,
    expiresIn: env.jwt.accessTokenTtl
  };
};

export const cookieOptions = {
  httpOnly: true,
  sameSite: "lax",
  secure: env.security.cookieSecure,
  domain: env.security.cookieDomain,
  path: "/",
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};

export const secureCookieOptions = {
  ...cookieOptions,
  secure: true,
  sameSite: "strict",
  httpOnly: true,
};

export const getDeviceInfo = (req) => {
  return {
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    deviceId: req.headers['x-device-id'] || uuidv4(),
    timestamp: new Date().toISOString()
  };
};

export const createAuditPayload = (action, resource, resourceId, oldValues, newValues, metadata = {}) => {
  return {
    action,
    resource,
    resourceId,
    oldValues: oldValues ? JSON.stringify(oldValues) : null,
    newValues: newValues ? JSON.stringify(newValues) : null,
    metadata: JSON.stringify(metadata),
    timestamp: new Date().toISOString()
  };
};

