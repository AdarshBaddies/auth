import jwt from "jsonwebtoken";
import { env } from "../config/env.js";

export const signAccessToken = (payload) =>
  jwt.sign(payload, env.jwtAccessSecret, { expiresIn: env.accessTokenTtl });

export const signRefreshToken = (payload) =>
  jwt.sign(payload, env.jwtRefreshSecret, { expiresIn: env.refreshTokenTtl });

export const verifyAccessToken = (token) =>
  jwt.verify(token, env.jwtAccessSecret);

export const verifyRefreshToken = (token) =>
  jwt.verify(token, env.jwtRefreshSecret);

export const cookieOptions = {
  httpOnly: true,
  sameSite: "lax",
  secure: env.cookieSecure,
  domain: env.cookieDomain,
  path: "/",
};

