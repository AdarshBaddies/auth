import jwt from "jsonwebtoken";

import database from "../config/db.js";
import { env } from "../config/env.js";



export const requireAuth = async (req, res, next) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.substring(7) : null;
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, env.jwtAccessSecret);
    //to fetch the user jwt and check
    const user = await database.query(
      `SELECT u.*, rt.token_hash, rt.id as token_id 
       FROM users u 
       JOIN refresh_tokens rt ON u.id = rt.user_id 
       WHERE u.id = $1 AND rt.revoked_at IS NULL AND rt.expires_at > NOW()`,
      [decoded.sub]
    );

    if (!user) return res.status(401).json({ message: "Unauthorized" });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
};

export const requireRoles = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: "Unauthorized" });
  if (!roles.includes(req.user.role)) return res.status(403).json({ message: "Forbidden" });
  next();
};

// Example: export common role guards for convenience
export const requireAdmin = requireRoles("admin");
export const requireTheaterOwner = requireRoles("theater-owner");

