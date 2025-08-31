import database from "../config/db.js";
import {
  generateTokenPair,
  cookieOptions,
  getDeviceInfo,
  createAuditPayload,
  verifyRefreshToken
} from "../utils/jwt.js";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";
import logger from "../utils/logger.js";
import { validateRegistration, validateLogin } from "../middlewares/validation.js";

const buildAuthResponse = (user) => ({
  id: user.id,
  email: user.email,
  first_name: user.first_name,
  last_name: user.last_name,
  role: user.role,
  status: user.status,
  email_verified: user.email_verified,
  mfa_enabled: user.mfa_enabled,
  profile_picture_url: user.profile_picture_url,
  created_at: user.created_at,
  updated_at: user.updated_at
});

const createAuditLog = async (userId, action, resource, resourceId, oldValues, newValues, metadata) => {
  try {
    const auditPayload = createAuditPayload(action, resource, resourceId, oldValues, newValues, metadata);
    await database.query(
      'INSERT INTO audit_logs (user_id, action, resource, resource_id, old_values, new_values, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [userId, auditPayload.action, auditPayload.resource, auditPayload.resourceId, auditPayload.oldValues, auditPayload.newValues, auditPayload.metadata]
    );
  } catch (error) {
    logger.error('Error creating audit log:', error);
  }
};

export const register = async (req, res, next) => {
  try {
    const { first_name, last_name, email, password, role = 'user' } = req.body;
    const deviceInfo = getDeviceInfo(req);

    // Check if user already exists
    const existingUser = await database.query(
      'SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ 
        success: false,
        message: "Email already registered" 
      });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Generate email verification token
    const emailVerificationToken = uuidv4();
    const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create user
    const result = await database.query(
      `INSERT INTO users (first_name, last_name, email, password_hash, role, email_verification_token, email_verification_expires) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [first_name, last_name, email, passwordHash, role, emailVerificationToken, emailVerificationExpires]
    );

    const user = result.rows[0];

    // Assign default role
    const roleResult = await database.query(
      'SELECT id FROM roles WHERE name = $1',
      [role]
    );

    if (roleResult.rows.length > 0) {
      await database.query(
        'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)',
        [user.id, roleResult.rows[0].id]
      );
    }

    // Create audit log
    await createAuditLog(
      user.id,
      'user_registered',
      'users',
      user.id,
      null,
      { email, first_name, last_name, role },
      { deviceInfo }
    );

    // Generate tokens
    const payload = { 
      sub: user.id, 
      role: user.role,
      email: user.email 
    };
    const tokens = generateTokenPair(payload);

    // Store refresh token
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    await database.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, device_info, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [user.id, refreshTokenHash, JSON.stringify(deviceInfo), deviceInfo.ip, deviceInfo.userAgent, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
    );

    // TODO: Send email verification
    logger.info(`User registered: ${email}`);

    res
      .cookie("refresh_token", tokens.refreshToken, cookieOptions)
      .status(201)
      .json({
        success: true,
        message: "User registered successfully. Please check your email for verification.",
        data: {
          user: buildAuthResponse(user),
          tokens: {
            accessToken: tokens.accessToken,
            expiresIn: tokens.expiresIn
          }
        }
      });

  } catch (error) {
    logger.error('Registration error:', error);
    next(error);
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const deviceInfo = getDeviceInfo(req);

    // Get user with password
    const result = await database.query(
      `SELECT u.*, ur.role_id, r.name as role_name, r.permissions 
       FROM users u 
       LEFT JOIN user_roles ur ON u.id = ur.user_id 
       LEFT JOIN roles r ON ur.role_id = r.id 
       WHERE u.email = $1 AND u.deleted_at IS NULL`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid credentials" 
      });
    }

    const user = result.rows[0];

    // Check if account is locked
    if (user.locked_until && new Date() < user.locked_until) {
      return res.status(423).json({
        success: false,
        message: "Account is temporarily locked. Please try again later."
      });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      // Increment failed login attempts
      const newFailedAttempts = user.failed_login_attempts + 1;
      let lockedUntil = null;
      
      if (newFailedAttempts >= 5) {
        lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // Lock for 30 minutes
      }

      await database.query(
        'UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
        [newFailedAttempts, lockedUntil, user.id]
      );

      return res.status(401).json({ 
        success: false,
        message: "Invalid credentials" 
      });
    }

    // Reset failed login attempts
    await database.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1',
      [user.id]
    );

    // Generate tokens
    const payload = { 
      sub: user.id, 
      role: user.role_name || user.role,
      email: user.email,
      permissions: user.permissions || []
    };
    const tokens = generateTokenPair(payload);

    // Store refresh token
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    await database.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, device_info, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [user.id, refreshTokenHash, JSON.stringify(deviceInfo), deviceInfo.ip, deviceInfo.userAgent, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
    );

    // Create audit log
    await createAuditLog(
      user.id,
      'user_login',
      'users',
      user.id,
      null,
      { last_login: new Date() },
      { deviceInfo }
    );

    logger.info(`User logged in: ${email}`);

    res
      .cookie("refresh_token", tokens.refreshToken, cookieOptions)
      .json({
        success: true,
        message: "Login successful",
        data: {
          user: buildAuthResponse(user),
          tokens: {
            accessToken: tokens.accessToken,
            expiresIn: tokens.expiresIn
          }
        }
      });

  } catch (error) {
    logger.error('Login error:', error);
    next(error);
  }
};

export const me = async (req, res) => {
  try {
    const user = req.user;
    
    // Get user with latest data
    const result = await database.query(
      'SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL',
      [user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    const currentUser = result.rows[0];

    res.json({
      success: true,
      data: {
        user: buildAuthResponse(currentUser)
      }
    });

  } catch (error) {
    logger.error('Get user profile error:', error);
    next(error);
  }
};

export const refresh = async (req, res, next) => {
  try {
    const token = req.cookies?.refresh_token;
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "No refresh token provided" 
      });
    }

    // Verify refresh token
    const decoded = verifyRefreshToken(token);
    
    // Get user and refresh token
    const result = await database.query(
      `SELECT u.*, rt.token_hash, rt.id as token_id 
       FROM users u 
       JOIN refresh_tokens rt ON u.id = rt.user_id 
       WHERE u.id = $1 AND rt.revoked_at IS NULL AND rt.expires_at > NOW()`,
      [decoded.sub]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid refresh token" 
      });
    }

    const user = result.rows[0];
    const refreshTokenRecord = result.rows[0];

    // Verify token hash
    const valid = await bcrypt.compare(token, refreshTokenRecord.token_hash);
    if (!valid) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid refresh token" 
      });
    }

    // Generate new tokens
    const payload = { 
      sub: user.id, 
      role: user.role,
      email: user.email 
    };
    const tokens = generateTokenPair(payload);

    // Revoke old refresh token
    await database.query(
      'UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = $1 WHERE id = $2',
      ['token_refreshed', refreshTokenRecord.token_id]
    );

    // Store new refresh token
    const newRefreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    const deviceInfo = getDeviceInfo(req);
    
    await database.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, device_info, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [user.id, newRefreshTokenHash, JSON.stringify(deviceInfo), deviceInfo.ip, deviceInfo.userAgent, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
    );

    res
      .cookie("refresh_token", tokens.refreshToken, cookieOptions)
      .json({
        success: true,
        message: "Token refreshed successfully",
        data: {
          user: buildAuthResponse(user),
          tokens: {
            accessToken: tokens.accessToken,
            expiresIn: tokens.expiresIn
          }
        }
      });

  } catch (error) {
    logger.error('Token refresh error:', error);
    next(error);
  }
};

export const logout = async (req, res, next) => {
  try {
    const token = req.cookies?.refresh_token;
    
    if (token && req.user) {
      // Revoke refresh token
      await database.query(
        'UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = $1 WHERE user_id = $2 AND revoked_at IS NULL',
        ['user_logout', req.user.id]
      );

      // Create audit log
      await createAuditLog(
        req.user.id,
        'user_logout',
        'users',
        req.user.id,
        null,
        null,
        { deviceInfo: getDeviceInfo(req) }
      );
    }

    res.clearCookie("refresh_token", cookieOptions);
    
    res.json({
      success: true,
      message: "Logged out successfully"
    });

  } catch (error) {
    logger.error('Logout error:', error);
    next(error);
  }
};

export const verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.params;

    const result = await database.query(
      'SELECT id, email FROM users WHERE email_verification_token = $1 AND email_verification_expires > NOW()',
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification token"
      });
    }

    const user = result.rows[0];

    await database.query(
      'UPDATE users SET email_verified = TRUE, email_verification_token = NULL, email_verification_expires = NULL WHERE id = $1',
      [user.id]
    );

    // Create audit log
    await createAuditLog(
      user.id,
      'email_verified',
      'users',
      user.id,
      { email_verified: false },
      { email_verified: true },
      { ip: req.ip }
    );

    res.json({
      success: true,
      message: "Email verified successfully"
    });

  } catch (error) {
    logger.error('Email verification error:', error);
    next(error);
  }
};

export const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    const result = await database.query(
      'SELECT id, email, first_name FROM users WHERE email = $1 AND deleted_at IS NULL',
      [email]
    );

    if (result.rows.length === 0) {
      // Don't reveal if email exists
      return res.json({
        success: true,
        message: "If an account with that email exists, a password reset link has been sent"
      });
    }

    const user = result.rows[0];
    const resetToken = uuidv4();
    const resetExpires = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour

    await database.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE id = $1',
      [resetToken, resetExpires, user.id]
    );

    // TODO: Send password reset email
    logger.info(`Password reset requested for: ${email}`);

    res.json({
      success: true,
      message: "If an account with that email exists, a password reset link has been sent"
    });

  } catch (error) {
    logger.error('Forgot password error:', error);
    next(error);
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    const { token, password } = req.body;

    const result = await database.query(
      'SELECT id, email FROM users WHERE password_reset_token = $1 AND password_reset_expires > NOW()',
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset token"
      });
    }

    const user = result.rows[0];
    const passwordHash = await bcrypt.hash(password, 12);

    await database.query(
      'UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires = NULL, failed_login_attempts = 0, locked_until = NULL WHERE id = $2',
      [passwordHash, user.id]
    );

    // Revoke all refresh tokens
    await database.query(
      'UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = $1 WHERE user_id = $2',
      ['password_reset', user.id]
    );

    // Create audit log
    await createAuditLog(
      user.id,
      'password_reset',
      'users',
      user.id,
      null,
      null,
      { ip: req.ip }
    );

    res.json({
      success: true,
      message: "Password reset successfully"
    });

  } catch (error) {
    logger.error('Password reset error:', error);
    next(error);
  }
};

