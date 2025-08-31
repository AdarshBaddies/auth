import database from "../config/db.js";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import { v4 as uuidv4 } from "uuid";
import logger from "../utils/logger.js";
import { createAuditLog } from "./auth.controller.js";

export const setupMFA = async (req, res, next) => {
  try {
    const userId = req.user.id;

    // Check if MFA is already enabled
    const userResult = await database.query(
      'SELECT mfa_enabled, mfa_secret FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows[0].mfa_enabled) {
      return res.status(400).json({
        success: false,
        message: "MFA is already enabled"
      });
    }

    // Generate new MFA secret
    const secret = speakeasy.generateSecret({
      name: `BookMyShow:${req.user.email}`,
      issuer: "BookMyShow",
      length: 32
    });

    // Generate backup codes
    const backupCodes = Array.from({ length: 10 }, () => 
      Math.random().toString(36).substring(2, 8).toUpperCase()
    );

    // Hash backup codes
    const hashedBackupCodes = backupCodes.map(code => 
      require('crypto').createHash('sha256').update(code).digest('hex')
    );

    // Update user with MFA secret and backup codes
    await database.query(
      'UPDATE users SET mfa_secret = $1, mfa_backup_codes = $2 WHERE id = $3',
      [secret.base32, hashedBackupCodes, userId]
    );

    // Generate QR code
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    // Create audit log
    await createAuditLog(
      userId,
      'mfa_setup',
      'users',
      userId,
      { mfa_enabled: false },
      { mfa_enabled: true },
      { ip: req.ip }
    );

    logger.info(`MFA setup initiated for user: ${req.user.email}`);

    res.json({
      success: true,
      message: "MFA setup initiated",
      data: {
        secret: secret.base32,
        qrCode,
        backupCodes,
        otpauthUrl: secret.otpauth_url
      }
    });

  } catch (error) {
    logger.error('MFA setup error:', error);
    next(error);
  }
};

export const verifyMFA = async (req, res, next) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;

    // Get user's MFA secret
    const userResult = await database.query(
      'SELECT mfa_secret, mfa_enabled FROM users WHERE id = $1',
      [userId]
    );

    if (!userResult.rows[0].mfa_enabled) {
      return res.status(400).json({
        success: false,
        message: "MFA is not enabled"
      });
    }

    const secret = userResult.rows[0].mfa_secret;

    // Verify TOTP token
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2 // Allow 2 time steps (60 seconds) for clock skew
    });

    if (!verified) {
      // Check if it's a backup code
      const backupCodeResult = await database.query(
        'SELECT mfa_backup_codes FROM users WHERE id = $1',
        [userId]
      );

      const backupCodes = backupCodeResult.rows[0].mfa_backup_codes || [];
      const hashedToken = require('crypto').createHash('sha256').update(token).digest('hex');
      
      const backupCodeIndex = backupCodes.indexOf(hashedToken);
      
      if (backupCodeIndex === -1) {
        return res.status(400).json({
          success: false,
          message: "Invalid MFA token"
        });
      }

      // Remove used backup code
      backupCodes.splice(backupCodeIndex, 1);
      await database.query(
        'UPDATE users SET mfa_backup_codes = $1 WHERE id = $2',
        [backupCodes, userId]
      );

      logger.info(`Backup code used for user: ${req.user.email}`);
    }

    // Create audit log
    await createAuditLog(
      userId,
      'mfa_verified',
      'users',
      userId,
      null,
      null,
      { ip: req.ip, method: verified ? 'totp' : 'backup_code' }
    );

    res.json({
      success: true,
      message: "MFA verification successful"
    });

  } catch (error) {
    logger.error('MFA verification error:', error);
    next(error);
  }
};

export const enableMFA = async (req, res, next) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;

    // Get user's MFA secret
    const userResult = await database.query(
      'SELECT mfa_secret FROM users WHERE id = $1',
      [userId]
    );

    const secret = userResult.rows[0].mfa_secret;

    if (!secret) {
      return res.status(400).json({
        success: false,
        message: "MFA setup not completed"
      });
    }

    // Verify TOTP token
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2
    });

    if (!verified) {
      return res.status(400).json({
        success: false,
        message: "Invalid MFA token"
      });
    }

    // Enable MFA
    await database.query(
      'UPDATE users SET mfa_enabled = TRUE WHERE id = $1',
      [userId]
    );

    // Create audit log
    await createAuditLog(
      userId,
      'mfa_enabled',
      'users',
      userId,
      { mfa_enabled: false },
      { mfa_enabled: true },
      { ip: req.ip }
    );

    logger.info(`MFA enabled for user: ${req.user.email}`);

    res.json({
      success: true,
      message: "MFA enabled successfully"
    });

  } catch (error) {
    logger.error('MFA enable error:', error);
    next(error);
  }
};

export const disableMFA = async (req, res, next) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;

    // Get user's MFA secret
    const userResult = await database.query(
      'SELECT mfa_secret, mfa_enabled FROM users WHERE id = $1',
      [userId]
    );

    if (!userResult.rows[0].mfa_enabled) {
      return res.status(400).json({
        success: false,
        message: "MFA is not enabled"
      });
    }

    const secret = userResult.rows[0].mfa_secret;

    // Verify TOTP token
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2
    });

    if (!verified) {
      return res.status(400).json({
        success: false,
        message: "Invalid MFA token"
      });
    }

    // Disable MFA
    await database.query(
      'UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_backup_codes = NULL WHERE id = $1',
      [userId]
    );

    // Revoke all refresh tokens (security measure)
    await database.query(
      'UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = $1 WHERE user_id = $2',
      ['mfa_disabled', userId]
    );

    // Create audit log
    await createAuditLog(
      userId,
      'mfa_disabled',
      'users',
      userId,
      { mfa_enabled: true },
      { mfa_enabled: false },
      { ip: req.ip }
    );

    logger.info(`MFA disabled for user: ${req.user.email}`);

    res.json({
      success: true,
      message: "MFA disabled successfully. You have been logged out for security."
    });

  } catch (error) {
    logger.error('MFA disable error:', error);
    next(error);
  }
};

export const generateBackupCodes = async (req, res, next) => {
  try {
    const userId = req.user.id;

    // Check if MFA is enabled
    const userResult = await database.query(
      'SELECT mfa_enabled FROM users WHERE id = $1',
      [userId]
    );

    if (!userResult.rows[0].mfa_enabled) {
      return res.status(400).json({
        success: false,
        message: "MFA is not enabled"
      });
    }

    // Generate new backup codes
    const backupCodes = Array.from({ length: 10 }, () => 
      Math.random().toString(36).substring(2, 8).toUpperCase()
    );

    // Hash backup codes
    const hashedBackupCodes = backupCodes.map(code => 
      require('crypto').createHash('sha256').update(code).digest('hex')
    );

    // Update user with new backup codes
    await database.query(
      'UPDATE users SET mfa_backup_codes = $1 WHERE id = $2',
      [hashedBackupCodes, userId]
    );

    // Create audit log
    await createAuditLog(
      userId,
      'backup_codes_regenerated',
      'users',
      userId,
      null,
      null,
      { ip: req.ip }
    );

    logger.info(`Backup codes regenerated for user: ${req.user.email}`);

    res.json({
      success: true,
      message: "New backup codes generated",
      data: {
        backupCodes
      }
    });

  } catch (error) {
    logger.error('Generate backup codes error:', error);
    next(error);
  }
};

export const getMFAStatus = async (req, res, next) => {
  try {
    const userId = req.user.id;

    const userResult = await database.query(
      'SELECT mfa_enabled, mfa_backup_codes FROM users WHERE id = $1',
      [userId]
    );

    const user = userResult.rows[0];

    res.json({
      success: true,
      data: {
        mfa_enabled: user.mfa_enabled,
        backup_codes_remaining: user.mfa_backup_codes ? user.mfa_backup_codes.length : 0
      }
    });

  } catch (error) {
    logger.error('Get MFA status error:', error);
    next(error);
  }
};
