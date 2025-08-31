import database from "../config/db.js";
import { generateTokenPair, cookieOptions, getDeviceInfo } from "../utils/jwt.js";
import { v4 as uuidv4 } from "uuid";
import logger from "../utils/logger.js";

const buildOAuthUser = (profile, provider) => ({
  email: profile.email,
  first_name: profile.first_name || profile.given_name || profile.name?.split(' ')[0] || 'User',
  last_name: profile.last_name || profile.family_name || profile.name?.split(' ').slice(1).join(' ') || 'User',
  profile_picture_url: profile.picture || profile.avatar_url,
  email_verified: true,
  oauth_provider: provider
});

const findOrCreateUser = async (profile, provider) => {
  try {
    // Check if OAuth account exists
    const oauthResult = await database.query(
      'SELECT ua.*, u.* FROM oauth_accounts ua JOIN users u ON ua.user_id = u.id WHERE ua.provider = $1 AND ua.provider_user_id = $2',
      [provider, profile.id]
    );

    if (oauthResult.rows.length > 0) {
      // User exists, update OAuth tokens
      const user = oauthResult.rows[0];
      await database.query(
        'UPDATE oauth_accounts SET access_token = $1, refresh_token = $2, expires_at = $3, updated_at = NOW() WHERE id = $4',
        [profile.accessToken, profile.refreshToken, profile.expiresAt, user.id]
      );
      return user;
    }

    // Check if user exists with same email
    const userResult = await database.query(
      'SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL',
      [profile.email]
    );

    if (userResult.rows.length > 0) {
      // User exists, link OAuth account
      const user = userResult.rows[0];
      await database.query(
        'INSERT INTO oauth_accounts (user_id, provider, provider_user_id, access_token, refresh_token, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
        [user.id, provider, profile.id, profile.accessToken, profile.refreshToken, profile.expiresAt]
      );
      return user;
    }

    // Create new user
    const newUser = buildOAuthUser(profile, provider);
    const userResult2 = await database.query(
      `INSERT INTO users (email, first_name, last_name, profile_picture_url, email_verified, role, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [newUser.email, newUser.first_name, newUser.last_name, newUser.profile_picture_url, newUser.email_verified, 'user', 'active']
    );

    const user = userResult2.rows[0];

    // Assign default role
    const roleResult = await database.query(
      'SELECT id FROM roles WHERE name = $1',
      ['user']
    );

    if (roleResult.rows.length > 0) {
      await database.query(
        'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)',
        [user.id, roleResult.rows[0].id]
      );
    }

    // Create OAuth account
    await database.query(
      'INSERT INTO oauth_accounts (user_id, provider, provider_user_id, access_token, refresh_token, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [user.id, provider, profile.id, profile.accessToken, profile.refreshToken, profile.expiresAt]
    );

    return user;
  } catch (error) {
    logger.error('Error in findOrCreateUser:', error);
    throw error;
  }
};

export const googleAuth = async (req, res, next) => {
  try {
    const { profile } = req.user;
    const deviceInfo = getDeviceInfo(req);

    const user = await findOrCreateUser(profile, 'google');

    // Generate tokens
    const payload = { 
      sub: user.id, 
      role: user.role,
      email: user.email,
      oauth_provider: 'google'
    };
    const tokens = generateTokenPair(payload);

    // Store refresh token
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    await database.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, device_info, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [user.id, refreshTokenHash, JSON.stringify(deviceInfo), deviceInfo.ip, deviceInfo.userAgent, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
    );

    // Create audit log
    await database.query(
      'INSERT INTO audit_logs (user_id, action, resource, resource_id, metadata) VALUES ($1, $2, $3, $4, $5)',
      [user.id, 'oauth_login', 'users', user.id, JSON.stringify({ provider: 'google', deviceInfo })]
    );

    logger.info(`Google OAuth login: ${user.email}`);

    res
      .cookie("refresh_token", tokens.refreshToken, cookieOptions)
      .json({
        success: true,
        message: "Google authentication successful",
        data: {
          user: {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            role: user.role,
            profile_picture_url: user.profile_picture_url,
            email_verified: user.email_verified
          },
          tokens: {
            accessToken: tokens.accessToken,
            expiresIn: tokens.expiresIn
          }
        }
      });

  } catch (error) {
    logger.error('Google OAuth error:', error);
    next(error);
  }
};

export const facebookAuth = async (req, res, next) => {
  try {
    const { profile } = req.user;
    const deviceInfo = getDeviceInfo(req);

    const user = await findOrCreateUser(profile, 'facebook');

    // Generate tokens
    const payload = { 
      sub: user.id, 
      role: user.role,
      email: user.email,
      oauth_provider: 'facebook'
    };
    const tokens = generateTokenPair(payload);

    // Store refresh token
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    await database.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, device_info, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [user.id, refreshTokenHash, JSON.stringify(deviceInfo), deviceInfo.ip, deviceInfo.userAgent, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
    );

    // Create audit log
    await database.query(
      'INSERT INTO audit_logs (user_id, action, resource, resource_id, metadata) VALUES ($1, $2, $3, $4, $5)',
      [user.id, 'oauth_login', 'users', user.id, JSON.stringify({ provider: 'facebook', deviceInfo })]
    );

    logger.info(`Facebook OAuth login: ${user.email}`);

    res
      .cookie("refresh_token", tokens.refreshToken, cookieOptions)
      .json({
        success: true,
        message: "Facebook authentication successful",
        data: {
          user: {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            role: user.role,
            profile_picture_url: user.profile_picture_url,
            email_verified: user.email_verified
          },
          tokens: {
            accessToken: tokens.accessToken,
            expiresIn: tokens.expiresIn
          }
        }
      });

  } catch (error) {
    logger.error('Facebook OAuth error:', error);
    next(error);
  }
};

export const appleAuth = async (req, res, next) => {
  try {
    const { profile } = req.user;
    const deviceInfo = getDeviceInfo(req);

    const user = await findOrCreateUser(profile, 'apple');

    // Generate tokens
    const payload = { 
      sub: user.id, 
      role: user.role,
      email: user.email,
      oauth_provider: 'apple'
    };
    const tokens = generateTokenPair(payload);

    // Store refresh token
    const refreshTokenHash = await bcrypt.hash(tokens.refreshToken, 10);
    await database.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, device_info, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [user.id, refreshTokenHash, JSON.stringify(deviceInfo), deviceInfo.ip, deviceInfo.userAgent, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
    );

    // Create audit log
    await database.query(
      'INSERT INTO audit_logs (user_id, action, resource, resource_id, metadata) VALUES ($1, $2, $3, $4, $5)',
      [user.id, 'oauth_login', 'users', user.id, JSON.stringify({ provider: 'apple', deviceInfo })]
    );

    logger.info(`Apple OAuth login: ${user.email}`);

    res
      .cookie("refresh_token", tokens.refreshToken, cookieOptions)
      .json({
        success: true,
        message: "Apple authentication successful",
        data: {
          user: {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            role: user.role,
            profile_picture_url: user.profile_picture_url,
            email_verified: user.email_verified
          },
          tokens: {
            accessToken: tokens.accessToken,
            expiresIn: tokens.expiresIn
          }
        }
      });

  } catch (error) {
    logger.error('Apple OAuth error:', error);
    next(error);
  }
};

export const linkOAuthAccount = async (req, res, next) => {
  try {
    const { provider, providerUserId, accessToken, refreshToken, expiresAt } = req.body;
    const userId = req.user.id;

    // Check if OAuth account already exists
    const existingResult = await database.query(
      'SELECT id FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2',
      [provider, providerUserId]
    );

    if (existingResult.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "OAuth account already linked to another user"
      });
    }

    // Link OAuth account
    await database.query(
      'INSERT INTO oauth_accounts (user_id, provider, provider_user_id, access_token, refresh_token, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [userId, provider, providerUserId, accessToken, refreshToken, expiresAt]
    );

    // Create audit log
    await database.query(
      'INSERT INTO audit_logs (user_id, action, resource, resource_id, metadata) VALUES ($1, $2, $3, $4, $5)',
      [userId, 'oauth_linked', 'oauth_accounts', userId, JSON.stringify({ provider, providerUserId })]
    );

    res.json({
      success: true,
      message: "OAuth account linked successfully"
    });

  } catch (error) {
    logger.error('Link OAuth account error:', error);
    next(error);
  }
};

export const unlinkOAuthAccount = async (req, res, next) => {
  try {
    const { provider } = req.params;
    const userId = req.user.id;

    // Unlink OAuth account
    const result = await database.query(
      'DELETE FROM oauth_accounts WHERE user_id = $1 AND provider = $2 RETURNING id',
      [userId, provider]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "OAuth account not found"
      });
    }

    // Create audit log
    await database.query(
      'INSERT INTO audit_logs (user_id, action, resource, resource_id, metadata) VALUES ($1, $2, $3, $4, $5)',
      [userId, 'oauth_unlinked', 'oauth_accounts', userId, JSON.stringify({ provider })]
    );

    res.json({
      success: true,
      message: "OAuth account unlinked successfully"
    });

  } catch (error) {
    logger.error('Unlink OAuth account error:', error);
    next(error);
  }
};
