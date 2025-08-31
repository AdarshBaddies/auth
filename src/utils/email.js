import nodemailer from 'nodemailer';
import { env } from '../config/env.js';
import logger from './logger.js';

class EmailService {
  constructor() {
    this.transporter = null;
    this.isConfigured = false;
  }

  async initialize() {
    try {
      // Check if email is configured
      if (!env.email.user || !env.email.pass) {
        logger.warn('Email service not configured - skipping initialization');
        return false;
      }

      this.transporter = nodemailer.createTransporter({
        host: env.email.host,
        port: env.email.port,
        secure: env.email.secure,
        auth: {
          user: env.email.user,
          pass: env.email.pass
        }
      });

      // Verify connection
      await this.transporter.verify();
      this.isConfigured = true;
      logger.info('✅ Email service initialized successfully');
      return true;
    } catch (error) {
      logger.error('❌ Failed to initialize email service:', error);
      return false;
    }
  }

  async sendEmail(to, subject, html, text) {
    if (!this.isConfigured) {
      logger.warn('Email service not configured - email not sent');
      return false;
    }

    try {
      const mailOptions = {
        from: env.email.from,
        to,
        subject,
        html,
        text
      };

      const info = await this.transporter.sendMail(mailOptions);
      logger.info(`Email sent successfully to ${to}:`, info.messageId);
      return true;
    } catch (error) {
      logger.error('Failed to send email:', error);
      return false;
    }
  }

  async sendVerificationEmail(to, token, firstName) {
    const subject = 'Verify Your Email - BookMyShow';
    const verificationUrl = `${env.app.baseUrl}/api/auth/verify-email/${token}`;
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Welcome to BookMyShow!</h2>
        <p>Hi ${firstName},</p>
        <p>Thank you for registering with BookMyShow. Please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationUrl}" 
             style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Verify Email
          </a>
        </div>
        <p>Or copy and paste this link in your browser:</p>
        <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, please ignore this email.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          This is an automated email from BookMyShow. Please do not reply.
        </p>
      </div>
    `;

    const text = `
      Welcome to BookMyShow!
      
      Hi ${firstName},
      
      Thank you for registering with BookMyShow. Please verify your email address by visiting:
      ${verificationUrl}
      
      This link will expire in 24 hours.
      
      If you didn't create an account, please ignore this email.
    `;

    return await this.sendEmail(to, subject, html, text);
  }

  async sendPasswordResetEmail(to, token, firstName) {
    const subject = 'Reset Your Password - BookMyShow';
    const resetUrl = `${env.app.frontendUrl}/reset-password?token=${token}`;
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset Request</h2>
        <p>Hi ${firstName},</p>
        <p>We received a request to reset your password. Click the button below to create a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" 
             style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Reset Password
          </a>
        </div>
        <p>Or copy and paste this link in your browser:</p>
        <p style="word-break: break-all; color: #666;">${resetUrl}</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request a password reset, please ignore this email and your password will remain unchanged.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          This is an automated email from BookMyShow. Please do not reply.
        </p>
      </div>
    `;

    const text = `
      Password Reset Request
      
      Hi ${firstName},
      
      We received a request to reset your password. Visit this link to create a new password:
      ${resetUrl}
      
      This link will expire in 1 hour.
      
      If you didn't request a password reset, please ignore this email.
    `;

    return await this.sendEmail(to, subject, html, text);
  }

  async sendWelcomeEmail(to, firstName) {
    const subject = 'Welcome to BookMyShow!';
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Welcome to BookMyShow!</h2>
        <p>Hi ${firstName},</p>
        <p>Your account has been successfully created and verified. You can now:</p>
        <ul>
          <li>Browse movies and shows</li>
          <li>Book tickets</li>
          <li>Manage your profile</li>
          <li>Set up two-factor authentication for extra security</li>
        </ul>
        <p>If you have any questions, feel free to contact our support team.</p>
        <p>Happy booking!</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          This is an automated email from BookMyShow. Please do not reply.
        </p>
      </div>
    `;

    const text = `
      Welcome to BookMyShow!
      
      Hi ${firstName},
      
      Your account has been successfully created and verified. You can now browse movies, book tickets, and manage your profile.
      
      Happy booking!
    `;

    return await this.sendEmail(to, subject, html, text);
  }

  async healthCheck() {
    try {
      if (!this.isConfigured) {
        return { status: 'not_configured' };
      }
      
      return {
        status: 'healthy',
        configured: true,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }
}

const emailService = new EmailService();
export default emailService;


