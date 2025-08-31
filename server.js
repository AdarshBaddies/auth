import app from "./src/app.js";
import database from "./src/config/db.js";
import redis from "./src/config/redis.js";
import emailService from "./src/utils/email.js";
import { env } from "./src/config/env.js";
import logger from "./src/utils/logger.js";

const start = async () => {
  try {
    // Connect to database
    await database.connect();
    logger.info('✅ Database connected');
    
    // Connect to Redis (optional)
    try {
      await redis.connect();
      logger.info('✅ Redis connected');
    } catch (error) {
      logger.warn('⚠️ Redis connection failed - continuing without Redis');
    }
    
    // Initialize email service (optional)
    try {
      await emailService.initialize();
      if (emailService.isConfigured) {
        logger.info('✅ Email service initialized');
      } else {
        logger.warn('⚠️ Email service not configured - emails will not be sent');
      }
    } catch (error) {
      logger.warn('⚠️ Email service initialization failed - continuing without email');
    }
    
    // Start server
    const server = app.listen(env.port, () => {
      logger.info(`🚀 ${env.app.name} v${env.app.version} running on port ${env.port}`);
      logger.info(`🌍 Environment: ${env.nodeEnv}`);
      logger.info(`🔗 Base URL: ${env.app.baseUrl}`);
      logger.info(`📧 Email: ${emailService.isConfigured ? 'Configured' : 'Not configured'}`);
      logger.info(`🗄️ Redis: ${redis.isConnected ? 'Connected' : 'Not connected'}`);
    });

    // Graceful shutdown
    const gracefulShutdown = async (signal) => {
      logger.info(`\n${signal} received. Starting graceful shutdown...`);
      
      server.close(async () => {
        logger.info('HTTP server closed');
        
        try {
          await database.close();
          logger.info('Database connection closed');
          
          if (redis.isConnected) {
            await redis.close();
            logger.info('Redis connection closed');
          }
          
          process.exit(0);
        } catch (error) {
          logger.error('Error during shutdown:', error);
          process.exit(1);
        }
      });

      // Force close after 10 seconds
      setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 10000);
    };

    // Handle shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
      gracefulShutdown('unhandledRejection');
    });

  } catch (error) {
    logger.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};

start();
