/**
 * CodeSaviour Enterprise Node.js Service
 * 
 * A secure, production-ready enterprise service providing:
 * - User authentication and authorization
 * - Admin management capabilities
 * - Comprehensive audit logging
 * - Performance monitoring
 * - Security hardening
 * - Health check endpoints
 * 
 * Author: CodeSaviour Team
 * Version: 1.0.0
 */

// =============================================================================
// ENVIRONMENT AND ERROR HANDLING SETUP
// =============================================================================

// Load environment variables from .env file
require('dotenv').config();

// Enable automatic async error handling for Express routes
require('express-async-errors');

// =============================================================================
// CORE DEPENDENCIES
// =============================================================================

// Express framework and security middleware
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

// =============================================================================
// APPLICATION MODULES
// =============================================================================

// Database and configuration
const { databaseManager } = require('./config/database');
const logger = require('./utils/logger');

// Middleware modules
const { globalErrorHandler, notFoundHandler, gracefulShutdown } = require('./middleware/errorHandler');
const { createSecurityMiddleware, corsOptions } = require('./middleware/security');
const { performanceMiddleware } = require('./middleware/performance');

// Services and models
const { AuditService } = require('./services/auditService');
const User = require('./models/User');

// =============================================================================
// ROUTE MODULES
// =============================================================================

const authRoutes = require('./routes/auth');           // Authentication endpoints
const adminRoutes = require('./routes/admin');         // Admin management
const healthRoutes = require('./routes/health');       // Health check endpoints
const auditRoutes = require('./routes/audit');         // Audit log access
const performanceRoutes = require('./routes/performance'); // Performance metrics

// =============================================================================
// ENVIRONMENT VALIDATION
// =============================================================================

/**
 * Validate that all required environment variables are present.
 * In production, missing variables will cause the application to exit.
 * In development, warnings are logged but the app continues to run.
 */
const requiredEnvVars = ['JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  logger.error('Missing required environment variables:', missingEnvVars);
  
  if (process.env.NODE_ENV === 'production') {
    logger.error('Exiting application due to missing environment variables in production');
    process.exit(1);
  } else {
    logger.warn('Missing environment variables in development mode. Some features may not work correctly.');
  }
}

// =============================================================================
// APPLICATION INITIALIZATION
// =============================================================================

// Initialize Express application
const app = express();
const PORT = process.env.PORT || 3000;

// Configure Express to trust proxy headers for accurate client IP detection
// This is essential for rate limiting and security logging
app.set('trust proxy', 1);

logger.info(`Initializing CodeSaviour Enterprise Service on port ${PORT}`);
logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'", "blob:"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false // Allow embedding for development
}));

// Apply performance monitoring middleware
app.use(performanceMiddleware);

// Apply enhanced security middleware
app.use(cors(corsOptions));
const securityMiddlewares = createSecurityMiddleware({
  rateLimit: 'general',
  sanitizeInput: true,
  requestSizeLimit: '10mb',
  apiVersioning: true,
  supportedVersions: ['v1'],
  requestLogging: true
});

// Apply all security middlewares
securityMiddlewares.forEach(middleware => app.use(middleware));

// Import auth rate limiter from security middleware
const { rateLimits } = require('./middleware/security');

// Body parsing middleware
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Note: Request logging is now handled by security middleware

// Serve static files from React build
const frontendPath = path.join(__dirname, '..', 'code-savior-landing', 'dist');
app.use(express.static(frontendPath));

// API routes
app.use('/api/health', healthRoutes);
app.use('/api/auth', rateLimits.auth, authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/performance', performanceRoutes);

// API info endpoint
app.get('/api', (req, res) => {
  res.json({
    success: true,
    message: 'Enterprise Node.js Service API',
    version: require('./package.json').version,
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    security: {
      oauth2: 'Enabled',
      rateLimit: 'Enabled',
      auditLogging: 'Enabled',
      apiVersioning: 'v1'
    },
    endpoints: {
      health: '/api/health',
      auth: '/api/auth',
      admin: '/api/admin',
      audit: '/api/audit',
      performance: '/api/performance'
    }
  });
});

// Serve React app for all non-API routes
app.get('*', (req, res) => {
  // Skip API routes
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  
  // Serve React app
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// Global error handling middleware (must be last)
app.use(globalErrorHandler);

// Initialize database and start server
const startServer = async () => {
  try {
    logger.info('Starting Enterprise Node.js Service...');
    
    // Connect to database
    const dbConnected = await databaseManager.connect();
    
    // Create default admin user if database is connected
    if (dbConnected && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
      try {
        await User.createAdmin(process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD);
      } catch (error) {
        logger.warn('Could not create admin user:', error.message);
      }
    } else if (!dbConnected) {
      logger.warn('Skipping admin user creation - no database connection');
    }
    
    // Start HTTP server
    const server = app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`, {
        environment: process.env.NODE_ENV || 'development',
        port: PORT,
        nodeVersion: process.version,
        pid: process.pid
      });
    });
    
    // Graceful shutdown handlers
    const shutdown = gracefulShutdown(server);
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    
    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${PORT} is already in use`);
      } else {
        logger.error('Server error:', error);
      }
      process.exit(1);
    });
    
    return server;
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Close server & exit process
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Start the server
if (require.main === module) {
  startServer();
}

module.exports = app;