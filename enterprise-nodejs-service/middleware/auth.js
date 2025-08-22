const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const logger = require('../utils/logger');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');

// OAuth2 clients
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Rate limiting configurations
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later',
    error: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const refreshRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 refresh requests per windowMs
  message: {
    success: false,
    message: 'Too many token refresh attempts, please try again later',
    error: 'REFRESH_RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Token blacklist (in production, use Redis)
const tokenBlacklist = new Set();

/**
 * Middleware to authenticate JWT tokens
 * Expects Authorization header with Bearer token
 */
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;

    if (!token) {
      logger.logSecurity('MISSING_TOKEN', 'No JWT token provided', req);
      return res.status(401).json({
        success: false,
        message: 'Access token is required',
        error: 'MISSING_TOKEN'
      });
    }

    // Verify JWT secret is configured
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      logger.error('JWT_SECRET environment variable is not configured');
      return res.status(500).json({
        success: false,
        message: 'Server configuration error',
        error: 'MISSING_JWT_SECRET'
      });
    }

    // Verify and decode the token
    const decoded = jwt.verify(token, jwtSecret, {
      algorithms: ['HS256'], // Only allow secure algorithm
      issuer: 'enterprise-service',
      maxAge: process.env.JWT_EXPIRES_IN || '15m'
    });

    // Validate token payload structure
    if (!decoded.userId || !decoded.email) {
      logger.logSecurity('INVALID_TOKEN_PAYLOAD', 'Token missing required fields', req);
      return res.status(401).json({
        success: false,
        message: 'Invalid token format',
        error: 'INVALID_TOKEN_PAYLOAD'
      });
    }

    // Fetch user from database to ensure they still exist and are active
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      logger.logSecurity('USER_NOT_FOUND', `User ${decoded.userId} not found`, req);
      return res.status(401).json({
        success: false,
        message: 'User not found',
        error: 'USER_NOT_FOUND'
      });
    }

    if (!user.is_active) {
      logger.logSecurity('INACTIVE_USER', `Inactive user ${user.email} attempted access`, req);
      return res.status(401).json({
        success: false,
        message: 'User account is inactive',
        error: 'INACTIVE_USER'
      });
    }

    if (user.isAccountLocked()) {
      logger.logSecurity('LOCKED_USER', `Locked user ${user.email} attempted access`, req);
      return res.status(401).json({
        success: false,
        message: 'User account is temporarily locked',
        error: 'LOCKED_USER'
      });
    }

    // Verify email matches (additional security check)
    if (user.email !== decoded.email) {
      logger.logSecurity('EMAIL_MISMATCH', `Token email mismatch for user ${user.email}`, req);
      return res.status(401).json({
        success: false,
        message: 'Token validation failed',
        error: 'EMAIL_MISMATCH'
      });
    }

    // Attach user to request object
    req.user = user;
    req.tokenPayload = decoded;

    logger.info('User authenticated successfully', {
      userId: user.id,
      email: user.email,
      role: user.role
    });

    next();
  } catch (error) {
    let errorMessage = 'Token validation failed';
    let errorCode = 'TOKEN_VALIDATION_FAILED';

    if (error.name === 'JsonWebTokenError') {
      errorMessage = 'Invalid token';
      errorCode = 'INVALID_TOKEN';
    } else if (error.name === 'TokenExpiredError') {
      errorMessage = 'Token has expired';
      errorCode = 'TOKEN_EXPIRED';
    } else if (error.name === 'NotBeforeError') {
      errorMessage = 'Token not active yet';
      errorCode = 'TOKEN_NOT_ACTIVE';
    }

    logger.logSecurity('TOKEN_VALIDATION_ERROR', {
      error: error.message,
      name: error.name,
      code: errorCode
    }, req);

    return res.status(401).json({
      success: false,
      message: errorMessage,
      error: errorCode
    });
  }
};

/**
 * Middleware to require admin role
 * Must be used after authenticateToken middleware
 */
const requireAdmin = (req, res, next) => {
  try {
    if (!req.user) {
      logger.error('requireAdmin middleware called without authentication');
      return res.status(500).json({
        success: false,
        message: 'Server configuration error',
        error: 'MISSING_AUTHENTICATION'
      });
    }

    if (!req.user.isAdmin()) {
      logger.logSecurity('UNAUTHORIZED_ADMIN_ACCESS', `User ${req.user.email} attempted admin access`, req);
      return res.status(403).json({
        success: false,
        message: 'Admin access required',
        error: 'INSUFFICIENT_PRIVILEGES'
      });
    }

    logger.info('Admin access granted', {
      userId: req.user.id,
      email: req.user.email
    });

    next();
  } catch (error) {
    logger.error('Error in requireAdmin middleware:', error);
    return res.status(500).json({
      success: false,
      message: 'Authorization check failed',
      error: 'AUTHORIZATION_ERROR'
    });
  }
};

/**
 * Middleware to optionally authenticate token
 * Continues even if no token is provided
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;

    if (!token) {
      return next();
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      return next();
    }

    const decoded = jwt.verify(token, jwtSecret, {
      algorithms: ['HS256'],
      issuer: 'enterprise-service'
    });

    const user = await User.findById(decoded.userId);
    
    if (user && user.is_active && !user.isAccountLocked()) {
      req.user = user;
      req.tokenPayload = decoded;
    }

    next();
  } catch (error) {
    // Silently continue without authentication
    next();
  }
};

/**
 * Generate JWT access and refresh tokens for user
 */
const generateTokens = (user) => {
  try {
    const jwtSecret = process.env.JWT_SECRET;
    const refreshSecret = process.env.JWT_REFRESH_SECRET;
    
    if (!jwtSecret || !refreshSecret) {
      throw new Error('JWT secrets are required');
    }

    const tokenId = crypto.randomUUID();
    const sessionId = crypto.randomUUID();

    // Access token payload
    const accessPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      tokenId,
      sessionId,
      type: 'access',
      iat: Math.floor(Date.now() / 1000),
      iss: 'enterprise-service'
    };

    // Refresh token payload
    const refreshPayload = {
      userId: user.id,
      email: user.email,
      tokenId,
      sessionId,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000),
      iss: 'enterprise-service'
    };

    const accessToken = jwt.sign(accessPayload, jwtSecret, {
      expiresIn: process.env.JWT_EXPIRES_IN || '15m',
      algorithm: 'HS256',
      issuer: 'enterprise-service'
    });

    const refreshToken = jwt.sign(refreshPayload, refreshSecret, {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
      algorithm: 'HS256',
      issuer: 'enterprise-service'
    });
    
    logger.info('JWT tokens generated', {
      userId: user.id,
      email: user.email,
      tokenId,
      sessionId
    });

    return {
      accessToken,
      refreshToken,
      tokenId,
      sessionId,
      expiresIn: process.env.JWT_EXPIRES_IN || '15m'
    };
  } catch (error) {
    logger.error('Error generating JWT tokens:', error);
    throw error;
  }
};

/**
 * Generate JWT token for user (legacy support)
 */
const generateToken = (user) => {
  const tokens = generateTokens(user);
  return tokens.accessToken;
};

/**
 * Verify JWT token without middleware context
 */
const verifyToken = (token) => {
  try {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error('JWT_SECRET environment variable is required');
    }

    return jwt.verify(token, jwtSecret, {
      algorithms: ['HS256'],
      issuer: 'enterprise-service'
    });
  } catch (error) {
    logger.error('Error verifying JWT token:', error);
    throw error;
  }
};

/**
 * Refresh JWT tokens
 */
const refreshTokens = async (refreshToken) => {
  try {
    const refreshSecret = process.env.JWT_REFRESH_SECRET;
    if (!refreshSecret) {
      throw new Error('JWT_REFRESH_SECRET environment variable is required');
    }

    // Check if token is blacklisted
    if (tokenBlacklist.has(refreshToken)) {
      throw new Error('Token has been revoked');
    }

    const decoded = jwt.verify(refreshToken, refreshSecret, {
      algorithms: ['HS256'],
      issuer: 'enterprise-service'
    });

    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    const user = await User.findById(decoded.userId);
    if (!user || !user.is_active || user.isAccountLocked()) {
      throw new Error('User not found or inactive');
    }

    // Blacklist the old refresh token
    tokenBlacklist.add(refreshToken);

    // Generate new tokens
    const tokens = generateTokens(user);
    
    logger.info('Tokens refreshed successfully', {
      userId: user.id,
      email: user.email,
      oldTokenId: decoded.tokenId,
      newTokenId: tokens.tokenId
    });

    return tokens;
  } catch (error) {
    logger.error('Error refreshing tokens:', error);
    throw error;
  }
};

/**
 * Revoke tokens (logout)
 */
const revokeTokens = (accessToken, refreshToken) => {
  try {
    if (accessToken) tokenBlacklist.add(accessToken);
    if (refreshToken) tokenBlacklist.add(refreshToken);
    
    logger.info('Tokens revoked successfully');
  } catch (error) {
    logger.error('Error revoking tokens:', error);
    throw error;
  }
};

/**
 * Verify Google OAuth2 token
 */
const verifyGoogleToken = async (idToken) => {
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    return {
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      emailVerified: payload.email_verified,
      provider: 'google'
    };
  } catch (error) {
    logger.error('Error verifying Google token:', error);
    throw error;
  }
};

/**
 * Verify GitHub OAuth2 token
 */
const verifyGitHubToken = async (accessToken) => {
  try {
    const response = await axios.get('https://api.github.com/user', {
      headers: {
        'Authorization': `token ${accessToken}`,
        'User-Agent': 'CodeSaviour-App'
      }
    });
    
    const emailResponse = await axios.get('https://api.github.com/user/emails', {
      headers: {
        'Authorization': `token ${accessToken}`,
        'User-Agent': 'CodeSaviour-App'
      }
    });
    
    const primaryEmail = emailResponse.data.find(email => email.primary);
    
    return {
      email: primaryEmail?.email,
      name: response.data.name || response.data.login,
      picture: response.data.avatar_url,
      emailVerified: primaryEmail?.verified || false,
      provider: 'github'
    };
  } catch (error) {
    logger.error('Error verifying GitHub token:', error);
    throw error;
  }
};

/**
 * API versioning middleware
 */
const apiVersion = (version) => {
  return (req, res, next) => {
    req.apiVersion = version;
    res.setHeader('API-Version', version);
    next();
  };
};

/**
 * Audit logging middleware
 */
const auditLog = (action) => {
  return (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
      // Log the audit event
      logger.info('AUDIT_LOG', {
        action,
        userId: req.user?.id,
        email: req.user?.email,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        timestamp: new Date().toISOString(),
        requestId: req.id || crypto.randomUUID()
      });
      
      originalSend.call(this, data);
    };
    
    next();
  };
};

module.exports = {
  authenticateToken,
  requireAdmin,
  optionalAuth,
  generateToken,
  generateTokens,
  refreshTokens,
  revokeTokens,
  verifyToken,
  verifyGoogleToken,
  verifyGitHubToken,
  authRateLimit,
  refreshRateLimit,
  apiVersion,
  auditLog,
  tokenBlacklist
};