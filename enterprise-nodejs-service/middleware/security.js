const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { AuditService, auditService, auditLogger } = require('../services/auditService');
const validator = require('validator');

// Rate limiting configurations
const createRateLimit = (windowMs, max, message, skipSuccessfulRequests = false) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      error: 'Too many requests',
      message,
      retryAfter: Math.ceil(windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    handler: async (req, res) => {
      // Log rate limit violation
      const clientIP = AuditService.getClientIP(req);
      await auditLogger.logSecurityViolation(
        req.user?.id || null,
        {
          type: 'RATE_LIMIT_EXCEEDED',
          endpoint: req.path,
          method: req.method,
          limit: max,
          windowMs
        },
        clientIP,
        req.get('User-Agent')
      );
      
      res.status(429).json({
        error: 'Too many requests',
        message,
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });
};

// Different rate limits for different endpoints
const rateLimits = {
  // Strict rate limiting for authentication endpoints
  auth: createRateLimit(
    15 * 60 * 1000, // 15 minutes
    5, // 5 attempts
    'Too many authentication attempts, please try again later',
    true
  ),
  
  // Moderate rate limiting for API endpoints
  api: createRateLimit(
    15 * 60 * 1000, // 15 minutes
    100, // 100 requests
    'Too many API requests, please try again later'
  ),
  
  // Lenient rate limiting for general endpoints
  general: createRateLimit(
    15 * 60 * 1000, // 15 minutes
    200, // 200 requests
    'Too many requests, please try again later'
  ),
  
  // Very strict for password reset
  passwordReset: createRateLimit(
    60 * 60 * 1000, // 1 hour
    3, // 3 attempts
    'Too many password reset attempts, please try again later'
  )
};

// Security headers middleware
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
  const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }
    
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        // Remove potential XSS and SQL injection patterns
        sanitized[key] = validator.escape(value.trim());
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = sanitizeObject(value);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  };
  
  // Sanitize request body
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeObject(req.body);
  }
  
  // Sanitize query parameters
  if (req.query && typeof req.query === 'object') {
    req.query = sanitizeObject(req.query);
  }
  
  next();
};

// IP whitelist/blacklist middleware
const ipFilter = (req, res, next) => {
  const clientIP = AuditService.getClientIP(req);
  
  // Check if IP is in blacklist (you can store this in database or config)
  const blacklistedIPs = process.env.BLACKLISTED_IPS ? 
    process.env.BLACKLISTED_IPS.split(',') : [];
  
  if (blacklistedIPs.includes(clientIP)) {
    auditLogger.logSecurityViolation(
      null,
      {
        type: 'BLACKLISTED_IP_ACCESS',
        clientIP
      },
      clientIP,
      req.get('User-Agent')
    );
    
    return res.status(403).json({
      error: 'Access denied',
      message: 'Your IP address has been blocked'
    });
  }
  
  next();
};

// Request size limiter
const requestSizeLimit = (maxSize = '10mb') => {
  return (req, res, next) => {
    const contentLength = parseInt(req.get('Content-Length') || '0');
    const maxBytes = parseSize(maxSize);
    
    if (contentLength > maxBytes) {
      const clientIP = AuditService.getClientIP(req);
      auditLogger.logSecurityViolation(
        req.user?.id || null,
        {
          type: 'REQUEST_SIZE_EXCEEDED',
          contentLength,
          maxBytes
        },
        clientIP,
        req.get('User-Agent')
      );
      
      return res.status(413).json({
        error: 'Request too large',
        message: `Request size exceeds ${maxSize} limit`
      });
    }
    
    next();
  };
};

// Helper function to parse size strings
function parseSize(size) {
  const units = {
    'b': 1,
    'kb': 1024,
    'mb': 1024 * 1024,
    'gb': 1024 * 1024 * 1024
  };
  
  const match = size.toLowerCase().match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/);
  if (!match) return 0;
  
  const value = parseFloat(match[1]);
  const unit = match[2] || 'b';
  
  return Math.floor(value * units[unit]);
}

// Suspicious activity detector
const suspiciousActivityDetector = async (req, res, next) => {
  const clientIP = AuditService.getClientIP(req);
  const userAgent = req.get('User-Agent') || '';
  
  // Check for suspicious patterns
  const suspiciousPatterns = [
    /bot|crawler|spider|scraper/i,
    /sqlmap|nmap|nikto|burp|owasp/i,
    /script|javascript|vbscript/i
  ];
  
  const isSuspicious = suspiciousPatterns.some(pattern => 
    pattern.test(userAgent) || pattern.test(req.path)
  );
  
  if (isSuspicious) {
    await auditLogger.logSecurityViolation(
      req.user?.id || null,
      {
        type: 'SUSPICIOUS_ACTIVITY',
        userAgent,
        path: req.path,
        method: req.method
      },
      clientIP,
      userAgent
    );
    
    // Don't block immediately, but log for monitoring
    // You can implement auto-blocking based on frequency
  }
  
  next();
};

// CORS configuration
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = process.env.ALLOWED_ORIGINS ? 
      process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'];
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-API-Version',
    'X-Session-ID'
  ]
};

// API versioning middleware
const apiVersioning = (supportedVersions = ['v1']) => {
  return (req, res, next) => {
    const version = req.headers['x-api-version'] || 
                   req.query.version || 
                   req.params.version || 
                   'v1';
    
    if (!supportedVersions.includes(version)) {
      return res.status(400).json({
        error: 'Unsupported API version',
        message: `Supported versions: ${supportedVersions.join(', ')}`,
        requestedVersion: version
      });
    }
    
    req.apiVersion = version;
    res.set('X-API-Version', version);
    next();
  };
};

// Request logging middleware
const requestLogger = async (req, res, next) => {
  const start = Date.now();
  
  // Log the request
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - start;
    const statusCode = res.statusCode;
    
    // Log API access
    const clientIP = AuditService.getClientIP(req);
    auditLogger.logApiAccess(
      req.user?.id || null,
      `${req.method} ${req.path}`,
      clientIP,
      req.get('User-Agent'),
      statusCode < 400
    ).catch(err => {
      console.error('Failed to log API access:', err);
    });
    
    originalSend.call(this, data);
  };
  
  next();
};

// Security middleware factory
const createSecurityMiddleware = (options = {}) => {
  const middlewares = [];
  
  // Always include basic security
  middlewares.push(securityHeaders);
  middlewares.push(ipFilter);
  middlewares.push(suspiciousActivityDetector);
  
  // Optional middlewares based on options
  if (options.rateLimit) {
    middlewares.push(rateLimits[options.rateLimit] || rateLimits.general);
  }
  
  if (options.sanitizeInput !== false) {
    middlewares.push(sanitizeInput);
  }
  
  if (options.requestSizeLimit) {
    middlewares.push(requestSizeLimit(options.requestSizeLimit));
  }
  
  if (options.apiVersioning) {
    middlewares.push(apiVersioning(options.supportedVersions));
  }
  
  if (options.requestLogging !== false) {
    middlewares.push(requestLogger);
  }
  
  return middlewares;
};

module.exports = {
  rateLimits,
  securityHeaders,
  sanitizeInput,
  ipFilter,
  requestSizeLimit,
  suspiciousActivityDetector,
  corsOptions,
  apiVersioning,
  requestLogger,
  createSecurityMiddleware
};