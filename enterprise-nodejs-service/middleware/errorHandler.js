const logger = require('../utils/logger');

/**
 * Development error response
 */
const sendErrorDev = (err, req, res) => {
  const error = {
    success: false,
    message: err.message,
    error: {
      status: err.status,
      statusCode: err.statusCode,
      name: err.name,
      stack: err.stack,
      details: err.details || null
    },
    request: {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      body: req.body,
      params: req.params,
      query: req.query
    },
    timestamp: new Date().toISOString()
  };

  res.status(err.statusCode || 500).json(error);
};

/**
 * Production error response
 */
const sendErrorProd = (err, req, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    const error = {
      success: false,
      message: err.message,
      error: err.code || 'OPERATIONAL_ERROR',
      timestamp: new Date().toISOString()
    };
    
    return res.status(err.statusCode || 500).json(error);
  }

  // Programming or other unknown error: don't leak error details
  const error = {
    success: false,
    message: 'Something went wrong on our end. Please try again later.',
    error: 'INTERNAL_SERVER_ERROR',
    timestamp: new Date().toISOString()
  };

  res.status(500).json(error);
};

/**
 * Handle MongoDB cast errors
 */
const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return createAppError(message, 400, 'INVALID_DATA', true);
};

/**
 * Handle MongoDB duplicate field errors
 */
const handleDuplicateFieldsDB = (err) => {
  const field = Object.keys(err.keyValue)[0];
  const value = err.keyValue[field];
  const message = `${field.charAt(0).toUpperCase() + field.slice(1)} '${value}' already exists`;
  return createAppError(message, 409, 'DUPLICATE_FIELD', true);
};

/**
 * Handle MongoDB validation errors
 */
const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid input data: ${errors.join('. ')}`;
  return createAppError(message, 400, 'VALIDATION_ERROR', true);
};

/**
 * Handle JWT errors
 */
const handleJWTError = () => {
  return createAppError('Invalid token. Please log in again.', 401, 'INVALID_TOKEN', true);
};

/**
 * Handle JWT expired errors
 */
const handleJWTExpiredError = () => {
  return createAppError('Your token has expired. Please log in again.', 401, 'TOKEN_EXPIRED', true);
};

/**
 * Handle rate limit errors
 */
const handleRateLimitError = () => {
  return createAppError('Too many requests. Please try again later.', 429, 'RATE_LIMIT_EXCEEDED', true);
};

/**
 * Create application error
 */
const createAppError = (message, statusCode, code, isOperational = true) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
  error.isOperational = isOperational;
  error.code = code;
  return error;
};

/**
 * Async error wrapper
 */
const catchAsync = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Global error handling middleware
 */
const globalErrorHandler = (err, req, res, next) => {
  // Set default values
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  // Log the error
  logger.logError(err, req);

  // Create error copy for manipulation
  let error = { ...err };
  error.message = err.message;
  error.name = err.name;
  error.stack = err.stack;

  // Handle specific error types
  if (error.name === 'CastError') {
    error = handleCastErrorDB(error);
  }
  
  if (error.code === 11000) {
    error = handleDuplicateFieldsDB(error);
  }
  
  if (error.name === 'ValidationError') {
    error = handleValidationErrorDB(error);
  }
  
  if (error.name === 'JsonWebTokenError') {
    error = handleJWTError();
  }
  
  if (error.name === 'TokenExpiredError') {
    error = handleJWTExpiredError();
  }
  
  if (error.type === 'entity.too.large') {
    error = createAppError('Request entity too large', 413, 'PAYLOAD_TOO_LARGE', true);
  }
  
  if (error.code === 'LIMIT_FILE_SIZE') {
    error = createAppError('File too large', 413, 'FILE_TOO_LARGE', true);
  }
  
  if (error.code === 'EBADCSRFTOKEN') {
    error = createAppError('Invalid CSRF token', 403, 'INVALID_CSRF_TOKEN', true);
  }

  // Handle rate limiting errors
  if (err.statusCode === 429 || err.code === 'RATE_LIMIT_EXCEEDED') {
    error = handleRateLimitError();
  }

  // Send error response based on environment
  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(error, req, res);
  } else {
    sendErrorProd(error, req, res);
  }
};

/**
 * Handle 404 errors for undefined routes
 */
const notFoundHandler = (req, res, next) => {
  const message = `Route ${req.originalUrl} not found`;
  const error = createAppError(message, 404, 'ROUTE_NOT_FOUND', true);
  
  logger.logSecurity('ROUTE_NOT_FOUND', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip
  }, req);
  
  next(error);
};

/**
 * Validation error formatter
 */
const formatValidationErrors = (errors) => {
  const formatted = {};
  
  errors.forEach(error => {
    const field = error.param || error.path || 'unknown';
    if (!formatted[field]) {
      formatted[field] = [];
    }
    formatted[field].push(error.msg || error.message);
  });
  
  return formatted;
};

/**
 * Express-validator error handler
 */
const handleValidationResult = (req, res, next) => {
  const { validationResult } = require('express-validator');
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const formattedErrors = formatValidationErrors(errors.array());
    
    logger.logSecurity('VALIDATION_ERROR', {
      errors: formattedErrors,
      body: req.body,
      params: req.params,
      query: req.query
    }, req);
    
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      error: 'VALIDATION_ERROR',
      details: formattedErrors,
      timestamp: new Date().toISOString()
    });
  }
  
  next();
};

/**
 * Graceful shutdown handler
 */
const gracefulShutdown = (server) => {
  return (signal) => {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);
    
    server.close((err) => {
      if (err) {
        logger.error('Error during server shutdown:', err);
        process.exit(1);
      }
      
      logger.info('Server closed successfully');
      process.exit(0);
    });
    
    // Force close after 30 seconds
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
  };
};

module.exports = {
  globalErrorHandler,
  notFoundHandler,
  catchAsync,
  createAppError,
  handleValidationResult,
  formatValidationErrors,
  gracefulShutdown
};