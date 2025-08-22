const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define log levels
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4
};

// Define log colors
const logColors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue'
};

// Add colors to winston
winston.addColors(logColors);

// Custom format for console output
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.colorize({ all: true }),
  winston.format.printf((info) => {
    const { timestamp, level, message, ...meta } = info;
    const metaString = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
    return `${timestamp} [${level}]: ${message} ${metaString}`;
  })
);

// Custom format for file output
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create transports array
const transports = [
  // Console transport
  new winston.transports.Console({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    format: consoleFormat,
    handleExceptions: true,
    handleRejections: true
  }),

  // File transport for all logs
  new winston.transports.File({
    filename: path.join(logsDir, 'app.log'),
    level: 'info',
    format: fileFormat,
    maxsize: 10485760, // 10MB
    maxFiles: 5,
    handleExceptions: true,
    handleRejections: true
  }),

  // File transport for error logs only
  new winston.transports.File({
    filename: path.join(logsDir, 'error.log'),
    level: 'error',
    format: fileFormat,
    maxsize: 10485760, // 10MB
    maxFiles: 5,
    handleExceptions: true,
    handleRejections: true
  })
];

// Add HTTP access log transport in production
if (process.env.NODE_ENV === 'production') {
  transports.push(
    new winston.transports.File({
      filename: path.join(logsDir, 'access.log'),
      level: 'http',
      format: fileFormat,
      maxsize: 10485760, // 10MB
      maxFiles: 10
    })
  );
}

// Create the logger
const logger = winston.createLogger({
  levels: logLevels,
  level: process.env.LOG_LEVEL || 'info',
  format: fileFormat,
  transports,
  exitOnError: false
});

// Create a stream object for Morgan HTTP logging
logger.stream = {
  write: (message) => {
    logger.http(message.trim());
  }
};

// Add custom methods for structured logging
logger.logRequest = (req, res, responseTime) => {
  const logData = {
    method: req.method,
    url: req.originalUrl,
    statusCode: res.statusCode,
    responseTime: `${responseTime}ms`,
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress,
    userId: req.user ? req.user.id : null
  };

  if (res.statusCode >= 400) {
    logger.warn('HTTP Request', logData);
  } else {
    logger.http('HTTP Request', logData);
  }
};

logger.logError = (error, req = null) => {
  const errorData = {
    message: error.message,
    stack: error.stack,
    name: error.name
  };

  if (req) {
    errorData.request = {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      body: req.body,
      params: req.params,
      query: req.query,
      ip: req.ip || req.connection.remoteAddress,
      userId: req.user ? req.user.id : null
    };
  }

  logger.error('Application Error', errorData);
};

logger.logSecurity = (event, details, req = null) => {
  const securityData = {
    event,
    details,
    timestamp: new Date().toISOString()
  };

  if (req) {
    securityData.request = {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      userId: req.user ? req.user.id : null
    };
  }

  logger.warn('Security Event', securityData);
};

logger.logAuth = (action, email, success, details = {}, req = null) => {
  const authData = {
    action,
    email,
    success,
    details,
    timestamp: new Date().toISOString()
  };

  if (req) {
    authData.request = {
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    };
  }

  if (success) {
    logger.info('Authentication Event', authData);
  } else {
    logger.warn('Authentication Event', authData);
  }
};

// Handle uncaught exceptions and unhandled rejections
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', {
    message: error.message,
    stack: error.stack,
    name: error.name
  });
  
  // Give winston time to write the log
  setTimeout(() => {
    process.exit(1);
  }, 1000);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', {
    reason: reason instanceof Error ? reason.message : reason,
    stack: reason instanceof Error ? reason.stack : null,
    promise: promise.toString()
  });
});

// Log startup information
logger.info('Logger initialized', {
  level: logger.level,
  environment: process.env.NODE_ENV || 'development',
  logsDirectory: logsDir
});

module.exports = logger;