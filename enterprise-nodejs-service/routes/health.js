const express = require('express');
const { databaseManager } = require('../config/database');
const { catchAsync } = require('../middleware/errorHandler');
const logger = require('../utils/logger');
const packageJson = require('../package.json');

const router = express.Router();

/**
 * @route   GET /api/health
 * @desc    Basic health check endpoint
 * @access  Public
 */
router.get('/', catchAsync(async (req, res) => {
  const healthCheck = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    service: 'Enterprise Node.js Service',
    version: packageJson.version,
    environment: process.env.NODE_ENV || 'development'
  };

  res.json({
    success: true,
    message: 'Service is healthy',
    data: healthCheck
  });
}));

/**
 * @route   GET /api/health/detailed
 * @desc    Detailed health check with database and system info
 * @access  Public
 */
router.get('/detailed', catchAsync(async (req, res) => {
  const startTime = Date.now();
  
  // Get database health
  const dbHealth = await databaseManager.healthCheck();
  
  // Get system information
  const systemInfo = {
    nodeVersion: process.version,
    platform: process.platform,
    architecture: process.arch,
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024 * 100) / 100,
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024 * 100) / 100,
      external: Math.round(process.memoryUsage().external / 1024 / 1024 * 100) / 100,
      rss: Math.round(process.memoryUsage().rss / 1024 / 1024 * 100) / 100
    },
    uptime: {
      process: process.uptime(),
      system: require('os').uptime()
    },
    loadAverage: require('os').loadavg(),
    cpus: require('os').cpus().length
  };

  // Calculate response time
  const responseTime = Date.now() - startTime;

  // Determine overall health status
  let overallStatus = 'healthy';
  let statusCode = 200;
  
  if (dbHealth.status === 'error' || dbHealth.status === 'disconnected') {
    overallStatus = 'unhealthy';
    statusCode = 503;
  } else if (responseTime > 5000) { // If response takes more than 5 seconds
    overallStatus = 'degraded';
    statusCode = 200;
  }

  const healthCheck = {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    responseTime: `${responseTime}ms`,
    service: {
      name: 'Enterprise Node.js Service',
      version: packageJson.version,
      environment: process.env.NODE_ENV || 'development',
      port: process.env.PORT || 3000
    },
    database: dbHealth,
    system: systemInfo,
    dependencies: {
      express: packageJson.dependencies.express,
      pg: packageJson.dependencies.pg,
      jsonwebtoken: packageJson.dependencies.jsonwebtoken,
      bcrypt: packageJson.dependencies.bcrypt
    }
  };

  // Log health check if there are issues
  if (overallStatus !== 'healthy') {
    logger.warn('Health check detected issues', {
      status: overallStatus,
      responseTime,
      dbStatus: dbHealth.status,
      memoryUsage: systemInfo.memory
    });
  }

  res.status(statusCode).json({
    success: overallStatus === 'healthy',
    message: `Service is ${overallStatus}`,
    data: healthCheck
  });
}));

/**
 * @route   GET /api/health/database
 * @desc    Database-specific health check
 * @access  Public
 */
router.get('/database', catchAsync(async (req, res) => {
  const startTime = Date.now();
  
  // Get database health
  const dbHealth = await databaseManager.healthCheck();
  const responseTime = Date.now() - startTime;
  
  // Get database statistics if connected
  let dbStats = null;
  if (dbHealth.status === 'connected') {
    try {
      dbStats = await databaseManager.getStats();
    } catch (error) {
      logger.error('Error getting database stats:', error);
    }
  }

  const healthCheck = {
    status: dbHealth.status,
    message: dbHealth.message,
    timestamp: new Date().toISOString(),
    responseTime: `${responseTime}ms`,
    connection: connectionStatus,
    details: dbHealth.details,
    statistics: dbStats ? {
      collections: dbStats.collections,
      documents: dbStats.objects,
      dataSize: `${Math.round(dbStats.dataSize / 1024 / 1024 * 100) / 100} MB`,
      storageSize: `${Math.round(dbStats.storageSize / 1024 / 1024 * 100) / 100} MB`,
      indexSize: `${Math.round(dbStats.indexSize / 1024 / 1024 * 100) / 100} MB`,
      indexes: dbStats.indexes
    } : null
  };

  const statusCode = dbHealth.status === 'connected' ? 200 : 503;
  
  res.status(statusCode).json({
    success: dbHealth.status === 'connected',
    message: dbHealth.message,
    data: healthCheck
  });
}));

/**
 * @route   GET /api/health/readiness
 * @desc    Kubernetes readiness probe endpoint
 * @access  Public
 */
router.get('/readiness', catchAsync(async (req, res) => {
  const dbHealth = await db.healthCheck();
  
  // Service is ready if database is connected
  const isReady = dbHealth.status === 'connected';
  
  const readinessCheck = {
    ready: isReady,
    timestamp: new Date().toISOString(),
    checks: {
      database: dbHealth.status === 'connected'
    }
  };

  const statusCode = isReady ? 200 : 503;
  
  res.status(statusCode).json({
    success: isReady,
    message: isReady ? 'Service is ready' : 'Service is not ready',
    data: readinessCheck
  });
}));

/**
 * @route   GET /api/health/liveness
 * @desc    Kubernetes liveness probe endpoint
 * @access  Public
 */
router.get('/liveness', catchAsync(async (req, res) => {
  // Simple liveness check - if we can respond, we're alive
  const livenessCheck = {
    alive: true,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    pid: process.pid
  };

  res.json({
    success: true,
    message: 'Service is alive',
    data: livenessCheck
  });
}));

/**
 * @route   GET /api/health/metrics
 * @desc    Basic metrics endpoint
 * @access  Public
 */
router.get('/metrics', catchAsync(async (req, res) => {
  const memUsage = process.memoryUsage();
  const cpuUsage = process.cpuUsage();
  
  const metrics = {
    timestamp: new Date().toISOString(),
    process: {
      pid: process.pid,
      uptime: process.uptime(),
      version: process.version,
      platform: process.platform,
      arch: process.arch
    },
    memory: {
      rss: Math.round(memUsage.rss / 1024 / 1024 * 100) / 100, // MB
      heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024 * 100) / 100, // MB
      heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024 * 100) / 100, // MB
      external: Math.round(memUsage.external / 1024 / 1024 * 100) / 100, // MB
      arrayBuffers: Math.round(memUsage.arrayBuffers / 1024 / 1024 * 100) / 100 // MB
    },
    cpu: {
      user: cpuUsage.user,
      system: cpuUsage.system
    },
    system: {
      loadAverage: require('os').loadavg(),
      totalMemory: Math.round(require('os').totalmem() / 1024 / 1024 / 1024 * 100) / 100, // GB
      freeMemory: Math.round(require('os').freemem() / 1024 / 1024 / 1024 * 100) / 100, // GB
      uptime: require('os').uptime(),
      cpus: require('os').cpus().length
    },
    database: db.getConnectionStatus()
  };

  res.json({
    success: true,
    message: 'Metrics retrieved successfully',
    data: metrics
  });
}));

/**
 * @route   GET /api/health/version
 * @desc    Service version information
 * @access  Public
 */
router.get('/version', catchAsync(async (req, res) => {
  const versionInfo = {
    service: packageJson.name,
    version: packageJson.version,
    description: packageJson.description,
    author: packageJson.author,
    license: packageJson.license,
    repository: packageJson.repository,
    engines: packageJson.engines,
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version,
    timestamp: new Date().toISOString()
  };

  res.json({
    success: true,
    message: 'Version information retrieved successfully',
    data: versionInfo
  });
}));

module.exports = router;