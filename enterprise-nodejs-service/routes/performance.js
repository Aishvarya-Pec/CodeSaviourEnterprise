const express = require('express');
const router = express.Router();
const { authenticateToken, requireAdmin } = require('../middleware/auth');
const { rateLimits } = require('../middleware/security');
const { getMetrics, healthCheck } = require('../middleware/performance');
const { databaseManager } = require('../config/database');
const logger = require('../utils/logger');
const { AuditService } = require('../services/auditService');

/**
 * @route GET /api/performance/metrics
 * @desc Get comprehensive performance metrics
 * @access Admin only
 */
router.get('/metrics', 
  rateLimits.api,
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      // Log access
      await AuditService.log({
        userId: req.user.id,
        action: 'VIEW_PERFORMANCE_METRICS',
        resource: 'performance',
        details: {
          endpoint: '/api/performance/metrics',
          userAgent: req.get('User-Agent'),
          ip: req.ip
        },
        success: true
      });

      // Get application metrics
      const appMetrics = getMetrics(req, res);
      
      // If response was already sent by getMetrics, return
      if (res.headersSent) {
        return;
      }

      res.json(appMetrics);
    } catch (error) {
      logger.error('Failed to get performance metrics', { 
        error: error.message,
        userId: req.user?.id 
      });
      
      await AuditService.log({
        userId: req.user?.id,
        action: 'VIEW_PERFORMANCE_METRICS',
        resource: 'performance',
        details: {
          endpoint: '/api/performance/metrics',
          error: error.message
        },
        success: false
      });

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve performance metrics',
        error: error.message
      });
    }
  }
);

/**
 * @route GET /api/performance/database
 * @desc Get database performance metrics
 * @access Admin only
 */
router.get('/database',
  rateLimits.api,
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      // Log access
      await AuditService.log({
        userId: req.user.id,
        action: 'VIEW_DATABASE_METRICS',
        resource: 'database',
        details: {
          endpoint: '/api/performance/database',
          userAgent: req.get('User-Agent'),
          ip: req.ip
        },
        success: true
      });

      const dbMetrics = await databaseManager.getPerformanceMetrics();
      const connectionInfo = databaseManager.getConnectionInfo();
      const healthStatus = await databaseManager.healthCheck();

      res.json({
        success: true,
        message: 'Database performance metrics retrieved successfully',
        data: {
          metrics: dbMetrics,
          connection: connectionInfo,
          health: healthStatus,
          timestamp: new Date().toISOString()
        }
      });
    } catch (error) {
      logger.error('Failed to get database performance metrics', { 
        error: error.message,
        userId: req.user?.id 
      });
      
      await AuditService.log({
        userId: req.user?.id,
        action: 'VIEW_DATABASE_METRICS',
        resource: 'database',
        details: {
          endpoint: '/api/performance/database',
          error: error.message
        },
        success: false
      });

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve database performance metrics',
        error: error.message
      });
    }
  }
);

/**
 * @route GET /api/performance/health
 * @desc Get comprehensive health check with performance data
 * @access Public (for monitoring systems)
 */
router.get('/health', 
  rateLimits.general,
  async (req, res) => {
    try {
      // Use the health check from performance middleware
      await healthCheck(req, res);
    } catch (error) {
      logger.error('Health check failed', { error: error.message });
      res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error.message
      });
    }
  }
);

/**
 * @route GET /api/performance/system
 * @desc Get system-level performance metrics
 * @access Admin only
 */
router.get('/system',
  rateLimits.api,
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      // Log access
      await AuditService.log({
        userId: req.user.id,
        action: 'VIEW_SYSTEM_METRICS',
        resource: 'system',
        details: {
          endpoint: '/api/performance/system',
          userAgent: req.get('User-Agent'),
          ip: req.ip
        },
        success: true
      });

      const { performanceMonitor } = require('../middleware/performance');
      const metrics = performanceMonitor.getMetrics();

      res.json({
        success: true,
        message: 'System performance metrics retrieved successfully',
        data: {
          system: metrics.system,
          uptime: metrics.uptime,
          timestamp: metrics.timestamp
        }
      });
    } catch (error) {
      logger.error('Failed to get system performance metrics', { 
        error: error.message,
        userId: req.user?.id 
      });
      
      await AuditService.log({
        userId: req.user?.id,
        action: 'VIEW_SYSTEM_METRICS',
        resource: 'system',
        details: {
          endpoint: '/api/performance/system',
          error: error.message
        },
        success: false
      });

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve system performance metrics',
        error: error.message
      });
    }
  }
);

/**
 * @route GET /api/performance/endpoints
 * @desc Get endpoint-specific performance metrics
 * @access Admin only
 */
router.get('/endpoints',
  rateLimits.api,
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      // Log access
      await AuditService.log({
        userId: req.user.id,
        action: 'VIEW_ENDPOINT_METRICS',
        resource: 'endpoints',
        details: {
          endpoint: '/api/performance/endpoints',
          userAgent: req.get('User-Agent'),
          ip: req.ip
        },
        success: true
      });

      const { performanceMonitor } = require('../middleware/performance');
      const metrics = performanceMonitor.getMetrics();

      res.json({
        success: true,
        message: 'Endpoint performance metrics retrieved successfully',
        data: {
          endpoints: metrics.endpoints,
          summary: {
            totalRequests: metrics.requests.total,
            averageResponseTime: metrics.requests.averageResponseTime,
            successRate: metrics.requests.successRate,
            requestsPerSecond: metrics.requests.requestsPerSecond
          },
          timestamp: metrics.timestamp
        }
      });
    } catch (error) {
      logger.error('Failed to get endpoint performance metrics', { 
        error: error.message,
        userId: req.user?.id 
      });
      
      await AuditService.log({
        userId: req.user?.id,
        action: 'VIEW_ENDPOINT_METRICS',
        resource: 'endpoints',
        details: {
          endpoint: '/api/performance/endpoints',
          error: error.message
        },
        success: false
      });

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve endpoint performance metrics',
        error: error.message
      });
    }
  }
);

/**
 * @route POST /api/performance/reset
 * @desc Reset performance metrics (useful for testing)
 * @access Admin only
 */
router.post('/reset',
  rateLimits.api,
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      // Log action
      await AuditService.log({
        userId: req.user.id,
        action: 'RESET_PERFORMANCE_METRICS',
        resource: 'performance',
        details: {
          endpoint: '/api/performance/reset',
          userAgent: req.get('User-Agent'),
          ip: req.ip
        },
        success: true
      });

      const { performanceMonitor } = require('../middleware/performance');
      performanceMonitor.resetMetrics();

      logger.info('Performance metrics reset', { userId: req.user.id });

      res.json({
        success: true,
        message: 'Performance metrics reset successfully',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Failed to reset performance metrics', { 
        error: error.message,
        userId: req.user?.id 
      });
      
      await AuditService.log({
        userId: req.user?.id,
        action: 'RESET_PERFORMANCE_METRICS',
        resource: 'performance',
        details: {
          endpoint: '/api/performance/reset',
          error: error.message
        },
        success: false
      });

      res.status(500).json({
        success: false,
        message: 'Failed to reset performance metrics',
        error: error.message
      });
    }
  }
);

module.exports = router;