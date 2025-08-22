const os = require('os');
const process = require('process');
const logger = require('../utils/logger');

// Performance metrics storage
class PerformanceMonitor {
  constructor() {
    this.metrics = {
      requests: {
        total: 0,
        successful: 0,
        failed: 0,
        averageResponseTime: 0,
        responseTimes: [],
        endpoints: new Map()
      },
      system: {
        startTime: Date.now(),
        lastCheck: Date.now()
      }
    };
    
    // Start system monitoring
    this.startSystemMonitoring();
  }

  /**
   * Record request metrics
   */
  recordRequest(req, res, responseTime) {
    const endpoint = `${req.method} ${req.route?.path || req.path}`;
    const isSuccessful = res.statusCode < 400;
    
    // Update global metrics
    this.metrics.requests.total++;
    if (isSuccessful) {
      this.metrics.requests.successful++;
    } else {
      this.metrics.requests.failed++;
    }
    
    // Update response times (keep last 1000 for rolling average)
    this.metrics.requests.responseTimes.push(responseTime);
    if (this.metrics.requests.responseTimes.length > 1000) {
      this.metrics.requests.responseTimes.shift();
    }
    
    // Calculate average response time
    this.metrics.requests.averageResponseTime = 
      this.metrics.requests.responseTimes.reduce((a, b) => a + b, 0) / 
      this.metrics.requests.responseTimes.length;
    
    // Update endpoint-specific metrics
    if (!this.metrics.requests.endpoints.has(endpoint)) {
      this.metrics.requests.endpoints.set(endpoint, {
        count: 0,
        successCount: 0,
        failCount: 0,
        totalResponseTime: 0,
        averageResponseTime: 0,
        minResponseTime: Infinity,
        maxResponseTime: 0,
        statusCodes: new Map()
      });
    }
    
    const endpointMetrics = this.metrics.requests.endpoints.get(endpoint);
    endpointMetrics.count++;
    endpointMetrics.totalResponseTime += responseTime;
    endpointMetrics.averageResponseTime = endpointMetrics.totalResponseTime / endpointMetrics.count;
    endpointMetrics.minResponseTime = Math.min(endpointMetrics.minResponseTime, responseTime);
    endpointMetrics.maxResponseTime = Math.max(endpointMetrics.maxResponseTime, responseTime);
    
    if (isSuccessful) {
      endpointMetrics.successCount++;
    } else {
      endpointMetrics.failCount++;
    }
    
    // Track status codes
    const statusCode = res.statusCode.toString();
    endpointMetrics.statusCodes.set(
      statusCode, 
      (endpointMetrics.statusCodes.get(statusCode) || 0) + 1
    );
  }

  /**
   * Get current performance metrics
   */
  getMetrics() {
    const now = Date.now();
    const uptime = now - this.metrics.system.startTime;
    
    return {
      timestamp: new Date().toISOString(),
      uptime: {
        milliseconds: uptime,
        seconds: Math.floor(uptime / 1000),
        minutes: Math.floor(uptime / (1000 * 60)),
        hours: Math.floor(uptime / (1000 * 60 * 60))
      },
      requests: {
        total: this.metrics.requests.total,
        successful: this.metrics.requests.successful,
        failed: this.metrics.requests.failed,
        successRate: this.metrics.requests.total > 0 ? 
          (this.metrics.requests.successful / this.metrics.requests.total * 100).toFixed(2) + '%' : '0%',
        averageResponseTime: Math.round(this.metrics.requests.averageResponseTime * 100) / 100,
        requestsPerSecond: this.metrics.requests.total / (uptime / 1000)
      },
      system: this.getSystemMetrics(),
      endpoints: this.getEndpointMetrics()
    };
  }

  /**
   * Get system performance metrics
   */
  getSystemMetrics() {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    
    return {
      memory: {
        rss: this.formatBytes(memUsage.rss),
        heapTotal: this.formatBytes(memUsage.heapTotal),
        heapUsed: this.formatBytes(memUsage.heapUsed),
        external: this.formatBytes(memUsage.external),
        arrayBuffers: this.formatBytes(memUsage.arrayBuffers || 0)
      },
      cpu: {
        user: cpuUsage.user,
        system: cpuUsage.system
      },
      os: {
        platform: os.platform(),
        arch: os.arch(),
        cpus: os.cpus().length,
        totalMemory: this.formatBytes(os.totalmem()),
        freeMemory: this.formatBytes(os.freemem()),
        loadAverage: os.loadavg(),
        uptime: os.uptime()
      },
      process: {
        pid: process.pid,
        version: process.version,
        nodeVersion: process.versions.node,
        v8Version: process.versions.v8
      }
    };
  }

  /**
   * Get endpoint-specific metrics
   */
  getEndpointMetrics() {
    const endpoints = [];
    
    for (const [endpoint, metrics] of this.metrics.requests.endpoints) {
      const statusCodes = {};
      for (const [code, count] of metrics.statusCodes) {
        statusCodes[code] = count;
      }
      
      endpoints.push({
        endpoint,
        count: metrics.count,
        successCount: metrics.successCount,
        failCount: metrics.failCount,
        successRate: (metrics.successCount / metrics.count * 100).toFixed(2) + '%',
        averageResponseTime: Math.round(metrics.averageResponseTime * 100) / 100,
        minResponseTime: metrics.minResponseTime === Infinity ? 0 : metrics.minResponseTime,
        maxResponseTime: metrics.maxResponseTime,
        statusCodes
      });
    }
    
    return endpoints.sort((a, b) => b.count - a.count); // Sort by request count
  }

  /**
   * Start system monitoring (periodic checks)
   */
  startSystemMonitoring() {
    const monitoringInterval = parseInt(process.env.PERFORMANCE_MONITORING_INTERVAL) || 60000; // 1 minute
    
    setInterval(() => {
      const metrics = this.getSystemMetrics();
      
      // Log performance metrics periodically
      logger.info('System Performance Metrics', {
        memory: metrics.memory,
        requests: {
          total: this.metrics.requests.total,
          averageResponseTime: this.metrics.requests.averageResponseTime,
          requestsPerSecond: this.metrics.requests.total / ((Date.now() - this.metrics.system.startTime) / 1000)
        }
      });
      
      // Check for performance issues
      this.checkPerformanceAlerts(metrics);
      
    }, monitoringInterval);
  }

  /**
   * Check for performance alerts
   */
  checkPerformanceAlerts(metrics) {
    const alerts = [];
    
    // Memory usage alerts - Use RSS memory vs total system memory for accurate calculation
    const rssMB = parseInt(metrics.memory.rss.replace(/[^0-9.]/g, ''));
    const totalSystemMemoryMB = os.totalmem() / (1024 * 1024);
    const memoryUsagePercent = (rssMB / totalSystemMemoryMB) * 100;
    
    // Only alert if memory usage is genuinely high (>80% of system memory)
    if (memoryUsagePercent > 80) {
      alerts.push({
        type: 'HIGH_MEMORY_USAGE',
        severity: 'CRITICAL',
        message: `System memory usage is ${memoryUsagePercent.toFixed(2)}%`,
        value: memoryUsagePercent
      });
    } else if (memoryUsagePercent > 60) {
      alerts.push({
        type: 'HIGH_MEMORY_USAGE',
        severity: 'WARNING',
        message: `System memory usage is ${memoryUsagePercent.toFixed(2)}%`,
        value: memoryUsagePercent
      });
    }
    
    // Response time alerts
    if (this.metrics.requests.averageResponseTime > 5000) { // 5 seconds
      alerts.push({
        type: 'SLOW_RESPONSE_TIME',
        severity: 'CRITICAL',
        message: `Average response time is ${this.metrics.requests.averageResponseTime.toFixed(2)}ms`,
        value: this.metrics.requests.averageResponseTime
      });
    } else if (this.metrics.requests.averageResponseTime > 2000) { // 2 seconds
      alerts.push({
        type: 'SLOW_RESPONSE_TIME',
        severity: 'WARNING',
        message: `Average response time is ${this.metrics.requests.averageResponseTime.toFixed(2)}ms`,
        value: this.metrics.requests.averageResponseTime
      });
    }
    
    // Error rate alerts - Only alert if we have meaningful traffic and actual errors
    const errorRate = this.metrics.requests.total > 0 ? 
      (this.metrics.requests.failed / this.metrics.requests.total) * 100 : 0;
    
    // Only check error rate if we have at least 10 requests to avoid false positives
    if (this.metrics.requests.total >= 10) {
      if (errorRate > 20) {
        alerts.push({
          type: 'HIGH_ERROR_RATE',
          severity: 'CRITICAL',
          message: `Error rate is ${errorRate.toFixed(2)}% (${this.metrics.requests.failed}/${this.metrics.requests.total} requests)`,
          value: errorRate
        });
      } else if (errorRate > 10) {
        alerts.push({
          type: 'HIGH_ERROR_RATE',
          severity: 'WARNING',
          message: `Error rate is ${errorRate.toFixed(2)}% (${this.metrics.requests.failed}/${this.metrics.requests.total} requests)`,
          value: errorRate
        });
      }
    }
    
    // Log alerts
    alerts.forEach(alert => {
      if (alert.severity === 'CRITICAL') {
        logger.error('Performance Alert', alert);
      } else {
        logger.warn('Performance Alert', alert);
      }
    });
  }

  /**
   * Reset metrics (useful for testing or periodic resets)
   */
  resetMetrics() {
    this.metrics.requests = {
      total: 0,
      successful: 0,
      failed: 0,
      averageResponseTime: 0,
      responseTimes: [],
      endpoints: new Map()
    };
    this.metrics.system.startTime = Date.now();
  }

  /**
   * Format bytes to human readable format
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}

// Create singleton instance
const performanceMonitor = new PerformanceMonitor();

/**
 * Performance monitoring middleware
 */
const performanceMiddleware = (req, res, next) => {
  const startTime = Date.now();
  
  // Override res.end to capture response time
  const originalEnd = res.end;
  res.end = function(...args) {
    const responseTime = Date.now() - startTime;
    
    // Record metrics
    performanceMonitor.recordRequest(req, res, responseTime);
    
    // Add performance headers only if headers haven't been sent
    if (!res.headersSent) {
      res.set({
        'X-Response-Time': `${responseTime}ms`,
        'X-Request-ID': req.headers['x-request-id'] || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      });
    }
    
    // Call original end method
    originalEnd.apply(this, args);
  };
  
  next();
};

/**
 * Get performance metrics endpoint handler
 */
const getMetrics = (req, res) => {
  try {
    const metrics = performanceMonitor.getMetrics();
    res.json({
      success: true,
      message: 'Performance metrics retrieved successfully',
      data: metrics
    });
  } catch (error) {
    logger.error('Failed to get performance metrics', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve performance metrics',
      error: error.message
    });
  }
};

/**
 * Health check with performance data
 */
const healthCheck = async (req, res) => {
  try {
    const metrics = performanceMonitor.getMetrics();
    const systemMetrics = metrics.system;
    
    // Determine health status based on metrics
    let status = 'healthy';
    let issues = [];
    
    // Check memory usage
    const heapUsedMB = parseInt(systemMetrics.memory.heapUsed.replace(/[^0-9]/g, ''));
    const heapTotalMB = parseInt(systemMetrics.memory.heapTotal.replace(/[^0-9]/g, ''));
    const memoryUsagePercent = (heapUsedMB / heapTotalMB) * 100;
    
    if (memoryUsagePercent > 90) {
      status = 'unhealthy';
      issues.push(`High memory usage: ${memoryUsagePercent.toFixed(2)}%`);
    } else if (memoryUsagePercent > 75) {
      status = 'degraded';
      issues.push(`Elevated memory usage: ${memoryUsagePercent.toFixed(2)}%`);
    }
    
    // Check response time
    if (metrics.requests.averageResponseTime > 5000) {
      status = 'unhealthy';
      issues.push(`Slow response time: ${metrics.requests.averageResponseTime.toFixed(2)}ms`);
    } else if (metrics.requests.averageResponseTime > 2000) {
      if (status === 'healthy') status = 'degraded';
      issues.push(`Elevated response time: ${metrics.requests.averageResponseTime.toFixed(2)}ms`);
    }
    
    const statusCode = status === 'healthy' ? 200 : status === 'degraded' ? 200 : 503;
    
    res.status(statusCode).json({
      status,
      timestamp: new Date().toISOString(),
      uptime: metrics.uptime,
      issues: issues.length > 0 ? issues : undefined,
      metrics: {
        requests: metrics.requests,
        memory: systemMetrics.memory,
        cpu: systemMetrics.cpu
      }
    });
  } catch (error) {
    logger.error('Health check failed', { error: error.message });
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
};

module.exports = {
  PerformanceMonitor,
  performanceMiddleware,
  getMetrics,
  healthCheck,
  performanceMonitor // Export singleton instance
};