const express = require('express');
const { AuditService } = require('../services/auditService');
const { authenticateToken, requireAdmin } = require('../middleware/auth');
const { rateLimits } = require('../middleware/security');
const { validationResult, query, param } = require('express-validator');

const router = express.Router();

// Apply rate limiting to audit endpoints
router.use(rateLimits.api);

// All audit routes require authentication and admin privileges
router.use(authenticateToken);
router.use(requireAdmin);

// Validation middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation errors',
      errors: errors.array()
    });
  }
  next();
};

/**
 * GET /api/audit/logs
 * Get audit logs with filtering and pagination
 */
router.get('/logs', [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('userId').optional().isMongoId().withMessage('Invalid user ID'),
  query('action').optional().isString().withMessage('Action must be a string'),
  query('severity').optional().isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).withMessage('Invalid severity level'),
  query('success').optional().isBoolean().withMessage('Success must be a boolean'),
  query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
  query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
  query('sortBy').optional().isIn(['timestamp', 'action', 'severity', 'userId']).withMessage('Invalid sort field'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc')
], handleValidationErrors, async (req, res) => {
  try {
    const filters = {
      userId: req.query.userId,
      action: req.query.action,
      severity: req.query.severity,
      success: req.query.success ? req.query.success === 'true' : undefined,
      ipAddress: req.query.ipAddress,
      startDate: req.query.startDate,
      endDate: req.query.endDate
    };

    // Remove undefined values
    Object.keys(filters).forEach(key => {
      if (filters[key] === undefined) {
        delete filters[key];
      }
    });

    const options = {
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 50,
      sortBy: req.query.sortBy || 'timestamp',
      sortOrder: req.query.sortOrder || 'desc'
    };

    const result = await AuditService.getAuditLogs(filters, options);

    // Log admin access to audit logs
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_ACCESS',
      resource: 'audit_logs',
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: true,
      details: { filters, options },
      severity: 'LOW'
    });

    res.json({
      success: true,
      message: 'Audit logs retrieved successfully',
      data: result
    });
  } catch (error) {
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_ACCESS',
      resource: 'audit_logs',
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: false,
      errorMessage: error.message,
      severity: 'MEDIUM'
    });

    res.status(500).json({
      success: false,
      message: 'Failed to retrieve audit logs',
      error: error.message
    });
  }
});

/**
 * GET /api/audit/summary
 * Get security summary statistics
 */
router.get('/summary', [
  query('timeframe').optional().isIn(['1h', '24h', '7d', '30d']).withMessage('Invalid timeframe')
], handleValidationErrors, async (req, res) => {
  try {
    const timeframe = req.query.timeframe || '24h';
    const summary = await AuditService.getSecuritySummary(timeframe);

    // Log admin access to security summary
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_ACCESS',
      resource: 'security_summary',
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: true,
      details: { timeframe },
      severity: 'LOW'
    });

    res.json({
      success: true,
      message: 'Security summary retrieved successfully',
      data: summary
    });
  } catch (error) {
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_ACCESS',
      resource: 'security_summary',
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: false,
      errorMessage: error.message,
      severity: 'MEDIUM'
    });

    res.status(500).json({
      success: false,
      message: 'Failed to retrieve security summary',
      error: error.message
    });
  }
});

/**
 * GET /api/audit/logs/:id
 * Get specific audit log entry
 */
router.get('/logs/:id', [
  param('id').isMongoId().withMessage('Invalid audit log ID')
], handleValidationErrors, async (req, res) => {
  try {
    const { AuditLog } = require('../services/auditService');
    const auditLog = await AuditLog.findById(req.params.id)
      .populate('userId', 'email name')
      .lean();

    if (!auditLog) {
      return res.status(404).json({
        success: false,
        message: 'Audit log not found'
      });
    }

    // Log admin access to specific audit log
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_ACCESS',
      resource: `audit_log_${req.params.id}`,
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: true,
      severity: 'LOW'
    });

    res.json({
      success: true,
      message: 'Audit log retrieved successfully',
      data: auditLog
    });
  } catch (error) {
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_ACCESS',
      resource: `audit_log_${req.params.id}`,
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: false,
      errorMessage: error.message,
      severity: 'MEDIUM'
    });

    res.status(500).json({
      success: false,
      message: 'Failed to retrieve audit log',
      error: error.message
    });
  }
});

/**
 * POST /api/audit/cleanup
 * Clean up old audit logs (retention policy)
 */
router.post('/cleanup', [
  query('retentionDays').optional().isInt({ min: 1, max: 365 }).withMessage('Retention days must be between 1 and 365')
], handleValidationErrors, async (req, res) => {
  try {
    const retentionDays = parseInt(req.query.retentionDays) || 90;
    const result = await AuditService.cleanupOldLogs(retentionDays);

    // Log cleanup action
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_MODIFICATION',
      resource: 'audit_logs_cleanup',
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: true,
      details: { 
        retentionDays,
        deletedCount: result.deletedCount
      },
      severity: 'MEDIUM'
    });

    res.json({
      success: true,
      message: 'Audit log cleanup completed successfully',
      data: {
        deletedCount: result.deletedCount,
        retentionDays
      }
    });
  } catch (error) {
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_MODIFICATION',
      resource: 'audit_logs_cleanup',
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: false,
      errorMessage: error.message,
      severity: 'HIGH'
    });

    res.status(500).json({
      success: false,
      message: 'Failed to cleanup audit logs',
      error: error.message
    });
  }
});

/**
 * GET /api/audit/export
 * Export audit logs as CSV
 */
router.get('/export', [
  query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
  query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
  query('format').optional().isIn(['csv', 'json']).withMessage('Format must be csv or json')
], handleValidationErrors, async (req, res) => {
  try {
    const filters = {
      startDate: req.query.startDate,
      endDate: req.query.endDate
    };

    // Remove undefined values
    Object.keys(filters).forEach(key => {
      if (filters[key] === undefined) {
        delete filters[key];
      }
    });

    const options = {
      page: 1,
      limit: 10000, // Large limit for export
      sortBy: 'timestamp',
      sortOrder: 'desc'
    };

    const result = await AuditService.getAuditLogs(filters, options);
    const format = req.query.format || 'csv';

    // Log export action
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_ACCESS',
      resource: 'audit_logs_export',
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: true,
      details: { 
        filters,
        format,
        recordCount: result.logs.length
      },
      severity: 'MEDIUM'
    });

    if (format === 'csv') {
      // Convert to CSV format
      const csvHeader = 'Timestamp,User ID,User Email,Action,Resource,IP Address,Success,Severity,Details\n';
      const csvRows = result.logs.map(log => {
        const userEmail = log.userId?.email || 'N/A';
        const details = JSON.stringify(log.details || {}).replace(/"/g, '""');
        return `"${log.timestamp}","${log.userId?._id || 'N/A'}","${userEmail}","${log.action}","${log.resource || 'N/A'}","${log.ipAddress}","${log.success}","${log.severity}","${details}"`;
      }).join('\n');

      const csvContent = csvHeader + csvRows;

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="audit-logs-${new Date().toISOString().split('T')[0]}.csv"`);
      res.send(csvContent);
    } else {
      // JSON format
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="audit-logs-${new Date().toISOString().split('T')[0]}.json"`);
      res.json(result);
    }
  } catch (error) {
    await AuditService.logEvent({
      userId: req.user.id,
      action: 'DATA_ACCESS',
      resource: 'audit_logs_export',
      ipAddress: AuditService.getClientIP(req),
      userAgent: req.get('User-Agent'),
      success: false,
      errorMessage: error.message,
      severity: 'HIGH'
    });

    res.status(500).json({
      success: false,
      message: 'Failed to export audit logs',
      error: error.message
    });
  }
});

module.exports = router;