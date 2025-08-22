const winston = require('winston');
const { databaseManager } = require('../config/database');
const logger = require('../utils/logger');

// Audit Service for PostgreSQL
class AuditService {
  constructor() {
    this.tableName = 'audit_logs';
    this.initializeTable();
  }

  /**
   * Initialize audit_logs table if it doesn't exist
   */
  async initializeTable() {
    try {
      const createTableQuery = `
        CREATE TABLE IF NOT EXISTS ${this.tableName} (
          id SERIAL PRIMARY KEY,
          user_id VARCHAR(255),
          action VARCHAR(50) NOT NULL CHECK (action IN (
            'LOGIN', 'LOGOUT', 'REGISTER', 'PASSWORD_CHANGE', 'TOKEN_REFRESH',
            'TOKEN_REVOKE', 'OAUTH_LOGIN', 'PROFILE_UPDATE', 'FAILED_LOGIN',
            'ACCOUNT_LOCKED', 'API_ACCESS', 'PERMISSION_DENIED', 'DATA_ACCESS',
            'DATA_MODIFICATION', 'SECURITY_VIOLATION'
          )),
          resource VARCHAR(255),
          details JSONB,
          ip_address INET NOT NULL,
          user_agent TEXT,
          session_id VARCHAR(255),
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          severity VARCHAR(20) DEFAULT 'INFO' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO')),
          status VARCHAR(20) DEFAULT 'SUCCESS' CHECK (status IN ('SUCCESS', 'FAILURE', 'PENDING')),
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Create indexes for better query performance
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON ${this.tableName}(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON ${this.tableName}(action);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON ${this.tableName}(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON ${this.tableName}(ip_address);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_severity ON ${this.tableName}(severity);
      `;
      
      await databaseManager.query(createTableQuery);
      logger.debug('Audit logs table initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize audit logs table', { error: error.message });
    }
  }

  /**
   * Log an audit event
   */
  async logEvent({
    userId = null,
    action,
    resource = null,
    details = null,
    ipAddress,
    userAgent = null,
    sessionId = null,
    severity = 'INFO',
    status = 'SUCCESS'
  }) {
    try {
      // Validate required fields
      if (!action || !ipAddress) {
        throw new Error('Action and IP address are required for audit logging');
      }

      // Validate action enum
      const validActions = [
        'LOGIN', 'LOGOUT', 'REGISTER', 'PASSWORD_CHANGE', 'TOKEN_REFRESH',
        'TOKEN_REVOKE', 'OAUTH_LOGIN', 'PROFILE_UPDATE', 'FAILED_LOGIN',
        'ACCOUNT_LOCKED', 'API_ACCESS', 'PERMISSION_DENIED', 'DATA_ACCESS',
        'DATA_MODIFICATION', 'SECURITY_VIOLATION'
      ];
      
      if (!validActions.includes(action)) {
        throw new Error(`Invalid action: ${action}`);
      }

      // Validate severity enum
      const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO'];
      if (!validSeverities.includes(severity)) {
        severity = 'INFO';
      }

      // Validate status enum
      const validStatuses = ['SUCCESS', 'FAILURE', 'PENDING'];
      if (!validStatuses.includes(status)) {
        status = 'SUCCESS';
      }

      const insertQuery = `
        INSERT INTO ${this.tableName} (
          user_id, action, resource, details, ip_address, 
          user_agent, session_id, severity, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, timestamp
      `;

      const values = [
        userId,
        action,
        resource,
        details ? JSON.stringify(details) : null,
        ipAddress,
        userAgent,
        sessionId,
        severity,
        status
      ];

      const result = await databaseManager.query(insertQuery, values);
      const auditLog = result.rows[0];

      // Log to Winston as well for immediate visibility
      const logLevel = this.mapSeverityToLogLevel(severity);
      logger.log(logLevel, 'Audit Event', {
        auditId: auditLog.id,
        userId,
        action,
        resource,
        ipAddress,
        severity,
        status,
        timestamp: auditLog.timestamp
      });

      return {
        success: true,
        auditId: auditLog.id,
        timestamp: auditLog.timestamp
      };
    } catch (error) {
      logger.error('Failed to log audit event', {
        error: error.message,
        action,
        userId,
        ipAddress
      });
      
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get audit logs with filtering and pagination
   */
  async getAuditLogs({
    userId = null,
    action = null,
    severity = null,
    startDate = null,
    endDate = null,
    ipAddress = null,
    limit = 100,
    offset = 0,
    sortBy = 'timestamp',
    sortOrder = 'DESC'
  } = {}) {
    try {
      let whereConditions = [];
      let queryParams = [];
      let paramIndex = 1;

      // Build WHERE conditions
      if (userId) {
        whereConditions.push(`user_id = $${paramIndex}`);
        queryParams.push(userId);
        paramIndex++;
      }

      if (action) {
        whereConditions.push(`action = $${paramIndex}`);
        queryParams.push(action);
        paramIndex++;
      }

      if (severity) {
        whereConditions.push(`severity = $${paramIndex}`);
        queryParams.push(severity);
        paramIndex++;
      }

      if (startDate) {
        whereConditions.push(`timestamp >= $${paramIndex}`);
        queryParams.push(startDate);
        paramIndex++;
      }

      if (endDate) {
        whereConditions.push(`timestamp <= $${paramIndex}`);
        queryParams.push(endDate);
        paramIndex++;
      }

      if (ipAddress) {
        whereConditions.push(`ip_address = $${paramIndex}`);
        queryParams.push(ipAddress);
        paramIndex++;
      }

      // Validate sort parameters
      const validSortColumns = ['timestamp', 'action', 'severity', 'user_id', 'id'];
      if (!validSortColumns.includes(sortBy)) {
        sortBy = 'timestamp';
      }

      const validSortOrders = ['ASC', 'DESC'];
      if (!validSortOrders.includes(sortOrder.toUpperCase())) {
        sortOrder = 'DESC';
      }

      // Build the query
      let query = `
        SELECT 
          id, user_id, action, resource, details, ip_address,
          user_agent, session_id, timestamp, severity, status,
          created_at, updated_at
        FROM ${this.tableName}
      `;

      if (whereConditions.length > 0) {
        query += ` WHERE ${whereConditions.join(' AND ')}`;
      }

      query += ` ORDER BY ${sortBy} ${sortOrder.toUpperCase()}`;
      query += ` LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
      
      queryParams.push(limit, offset);

      // Get total count for pagination
      let countQuery = `SELECT COUNT(*) as total FROM ${this.tableName}`;
      if (whereConditions.length > 0) {
        countQuery += ` WHERE ${whereConditions.join(' AND ')}`;
      }

      const [logsResult, countResult] = await Promise.all([
        databaseManager.query(query, queryParams),
        databaseManager.query(countQuery, queryParams.slice(0, -2)) // Remove limit and offset
      ]);

      return {
        success: true,
        data: logsResult.rows,
        pagination: {
          total: parseInt(countResult.rows[0].total),
          limit,
          offset,
          hasMore: (offset + limit) < parseInt(countResult.rows[0].total)
        }
      };
    } catch (error) {
      logger.error('Failed to get audit logs', { error: error.message });
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get audit statistics
   */
  async getAuditStats({
    startDate = null,
    endDate = null,
    userId = null
  } = {}) {
    try {
      let whereConditions = [];
      let queryParams = [];
      let paramIndex = 1;

      if (startDate) {
        whereConditions.push(`timestamp >= $${paramIndex}`);
        queryParams.push(startDate);
        paramIndex++;
      }

      if (endDate) {
        whereConditions.push(`timestamp <= $${paramIndex}`);
        queryParams.push(endDate);
        paramIndex++;
      }

      if (userId) {
        whereConditions.push(`user_id = $${paramIndex}`);
        queryParams.push(userId);
        paramIndex++;
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

      const statsQuery = `
        SELECT 
          COUNT(*) as total_events,
          COUNT(DISTINCT user_id) as unique_users,
          COUNT(DISTINCT ip_address) as unique_ips,
          action,
          severity,
          status,
          COUNT(*) as count
        FROM ${this.tableName}
        ${whereClause}
        GROUP BY ROLLUP(action, severity, status)
        ORDER BY count DESC
      `;

      const result = await databaseManager.query(statsQuery, queryParams);
      
      // Process results to create structured statistics
      const stats = {
        totalEvents: 0,
        uniqueUsers: 0,
        uniqueIps: 0,
        byAction: {},
        bySeverity: {},
        byStatus: {}
      };

      result.rows.forEach(row => {
        if (!row.action && !row.severity && !row.status) {
          // This is the total row
          stats.totalEvents = parseInt(row.count);
        } else if (row.action && !row.severity && !row.status) {
          // Action breakdown
          stats.byAction[row.action] = parseInt(row.count);
        } else if (!row.action && row.severity && !row.status) {
          // Severity breakdown
          stats.bySeverity[row.severity] = parseInt(row.count);
        } else if (!row.action && !row.severity && row.status) {
          // Status breakdown
          stats.byStatus[row.status] = parseInt(row.count);
        }
      });

      return {
        success: true,
        data: stats
      };
    } catch (error) {
      logger.error('Failed to get audit statistics', { error: error.message });
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Delete old audit logs (for cleanup)
   */
  async cleanupOldLogs(daysToKeep = 90) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

      const deleteQuery = `
        DELETE FROM ${this.tableName}
        WHERE timestamp < $1
      `;

      const result = await databaseManager.query(deleteQuery, [cutoffDate]);
      
      logger.info('Audit logs cleanup completed', {
        deletedRows: result.rowCount,
        cutoffDate: cutoffDate.toISOString()
      });

      return {
        success: true,
        deletedRows: result.rowCount
      };
    } catch (error) {
      logger.error('Failed to cleanup audit logs', { error: error.message });
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Map severity to log level
   */
  mapSeverityToLogLevel(severity) {
    const mapping = {
      'LOW': 'info',
      'MEDIUM': 'warn',
      'HIGH': 'error',
      'CRITICAL': 'error',
      'INFO': 'info'
    };
    return mapping[severity] || 'info';
  }

  /**
   * Extract client IP address from request
   */
  static getClientIP(req) {
    return req.ip ||
           req.connection?.remoteAddress ||
           req.socket?.remoteAddress ||
           (req.connection?.socket ? req.connection.socket.remoteAddress : null) ||
           req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] ||
           req.headers['x-client-ip'] ||
           '127.0.0.1';
  }
}

// Create singleton instance
const auditService = new AuditService();

// Convenience functions for common audit events
const auditLogger = {
  /**
   * Log user authentication events
   */
  logAuth: (action, userId, ipAddress, userAgent, sessionId, success = true) => {
    return auditService.logEvent({
      userId,
      action,
      ipAddress,
      userAgent,
      sessionId,
      severity: success ? 'INFO' : 'HIGH',
      status: success ? 'SUCCESS' : 'FAILURE'
    });
  },

  /**
   * Log API access events
   */
  logApiAccess: (userId, resource, ipAddress, userAgent, success = true) => {
    return auditService.logEvent({
      userId,
      action: 'API_ACCESS',
      resource,
      ipAddress,
      userAgent,
      severity: 'INFO',
      status: success ? 'SUCCESS' : 'FAILURE'
    });
  },

  /**
   * Log security violations
   */
  logSecurityViolation: (userId, details, ipAddress, userAgent) => {
    return auditService.logEvent({
      userId,
      action: 'SECURITY_VIOLATION',
      details,
      ipAddress,
      userAgent,
      severity: 'CRITICAL',
      status: 'FAILURE'
    });
  },

  /**
   * Log data access/modification events
   */
  logDataAccess: (userId, action, resource, details, ipAddress, userAgent) => {
    return auditService.logEvent({
      userId,
      action,
      resource,
      details,
      ipAddress,
      userAgent,
      severity: 'MEDIUM',
      status: 'SUCCESS'
    });
  }
};

module.exports = {
  AuditService,
  auditService,
  auditLogger
};