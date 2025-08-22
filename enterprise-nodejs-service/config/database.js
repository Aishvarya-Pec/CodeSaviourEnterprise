const { Pool } = require('pg');
const logger = require('../utils/logger');
const { performanceMonitor } = require('../middleware/performance');

// Database connection configuration with connection pooling
class DatabaseManager {
  constructor() {
    this.pool = null;
    this.isConnected = false;
    this.connectionAttempts = 0;
    this.maxRetries = 5;
    this.retryDelay = 5000; // 5 seconds
  }

  /**
   * Connect to PostgreSQL with optimized connection pooling
   */
  async connect() {
    if (this.isConnected && this.pool) {
      logger.info('Database already connected');
      return true;
    }

    if (!process.env.DB_PASSWORD && !process.env.DATABASE_URL && !process.env.POSTGRES_URI) {
      logger.warn('Database credentials not provided. Running without database connection.');
      return false;
    }

    const connectionConfig = process.env.DATABASE_URL || process.env.POSTGRES_URI ? {
      connectionString: process.env.DATABASE_URL || process.env.POSTGRES_URI,
      // Connection Pool Settings
      max: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
      min: parseInt(process.env.DB_MIN_POOL_SIZE) || 2,
      idleTimeoutMillis: parseInt(process.env.DB_MAX_IDLE_TIME) || 30000,
      connectionTimeoutMillis: parseInt(process.env.DB_CONNECT_TIMEOUT) || 10000,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      application_name: process.env.APP_NAME || 'enterprise-nodejs-service'
    } : {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT) || 5432,
      database: process.env.DB_NAME || 'enterprise_db',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD,
       // Connection Pool Settings
       max: parseInt(process.env.DB_MAX_POOL_SIZE) || 10, // Maximum number of connections
       min: parseInt(process.env.DB_MIN_POOL_SIZE) || 2,  // Minimum number of connections
       idleTimeoutMillis: parseInt(process.env.DB_MAX_IDLE_TIME) || 30000, // Close connections after 30s of inactivity
       connectionTimeoutMillis: parseInt(process.env.DB_CONNECT_TIMEOUT) || 10000, // How long to wait for initial connection
       
       // SSL Settings
       ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
       
       // Application Name for monitoring
       application_name: process.env.APP_NAME || 'enterprise-nodejs-service'
     };

    try {
      this.connectionAttempts++;
      logger.info(`Attempting database connection (attempt ${this.connectionAttempts}/${this.maxRetries})`, {
        host: this.maskConnectionString(connectionConfig.connectionString),
        poolSize: connectionConfig.max
      });

      this.pool = new Pool(connectionConfig);
      
      // Test the connection
      const client = await this.pool.connect();
      const result = await client.query('SELECT NOW()');
      client.release();
      
      this.isConnected = true;
      this.connectionAttempts = 0;
      
      logger.info('Database connected successfully', {
        timestamp: result.rows[0].now,
        poolSize: connectionConfig.max,
        minPoolSize: connectionConfig.min
      });

      // Set up connection event listeners
      this.setupEventListeners();
      
      return true;
    } catch (error) {
      logger.error('Database connection failed', {
        error: error.message,
        attempt: this.connectionAttempts,
        maxRetries: this.maxRetries
      });

      if (this.connectionAttempts < this.maxRetries) {
        logger.info(`Retrying connection in ${this.retryDelay / 1000} seconds...`);
        await this.delay(this.retryDelay);
        return this.connect(); // Recursive retry
      } else {
        logger.error('Max connection attempts reached. Database unavailable.');
        return false;
      }
    }
  }

  /**
   * Set up PostgreSQL connection event listeners
   */
  setupEventListeners() {
    if (!this.pool) return;

    this.pool.on('connect', (client) => {
      logger.debug('New PostgreSQL client connected');
    });

    this.pool.on('error', (error, client) => {
      logger.error('PostgreSQL pool error', { error: error.message });
      this.isConnected = false;
    });

    this.pool.on('remove', (client) => {
      logger.debug('PostgreSQL client removed from pool');
    });

    // Handle application termination
    process.on('SIGINT', async () => {
      await this.disconnect();
      process.exit(0);
    });

    process.on('SIGTERM', async () => {
      await this.disconnect();
      process.exit(0);
    });
  }

  /**
   * Gracefully disconnect from database
   */
  async disconnect() {
    if (!this.pool) {
      logger.info('No database connection to close');
      return;
    }

    try {
      await this.pool.end();
      this.isConnected = false;
      this.pool = null;
      logger.info('Database connection closed successfully');
    } catch (error) {
      logger.error('Error closing database connection', { error: error.message });
    }
  }

  /**
   * Get database connection pool
   */
  getPool() {
    if (!this.pool) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.pool;
  }

  /**
   * Execute a query with automatic connection management
   */
  async query(text, params = []) {
    if (!this.pool) {
      throw new Error('Database not connected');
    }

    const start = Date.now();
    try {
      const result = await this.pool.query(text, params);
      const duration = Date.now() - start;
      
      logger.debug('Query executed', {
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        duration: `${duration}ms`,
        rows: result.rowCount
      });
      
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      logger.error('Query failed', {
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        error: error.message,
        duration: `${duration}ms`
      });
      throw error;
    }
  }

  /**
   * Get a client from the pool for transactions
   */
  async getClient() {
    if (!this.pool) {
      throw new Error('Database not connected');
    }
    return await this.pool.connect();
  }

  /**
   * Check database health
   */
  async healthCheck() {
    if (!this.isConnected || !this.pool) {
      return {
        status: 'disconnected',
        message: 'Database not connected'
      };
    }

    try {
      const start = Date.now();
      await this.pool.query('SELECT 1');
      const responseTime = Date.now() - start;
      
      return {
        status: 'connected',
        responseTime: `${responseTime}ms`,
        totalConnections: this.pool.totalCount,
        idleConnections: this.pool.idleCount,
        waitingConnections: this.pool.waitingCount
      };
    } catch (error) {
      logger.error('Database health check failed', { error: error.message });
      return {
        status: 'error',
        message: error.message
      };
    }
  }

  /**
   * Get database statistics
   */
  async getStats() {
    if (!this.pool) {
      return null;
    }

    try {
      const result = await this.pool.query(`
        SELECT 
          current_database() as database_name,
          current_user as current_user,
          version() as version,
          pg_database_size(current_database()) as database_size
      `);
      
      return {
        ...result.rows[0],
        pool_stats: {
          total_connections: this.pool.totalCount,
          idle_connections: this.pool.idleCount,
          waiting_connections: this.pool.waitingCount
        }
      };
    } catch (error) {
      logger.error('Failed to get database stats', { error: error.message });
      return null;
    }
  }

  /**
   * Mask sensitive information in connection string
   */
  maskConnectionString(connectionString) {
    if (!connectionString) return 'Not provided';
    return connectionString.replace(/\/\/[^@]+@/, '//***:***@');
  }

  /**
   * Delay utility for retry logic
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get connection status
   */
  isHealthy() {
    return this.isConnected && this.pool;
  }
}

// Create singleton instance
const databaseManager = new DatabaseManager();

module.exports = {
  databaseManager,
  DatabaseManager
};