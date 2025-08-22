const { Pool } = require('pg');
const logger = require('../utils/logger');

class DatabaseConnection {
  constructor() {
    this.pool = null;
    this.isConnected = false;
    this.connectionAttempts = 0;
    this.maxRetries = 5;
  }

  async connect() {
    try {
      const dbConfig = {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        database: process.env.DB_NAME || 'enterprise_db',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD,
        max: 20, // Maximum number of clients in the pool
        idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
        connectionTimeoutMillis: 2000, // Return an error after 2 seconds if connection could not be established
        maxUses: 7500, // Close (and replace) a connection after it has been used 7500 times
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
      };

      if (!dbConfig.password) {
        logger.warn('DB_PASSWORD not provided. Running without database connection.');
        this.isConnected = false;
        return false;
      }

      this.pool = new Pool(dbConfig);
      
      // Test the connection
      const client = await this.pool.connect();
      await client.query('SELECT NOW()');
      client.release();
      
      this.isConnected = true;
      this.connectionAttempts = 0;
      
      logger.info('Successfully connected to PostgreSQL', {
        database: dbConfig.database,
        host: dbConfig.host,
        port: dbConfig.port,
        poolSize: dbConfig.max
      });

      // Handle pool events
      this.pool.on('error', (error) => {
        logger.error('PostgreSQL pool error:', error);
        this.isConnected = false;
      });

      this.pool.on('connect', () => {
        logger.debug('New PostgreSQL client connected');
      });

      this.pool.on('remove', () => {
        logger.debug('PostgreSQL client removed from pool');
      });

      // Graceful shutdown
      process.on('SIGINT', this.gracefulShutdown.bind(this));
      process.on('SIGTERM', this.gracefulShutdown.bind(this));

      // Initialize database schema
      await this.initializeSchema();

    } catch (error) {
      this.connectionAttempts++;
      logger.error(`PostgreSQL connection failed (attempt ${this.connectionAttempts}/${this.maxRetries}):`, error.message);
      
      if (this.connectionAttempts >= this.maxRetries) {
        logger.error('Max connection attempts reached. Exiting application.');
        process.exit(1);
      }
      
      // Retry connection after delay
      setTimeout(() => this.connect(), 5000);
    }
  }

  async initializeSchema() {
    try {
      const client = await this.pool.connect();
      
      // Create users table with proper security measures
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          role VARCHAR(50) DEFAULT 'user',
          is_active BOOLEAN DEFAULT true,
          is_locked BOOLEAN DEFAULT false,
          login_attempts INTEGER DEFAULT 0,
          last_login_attempt TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          locked_until TIMESTAMP,
          refresh_token_hash VARCHAR(255),
          CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'),
          CONSTRAINT valid_role CHECK (role IN ('user', 'admin', 'moderator'))
        )
      `);

      // Create audit logs table
      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id),
          action VARCHAR(100) NOT NULL,
          resource VARCHAR(100),
          details JSONB,
          ip_address INET,
          user_agent TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX (user_id, created_at),
          INDEX (action, created_at)
        )
      `);

      // Create sessions table for secure session management
      await client.query(`
        CREATE TABLE IF NOT EXISTS sessions (
          id VARCHAR(255) PRIMARY KEY,
          user_id INTEGER REFERENCES users(id),
          data JSONB NOT NULL,
          expires_at TIMESTAMP NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX (user_id),
          INDEX (expires_at)
        )
      `);

      // Create function to update updated_at timestamp
      await client.query(`
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
          NEW.updated_at = CURRENT_TIMESTAMP;
          RETURN NEW;
        END;
        $$ language 'plpgsql';
      `);

      // Create trigger for users table
      await client.query(`
        DROP TRIGGER IF EXISTS update_users_updated_at ON users;
        CREATE TRIGGER update_users_updated_at
          BEFORE UPDATE ON users
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();
      `);

      client.release();
      logger.info('Database schema initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize database schema:', error);
      throw error;
    }
  }

  async healthCheck() {
    try {
      if (!this.isConnected || !this.pool) {
        return { status: 'disconnected', message: 'Database connection is down' };
      }

      const client = await this.pool.connect();
      const result = await client.query('SELECT NOW() as current_time, version() as version');
      const stats = {
        totalConnections: this.pool.totalCount,
        idleConnections: this.pool.idleCount,
        waitingConnections: this.pool.waitingCount
      };
      client.release();
      
      return {
        status: 'connected',
        message: 'Database is healthy',
        timestamp: result.rows[0].current_time,
        version: result.rows[0].version,
        connectionPool: stats
      };
    } catch (error) {
      logger.error('Database health check failed:', error);
      return {
        status: 'error',
        message: 'Database health check failed',
        error: error.message
      };
    }
  }

  async query(text, params) {
    if (!this.pool) {
      throw new Error('Database not connected');
    }
    
    const start = Date.now();
    try {
      const result = await this.pool.query(text, params);
      const duration = Date.now() - start;
      
      logger.debug('Executed query', {
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        duration: `${duration}ms`,
        rows: result.rowCount
      });
      
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      logger.error('Query failed', {
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        duration: `${duration}ms`,
        error: error.message
      });
      throw error;
    }
  }

  async transaction(callback) {
    if (!this.pool) {
      throw new Error('Database not connected');
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async gracefulShutdown() {
    logger.info('Closing PostgreSQL connection pool...');
    
    if (this.pool) {
      try {
        await this.pool.end();
        logger.info('PostgreSQL connection pool closed successfully');
      } catch (error) {
        logger.error('Error closing PostgreSQL connection pool:', error);
      }
    }
    
    this.isConnected = false;
  }
}

// Create singleton instance
const databaseManager = new DatabaseConnection();

module.exports = {
  databaseManager,
  DatabaseConnection
};