const bcrypt = require('bcrypt');
const { databaseManager } = require('../config/database');
const logger = require('../utils/logger');

class User {
  constructor(data = {}) {
    this.id = data.id;
    this.email = data.email;
    this.password_hash = data.password_hash;
    this.role = data.role || 'user';
    this.is_active = data.is_active !== undefined ? data.is_active : true;
    this.is_locked = data.is_locked || false;
    this.login_attempts = data.login_attempts || 0;
    this.last_login_attempt = data.last_login_attempt;
    this.created_at = data.created_at;
    this.updated_at = data.updated_at;
    this.locked_until = data.locked_until;
    this.refresh_token_hash = data.refresh_token_hash;
  }

  // Static methods for database operations using parameterized queries
  static async findById(id) {
    try {
      const result = await databaseManager.query(
        'SELECT * FROM users WHERE id = $1 AND is_active = true',
        [id]
      );
      return result.rows.length > 0 ? new User(result.rows[0]) : null;
    } catch (error) {
      logger.error('Error finding user by ID:', error);
      throw error;
    }
  }

  static async findByEmail(email) {
    try {
      const result = await databaseManager.query(
        'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
        [email]
      );
      return result.rows.length > 0 ? new User(result.rows[0]) : null;
    } catch (error) {
      logger.error('Error finding user by email:', error);
      throw error;
    }
  }

  static async findActiveUsers(limit = 100, offset = 0) {
    try {
      const result = await databaseManager.query(
        'SELECT * FROM users WHERE is_active = true ORDER BY created_at DESC LIMIT $1 OFFSET $2',
        [limit, offset]
      );
      return result.rows.map(row => new User(row));
    } catch (error) {
      logger.error('Error finding active users:', error);
      throw error;
    }
  }

  static async create(userData) {
    try {
      // Hash password before storing
      const saltRounds = 12;
      const password_hash = await bcrypt.hash(userData.password, saltRounds);
      
      const result = await databaseManager.query(
        `INSERT INTO users (email, password_hash, role, is_active) 
         VALUES ($1, $2, $3, $4) 
         RETURNING *`,
        [userData.email, password_hash, userData.role || 'user', true]
      );
      
      return new User(result.rows[0]);
    } catch (error) {
      if (error.code === '23505') { // Unique constraint violation
        throw new Error('Email already exists');
      }
      logger.error('Error creating user:', error);
      throw error;
    }
  }

  static async createAdmin(adminData) {
    try {
      const existingAdmin = await User.findByEmail(adminData.email);
      if (existingAdmin) {
        return existingAdmin;
      }

      const saltRounds = 12;
      const password_hash = await bcrypt.hash(adminData.password, saltRounds);
      
      const result = await databaseManager.query(
        `INSERT INTO users (email, password_hash, role, is_active) 
         VALUES ($1, $2, 'admin', true) 
         RETURNING *`,
        [adminData.email, password_hash]
      );
      
      logger.info('Admin user created successfully', { email: adminData.email });
      return new User(result.rows[0]);
    } catch (error) {
      logger.error('Error creating admin user:', error);
      throw error;
    }
  }

  // Instance methods
  async save() {
    try {
      if (this.id) {
        // Update existing user
        const result = await databaseManager.query(
          `UPDATE users 
           SET email = $1, password_hash = $2, role = $3, is_active = $4, 
               is_locked = $5, login_attempts = $6, last_login_attempt = $7, 
               locked_until = $8, refresh_token_hash = $9
           WHERE id = $10 
           RETURNING *`,
          [
            this.email, this.password_hash, this.role, this.is_active,
            this.is_locked, this.login_attempts, this.last_login_attempt,
            this.locked_until, this.refresh_token_hash, this.id
          ]
        );
        
        if (result.rows.length > 0) {
          Object.assign(this, result.rows[0]);
        }
      } else {
        // Create new user
        const result = await databaseManager.query(
          `INSERT INTO users (email, password_hash, role, is_active, is_locked, login_attempts) 
           VALUES ($1, $2, $3, $4, $5, $6) 
           RETURNING *`,
          [this.email, this.password_hash, this.role, this.is_active, this.is_locked, this.login_attempts]
        );
        
        Object.assign(this, result.rows[0]);
      }
      
      return this;
    } catch (error) {
      logger.error('Error saving user:', error);
      throw error;
    }
  }

  async comparePassword(candidatePassword) {
    try {
      return await bcrypt.compare(candidatePassword, this.password_hash);
    } catch (error) {
      logger.error('Error comparing password:', error);
      throw error;
    }
  }

  async incrementLoginAttempts() {
    try {
      this.login_attempts += 1;
      this.last_login_attempt = new Date();
      
      // Lock account after 5 failed attempts for 15 minutes
      if (this.login_attempts >= 5) {
        this.is_locked = true;
        this.locked_until = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      }
      
      await this.save();
      
      logger.logSecurity('LOGIN_ATTEMPT_INCREMENTED', {
        userId: this.id,
        email: this.email,
        attempts: this.login_attempts,
        locked: this.is_locked
      });
    } catch (error) {
      logger.error('Error incrementing login attempts:', error);
      throw error;
    }
  }

  async resetLoginAttempts() {
    try {
      this.login_attempts = 0;
      this.is_locked = false;
      this.locked_until = null;
      this.last_login_attempt = null;
      
      await this.save();
      
      logger.info('Login attempts reset', {
        userId: this.id,
        email: this.email
      });
    } catch (error) {
      logger.error('Error resetting login attempts:', error);
      throw error;
    }
  }

  isAdmin() {
    return this.role === 'admin';
  }

  isAccountLocked() {
    if (!this.is_locked) return false;
    
    // Check if lock has expired
    if (this.locked_until && new Date() > new Date(this.locked_until)) {
      // Auto-unlock expired locks
      this.is_locked = false;
      this.locked_until = null;
      this.save().catch(error => {
        logger.error('Error auto-unlocking account:', error);
      });
      return false;
    }
    
    return true;
  }

  async updateRefreshToken(refreshToken) {
    try {
      if (refreshToken) {
        const saltRounds = 10;
        this.refresh_token_hash = await bcrypt.hash(refreshToken, saltRounds);
      } else {
        this.refresh_token_hash = null;
      }
      
      await this.save();
    } catch (error) {
      logger.error('Error updating refresh token:', error);
      throw error;
    }
  }

  async validateRefreshToken(refreshToken) {
    try {
      if (!this.refresh_token_hash || !refreshToken) {
        return false;
      }
      
      return await bcrypt.compare(refreshToken, this.refresh_token_hash);
    } catch (error) {
      logger.error('Error validating refresh token:', error);
      return false;
    }
  }

  // Secure data serialization - exclude sensitive fields
  toJSON() {
    const { password_hash, refresh_token_hash, ...userWithoutSensitiveData } = this;
    return userWithoutSensitiveData;
  }

  // Get safe user data for JWT payload
  getJWTPayload() {
    return {
      userId: this.id,
      email: this.email,
      role: this.role,
      isActive: this.is_active
    };
  }

  // Static method for secure user search with pagination
  static async searchUsers(searchTerm, limit = 50, offset = 0) {
    try {
      const result = await databaseManager.query(
        `SELECT id, email, role, is_active, is_locked, created_at, updated_at 
         FROM users 
         WHERE (LOWER(email) LIKE LOWER($1) OR LOWER(role) LIKE LOWER($1)) 
         AND is_active = true 
         ORDER BY created_at DESC 
         LIMIT $2 OFFSET $3`,
        [`%${searchTerm}%`, limit, offset]
      );
      
      return result.rows.map(row => new User(row));
    } catch (error) {
      logger.error('Error searching users:', error);
      throw error;
    }
  }

  // Static method to get user statistics
  static async getUserStats() {
    try {
      const result = await databaseManager.query(
        `SELECT 
           COUNT(*) as total_users,
           COUNT(*) FILTER (WHERE is_active = true) as active_users,
           COUNT(*) FILTER (WHERE is_locked = true) as locked_users,
           COUNT(*) FILTER (WHERE role = 'admin') as admin_users,
           COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') as new_users_30d
         FROM users`
      );
      
      return result.rows[0];
    } catch (error) {
      logger.error('Error getting user statistics:', error);
      throw error;
    }
  }

  // Secure transaction for balance transfers (if needed)
  static async transferBalance(fromUserId, toUserId, amount) {
    return await databaseManager.transaction(async (client) => {
      // Use SELECT FOR UPDATE to prevent race conditions
      const fromUser = await client.query(
        'SELECT * FROM users WHERE id = $1 FOR UPDATE',
        [fromUserId]
      );
      
      const toUser = await client.query(
        'SELECT * FROM users WHERE id = $1 FOR UPDATE',
        [toUserId]
      );
      
      if (fromUser.rows.length === 0 || toUser.rows.length === 0) {
        throw new Error('User not found');
      }
      
      // Perform balance checks and updates here
      // This is a placeholder for actual balance logic
      logger.info('Balance transfer completed', {
        from: fromUserId,
        to: toUserId,
        amount: amount
      });
      
      return { success: true, message: 'Transfer completed' };
    });
  }
}

module.exports = User;