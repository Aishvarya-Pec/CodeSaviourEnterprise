const NodeCache = require('node-cache');
const logger = require('./logger');
const crypto = require('crypto');

/**
 * Secure cache implementation with TTL and invalidation
 * Fixes LRU cache issues with proper TTL and write invalidation
 */
class SecureCache {
  constructor(options = {}) {
    const {
      stdTTL = 300, // 5 minutes default TTL
      checkperiod = 60, // Check for expired keys every 60 seconds
      maxKeys = 1000, // Maximum number of keys
      deleteOnExpire = true,
      useClones = false // Don't clone objects for better performance
    } = options;

    this.cache = new NodeCache({
      stdTTL,
      checkperiod,
      maxKeys,
      deleteOnExpire,
      useClones
    });

    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      invalidations: 0
    };

    // Set up event listeners
    this.cache.on('set', (key, value) => {
      this.stats.sets++;
      logger.debug('Cache SET', { key, hasValue: !!value });
    });

    this.cache.on('del', (key, value) => {
      this.stats.deletes++;
      logger.debug('Cache DELETE', { key });
    });

    this.cache.on('expired', (key, value) => {
      logger.debug('Cache EXPIRED', { key });
    });

    this.cache.on('flush', () => {
      logger.info('Cache FLUSHED');
    });

    // Bind methods to preserve context
    this.get = this.get.bind(this);
    this.set = this.set.bind(this);
    this.del = this.del.bind(this);
    this.invalidate = this.invalidate.bind(this);
  }

  /**
   * Get value from cache
   * @param {string} key - Cache key
   * @returns {*} - Cached value or undefined
   */
  get(key) {
    try {
      const sanitizedKey = this._sanitizeKey(key);
      const value = this.cache.get(sanitizedKey);
      
      if (value !== undefined) {
        this.stats.hits++;
        logger.debug('Cache HIT', { key: sanitizedKey });
        return value;
      } else {
        this.stats.misses++;
        logger.debug('Cache MISS', { key: sanitizedKey });
        return undefined;
      }
    } catch (error) {
      logger.error('Cache GET error:', error);
      this.stats.misses++;
      return undefined;
    }
  }

  /**
   * Set value in cache with optional TTL
   * @param {string} key - Cache key
   * @param {*} value - Value to cache
   * @param {number} ttl - Time to live in seconds (optional)
   * @returns {boolean} - Success status
   */
  set(key, value, ttl) {
    try {
      const sanitizedKey = this._sanitizeKey(key);
      
      // Don't cache null or undefined values
      if (value === null || value === undefined) {
        logger.debug('Skipping cache SET for null/undefined value', { key: sanitizedKey });
        return false;
      }

      const success = this.cache.set(sanitizedKey, value, ttl);
      
      if (success) {
        logger.debug('Cache SET success', { 
          key: sanitizedKey, 
          ttl: ttl || 'default',
          valueType: typeof value
        });
      } else {
        logger.warn('Cache SET failed', { key: sanitizedKey });
      }
      
      return success;
    } catch (error) {
      logger.error('Cache SET error:', error);
      return false;
    }
  }

  /**
   * Delete value from cache
   * @param {string} key - Cache key
   * @returns {number} - Number of deleted keys
   */
  del(key) {
    try {
      const sanitizedKey = this._sanitizeKey(key);
      const deleted = this.cache.del(sanitizedKey);
      
      if (deleted > 0) {
        logger.debug('Cache DELETE success', { key: sanitizedKey, count: deleted });
      }
      
      return deleted;
    } catch (error) {
      logger.error('Cache DELETE error:', error);
      return 0;
    }
  }

  /**
   * Check if key exists in cache
   * @param {string} key - Cache key
   * @returns {boolean} - Existence status
   */
  has(key) {
    try {
      const sanitizedKey = this._sanitizeKey(key);
      return this.cache.has(sanitizedKey);
    } catch (error) {
      logger.error('Cache HAS error:', error);
      return false;
    }
  }

  /**
   * Get multiple values from cache
   * @param {string[]} keys - Array of cache keys
   * @returns {Object} - Object with key-value pairs
   */
  mget(keys) {
    try {
      const sanitizedKeys = keys.map(key => this._sanitizeKey(key));
      const values = this.cache.mget(sanitizedKeys);
      
      // Update stats
      Object.keys(values).forEach(key => {
        if (values[key] !== undefined) {
          this.stats.hits++;
        } else {
          this.stats.misses++;
        }
      });
      
      return values;
    } catch (error) {
      logger.error('Cache MGET error:', error);
      return {};
    }
  }

  /**
   * Set multiple values in cache
   * @param {Object} keyValuePairs - Object with key-value pairs
   * @param {number} ttl - Time to live in seconds (optional)
   * @returns {boolean} - Success status
   */
  mset(keyValuePairs, ttl) {
    try {
      const sanitizedPairs = {};
      
      Object.entries(keyValuePairs).forEach(([key, value]) => {
        if (value !== null && value !== undefined) {
          sanitizedPairs[this._sanitizeKey(key)] = value;
        }
      });
      
      const success = this.cache.mset(sanitizedPairs, ttl);
      
      if (success) {
        this.stats.sets += Object.keys(sanitizedPairs).length;
        logger.debug('Cache MSET success', { 
          count: Object.keys(sanitizedPairs).length,
          ttl: ttl || 'default'
        });
      }
      
      return success;
    } catch (error) {
      logger.error('Cache MSET error:', error);
      return false;
    }
  }

  /**
   * Invalidate cache entries by pattern
   * @param {string} pattern - Pattern to match keys (supports wildcards)
   * @returns {number} - Number of invalidated keys
   */
  invalidate(pattern) {
    try {
      const keys = this.cache.keys();
      let invalidated = 0;
      
      const regex = new RegExp(
        pattern
          .replace(/\*/g, '.*')
          .replace(/\?/g, '.')
      );
      
      keys.forEach(key => {
        if (regex.test(key)) {
          this.cache.del(key);
          invalidated++;
        }
      });
      
      this.stats.invalidations += invalidated;
      
      logger.info('Cache invalidation completed', {
        pattern,
        invalidated,
        totalKeys: keys.length
      });
      
      return invalidated;
    } catch (error) {
      logger.error('Cache invalidation error:', error);
      return 0;
    }
  }

  /**
   * Invalidate cache entries for specific user
   * @param {string} userId - User ID
   * @returns {number} - Number of invalidated keys
   */
  invalidateUser(userId) {
    return this.invalidate(`user:${userId}:*`);
  }

  /**
   * Invalidate cache entries for specific resource type
   * @param {string} resourceType - Resource type (e.g., 'users', 'posts')
   * @returns {number} - Number of invalidated keys
   */
  invalidateResource(resourceType) {
    return this.invalidate(`${resourceType}:*`);
  }

  /**
   * Get cache statistics
   * @returns {Object} - Cache statistics
   */
  getStats() {
    const cacheStats = this.cache.getStats();
    
    return {
      ...this.stats,
      keys: cacheStats.keys,
      hits: cacheStats.hits || this.stats.hits,
      misses: cacheStats.misses || this.stats.misses,
      hitRate: this.stats.hits / (this.stats.hits + this.stats.misses) || 0,
      ksize: cacheStats.ksize,
      vsize: cacheStats.vsize
    };
  }

  /**
   * Clear all cache entries
   */
  flush() {
    try {
      this.cache.flushAll();
      
      // Reset stats
      this.stats = {
        hits: 0,
        misses: 0,
        sets: 0,
        deletes: 0,
        invalidations: 0
      };
      
      logger.info('Cache flushed successfully');
    } catch (error) {
      logger.error('Cache flush error:', error);
    }
  }

  /**
   * Get all cache keys
   * @returns {string[]} - Array of cache keys
   */
  keys() {
    try {
      return this.cache.keys();
    } catch (error) {
      logger.error('Cache keys error:', error);
      return [];
    }
  }

  /**
   * Get TTL for a key
   * @param {string} key - Cache key
   * @returns {number} - TTL in seconds, 0 if no TTL, undefined if key doesn't exist
   */
  getTtl(key) {
    try {
      const sanitizedKey = this._sanitizeKey(key);
      return this.cache.getTtl(sanitizedKey);
    } catch (error) {
      logger.error('Cache getTtl error:', error);
      return undefined;
    }
  }

  /**
   * Set TTL for existing key
   * @param {string} key - Cache key
   * @param {number} ttl - TTL in seconds
   * @returns {boolean} - Success status
   */
  setTtl(key, ttl) {
    try {
      const sanitizedKey = this._sanitizeKey(key);
      return this.cache.ttl(sanitizedKey, ttl);
    } catch (error) {
      logger.error('Cache setTtl error:', error);
      return false;
    }
  }

  /**
   * Sanitize cache key to prevent injection
   * @private
   */
  _sanitizeKey(key) {
    if (typeof key !== 'string') {
      throw new Error('Cache key must be a string');
    }
    
    // Remove dangerous characters and limit length
    const sanitized = key
      .replace(/[^a-zA-Z0-9:_-]/g, '_')
      .substring(0, 250);
    
    if (sanitized.length === 0) {
      throw new Error('Invalid cache key after sanitization');
    }
    
    return sanitized;
  }

  /**
   * Generate cache key with hash for complex objects
   * @param {string} prefix - Key prefix
   * @param {*} data - Data to hash
   * @returns {string} - Generated cache key
   */
  generateKey(prefix, data) {
    try {
      const hash = crypto
        .createHash('sha256')
        .update(JSON.stringify(data))
        .digest('hex')
        .substring(0, 16);
      
      return `${prefix}:${hash}`;
    } catch (error) {
      logger.error('Cache key generation error:', error);
      return `${prefix}:${Date.now()}`;
    }
  }

  /**
   * Wrap a function with caching
   * @param {Function} fn - Function to wrap
   * @param {Object} options - Caching options
   * @returns {Function} - Wrapped function
   */
  wrap(fn, options = {}) {
    const {
      keyGenerator = (...args) => `fn:${fn.name}:${JSON.stringify(args)}`,
      ttl,
      invalidateOnError = false
    } = options;

    return async (...args) => {
      try {
        const key = keyGenerator(...args);
        
        // Try to get from cache first
        let result = this.get(key);
        
        if (result !== undefined) {
          return result;
        }
        
        // Execute function and cache result
        result = await fn(...args);
        
        if (result !== null && result !== undefined) {
          this.set(key, result, ttl);
        }
        
        return result;
      } catch (error) {
        if (invalidateOnError) {
          const key = keyGenerator(...args);
          this.del(key);
        }
        throw error;
      }
    };
  }

  /**
   * Close cache and cleanup
   */
  close() {
    try {
      this.cache.close();
      logger.info('Cache closed successfully');
    } catch (error) {
      logger.error('Cache close error:', error);
    }
  }
}

// Create default cache instance
const defaultCache = new SecureCache({
  stdTTL: 300, // 5 minutes
  checkperiod: 60, // 1 minute
  maxKeys: 1000
});

// Cache middleware for Express routes
const cacheMiddleware = (options = {}) => {
  const {
    ttl = 300,
    keyGenerator = (req) => `route:${req.method}:${req.originalUrl}`,
    condition = () => true,
    cache = defaultCache
  } = options;

  return (req, res, next) => {
    try {
      // Skip caching if condition is not met
      if (!condition(req)) {
        return next();
      }

      const key = keyGenerator(req);
      const cachedResponse = cache.get(key);

      if (cachedResponse) {
        logger.debug('Serving cached response', { key });
        return res.json(cachedResponse);
      }

      // Override res.json to cache the response
      const originalJson = res.json;
      res.json = function(data) {
        // Cache successful responses only
        if (res.statusCode >= 200 && res.statusCode < 300) {
          cache.set(key, data, ttl);
        }
        return originalJson.call(this, data);
      };

      next();
    } catch (error) {
      logger.error('Cache middleware error:', error);
      next();
    }
  };
};

module.exports = {
  SecureCache,
  defaultCache,
  cacheMiddleware
};