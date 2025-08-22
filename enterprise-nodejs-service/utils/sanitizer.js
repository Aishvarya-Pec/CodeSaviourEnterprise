const deepmerge = require('deepmerge');
const validator = require('validator');
const logger = require('./logger');

/**
 * Safe object sanitization to prevent prototype pollution
 * Uses deepmerge with custom clone function for security
 */
class Sanitizer {
  /**
   * Sanitize object to prevent prototype pollution
   * @param {Object} obj - Object to sanitize
   * @param {Object} options - Sanitization options
   * @returns {Object} - Sanitized object
   */
  static sanitizeObject(obj, options = {}) {
    try {
      if (!obj || typeof obj !== 'object') {
        return obj;
      }

      const {
        allowedKeys = null, // Array of allowed keys, null means all keys allowed
        maxDepth = 10,
        removeNullValues = false,
        removeEmptyStrings = false,
        trimStrings = true
      } = options;

      return this._deepSanitize(obj, {
        allowedKeys,
        maxDepth,
        removeNullValues,
        removeEmptyStrings,
        trimStrings,
        currentDepth: 0
      });
    } catch (error) {
      logger.error('Error sanitizing object:', error);
      throw new Error('Object sanitization failed');
    }
  }

  /**
   * Deep sanitization with prototype pollution protection
   * @private
   */
  static _deepSanitize(obj, options) {
    const { allowedKeys, maxDepth, removeNullValues, removeEmptyStrings, trimStrings, currentDepth } = options;

    // Prevent deep recursion
    if (currentDepth >= maxDepth) {
      logger.warn('Maximum sanitization depth reached', { maxDepth, currentDepth });
      return {};
    }

    // Handle arrays
    if (Array.isArray(obj)) {
      return obj
        .map(item => {
          if (typeof item === 'object' && item !== null) {
            return this._deepSanitize(item, { ...options, currentDepth: currentDepth + 1 });
          }
          return this._sanitizeValue(item, { removeNullValues, removeEmptyStrings, trimStrings });
        })
        .filter(item => {
          if (removeNullValues && (item === null || item === undefined)) return false;
          if (removeEmptyStrings && item === '') return false;
          return true;
        });
    }

    // Handle objects
    if (typeof obj === 'object' && obj !== null) {
      const sanitized = {};

      for (const [key, value] of Object.entries(obj)) {
        // Prevent prototype pollution
        if (this._isDangerousKey(key)) {
          logger.warn('Dangerous key detected and removed', { key });
          continue;
        }

        // Check allowed keys
        if (allowedKeys && !allowedKeys.includes(key)) {
          logger.debug('Key not in allowed list', { key, allowedKeys });
          continue;
        }

        // Sanitize key
        const sanitizedKey = this._sanitizeKey(key);
        if (!sanitizedKey) {
          continue;
        }

        // Recursively sanitize value
        if (typeof value === 'object' && value !== null) {
          const sanitizedValue = this._deepSanitize(value, { ...options, currentDepth: currentDepth + 1 });
          if (Object.keys(sanitizedValue).length > 0 || Array.isArray(sanitizedValue)) {
            sanitized[sanitizedKey] = sanitizedValue;
          }
        } else {
          const sanitizedValue = this._sanitizeValue(value, { removeNullValues, removeEmptyStrings, trimStrings });
          if (sanitizedValue !== undefined) {
            sanitized[sanitizedKey] = sanitizedValue;
          }
        }
      }

      return sanitized;
    }

    return this._sanitizeValue(obj, { removeNullValues, removeEmptyStrings, trimStrings });
  }

  /**
   * Check if key is dangerous for prototype pollution
   * @private
   */
  static _isDangerousKey(key) {
    const dangerousKeys = [
      '__proto__',
      'constructor',
      'prototype',
      '__defineGetter__',
      '__defineSetter__',
      '__lookupGetter__',
      '__lookupSetter__',
      'hasOwnProperty',
      'isPrototypeOf',
      'propertyIsEnumerable',
      'toString',
      'valueOf'
    ];

    return dangerousKeys.includes(key) || key.startsWith('__');
  }

  /**
   * Sanitize object key
   * @private
   */
  static _sanitizeKey(key) {
    if (typeof key !== 'string') {
      return null;
    }

    // Remove dangerous characters
    const sanitized = key
      .replace(/[<>"'&]/g, '') // Remove HTML/XML dangerous chars
      .replace(/[\x00-\x1f\x7f-\x9f]/g, '') // Remove control characters
      .trim();

    // Validate key length
    if (sanitized.length === 0 || sanitized.length > 100) {
      return null;
    }

    return sanitized;
  }

  /**
   * Sanitize primitive values
   * @private
   */
  static _sanitizeValue(value, options) {
    const { removeNullValues, removeEmptyStrings, trimStrings } = options;

    // Handle null/undefined
    if (value === null || value === undefined) {
      return removeNullValues ? undefined : value;
    }

    // Handle strings
    if (typeof value === 'string') {
      let sanitized = value;
      
      if (trimStrings) {
        sanitized = sanitized.trim();
      }
      
      if (removeEmptyStrings && sanitized === '') {
        return undefined;
      }
      
      // Remove null bytes and control characters
      sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
      
      return sanitized;
    }

    // Handle numbers
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        logger.warn('Non-finite number detected', { value });
        return 0;
      }
      return value;
    }

    // Handle booleans
    if (typeof value === 'boolean') {
      return value;
    }

    // Handle dates
    if (value instanceof Date) {
      return isNaN(value.getTime()) ? new Date() : value;
    }

    // For other types, return as-is but log warning
    logger.warn('Unexpected value type during sanitization', { type: typeof value, value });
    return value;
  }

  /**
   * Sanitize HTML input to prevent XSS
   * @param {string} input - HTML input to sanitize
   * @returns {string} - Sanitized HTML
   */
  static sanitizeHTML(input) {
    if (typeof input !== 'string') {
      return '';
    }

    return validator.escape(input)
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control characters
      .trim();
  }

  /**
   * Sanitize SQL input to prevent injection
   * Note: This is a basic sanitizer. Always use parameterized queries!
   * @param {string} input - SQL input to sanitize
   * @returns {string} - Sanitized input
   */
  static sanitizeSQL(input) {
    if (typeof input !== 'string') {
      return '';
    }

    // Remove dangerous SQL characters and keywords
    return input
      .replace(/[';"\\]/g, '') // Remove quotes and backslashes
      .replace(/--/g, '') // Remove SQL comments
      .replace(/\/\*/g, '') // Remove block comment start
      .replace(/\*\//g, '') // Remove block comment end
      .replace(/\b(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC|EXECUTE|UNION|SELECT)\b/gi, '') // Remove dangerous keywords
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control characters
      .trim();
  }

  /**
   * Sanitize email input
   * @param {string} email - Email to sanitize
   * @returns {string|null} - Sanitized email or null if invalid
   */
  static sanitizeEmail(email) {
    if (typeof email !== 'string') {
      return null;
    }

    const sanitized = email.toLowerCase().trim();
    
    if (!validator.isEmail(sanitized)) {
      return null;
    }

    return sanitized;
  }

  /**
   * Sanitize URL input
   * @param {string} url - URL to sanitize
   * @returns {string|null} - Sanitized URL or null if invalid
   */
  static sanitizeURL(url) {
    if (typeof url !== 'string') {
      return null;
    }

    const sanitized = url.trim();
    
    if (!validator.isURL(sanitized, {
      protocols: ['http', 'https'],
      require_protocol: true
    })) {
      return null;
    }

    return sanitized;
  }

  /**
   * Safe merge objects using deepmerge with security options
   * @param {Object} target - Target object
   * @param {Object} source - Source object
   * @param {Object} options - Merge options
   * @returns {Object} - Safely merged object
   */
  static safeMerge(target, source, options = {}) {
    try {
      const mergeOptions = {
        // Custom clone function to prevent prototype pollution
        clone: (value) => {
          if (value && typeof value === 'object') {
            return this.sanitizeObject(value, options.sanitizeOptions);
          }
          return value;
        },
        // Custom merge function for arrays
        arrayMerge: options.arrayMerge || ((target, source) => {
          return source; // Replace arrays by default
        }),
        // Custom merge function for objects
        customMerge: (key) => {
          if (this._isDangerousKey(key)) {
            return () => undefined; // Ignore dangerous keys
          }
          return undefined; // Use default merge
        }
      };

      // Sanitize inputs first
      const sanitizedTarget = this.sanitizeObject(target, options.sanitizeOptions);
      const sanitizedSource = this.sanitizeObject(source, options.sanitizeOptions);

      return deepmerge(sanitizedTarget, sanitizedSource, mergeOptions);
    } catch (error) {
      logger.error('Error in safe merge:', error);
      throw new Error('Safe merge failed');
    }
  }

  /**
   * Validate and sanitize request body
   * @param {Object} body - Request body to sanitize
   * @param {Object} schema - Validation schema
   * @returns {Object} - Sanitized body
   */
  static sanitizeRequestBody(body, schema = {}) {
    try {
      const {
        allowedFields = null,
        maxDepth = 5,
        maxSize = 1024 * 1024, // 1MB
        removeNullValues = true,
        removeEmptyStrings = false,
        trimStrings = true
      } = schema;

      // Check body size (rough estimate)
      const bodySize = JSON.stringify(body).length;
      if (bodySize > maxSize) {
        throw new Error(`Request body too large: ${bodySize} bytes`);
      }

      return this.sanitizeObject(body, {
        allowedKeys: allowedFields,
        maxDepth,
        removeNullValues,
        removeEmptyStrings,
        trimStrings
      });
    } catch (error) {
      logger.error('Error sanitizing request body:', error);
      throw error;
    }
  }
}

module.exports = Sanitizer;