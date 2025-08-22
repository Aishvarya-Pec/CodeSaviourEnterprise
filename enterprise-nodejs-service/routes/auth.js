const express = require('express');
const { body } = require('express-validator');
const User = require('../models/User');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { 
  generateToken, 
  generateTokens, 
  refreshTokens, 
  revokeTokens,
  authenticateToken, 
  verifyGoogleToken, 
  verifyGitHubToken,
  authRateLimit,
  refreshRateLimit,
  apiVersion,
  auditLog
} = require('../middleware/auth');
const { catchAsync, handleValidationResult, createAppError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();

// Apply API versioning
router.use(apiVersion('v1'));

// Validation rules for registration
const registerValidation = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail()
    .isLength({ max: 255 })
    .withMessage('Email cannot exceed 255 characters'),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),
  
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    })
];

// Validation rules for login
const loginValidation = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', registerValidation, handleValidationResult, catchAsync(async (req, res) => {
  const { email, password } = req.body;

  // Check if user already exists
  const existingUser = await User.findByEmail(email);
  if (existingUser) {
    logger.logAuth('REGISTER_ATTEMPT', email, false, { reason: 'User already exists' }, req);
    throw createAppError('User with this email already exists', 409, 'USER_EXISTS', true);
  }

  // Create new user (hashing handled in model)
  const user = await User.create({
    email,
    password,
    role: 'user'
  });

  // Generate JWT tokens
  const tokens = generateTokens(user);

  // Log successful registration
  logger.logAuth('REGISTER', email, true, { userId: user.id }, req);

  // Return success response (password is excluded by toJSON transform)
  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: {
      user,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.expiresIn,
      tokenType: 'Bearer'
    }
  });
}));

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user and return token
 * @access  Public
 */
router.post('/login', loginValidation, handleValidationResult, catchAsync(async (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  const user = await User.findByEmail(email);
  
  if (!user) {
    logger.logAuth('LOGIN_ATTEMPT', email, false, { reason: 'User not found' }, req);
    throw createAppError('Invalid email or password', 401, 'INVALID_CREDENTIALS', true);
  }

  // Check if account is locked
  if (user.isAccountLocked()) {
    const lockTimeRemaining = user.locked_until ? Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / (1000 * 60)) : 15;
    logger.logAuth('LOGIN_ATTEMPT', email, false, { 
      reason: 'Account locked',
      lockTimeRemaining: `${lockTimeRemaining} minutes`
    }, req);
    
    throw createAppError(
      `Account is temporarily locked. Try again in ${lockTimeRemaining} minutes.`,
      423,
      'ACCOUNT_LOCKED',
      true
    );
  }

  // Check if account is active
  if (!user.is_active) {
    logger.logAuth('LOGIN_ATTEMPT', email, false, { reason: 'Account inactive' }, req);
    throw createAppError('Account is inactive. Please contact support.', 401, 'ACCOUNT_INACTIVE', true);
  }

  // Verify password
  const isPasswordValid = await user.comparePassword(password);
  
  if (!isPasswordValid) {
    // Increment login attempts
    await user.incrementLoginAttempts();
    
    logger.logAuth('LOGIN_ATTEMPT', email, false, { 
      reason: 'Invalid password',
      attempts: user.login_attempts
    }, req);
    
    throw createAppError('Invalid email or password', 401, 'INVALID_CREDENTIALS', true);
  }

  // Reset login attempts on successful login
  await user.resetLoginAttempts();

  // Generate JWT tokens (access + refresh)
  const tokens = generateTokens(user);

  // Log successful login
  logger.logAuth('LOGIN', email, true, { 
    userId: user.id,
    role: user.role,
    tokenId: tokens.tokenId,
    sessionId: tokens.sessionId
  }, req);

  // Return success response (password is excluded by toJSON transform)
  const userResponse = user.toJSON();
  
  res.json({
    success: true,
    message: 'Login successful',
    data: {
      user: userResponse,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.expiresIn,
      tokenType: 'Bearer'
    }
  });
}));

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user and revoke tokens
 * @access  Private
 */
router.post('/logout', authenticateToken, auditLog('LOGOUT'), catchAsync(async (req, res) => {
  const { refreshToken } = req.body;
  const accessToken = req.headers.authorization?.substring(7);
  
  // Revoke tokens
  revokeTokens(accessToken, refreshToken);
  
  // Log logout event
  logger.logAuth('LOGOUT', req.user.email, true, { 
    userId: req.user.id,
    tokenId: req.tokenPayload?.tokenId,
    sessionId: req.tokenPayload?.sessionId
  }, req);

  res.json({
    success: true,
    message: 'Logout successful. Tokens have been revoked.'
  });
}));

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public
 */
router.post('/refresh', refreshRateLimit, [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required')
], handleValidationResult, catchAsync(async (req, res) => {
  const { refreshToken } = req.body;
  
  try {
    const tokens = await refreshTokens(refreshToken);
    
    res.json({
      success: true,
      message: 'Tokens refreshed successfully',
      data: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn,
        tokenType: 'Bearer'
      }
    });
  } catch (error) {
    logger.logSecurity('REFRESH_TOKEN_ERROR', error.message, req);
    throw createAppError('Invalid or expired refresh token', 401, 'INVALID_REFRESH_TOKEN', true);
  }
}));

/**
 * @route   POST /api/auth/oauth/google
 * @desc    Authenticate with Google OAuth2
 * @access  Public
 */
router.post('/oauth/google', authRateLimit, [
  body('idToken')
    .notEmpty()
    .withMessage('Google ID token is required')
], handleValidationResult, catchAsync(async (req, res) => {
  const { idToken } = req.body;
  
  try {
    const googleUser = await verifyGoogleToken(idToken);
    
    // Find or create user
    let user = await User.findByEmail(googleUser.email);
    
    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString('hex');
      user = await User.create({
        email: googleUser.email,
        password: randomPassword,
        role: 'user'
      });
      
      logger.logAuth('OAUTH_REGISTER', googleUser.email, true, {
        userId: user.id,
        provider: 'google'
      }, req);
    } else {
      // Update user info if needed
      if (user.provider !== 'google') {
        user.provider = 'google';
        user.picture = googleUser.picture;
        await user.save();
      }
    }
    
    if (!user.is_active) {
      throw createAppError('Account is inactive', 401, 'ACCOUNT_INACTIVE', true);
    }
    
    const tokens = generateTokens(user);
    
    logger.logAuth('OAUTH_LOGIN', googleUser.email, true, {
      userId: user.id,
      provider: 'google',
      tokenId: tokens.tokenId
    }, req);
    
    res.json({
      success: true,
      message: 'Google OAuth login successful',
      data: {
        user: user.toJSON(),
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn,
        tokenType: 'Bearer'
      }
    });
  } catch (error) {
    logger.logSecurity('OAUTH_ERROR', `Google OAuth failed: ${error.message}`, req);
    throw createAppError('Google authentication failed', 401, 'OAUTH_FAILED', true);
  }
}));

/**
 * @route   POST /api/auth/oauth/github
 * @desc    Authenticate with GitHub OAuth2
 * @access  Public
 */
router.post('/oauth/github', authRateLimit, [
  body('accessToken')
    .notEmpty()
    .withMessage('GitHub access token is required')
], handleValidationResult, catchAsync(async (req, res) => {
  const { accessToken } = req.body;
  
  try {
    const githubUser = await verifyGitHubToken(accessToken);
    
    if (!githubUser.email) {
      throw createAppError('GitHub account must have a public email', 400, 'NO_PUBLIC_EMAIL', true);
    }
    
    // Find or create user
    let user = await User.findByEmail(githubUser.email);
    
    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString('hex');
      user = await User.create({
        email: githubUser.email,
        password: randomPassword,
        role: 'user'
      });
      
      logger.logAuth('OAUTH_REGISTER', githubUser.email, true, {
        userId: user.id,
        provider: 'github'
      }, req);
    } else {
      // Update user info if needed
      if (user.provider !== 'github') {
        user.provider = 'github';
        user.picture = githubUser.picture;
        await user.save();
      }
    }
    
    if (!user.is_active) {
      throw createAppError('Account is inactive', 401, 'ACCOUNT_INACTIVE', true);
    }
    
    const tokens = generateTokens(user);
    
    logger.logAuth('OAUTH_LOGIN', githubUser.email, true, {
      userId: user.id,
      provider: 'github',
      tokenId: tokens.tokenId
    }, req);
    
    res.json({
      success: true,
      message: 'GitHub OAuth login successful',
      data: {
        user: user.toJSON(),
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn,
        tokenType: 'Bearer'
      }
    });
  } catch (error) {
    logger.logSecurity('OAUTH_ERROR', `GitHub OAuth failed: ${error.message}`, req);
    throw createAppError('GitHub authentication failed', 401, 'OAUTH_FAILED', true);
  }
}));

/**
 * @route   GET /api/auth/profile
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/profile', authenticateToken, catchAsync(async (req, res) => {
  // Fetch fresh user data
  const user = await User.findById(req.user.id);
  
  if (!user) {
    throw createAppError('User not found', 404, 'USER_NOT_FOUND', true);
  }

  res.json({
    success: true,
    message: 'Profile retrieved successfully',
    data: {
      user
    }
  });
}));

/**
 * @route   PUT /api/auth/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put('/profile', 
  authenticateToken,
  [
    body('email')
      .optional()
      .isEmail()
      .withMessage('Please provide a valid email address')
      .normalizeEmail()
      .isLength({ max: 255 })
      .withMessage('Email cannot exceed 255 characters')
  ],
  handleValidationResult,
  catchAsync(async (req, res) => {
    const { email } = req.body;
    const userId = req.user.id;

    // If email is being updated, check if it's already taken
    if (email && email !== req.user.email) {
      const existingUser = await User.findByEmail(email);
      if (existingUser && existingUser.id !== userId) {
        throw createAppError('Email is already in use', 409, 'EMAIL_EXISTS', true);
      }
    }

    // Update user
    const user = await User.findById(userId);
    if (!user) {
      throw createAppError('User not found', 404, 'USER_NOT_FOUND', true);
    }
    if (email) {
      user.email = email;
    }
    const updatedUser = await user.save();

    if (!updatedUser) {
      throw createAppError('User not found', 404, 'USER_NOT_FOUND', true);
    }

    logger.info('User profile updated', {
      userId: updatedUser.id,
      email: updatedUser.email,
      updatedFields: Object.keys(req.body)
    });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: updatedUser
      }
    });
  })
);

/**
 * @route   PUT /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.put('/change-password',
  authenticateToken,
  [
    body('currentPassword')
      .notEmpty()
      .withMessage('Current password is required'),
    
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('New password must be at least 8 characters long')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('New password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),
    
    body('confirmNewPassword')
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error('New password confirmation does not match new password');
        }
        return true;
      })
  ],
  handleValidationResult,
  catchAsync(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    // Get user with password
    const user = await User.findById(userId);
    
    if (!user) {
      throw createAppError('User not found', 404, 'USER_NOT_FOUND', true);
    }

    // Verify current password
    const isCurrentPasswordValid = await user.comparePassword(currentPassword);
    
    if (!isCurrentPasswordValid) {
      logger.logSecurity('INVALID_PASSWORD_CHANGE', 'Invalid current password provided', req);
      throw createAppError('Current password is incorrect', 401, 'INVALID_CURRENT_PASSWORD', true);
    }

    // Update password by hashing and saving
    user.password_hash = await bcrypt.hash(newPassword, 12);
    await user.save();

    logger.logAuth('PASSWORD_CHANGE', user.email, true, { userId: user.id }, req);

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  })
);

/**
 * @route   GET /api/auth/verify-token
 * @desc    Verify if token is valid
 * @access  Private
 */
router.get('/verify-token', authenticateToken, catchAsync(async (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      user: req.user,
      tokenPayload: {
        userId: req.tokenPayload.userId,
        email: req.tokenPayload.email,
        role: req.tokenPayload.role,
        iat: req.tokenPayload.iat,
        exp: req.tokenPayload.exp
      }
    }
  });
}));

module.exports = router;