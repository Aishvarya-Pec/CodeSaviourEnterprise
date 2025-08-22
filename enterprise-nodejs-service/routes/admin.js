const express = require('express');
const { body, query } = require('express-validator');
const User = require('../models/User');
const { authenticateToken, requireAdmin } = require('../middleware/auth');
const { catchAsync, handleValidationResult, createAppError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();

// Apply authentication and admin authorization to all routes
router.use(authenticateToken);
router.use(requireAdmin);

/**
 * @route   GET /api/admin/users
 * @desc    Get all users with pagination and filtering
 * @access  Admin only
 */
router.get('/users',
  [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100'),
    
    query('role')
      .optional()
      .isIn(['user', 'admin'])
      .withMessage('Role must be either user or admin'),
    
    query('isActive')
      .optional()
      .isBoolean()
      .withMessage('isActive must be a boolean'),
    
    query('search')
      .optional()
      .isLength({ min: 1, max: 100 })
      .withMessage('Search term must be between 1 and 100 characters')
  ],
  handleValidationResult,
  catchAsync(async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Build filter object
    const filter = {};
    
    if (req.query.role) {
      filter.role = req.query.role;
    }
    
    if (req.query.isActive !== undefined) {
      filter.isActive = req.query.isActive === 'true';
    }
    
    if (req.query.search) {
      filter.email = { $regex: req.query.search, $options: 'i' };
    }

    // Get users with pagination
    const [users, totalUsers] = await Promise.all([
      User.find(filter)
        .select('-password')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments(filter)
    ]);

    const totalPages = Math.ceil(totalUsers / limit);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    logger.info('Admin users list retrieved', {
      adminId: req.user._id,
      adminEmail: req.user.email,
      page,
      limit,
      totalUsers,
      filter
    });

    res.json({
      success: true,
      message: 'Users retrieved successfully',
      data: {
        users,
        pagination: {
          currentPage: page,
          totalPages,
          totalUsers,
          hasNextPage,
          hasPrevPage,
          limit
        },
        filter
      }
    });
  })
);

/**
 * @route   GET /api/admin/users/:id
 * @desc    Get specific user by ID
 * @access  Admin only
 */
router.get('/users/:id', catchAsync(async (req, res) => {
  const { id } = req.params;

  const user = await User.findById(id).select('-password');
  
  if (!user) {
    throw createAppError('User not found', 404, 'USER_NOT_FOUND', true);
  }

  logger.info('Admin user details retrieved', {
    adminId: req.user._id,
    adminEmail: req.user.email,
    targetUserId: user._id,
    targetUserEmail: user.email
  });

  res.json({
    success: true,
    message: 'User retrieved successfully',
    data: {
      user
    }
  });
}));

/**
 * @route   PUT /api/admin/users/:id
 * @desc    Update user by ID
 * @access  Admin only
 */
router.put('/users/:id',
  [
    body('email')
      .optional()
      .isEmail()
      .withMessage('Please provide a valid email address')
      .normalizeEmail()
      .isLength({ max: 255 })
      .withMessage('Email cannot exceed 255 characters'),
    
    body('role')
      .optional()
      .isIn(['user', 'admin'])
      .withMessage('Role must be either user or admin'),
    
    body('isActive')
      .optional()
      .isBoolean()
      .withMessage('isActive must be a boolean')
  ],
  handleValidationResult,
  catchAsync(async (req, res) => {
    const { id } = req.params;
    const { email, role, isActive } = req.body;

    // Find the user to update
    const user = await User.findById(id);
    
    if (!user) {
      throw createAppError('User not found', 404, 'USER_NOT_FOUND', true);
    }

    // Prevent admin from deactivating themselves
    if (user._id.toString() === req.user._id.toString() && isActive === false) {
      throw createAppError('You cannot deactivate your own account', 400, 'CANNOT_DEACTIVATE_SELF', true);
    }

    // Prevent admin from changing their own role to user
    if (user._id.toString() === req.user._id.toString() && role === 'user') {
      throw createAppError('You cannot change your own role', 400, 'CANNOT_CHANGE_OWN_ROLE', true);
    }

    // Check if email is already taken by another user
    if (email && email !== user.email) {
      const existingUser = await User.findByEmail(email);
      if (existingUser && existingUser._id.toString() !== id) {
        throw createAppError('Email is already in use', 409, 'EMAIL_EXISTS', true);
      }
    }

    // Update user
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { email, role, isActive },
      { new: true, runValidators: true }
    ).select('-password');

    logger.info('Admin updated user', {
      adminId: req.user._id,
      adminEmail: req.user.email,
      targetUserId: updatedUser._id,
      targetUserEmail: updatedUser.email,
      updatedFields: Object.keys(req.body)
    });

    res.json({
      success: true,
      message: 'User updated successfully',
      data: {
        user: updatedUser
      }
    });
  })
);

/**
 * @route   DELETE /api/admin/users/:id
 * @desc    Delete user by ID
 * @access  Admin only
 */
router.delete('/users/:id', catchAsync(async (req, res) => {
  const { id } = req.params;

  // Find the user to delete
  const user = await User.findById(id);
  
  if (!user) {
    throw createAppError('User not found', 404, 'USER_NOT_FOUND', true);
  }

  // Prevent admin from deleting themselves
  if (user._id.toString() === req.user._id.toString()) {
    throw createAppError('You cannot delete your own account', 400, 'CANNOT_DELETE_SELF', true);
  }

  // Delete the user
  await User.findByIdAndDelete(id);

  logger.warn('Admin deleted user', {
    adminId: req.user._id,
    adminEmail: req.user.email,
    deletedUserId: user._id,
    deletedUserEmail: user.email
  });

  res.json({
    success: true,
    message: 'User deleted successfully',
    data: {
      deletedUser: {
        id: user._id,
        email: user.email
      }
    }
  });
}));

/**
 * @route   POST /api/admin/users/:id/unlock
 * @desc    Unlock user account
 * @access  Admin only
 */
router.post('/users/:id/unlock', catchAsync(async (req, res) => {
  const { id } = req.params;

  const user = await User.findById(id);
  
  if (!user) {
    throw createAppError('User not found', 404, 'USER_NOT_FOUND', true);
  }

  if (!user.isLocked) {
    throw createAppError('User account is not locked', 400, 'ACCOUNT_NOT_LOCKED', true);
  }

  // Reset login attempts and unlock
  await user.resetLoginAttempts();

  logger.info('Admin unlocked user account', {
    adminId: req.user._id,
    adminEmail: req.user.email,
    targetUserId: user._id,
    targetUserEmail: user.email
  });

  res.json({
    success: true,
    message: 'User account unlocked successfully',
    data: {
      user: {
        id: user._id,
        email: user.email,
        isLocked: false
      }
    }
  });
}));

/**
 * @route   GET /api/admin/stats
 * @desc    Get system statistics
 * @access  Admin only
 */
router.get('/stats', catchAsync(async (req, res) => {
  const [totalUsers, activeUsers, adminUsers, lockedUsers] = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ isActive: true }),
    User.countDocuments({ role: 'admin' }),
    User.countDocuments({ lockUntil: { $gt: new Date() } })
  ]);

  // Get user registration stats for the last 30 days
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
  
  const recentRegistrations = await User.countDocuments({
    createdAt: { $gte: thirtyDaysAgo }
  });

  // Get users by role
  const usersByRole = await User.aggregate([
    {
      $group: {
        _id: '$role',
        count: { $sum: 1 }
      }
    }
  ]);

  // Get recent users (last 10)
  const recentUsers = await User.find()
    .select('email role isActive createdAt')
    .sort({ createdAt: -1 })
    .limit(10)
    .lean();

  const stats = {
    users: {
      total: totalUsers,
      active: activeUsers,
      inactive: totalUsers - activeUsers,
      locked: lockedUsers,
      recentRegistrations
    },
    roles: {
      admin: adminUsers,
      user: totalUsers - adminUsers
    },
    usersByRole,
    recentUsers
  };

  logger.info('Admin retrieved system stats', {
    adminId: req.user._id,
    adminEmail: req.user.email
  });

  res.json({
    success: true,
    message: 'System statistics retrieved successfully',
    data: stats
  });
}));

/**
 * @route   POST /api/admin/create-user
 * @desc    Create a new user (admin only)
 * @access  Admin only
 */
router.post('/create-user',
  [
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
    
    body('role')
      .optional()
      .isIn(['user', 'admin'])
      .withMessage('Role must be either user or admin'),
    
    body('isActive')
      .optional()
      .isBoolean()
      .withMessage('isActive must be a boolean')
  ],
  handleValidationResult,
  catchAsync(async (req, res) => {
    const { email, password, role = 'user', isActive = true } = req.body;

    // Check if user already exists
    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      throw createAppError('User with this email already exists', 409, 'USER_EXISTS', true);
    }

    // Create new user
    const user = new User({
      email,
      password,
      role,
      isActive
    });

    await user.save();

    logger.info('Admin created new user', {
      adminId: req.user._id,
      adminEmail: req.user.email,
      newUserId: user._id,
      newUserEmail: user.email,
      newUserRole: user.role
    });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        user: user.toJSON() // Password excluded by toJSON transform
      }
    });
  })
);

module.exports = router;