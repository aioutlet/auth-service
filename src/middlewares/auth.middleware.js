import jwt from 'jsonwebtoken';
import { asyncHandler } from './asyncHandler.js';
import ErrorResponse from '../utils/ErrorResponse.js';
import logger from '../observability/logging/index.js';

/**
 * Middleware for JWT authentication in the auth service.
 * Checks for a JWT in the Authorization header or cookies, verifies it, and attaches user info to req.user.
 * Responds with 401 Unauthorized if the token is missing or invalid.
 */
const authMiddleware = asyncHandler(async (req, res, next) => {
  let token;

  // Debug: Log request details
  logger.debug('Auth middleware - checking for token', {
    hasAuthHeader: !!req.headers.authorization,
    hasCookies: !!req.cookies,
    cookieKeys: req.cookies ? Object.keys(req.cookies) : [],
    authHeader: req.headers.authorization ? `${req.headers.authorization.substring(0, 20)}...` : 'none',
  });

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
    logger.debug('Auth middleware - token from Authorization header');
  } else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
    logger.debug('Auth middleware - token from JWT cookie', {
      tokenLength: token ? token.length : 0,
      tokenStart: token ? `${token.substring(0, 20)}...` : 'none',
    });
  }

  if (!token) {
    logger.warn('Auth middleware - no token found', {
      hasAuthHeader: !!req.headers.authorization,
      hasCookies: !!req.cookies,
      cookieKeys: req.cookies ? Object.keys(req.cookies) : [],
    });
    return next(new ErrorResponse('Not authorized to access this route', 401));
  }

  try {
    logger.debug('Auth middleware - verifying JWT token', {
      tokenLength: token.length,
      jwtSecret: process.env.JWT_SECRET ? 'set' : 'not set',
    });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    logger.debug('Auth middleware - JWT decoded successfully', {
      userId: decoded.id,
      email: decoded.email,
      roles: decoded.roles,
      exp: decoded.exp,
    });
    req.user = {
      id: decoded.id,
      email: decoded.email,
      roles: decoded.roles,
    };
    next();
  } catch (error) {
    logger.error('Auth middleware - JWT verification failed', {
      error: error.message,
      errorName: error.name,
      tokenLength: token.length,
    });
    // Pass the original JWT error to centralized error handler
    // The errorHandler middleware will handle TokenExpiredError, JsonWebTokenError, etc.
    return next(error);
  }
});

/**
 * Middleware to require one or more user roles (e.g., 'admin', 'user').
 * Responds with 403 Forbidden if the user does not have any of the required roles.
 */
const authorizeRoles =
  (...roles) =>
  (req, res, next) => {
    if (!req.user || !roles.some((role) => req.user.roles?.includes(role))) {
      return next(new ErrorResponse('Forbidden: insufficient role', 403));
    }
    next();
  };

// Export all functions
export { authMiddleware, authorizeRoles };
