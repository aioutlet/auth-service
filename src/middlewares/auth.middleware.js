import jwt from 'jsonwebtoken';
import { asyncHandler } from './asyncHandler.js';
import ErrorResponse from '../core/errors.js';
import logger from '../core/logger.js';
import { getJwtConfig } from '../services/dapr.secretManager.js';

// Cache JWT config to avoid repeated Dapr calls
let _jwtConfigCache = null;

async function getCachedJwtConfig() {
  if (_jwtConfigCache === null) {
    _jwtConfigCache = await getJwtConfig();
  }
  return _jwtConfigCache;
}

/**
 * Middleware for JWT authentication in the auth service.
 * Checks for a JWT in the Authorization header or cookies, verifies it, and attaches user info to req.user.
 * Responds with 401 Unauthorized if the token is missing or invalid.
 */
const authMiddleware = asyncHandler(async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    logger.warn('Auth middleware - no token found', req);
    return next(new ErrorResponse('Not authorized to access this route', 401));
  }

  try {
    const jwtConfig = await getCachedJwtConfig();
    const decoded = jwt.verify(token, jwtConfig.secret);

    // Validate standard claims
    if (!decoded.sub || !decoded.iss || !decoded.aud) {
      throw new Error('Invalid token structure');
    }

    // Map standard JWT claims to req.user
    req.user = {
      id: decoded.sub, // Standard 'sub' claim
      email: decoded.email,
      name: decoded.name,
      roles: decoded.roles || [],
      emailVerified: decoded.emailVerified || false,
    };
    next();
  } catch (error) {
    logger.warn('Auth middleware - JWT verification failed', {
      error: error.message,
      errorName: error.name,
      correlationId: req.correlationId,
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
