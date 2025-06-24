import jwt from 'jsonwebtoken';
import asyncHandler from './asyncHandler.js';
import ErrorResponse from '../utils/ErrorResponse.js';

/**
 * Middleware for JWT authentication in the auth service.
 * Checks for a JWT in the Authorization header or cookies, verifies it, and attaches user info to req.user.
 * Responds with 401 Unauthorized if the token is missing or invalid.
 */
const authMiddleware = asyncHandler(async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(new ErrorResponse('Not authorized to access this route', 401));
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = {
      id: decoded.id,
      email: decoded.email,
      roles: decoded.roles,
    };
    next();
  } catch {
    return next(new ErrorResponse('Not authorized to access this route', 401));
  }
});

/**
 * Middleware to require one or more user roles (e.g., 'admin', 'user').
 * Responds with 403 Forbidden if the user does not have any of the required roles.
 */
export const authorizeRoles =
  (...roles) =>
  (req, res, next) => {
    if (!req.user || !roles.some((role) => req.user.roles?.includes(role))) {
      return res.status(403).json({ error: 'Forbidden: insufficient role' });
    }
    next();
  };

export default authMiddleware;
