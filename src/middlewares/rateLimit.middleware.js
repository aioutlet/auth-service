import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import logger from '../utils/logger.js';

// Rate limiting configuration based on endpoint sensitivity
const rateLimitConfig = {
  // Authentication endpoints (most strict)
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: {
      error: 'Too many authentication attempts',
      message: 'Please try again later',
      retryAfter: 15 * 60 * 1000,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded for authentication', {
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent'),
        correlationId: req.correlationId,
      });
      res.status(429).json({
        error: 'Too many authentication attempts',
        message: 'Please try again later',
        retryAfter: 15 * 60 * 1000,
      });
    },
  },

  // Password-related endpoints (strict)
  password: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // 3 attempts per window
    message: {
      error: 'Too many password change attempts',
      message: 'Please try again later',
      retryAfter: 15 * 60 * 1000,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded for password operations', {
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent'),
        correlationId: req.correlationId,
      });
      res.status(429).json({
        error: 'Too many password change attempts',
        message: 'Please try again later',
        retryAfter: 15 * 60 * 1000,
      });
    },
  },

  // Registration endpoint (moderate)
  registration: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 registrations per hour
    message: {
      error: 'Too many registration attempts',
      message: 'Please try again later',
      retryAfter: 60 * 60 * 1000,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded for registration', {
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent'),
        correlationId: req.correlationId,
      });
      res.status(429).json({
        error: 'Too many registration attempts',
        message: 'Please try again later',
        retryAfter: 60 * 60 * 1000,
      });
    },
  },

  // Email verification/resend (moderate)
  emailActions: {
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5, // 5 attempts per window
    message: {
      error: 'Too many email action attempts',
      message: 'Please try again later',
      retryAfter: 10 * 60 * 1000,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded for email actions', {
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent'),
        correlationId: req.correlationId,
      });
      res.status(429).json({
        error: 'Too many email action attempts',
        message: 'Please try again later',
        retryAfter: 10 * 60 * 1000,
      });
    },
  },

  // Token refresh (moderate)
  tokenRefresh: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 refresh attempts per window
    message: {
      error: 'Too many token refresh attempts',
      message: 'Please try again later',
      retryAfter: 5 * 60 * 1000,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded for token refresh', {
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent'),
        correlationId: req.correlationId,
      });
      res.status(429).json({
        error: 'Too many token refresh attempts',
        message: 'Please try again later',
        retryAfter: 5 * 60 * 1000,
      });
    },
  },

  // General API endpoints (lenient)
  general: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    message: {
      error: 'Too many requests',
      message: 'Please try again later',
      retryAfter: 15 * 60 * 1000,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded for general API', {
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent'),
        correlationId: req.correlationId,
      });
      res.status(429).json({
        error: 'Too many requests',
        message: 'Please try again later',
        retryAfter: 15 * 60 * 1000,
      });
    },
  },
};

// Progressive delay for failed authentication attempts
const authSlowDown = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 2, // Start delaying after 2 attempts
  delayMs: 500, // Increase delay by 500ms for each attempt after delayAfter
  maxDelayMs: 20000, // Maximum delay of 20 seconds
  skipFailedRequests: false,
  skipSuccessfulRequests: true, // Don't delay successful requests
  onLimitReached: (req, res) => {
    logger.warn('Slow down triggered for authentication', {
      ip: req.ip,
      path: req.path,
      userAgent: req.get('User-Agent'),
      correlationId: req.correlationId,
    });
  },
});

// Create rate limiters
export const authRateLimit = rateLimit(rateLimitConfig.auth);
export const passwordRateLimit = rateLimit(rateLimitConfig.password);
export const registrationRateLimit = rateLimit(rateLimitConfig.registration);
export const emailActionsRateLimit = rateLimit(rateLimitConfig.emailActions);
export const tokenRefreshRateLimit = rateLimit(rateLimitConfig.tokenRefresh);
export const generalRateLimit = rateLimit(rateLimitConfig.general);

// Export slow down middleware for authentication
export { authSlowDown };

// Utility function to skip rate limiting for health checks and monitoring
export const skipHealthChecks = (req) => {
  return req.path.startsWith('/health') || req.path.startsWith('/metrics');
};

// Apply skipHealthChecks to all rate limiters
[
  authRateLimit,
  passwordRateLimit,
  registrationRateLimit,
  emailActionsRateLimit,
  tokenRefreshRateLimit,
  generalRateLimit,
].forEach((limiter) => {
  limiter.skip = skipHealthChecks;
});

export default {
  authRateLimit,
  passwordRateLimit,
  registrationRateLimit,
  emailActionsRateLimit,
  tokenRefreshRateLimit,
  generalRateLimit,
  authSlowDown,
};
