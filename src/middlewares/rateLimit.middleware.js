import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import logger from '../observability/index.js';

// Simple environment checks
const isProduction = () => process.env.NODE_ENV === 'production';
const isDevelopment = () => process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'local';

/**
 * Rate limiting configuration for different environments
 */
const RATE_LIMIT_CONFIG = {
  local: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // Very generous for development
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },
  development: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500, // More restrictive than local
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },
  staging: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Production-like limits
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },
  production: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Strict production limits
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },
  test: {
    windowMs: 15 * 60 * 1000,
    max: 10000, // Very high for testing
    standardHeaders: false,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    skipFailedRequests: true,
  },
};

/**
 * Auth-specific rate limiting configurations
 */
const AUTH_RATE_LIMITS = {
  // Login attempts - very strict
  login: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: isProduction() ? 5 : 20, // 5 attempts in prod, 20 in dev
    message: {
      error: 'Too many login attempts',
      retryAfter: '15 minutes',
    },
    standardHeaders: true,
    skipSuccessfulRequests: false, // Count both success and failure
  },

  // Registration - moderate restrictions
  register: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: isProduction() ? 3 : 10, // 3 registrations per hour in prod
    message: {
      error: 'Too many registration attempts',
      retryAfter: '1 hour',
    },
    standardHeaders: true,
  },

  // Password reset - strict but not as strict as login
  passwordReset: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: isProduction() ? 3 : 10, // 3 reset attempts per hour
    message: {
      error: 'Too many password reset attempts',
      retryAfter: '1 hour',
    },
    standardHeaders: true,
  },

  // Token refresh - moderate
  tokenRefresh: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: isProduction() ? 10 : 50, // 10 refreshes per 15 min
    message: {
      error: 'Too many token refresh attempts',
      retryAfter: '15 minutes',
    },
    standardHeaders: true,
  },

  // Profile updates - moderate
  profileUpdate: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: isProduction() ? 10 : 50, // 10 updates per hour
    message: {
      error: 'Too many profile update attempts',
      retryAfter: '1 hour',
    },
    standardHeaders: true,
  },
};

/**
 * Create rate limit error handler
 * @param {string} operation - Operation type for logging
 * @returns {Function} - Rate limit handler
 */
function createRateLimitHandler(operation) {
  return async (req, res) => {
    const clientId = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.get('User-Agent') || 'unknown';

    // Log rate limit exceeded
    logger.securityEvent('rate_limit_exceeded', 'high', `Rate limit exceeded for ${operation}`, {
      operation,
      clientId,
      userAgent,
      url: req.originalUrl,
      method: req.method,
      userId: req.user?.id || null,
    });

    // Add tracing information
    await withSpan(`RATE_LIMIT ${operation}`, {}, async () => {
      addSpanAttributes({
        'rate_limit.operation': operation,
        'rate_limit.exceeded': true,
        'rate_limit.client_id': clientId,
        'http.status_code': 429,
      });
    });

    // Return rate limit error
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: req.rateLimit?.message || 'Too many requests, please try again later.',
      retryAfter: req.rateLimit?.resetTime ? new Date(req.rateLimit.resetTime) : null,
      limit: req.rateLimit?.limit,
      remaining: req.rateLimit?.remaining || 0,
    });
  };
}

/**
 * Create general rate limiter
 * @param {Object} customConfig - Custom configuration overrides
 * @returns {Function} - Express rate limiting middleware
 */
export function createRateLimiter(customConfig = {}) {
  const environment = getCurrentEnvironment();
  const config = {
    ...RATE_LIMIT_CONFIG[environment],
    ...customConfig,
  };

  return rateLimit({
    ...config,
    handler: createRateLimitHandler('general'),
    keyGenerator: (req) => {
      // Use combination of IP and user ID if available
      const baseKey = req.ip || req.connection.remoteAddress || 'unknown';
      const userKey = req.user?.id ? `user:${req.user.id}` : '';
      return userKey ? `${baseKey}:${userKey}` : baseKey;
    },
    onLimitReached: (req) => {
      logger.warn('Rate limit reached', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl,
        userId: req.user?.id || null,
      });
    },
  });
}

/**
 * Create auth-specific rate limiters
 */
export const authRateLimiters = {
  login: rateLimit({
    ...AUTH_RATE_LIMITS.login,
    handler: createRateLimitHandler('login'),
    keyGenerator: (req) => {
      // For login, use IP + username/email combination
      const ip = req.ip || 'unknown';
      const identifier = req.body?.username || req.body?.email || req.body?.identifier || '';
      return `login:${ip}:${identifier.toLowerCase()}`;
    },
  }),

  register: rateLimit({
    ...AUTH_RATE_LIMITS.register,
    handler: createRateLimitHandler('register'),
    keyGenerator: (req) => {
      // For registration, use IP + email combination
      const ip = req.ip || 'unknown';
      const email = req.body?.email || '';
      return `register:${ip}:${email.toLowerCase()}`;
    },
  }),

  passwordReset: rateLimit({
    ...AUTH_RATE_LIMITS.passwordReset,
    handler: createRateLimitHandler('passwordReset'),
    keyGenerator: (req) => {
      // For password reset, use IP + email combination
      const ip = req.ip || 'unknown';
      const email = req.body?.email || '';
      return `reset:${ip}:${email.toLowerCase()}`;
    },
  }),

  tokenRefresh: rateLimit({
    ...AUTH_RATE_LIMITS.tokenRefresh,
    handler: createRateLimitHandler('tokenRefresh'),
    keyGenerator: (req) => {
      // For token refresh, use IP + user ID
      const ip = req.ip || 'unknown';
      const userId = req.user?.id || req.body?.userId || '';
      return `refresh:${ip}:${userId}`;
    },
  }),

  profileUpdate: rateLimit({
    ...AUTH_RATE_LIMITS.profileUpdate,
    handler: createRateLimitHandler('profileUpdate'),
    keyGenerator: (req) => {
      // For profile updates, primarily use user ID
      const userId = req.user?.id || '';
      const ip = req.ip || 'unknown';
      return userId ? `profile:${userId}` : `profile:${ip}`;
    },
  }),
};

/**
 * Create slow down middleware for gradual response delays
 * @param {Object} customConfig - Custom configuration
 * @returns {Function} - Express slow down middleware
 */
export function createSlowDown(customConfig = {}) {
  const environment = getCurrentEnvironment();
  const isDev = isDevelopment();

  const defaultConfig = {
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: isDev ? 10 : 2, // Allow 2 requests per window in prod, 10 in dev
    delayMs: isDev ? 100 : 500, // Delay subsequent requests by 500ms in prod, 100ms in dev
    maxDelayMs: isDev ? 2000 : 10000, // Maximum delay of 10 seconds in prod, 2 seconds in dev
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
  };

  const config = { ...defaultConfig, ...customConfig };

  return slowDown({
    ...config,
    onLimitReached: (req, res) => {
      logger.warn('Slow down limit reached', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl,
        delay: res.getHeader('Retry-After'),
        userId: req.user?.id || null,
      });

      // Add tracing information
      withSpan('SLOW_DOWN_LIMIT', {}, async () => {
        addSpanAttributes({
          'slow_down.triggered': true,
          'slow_down.ip': req.ip,
          'slow_down.delay_ms': config.delayMs,
        });
      });
    },
  });
}

/**
 * Create IP-based rate limiter for suspicious activity
 * @returns {Function} - Express rate limiting middleware
 */
export function createSuspiciousActivityLimiter() {
  return rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: isProduction() ? 20 : 100, // Very restrictive for suspicious IPs
    message: {
      error: 'Suspicious activity detected',
      message: 'Your IP has been temporarily restricted due to suspicious activity',
      retryAfter: '1 hour',
    },
    standardHeaders: true,
    handler: async (req, res) => {
      logger.securityEvent('suspicious_activity_blocked', 'high', 'Suspicious activity rate limit triggered', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl,
        method: req.method,
      });

      res.status(429).json({
        error: 'Access temporarily restricted',
        message: 'Suspicious activity detected. Please try again later.',
        retryAfter: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
      });
    },
  });
}

/**
 * Express middleware to apply appropriate rate limiting based on request type
 * @returns {Function} - Express middleware
 */
export function smartRateLimiter() {
  return (req, res, next) => {
    const path = req.path.toLowerCase();
    const method = req.method.toUpperCase();

    // Apply specific rate limiters based on the endpoint
    if (path.includes('/login') && method === 'POST') {
      return authRateLimiters.login(req, res, next);
    }

    if (path.includes('/register') && method === 'POST') {
      return authRateLimiters.register(req, res, next);
    }

    if (path.includes('/password') && path.includes('/reset') && method === 'POST') {
      return authRateLimiters.passwordReset(req, res, next);
    }

    if (path.includes('/token') && path.includes('/refresh') && method === 'POST') {
      return authRateLimiters.tokenRefresh(req, res, next);
    }

    if (path.includes('/profile') && (method === 'PUT' || method === 'PATCH')) {
      return authRateLimiters.profileUpdate(req, res, next);
    }

    // Apply general rate limiter for other endpoints
    return createRateLimiter()(req, res, next);
  };
}

/**
 * Get rate limiting statistics
 * @returns {Object} - Rate limiting statistics
 */
export function getRateLimitStats() {
  return {
    service: 'auth-service',
    environment: getCurrentEnvironment(),
    configuration: {
      general: RATE_LIMIT_CONFIG[getCurrentEnvironment()],
      auth_specific: AUTH_RATE_LIMITS,
    },
    settings: {
      production_limits: isProduction(),
      development_mode: isDevelopment(),
    },
  };
}
