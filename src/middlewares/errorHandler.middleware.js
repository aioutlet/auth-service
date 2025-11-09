import logger from '../core/logger.js';

/**
 * Centralized error handler middleware for consistent error responses
 * Captures all errors thrown in the application and formats them appropriately
 */
const errorHandler = (err, req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  const traceId = req.traceId || 'no-trace';

  // Log the error with full details including trace context
  logger.error(`Request failed: ${req.method} ${req.originalUrl} - ${err.message || 'Unknown error'}`, {
    traceId,
    spanId: req.spanId,
    method: req.method,
    url: req.originalUrl,
    status,
    errorCode: err.code || 'INTERNAL_ERROR',
    errorMessage: err.message,
    errorStack: err.stack,
    userId: req.user?.id,
  });

  // Send standardized error response
  res.status(status).json({
    error: {
      code: err.code || 'INTERNAL_ERROR',
      message: err.message || 'Internal server error',
      details: err.details || null,
      traceId: req.traceId,
    },
  });
};

export { errorHandler };
