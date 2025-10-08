import logger from '../observability/logging/index.js';
import ErrorResponse from '../utils/ErrorResponse.js';

/**
 * Global error handler middleware for the auth service
 * Handles different types of errors and provides environment-specific responses
 */
const errorHandler = (err, req, res, _next) => {
  const isDev = process.env.NODE_ENV === 'development';
  let error = { ...err };
  error.message = err.message;

  // Log error details for debugging
  logger.error('Error occurred', {
    message: err.message,
    statusCode: err.statusCode,
    stack: isDev ? err.stack : 'Stack trace hidden in production',
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    user: req.user?.id || 'anonymous',
  });

  // Handle JWT errors specifically
  if (err.name === 'JsonWebTokenError') {
    const message = 'Invalid token format';
    error = new ErrorResponse(message, 401);
  }

  if (err.name === 'TokenExpiredError') {
    const message = 'Token has expired';
    error = new ErrorResponse(message, 401);
  }

  // Handle Mongoose validation errors
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors)
      .map((val) => val.message)
      .join(', ');
    error = new ErrorResponse(message, 400);
  }

  // Handle Mongoose duplicate key errors
  if (err.code === 11000) {
    const message = 'Duplicate resource detected';
    error = new ErrorResponse(message, 409);
  }

  // Handle Mongoose cast errors (invalid ObjectId)
  if (err.name === 'CastError') {
    const message = 'Invalid resource ID format';
    error = new ErrorResponse(message, 400);
  }

  // Prepare response based on environment
  const response = {
    success: false,
    error: error.message || 'Internal Server Error',
  };

  // Add validation errors if present
  if (error.validationErrors) {
    response.validationErrors = error.validationErrors;
  }

  // Add development-only details
  if (isDev) {
    response.stack = error.stack;
    response.details = {
      name: error.name,
      statusCode: error.statusCode,
      ...(err.code && { code: err.code }),
    };
    // In development, log detailed error info
    logger.error('API Error', req, {
      operation: 'error_handler',
      error: {
        message: error.message,
        statusCode: error.statusCode,
        validationErrors: error.validationErrors,
        path: req.originalUrl,
        method: req.method,
      },
    });
  }

  res.status(error.statusCode || 500).json(response);
};

// Export all functions
export { errorHandler };
