/**
 * Correlation ID helper utilities
 */
class CorrelationIdHelper {
  /**
   * Get correlation ID from request
   * @param {Object} req - Express request object
   * @returns {string} correlation ID
   */
  static getCorrelationId(req) {
    return req.correlationId || 'unknown';
  }

  /**
   * Create correlation ID header for outgoing requests
   * @param {Object} req - Express request object
   * @returns {Object} headers object with correlation ID
   */
  static createHeaders(req) {
    return {
      'X-Correlation-ID': this.getCorrelationId(req),
      'Content-Type': 'application/json',
    };
  }

  /**
   * Log with correlation ID
   * @param {Object} req - Express request object
   * @param {string} level - Log level (info, error, warn, debug)
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   */
  static log(req, level, message, meta = {}) {
    const correlationId = this.getCorrelationId(req);
    const logData = {
      correlationId,
      message,
      ...meta,
    };

    console[level](`[${correlationId}] ${message}`, logData);
  }
}

export default CorrelationIdHelper;
