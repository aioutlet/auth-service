import winston from 'winston';
import { colorizeLevel } from './colorize.js';

/**
 * Standardized logger configuration for Node.js services
 * Supports both development and production environments with correlation ID integration
 */

// Environment-based configuration
const isDevelopment = process.env.NODE_ENV === 'development';
const isProduction = process.env.NODE_ENV === 'production';
const isTest = process.env.NODE_ENV === 'test';

const serviceName = process.env.SERVICE_NAME || 'auth-service';
const logLevel = process.env.LOG_LEVEL || (isDevelopment ? 'debug' : 'info');
const logFormat = process.env.LOG_FORMAT || (isProduction ? 'json' : 'console');
const logToFile = process.env.LOG_TO_FILE === 'true';
const logToConsole = process.env.LOG_TO_CONSOLE !== 'false';
const logFilePath = process.env.LOG_FILE_PATH || `${serviceName}.log`;

// Custom format for development console output
const consoleFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.printf(({ timestamp, level, message, correlationId, operation, duration, userId, ...meta }) => {
    const ts = timestamp;
    const corrId = correlationId ? `[${correlationId}]` : '[no-correlation]';

    // Build metadata string
    const metaFields = [];
    if (userId) metaFields.push(`userId=${userId}`);
    if (operation) metaFields.push(`operation=${operation}`);
    if (duration) metaFields.push(`duration=${duration}ms`);

    // Add remaining metadata
    Object.keys(meta).forEach((key) => {
      if (meta[key] !== undefined && meta[key] !== null) {
        metaFields.push(`${key}=${JSON.stringify(meta[key])}`);
      }
    });

    const metaStr = metaFields.length > 0 ? ` | ${metaFields.join(', ')}` : '';
    const logMessage = `[${ts}] [${level.toUpperCase()}] ${serviceName} ${corrId}: ${message}${metaStr}`;

    return isDevelopment ? colorizeLevel(level, logMessage) : logMessage;
  })
);

// JSON format for production
const jsonFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.json(),
  winston.format.printf((info) => {
    return JSON.stringify({
      timestamp: info.timestamp,
      level: info.level.toUpperCase(),
      service: serviceName,
      correlationId: info.correlationId || null,
      message: info.message,
      ...info,
    });
  })
);

// Create transports based on configuration
const transports = [];

if (logToConsole && !isTest) {
  transports.push(
    new winston.transports.Console({
      format: logFormat === 'json' ? jsonFormat : consoleFormat,
      level: logLevel,
    })
  );
}

if (logToFile) {
  transports.push(
    new winston.transports.File({
      filename: logFilePath,
      format: jsonFormat,
      level: logLevel,
    })
  );
}

// Create the logger
const logger = winston.createLogger({
  level: logLevel,
  transports,
  // Handle uncaught exceptions and rejections
  exceptionHandlers: logToFile ? [new winston.transports.File({ filename: `${serviceName}-exceptions.log` })] : [],
  rejectionHandlers: logToFile ? [new winston.transports.File({ filename: `${serviceName}-rejections.log` })] : [],
});

/**
 * Enhanced logging methods with correlation ID and metadata support
 */
class StandardLogger {
  constructor(baseLogger) {
    this.logger = baseLogger;
  }

  /**
   * Create log entry with standard fields
   */
  _log(level, message, req = null, metadata = {}) {
    const logData = {
      level,
      message,
      correlationId: req?.correlationId || metadata.correlationId || null,
      userId: req?.user?.id || metadata.userId || null,
      operation: metadata.operation || null,
      duration: metadata.duration || null,
      ...metadata,
    };

    // Remove undefined/null values to keep logs clean
    Object.keys(logData).forEach((key) => {
      if (logData[key] === undefined || logData[key] === null) {
        delete logData[key];
      }
    });

    this.logger.log(logData);
  }

  /**
   * Info level logging
   */
  info(message, req = null, metadata = {}) {
    this._log('info', message, req, metadata);
  }

  /**
   * Debug level logging
   */
  debug(message, req = null, metadata = {}) {
    this._log('debug', message, req, metadata);
  }

  /**
   * Warning level logging
   */
  warn(message, req = null, metadata = {}) {
    this._log('warn', message, req, metadata);
  }

  /**
   * Error level logging
   */
  error(message, req = null, metadata = {}) {
    // Handle Error objects
    if (metadata.error instanceof Error) {
      metadata.error = {
        name: metadata.error.name,
        message: metadata.error.message,
        stack: metadata.error.stack,
      };
    }
    this._log('error', message, req, metadata);
  }

  /**
   * Fatal level logging (maps to error in Winston)
   */
  fatal(message, req = null, metadata = {}) {
    this.error(message, req, { ...metadata, level: 'FATAL' });
  }

  /**
   * Log operation start
   */
  operationStart(operation, req = null, metadata = {}) {
    this.debug(`Starting operation: ${operation}`, req, {
      operation,
      operationStart: true,
      ...metadata,
    });
    return Date.now();
  }

  /**
   * Log operation completion
   */
  operationComplete(operation, startTime, req = null, metadata = {}) {
    const duration = Date.now() - startTime;
    this.info(`Completed operation: ${operation}`, req, {
      operation,
      duration,
      operationComplete: true,
      ...metadata,
    });
    return duration;
  }

  /**
   * Log operation failure
   */
  operationFailed(operation, startTime, error, req = null, metadata = {}) {
    const duration = Date.now() - startTime;
    this.error(`Failed operation: ${operation}`, req, {
      operation,
      duration,
      error,
      operationFailed: true,
      ...metadata,
    });
    return duration;
  }

  /**
   * Log business events
   */
  business(event, req = null, metadata = {}) {
    this.info(`Business event: ${event}`, req, {
      businessEvent: event,
      ...metadata,
    });
  }

  /**
   * Log security events
   */
  security(event, req = null, metadata = {}) {
    this.warn(`Security event: ${event}`, req, {
      securityEvent: event,
      ...metadata,
    });
  }

  /**
   * Log performance metrics
   */
  performance(operation, duration, req = null, metadata = {}) {
    const level = duration > 1000 ? 'warn' : 'info';
    this._log(level, `Performance: ${operation}`, req, {
      operation,
      duration,
      performance: true,
      ...metadata,
    });
  }
}

// Create and export the standard logger instance
const standardLogger = new StandardLogger(logger);

// Log service startup
standardLogger.info('Logger initialized', null, {
  logLevel,
  logFormat,
  logToFile,
  logToConsole,
  environment: process.env.NODE_ENV,
});

export default standardLogger;
