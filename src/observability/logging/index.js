/**
 * Centralized logging module
 * Exports a singleton logger instance configured from environment variables
 */

import Logger from './logger.js';

// Create and export singleton logger instance
const logger = new Logger();

export default logger;
