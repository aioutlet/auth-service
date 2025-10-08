/**
 * Observability module exports
 * Centralized access to all observability functionality including logging and tracing
 */

// Logging exports
import logger from './logging/index.js';
export default logger;

// Tracing exports
export {
  initializeTracing,
  shutdownTracing,
  isTracingEnabled,
  getTracingContext,
  createOperationSpan,
} from './tracing/index.js';
