// OpenTelemetry tracing setup for user-service
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import process from 'process';
import logger from '../logging/index.js';

// SDK initialization
let sdk = null;
const environment = process.env.NODE_ENV || 'development';
const enableTracing = process.env.ENABLE_TRACING !== 'false' && environment !== 'test';

/**
 * Initialize OpenTelemetry SDK
 * @returns {boolean} - True if initialization was successful
 */
export function initializeTracing() {
  if (!enableTracing) {
    return false;
  }

  if (sdk) {
    return true; // Already initialized
  }

  try {
    sdk = new NodeSDK({
      traceExporter: new OTLPTraceExporter({
        url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318/v1/traces',
      }),
      serviceName: process.env.OTEL_SERVICE_NAME || 'auth-service',
      instrumentations: [getNodeAutoInstrumentations()],
    });

    sdk.start();
    logger.info('OpenTelemetry tracing initialized', null, { operation: 'tracing_init' });
    return true;
  } catch (error) {
    logger.warn('Failed to initialize OpenTelemetry', null, { operation: 'tracing_init', error: error.message });
    return false;
  }
}

/**
 * Shutdown OpenTelemetry SDK
 * @returns {Promise<void>}
 */
export function shutdownTracing() {
  if (sdk) {
    return sdk
      .shutdown()
      .then(() => logger.info('Tracing terminated', null, { operation: 'tracing_shutdown' }))
      .catch((error) => logger.error('Error terminating tracing', null, { operation: 'tracing_shutdown', error }));
  }
  return Promise.resolve();
}

/**
 * Check if tracing is enabled
 * @returns {boolean} - True if tracing is enabled
 */
export function isTracingEnabled() {
  return enableTracing;
}
