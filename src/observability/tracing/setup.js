/**
 * OpenTelemetry tracing setup for auth-service
 * Auto-initializes on import (standard pattern)
 * Uses console.log for initialization messages (industry standard)
 */
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';

// SDK initialization
let sdk = null;
const environment = process.env.NODE_ENV || 'development';
const enableTracing = process.env.ENABLE_TRACING !== 'false' && environment !== 'test';

// Auto-initialize on import (standard Express + OpenTelemetry pattern)
if (enableTracing) {
  console.log('[TRACING] Initializing OpenTelemetry tracing...');

  try {
    sdk = new NodeSDK({
      traceExporter: new OTLPTraceExporter({
        url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318/v1/traces',
        headers: {},
      }),
      serviceName: process.env.SERVICE_NAME || 'auth-service',
      serviceVersion: process.env.SERVICE_VERSION || '1.0.0',
      instrumentations: [
        getNodeAutoInstrumentations({
          '@opentelemetry/instrumentation-fs': {
            enabled: false,
          },
        }),
      ],
    });

    sdk.start();
    console.log('[TRACING] ✅ OpenTelemetry tracing initialized successfully');

    // Graceful shutdown
    process.on('SIGTERM', () => {
      sdk
        .shutdown()
        .then(() => console.log('[TRACING] Tracing terminated'))
        .catch((error) => console.error('[TRACING] Error terminating tracing:', error.message))
        .finally(() => process.exit(0));
    });
  } catch (error) {
    console.warn('[TRACING] ⚠️  Failed to initialize OpenTelemetry:', error.message);
  }
}

// Export for reference
export { enableTracing };
