// This file must be imported FIRST, before any other modules
// OpenTelemetry auto-instrumentation needs to be loaded before the application code

import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';

// Check if tracing should be enabled
const environment = process.env.NODE_ENV || 'development';
const enableTracing = process.env.ENABLE_TRACING !== 'false' && environment !== 'test';

if (enableTracing) {
  console.log('Initializing OpenTelemetry tracing...');

  try {
    const sdk = new NodeSDK({
      traceExporter: new OTLPTraceExporter({
        url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318/v1/traces',
        headers: {},
      }),
      serviceName: process.env.SERVICE_NAME || process.env.OTEL_SERVICE_NAME || 'auth-service',
      serviceVersion: process.env.SERVICE_VERSION || process.env.OTEL_SERVICE_VERSION || '1.0.0',
      instrumentations: [
        getNodeAutoInstrumentations({
          // Disable file system instrumentation that can be noisy
          '@opentelemetry/instrumentation-fs': {
            enabled: false,
          },
        }),
      ],
    });

    sdk.start();
    console.log('✅ OpenTelemetry tracing initialized successfully');

    // Graceful shutdown
    process.on('SIGTERM', () => {
      sdk
        .shutdown()
        .then(() => console.log('Tracing terminated'))
        .catch((error) => console.error('Error terminating tracing', error))
        .finally(() => process.exit(0));
    });
  } catch (error) {
    console.warn('⚠️ Failed to initialize OpenTelemetry:', error.message);
  }
} else {
  console.log('Tracing disabled for environment:', environment);
}
