import logger from '../core/logger.js';
import { resolveAsync } from '../core/serviceResolver.js';
import { getMessagingProvider } from '../messaging/index.js';

// Service invocation mode (independent from messaging)
const PLATFORM_MODE = process.env.PLATFORM_MODE || 'direct';
const USE_DAPR = PLATFORM_MODE === 'dapr';

// Dapr sidecar configuration (only used when PLATFORM_MODE=dapr)
const DAPR_HOST = process.env.DAPR_HOST || 'localhost';
const DAPR_HTTP_PORT = process.env.DAPR_HTTP_PORT || '3500';

// Service App IDs for Dapr service invocation (used when PLATFORM_MODE=dapr)
const SERVICE_APP_IDS = {
  'user-service': process.env.USER_SERVICE_APP_ID || 'user-service',
};

// Direct HTTP URLs resolved via serviceResolver (port registry local, SERVICE_BASE_URL on Azure)

/**
 * Invoke a method on another service
 * - When MESSAGING_PROVIDER=dapr: Uses Dapr service invocation
 * - Otherwise: Uses direct HTTP calls
 *
 * @param {string} serviceName - The logical service name (e.g., 'user-service')
 * @param {string} methodName - The method/endpoint to invoke
 * @param {string} httpMethod - The HTTP method (GET, POST, DELETE, etc.)
 * @param {object} data - The request body (for POST/PUT)
 * @param {object} metadata - Additional metadata (headers, query params)
 * @returns {Promise<object>} - The response from the service
 */
export async function invokeService(serviceName, methodName, httpMethod = 'GET', data = null, metadata = {}) {
  try {
    let url;
    const cleanMethodName = methodName.startsWith('/') ? methodName.slice(1) : methodName;

    if (USE_DAPR) {
      // Dapr service invocation: http://localhost:3500/v1.0/invoke/{appId}/method/{method}
      const appId = SERVICE_APP_IDS[serviceName] || serviceName;
      url = `http://${DAPR_HOST}:${DAPR_HTTP_PORT}/v1.0/invoke/${appId}/method/${cleanMethodName}`;

      logger.debug('Invoking service via Dapr', {
        operation: 'dapr_service_invocation',
        serviceName,
        appId,
        url,
        httpMethod,
      });
    } else {
      // Direct HTTP call — resolved via serviceResolver
      const baseUrl = await resolveAsync(serviceName);
      url = `${baseUrl}/${cleanMethodName}`;

      logger.debug('Invoking service via HTTP', {
        operation: 'http_service_invocation',
        serviceName,
        url,
        httpMethod,
      });
    }

    const options = {
      method: httpMethod.toUpperCase(),
      headers: {
        'Content-Type': 'application/json',
        // Add service token for inter-service authentication
        'X-Service-Token': process.env.USER_SERVICE_TOKEN || '',
        ...metadata.headers,
      },
    };

    if (data && httpMethod.toUpperCase() !== 'GET') {
      options.body = JSON.stringify(data);
    }

    const response = await fetch(url, options);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }
    return null;
  } catch (error) {
    logger.error('Service invocation failed', {
      operation: USE_DAPR ? 'dapr_service_invocation' : 'http_service_invocation',
      serviceName,
      methodName,
      httpMethod,
      error: error.message,
      errorStack: error.stack,
    });
    throw error;
  }
}
/**
 * Publish an event to a topic via messaging provider
 *
 * Dapr handles CloudEvents wrapping/unwrapping automatically.
 * We send just the business data, and Dapr will:
 * 1. Wrap it in CloudEvents format when publishing
 * 2. Deliver the data to subscribers with CloudEvents metadata
 *
 * @param {string} topicName - The topic to publish to (e.g., 'auth.user.registered')
 * @param {object} eventData - The event payload (business data)
 * @returns {Promise<void>}
 */
export async function publishEvent(topicName, eventData) {
  try {
    const traceId = eventData.traceId || generateEventId();

    // Add metadata for tracing
    const eventPayload = {
      ...eventData,
      // Include source and timestamp for auditing
      source: 'auth-service',
      timestamp: new Date().toISOString(),
      traceId,
    };

    logger.debug('Publishing event via Dapr (native CloudEvents)', {
      operation: 'messaging_pubsub',
      topicName,
      traceId,
      dataKeys: Object.keys(eventData || {}),
      hasEmail: !!eventData?.email,
    });

    const provider = await getMessagingProvider();
    const success = await provider.publishEvent(topicName, eventPayload, traceId);

    if (success) {
      logger.info('Event published successfully via Dapr', {
        operation: 'messaging_pubsub',
        topicName,
        traceId,
      });
    }
  } catch (error) {
    logger.error('Failed to publish event', {
      operation: 'messaging_pubsub',
      topicName,
      error: error.message,
      errorStack: error.stack,
      traceId: eventData?.traceId,
    });
    // Don't throw - graceful degradation
  }
}

/**
 * Generate a unique event ID
 * @returns {string} - Unique event ID
 */
function generateEventId() {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

export default {
  invokeService,
  publishEvent,
};
