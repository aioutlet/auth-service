import logger from '../core/logger.js';

const DAPR_HOST = process.env.DAPR_HOST || 'localhost';
const DAPR_HTTP_PORT = process.env.DAPR_HTTP_PORT || '3504';
const DAPR_PUBSUB_NAME = process.env.DAPR_PUBSUB_NAME || 'auth-pubsub';

// Service URL mapping for direct HTTP calls (fallback when Dapr not available)
const SERVICE_URLS = {
  'user-service': process.env.USER_SERVICE_URL || 'http://localhost:1002',
  'product-service': process.env.PRODUCT_SERVICE_URL || 'http://localhost:1001',
  'order-service': process.env.ORDER_SERVICE_URL || 'http://localhost:5001',
};

// Lazy load Dapr client
let daprClient = null;
let daprAvailable = null;

/**
 * Check if Dapr sidecar is available
 */
async function checkDaprAvailability() {
  if (daprAvailable !== null) {
    return daprAvailable;
  }

  try {
    const response = await fetch(`http://${DAPR_HOST}:${DAPR_HTTP_PORT}/v1.0/healthz`, {
      method: 'GET',
      signal: AbortSignal.timeout(500),
    });

    daprAvailable = response.status === 204;
    logger.info(`Dapr health check result: ${daprAvailable}`, {
      event: 'dapr_health_check_result',
      available: daprAvailable,
      status: response.status,
    });

    return daprAvailable;
  } catch (error) {
    daprAvailable = false;
    logger.info(`Dapr not available: ${error.message}`, {
      event: 'dapr_health_check_failed',
      error: error.message,
    });
    return false;
  }
}

async function getDaprClient() {
  if (!daprClient) {
    const { DaprClient, CommunicationProtocolEnum } = await import('@dapr/dapr');
    daprClient = new DaprClient({
      daprHost: DAPR_HOST,
      daprPort: DAPR_HTTP_PORT,
      communicationProtocol: CommunicationProtocolEnum.HTTP,
    });
  }
  return daprClient;
}

/**
 * Invoke a method on another service via Dapr or direct HTTP
 * @param {string} appId - The app ID of the target service
 * @param {string} methodName - The method/endpoint to invoke
 * @param {string} httpMethod - The HTTP method (GET, POST, DELETE, etc.)
 * @param {object} data - The request body (for POST/PUT)
 * @param {object} metadata - Additional metadata (headers, query params)
 * @returns {Promise<object>} - The response from the service
 */
export async function invokeService(appId, methodName, httpMethod = 'GET', data = null, metadata = {}) {
  const isDaprAvailable = await checkDaprAvailability();
  
  if (isDaprAvailable) {
    return invokeDaprService(appId, methodName, httpMethod, data, metadata);
  } else {
    return invokeDirectHttp(appId, methodName, httpMethod, data, metadata);
  }
}

/**
 * Invoke service via Dapr
 */
async function invokeDaprService(appId, methodName, httpMethod, data, metadata) {
  try {
    logger.debug('Invoking service via Dapr', {
      operation: 'dapr_service_invocation',
      appId,
      methodName,
      httpMethod,
    });

    const client = await getDaprClient();
    const response = await client.invoker.invoke(appId, methodName, httpMethod, data, metadata);

    logger.debug('Service invocation successful', {
      operation: 'dapr_service_invocation',
      appId,
      methodName,
      httpMethod,
    });

    return response;
  } catch (error) {
    logger.error('Service invocation failed', {
      operation: 'dapr_service_invocation',
      appId,
      methodName,
      httpMethod,
      error: error.message,
      errorStack: error.stack,
    });
    throw error;
  }
}

/**
 * Invoke service via direct HTTP call
 */
async function invokeDirectHttp(appId, methodName, httpMethod, data, metadata) {
  try {
    const baseUrl = SERVICE_URLS[appId];
    if (!baseUrl) {
      throw new Error(`No service URL configured for ${appId}`);
    }

    const url = `${baseUrl}/${methodName}`;
    logger.debug('Invoking service via direct HTTP', {
      operation: 'direct_http',
      appId,
      url,
      httpMethod,
    });

    const fetchOptions = {
      method: httpMethod,
      headers: {
        'Content-Type': 'application/json',
        ...metadata?.headers,
      },
    };

    if (data && httpMethod !== 'GET' && httpMethod !== 'DELETE') {
      fetchOptions.body = JSON.stringify(data);
    }

    const response = await fetch(url, fetchOptions);

    if (!response.ok) {
      const errorText = await response.text();
      const error = new Error(`HTTP ${response.status}: ${errorText}`);
      error.statusCode = response.status;
      throw error;
    }

    const responseData = await response.json();

    logger.debug('Direct HTTP invocation successful', {
      operation: 'direct_http',
      appId,
      url,
      httpMethod,
      status: response.status,
    });

    return responseData;
  } catch (error) {
    logger.error('Direct HTTP invocation failed', {
      operation: 'direct_http',
      appId,
      methodName,
      httpMethod,
      error: error.message,
      errorStack: error.stack,
    });
    throw error;
  }
/**
 * Publish an event to a topic via Dapr pub/sub
 * @param {string} topicName - The topic to publish to
 * @param {object} eventData - The event data to publish
 * @returns {Promise<void>}
 */
export async function publishEvent(topicName, eventData) {
  const isDaprAvailable = await checkDaprAvailability();
  
  if (!isDaprAvailable) {
    logger.warn('Dapr not available, skipping event publish', {
      operation: 'dapr_pubsub',
      topicName,
    });
    return;
  }

  try {
    const event = {
      eventId: generateEventId(),
      eventType: topicName,
      timestamp: new Date().toISOString(),
      source: 'auth-service',
      data: eventData,
      metadata: {
        traceId: eventData.traceId || generateEventId(),
        version: '1.0',
      },
    };

    logger.debug('Publishing event via Dapr', {
      operation: 'dapr_pubsub',
      topicName,
      eventId: event.eventId,
      traceId: event.metadata.traceId,
    });

    const client = await getDaprClient();
    await client.pubsub.publish(DAPR_PUBSUB_NAME, topicName, event);

    logger.info('Event published successfully', {
      operation: 'dapr_pubsub',
      topicName,
      eventId: event.eventId,
      traceId: event.metadata.traceId,
    });
  } catch (error) {
    logger.error('Failed to publish event via Dapr', {
      operation: 'dapr_pubsub',
      topicName,
      error: error.message,
      errorStack: error.stack,
      traceId: eventData?.traceId,
    });
    // Don't throw - graceful degradation (app continues even if event publishing fails)
  }
}   // Don't throw - graceful degradation (app continues even if event publishing fails)
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
