import { DaprClient, CommunicationProtocolEnum } from '@dapr/dapr';
import logger from '../core/logger.js';

const DAPR_HOST = process.env.DAPR_HOST || 'localhost';
const DAPR_HTTP_PORT = process.env.DAPR_HTTP_PORT || '3504';
const DAPR_PUBSUB_NAME = process.env.DAPR_PUBSUB_NAME || 'auth-pubsub';

// Initialize Dapr client
const daprClient = new DaprClient({
  daprHost: DAPR_HOST,
  daprPort: DAPR_HTTP_PORT,
  communicationProtocol: CommunicationProtocolEnum.HTTP,
});

/**
 * Invoke a method on another service via Dapr
 * @param {string} appId - The app ID of the target service
 * @param {string} methodName - The method/endpoint to invoke
 * @param {string} httpMethod - The HTTP method (GET, POST, DELETE, etc.)
 * @param {object} data - The request body (for POST/PUT)
 * @param {object} metadata - Additional metadata (headers, query params)
 * @returns {Promise<object>} - The response from the service
 */
export async function invokeService(appId, methodName, httpMethod = 'GET', data = null, metadata = {}) {
  try {
    logger.debug('Invoking service via Dapr', {
      operation: 'dapr_service_invocation',
      appId,
      methodName,
      httpMethod,
    });

    const response = await daprClient.invoker.invoke(appId, methodName, httpMethod, data, metadata);

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
 * Publish an event to a topic via Dapr pub/sub
 * @param {string} topicName - The topic to publish to
 * @param {object} eventData - The event data to publish
 * @returns {Promise<void>}
 */
export async function publishEvent(topicName, eventData) {
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

    await daprClient.pubsub.publish(DAPR_PUBSUB_NAME, topicName, event);

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
    throw error;
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
