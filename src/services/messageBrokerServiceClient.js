import logger from '../observability/logging/index.js';

const MESSAGE_BROKER_SERVICE_URL = process.env.MESSAGE_BROKER_SERVICE_URL || 'http://localhost:4000';
const MESSAGE_BROKER_API_KEY = process.env.MESSAGE_BROKER_API_KEY || 'dev-api-key-12345';

/**
 * Publish an event to the message broker service
 * @param {string} routingKey - The routing key/topic for the event
 * @param {object} eventData - The event data to publish
 * @returns {Promise<object|null>} - Response from message broker or null on failure
 */
export async function publishEvent(routingKey, eventData) {
  try {
    const event = {
      eventId: generateEventId(),
      eventType: routingKey,
      timestamp: new Date().toISOString(),
      source: 'auth-service',
      data: eventData,
      metadata: {
        correlationId: eventData.correlationId || generateEventId(),
        version: '1.0',
      },
    };

    const payload = {
      topic: routingKey,
      data: event,
    };

    const url = `${MESSAGE_BROKER_SERVICE_URL}/api/v1/publish`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${MESSAGE_BROKER_API_KEY}`,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const result = await response.json();

    if (result && result.success) {
      logger.info('Event published via Message Broker Service', null, {
        operation: 'message_broker_publish',
        routingKey,
        eventId: event.eventId,
        messageId: result.message_id,
      });
      return result;
    } else {
      throw new Error('Failed to publish event');
    }
  } catch (error) {
    logger.error('Failed to publish event via Message Broker Service', null, {
      operation: 'message_broker_publish',
      routingKey,
      error: error.message,
    });
    // Don't throw - graceful degradation (app continues even if event publishing fails)
    return null;
  }
}

/**
 * Get statistics from the message broker service
 * @returns {Promise<object|null>} - Stats or null on failure
 */
export async function getStats() {
  try {
    const url = `${MESSAGE_BROKER_SERVICE_URL}/api/v1/stats`;
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    logger.error('Failed to get Message Broker Service stats', null, {
      operation: 'message_broker_stats',
      error: error.message,
    });
    return null;
  }
}

/**
 * Generate a unique event ID
 * @returns {string} - Unique event ID
 */
function generateEventId() {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

// Export as default object for backward compatibility
export default {
  publishEvent,
  getStats,
};
