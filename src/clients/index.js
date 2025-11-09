/**
 * External Clients
 * Exports clients for external service communication
 */

export { default as daprClient } from './dapr.service.client.js';
export { secretManager, getJwtConfig } from './dapr.secret.manager.js';
export { default as userServiceClient } from './user.service.client.js';
