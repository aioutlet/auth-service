/**
 * Custom Assertions Helper
 * Provides reusable assertion patterns for tests
 */

/**
 * Assert response has expected status
 */
export function assertStatus(response, expectedStatus) {
  expect(response.status).toBe(expectedStatus);
}

/**
 * Assert response is successful (2xx)
 */
export function assertSuccess(response) {
  expect(response.status).toBeGreaterThanOrEqual(200);
  expect(response.status).toBeLessThan(300);
}

/**
 * Assert response is error (4xx or 5xx)
 */
export function assertError(response) {
  expect(response.status).toBeGreaterThanOrEqual(400);
}

/**
 * Assert response has expected structure
 */
export function assertResponseStructure(response, structure) {
  expect(response.data).toMatchObject(structure);
}

/**
 * Assert response contains fields
 */
export function assertHasFields(object, fields) {
  fields.forEach((field) => {
    expect(object).toHaveProperty(field);
  });
}

/**
 * Assert JWT token is valid format
 */
export function assertValidToken(token) {
  expect(token).toBeDefined();
  expect(typeof token).toBe('string');
  expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
}

/**
 * Assert user object has required fields
 */
export function assertValidUser(user) {
  assertHasFields(user, ['_id', 'email', 'firstName', 'lastName', 'createdAt']);
  expect(user.password).toBeUndefined(); // Password should never be returned
}

/**
 * Assert order object has required fields
 */
export function assertValidOrder(order) {
  assertHasFields(order, ['orderId', 'customerId', 'items', 'status', 'totalAmount', 'createdAt']);
  expect(order.items).toBeInstanceOf(Array);
  expect(order.items.length).toBeGreaterThan(0);
}

/**
 * Assert email format is valid
 */
export function assertValidEmail(email) {
  expect(email).toMatch(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
}

/**
 * Assert timestamp is recent (within last N seconds)
 */
export function assertRecentTimestamp(timestamp, maxAgeSeconds = 60) {
  const now = Date.now();
  const timestampMs = new Date(timestamp).getTime();
  const ageMs = now - timestampMs;
  expect(ageMs).toBeLessThan(maxAgeSeconds * 1000);
  expect(ageMs).toBeGreaterThanOrEqual(0);
}

/**
 * Assert array contains item matching predicate
 */
export function assertArrayContains(array, predicate) {
  expect(array).toBeInstanceOf(Array);
  const found = array.some(predicate);
  expect(found).toBe(true);
}

/**
 * Assert response contains error message
 */
export function assertErrorMessage(response, expectedMessage) {
  expect(response.data).toHaveProperty('error');
  if (expectedMessage) {
    expect(response.data.error).toContain(expectedMessage);
  }
}

/**
 * Assert AWS EventBridge message structure
 */
export function assertValidEventBridgeMessage(message) {
  assertHasFields(message, ['source', 'eventType', 'eventVersion', 'eventId', 'timestamp', 'data']);
  expect(message.source).toMatch(/^[a-z0-9.-]+$/); // Valid source format
  expect(message.eventType).toMatch(/^[a-z]+\.[a-z]+$/); // e.g., user.created
  expect(message.eventVersion).toMatch(/^v\d+$/); // e.g., v1
}

export default {
  assertStatus,
  assertSuccess,
  assertError,
  assertResponseStructure,
  assertHasFields,
  assertValidToken,
  assertValidUser,
  assertValidOrder,
  assertValidEmail,
  assertRecentTimestamp,
  assertArrayContains,
  assertErrorMessage,
  assertValidEventBridgeMessage,
};
