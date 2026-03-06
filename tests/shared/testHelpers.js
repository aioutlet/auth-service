/**
 * Test helper functions for creating mock objects
 */

export function createMockReqRes(overrides = {}) {
  const defaultReq = {
    body: {},
    params: {},
    query: {},
    headers: {},
    cookies: {},
    ip: '127.0.0.1',
    method: 'GET',
    originalUrl: '/test',
    get: jest.fn(),
    correlationId: 'test-correlation-id',
  };

  // Deep merge specific properties if provided
  const mergedBody = { ...defaultReq.body, ...overrides.body };
  const mergedParams = { ...defaultReq.params, ...overrides.params };
  const mergedQuery = { ...defaultReq.query, ...overrides.query };
  const mergedHeaders = { ...defaultReq.headers, ...overrides.headers };
  const mergedCookies = { ...defaultReq.cookies, ...overrides.cookies };

  const req = {
    ...defaultReq,
    ...overrides,
    // Override with merged versions
    body: mergedBody,
    params: mergedParams,
    query: mergedQuery,
    headers: mergedHeaders,
    cookies: mergedCookies,
  };

  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    cookie: jest.fn().mockReturnThis(),
    clearCookie: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
  };

  return { req, res };
}

export function createMockNext() {
  return jest.fn();
}

export function createMockUser(overrides = {}) {
  return {
    _id: '507f1f77bcf86cd799439011',
    email: 'test@example.com',
    firstName: 'Test',
    lastName: 'User',
    name: 'Test User',
    password: '$2b$10$hashedPassword',
    roles: ['customer'],
    isEmailVerified: true,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}
