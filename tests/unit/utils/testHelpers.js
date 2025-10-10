// Test utilities and helper functions
import httpMocks from 'node-mocks-http';

/**
 * Create mock Express request and response objects
 */
export const createMockReqRes = (options = {}) => {
  const req = httpMocks.createRequest({
    ...options,
    cookies: options.cookies || {},
    headers: options.headers || {},
    user: options.user || null,
  });

  const res = httpMocks.createResponse();
  
  // Add cookie method to mock response
  res.cookie = jest.fn();
  res.clearCookie = jest.fn();
  
  return { req, res };
};

/**
 * Create a mock user object
 */
export const createMockUser = (overrides = {}) => ({
  _id: '507f1f77bcf86cd799439011',
  email: 'test@example.com',
  firstName: 'Test',
  lastName: 'User',
  roles: ['customer'],
  isEmailVerified: true,
  isActive: true,
  ...overrides,
});

/**
 * Create mock next function
 */
export const createMockNext = () => jest.fn();

/**
 * Mock fetch for external API calls
 */
export const mockFetch = (responseData, status = 200, ok = true) => {
  global.fetch = jest.fn(() =>
    Promise.resolve({
      ok,
      status,
      json: () => Promise.resolve(responseData),
      text: () => Promise.resolve(JSON.stringify(responseData)),
      headers: {
        get: (header) => {
          if (header === 'content-type') {return 'application/json';}
          return null;
        },
      },
    }),
  );
};

/**
 * Create a spy that resolves with given data
 */
export const createResolvedSpy = (data) => jest.fn().mockResolvedValue(data);

/**
 * Create a spy that rejects with given error
 */
export const createRejectedSpy = (error) => jest.fn().mockRejectedValue(error);