// Global test setup and utilities

// Note: Environment variables are loaded by setupEnv.js (runs before this file)

// Mock console methods to reduce test noise (optional - comment out if you need to debug)
const originalConsoleError = console.error;
beforeAll(() => {
  // Suppress winston "no transports" warnings in tests
  console.error = (...args) => {
    const message = args[0];
    if (typeof message === 'string' && message.includes('[winston]') && message.includes('no transports')) {
      return; // Suppress this specific warning
    }
    originalConsoleError.apply(console, args);
  };
});

afterAll(() => {
  // Restore original console.error
  console.error = originalConsoleError;
});

// Clean up after each test
afterEach(async () => {
  // Clear all mocks
  jest.clearAllMocks();
});
