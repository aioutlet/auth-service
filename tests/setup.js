// Global test setup and utilities
import mongoose from 'mongoose';

// Mock environment variables for testing
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
process.env.JWT_ALGORITHM = 'HS256';
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.USER_SERVICE_URL = 'http://test-user-service';
process.env.BASE_URL = 'http://localhost:4000';

// Mock global mongoUrl for session store
global.mongoUrl = 'mongodb://test:27017/auth-test';

// Clean up after each test
afterEach(async () => {
  // Clear all mocks
  jest.clearAllMocks();
});

// Global teardown
afterAll(async () => {
  // Close mongoose connection if open
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
});