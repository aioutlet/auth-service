// Global test setup and utilities
import mongoose from 'mongoose';
import dotenv from 'dotenv';

// Load environment variables from .env file
// This ensures tests validate the actual .env configuration
dotenv.config();

// Only override NODE_ENV to ensure we're in test mode
process.env.NODE_ENV = 'test';

// Set global mongoUrl from loaded environment variables
global.mongoUrl = process.env.MONGODB_URI || 'mongodb://localhost:27021/auth_service_local_db';

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
