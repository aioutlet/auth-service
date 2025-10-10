// Setup environment variables before any tests run
// This runs before setupFilesAfterEnv
import dotenv from 'dotenv';

// Suppress dotenv console output in tests
const originalLog = console.log;
console.log = () => {}; // Temporarily disable console.log

// Load environment variables
dotenv.config();

// Restore console.log
console.log = originalLog;

// Set NODE_ENV to test
process.env.NODE_ENV = 'test';
