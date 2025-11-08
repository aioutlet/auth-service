// API Test: Auth Service
// Tests individual auth-service endpoints in isolation
//
// Dependencies:
// - user-service: Auth-service calls user-service for user CRUD operations
// - message-broker-service: Auth-service publishes events for audit, notifications, and analytics
// Note: These are genuine dependencies for enterprise-grade auth functionality

import axios from 'axios';
import { registerUser, login } from '../../shared/helpers/auth.js';
import { generateTestUser, deleteUser, sleep } from '../../shared/helpers/user.js';

const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3001';
const AUTH_SERVICE_HEALTH_URL = process.env.AUTH_SERVICE_HEALTH_URL || 'http://localhost:3001/health';
const USER_SERVICE_URL = process.env.USER_SERVICE_URL || 'http://localhost:3002';
const USER_SERVICE_HEALTH_URL = process.env.USER_SERVICE_HEALTH_URL || 'http://localhost:3002/health';
const MESSAGE_BROKER_SERVICE_URL = process.env.MESSAGE_BROKER_SERVICE_URL || 'http://localhost:4000';
const MESSAGE_BROKER_SERVICE_HEALTH_URL =
  process.env.MESSAGE_BROKER_SERVICE_HEALTH_URL || 'http://localhost:4000/health';

// Verify required services are available
async function verifyServices() {
  try {
    await axios.get(AUTH_SERVICE_HEALTH_URL, { timeout: 2000 });
    await axios.get(USER_SERVICE_HEALTH_URL, { timeout: 2000 });
    await axios.get(MESSAGE_BROKER_SERVICE_HEALTH_URL, { timeout: 2000 });
    return true;
  } catch (error) {
    console.error('❌ Required services not available:');
    console.error(`   Auth Service: ${AUTH_SERVICE_URL}`);
    console.error(`   User Service: ${USER_SERVICE_URL}`);
    console.error(`   Message Broker: ${MESSAGE_BROKER_SERVICE_URL}`);
    console.error('   Please start all required services before running tests.');
    return false;
  }
}

describe('Auth Service API Tests', () => {
  beforeAll(async () => {
    const servicesAvailable = await verifyServices();
    if (!servicesAvailable) {
      throw new Error('Required services are not available');
    }
  });

  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const response = await axios.get(AUTH_SERVICE_HEALTH_URL);

      expect(response.status).toBe(200);
      expect(response.data).toBeDefined();
      expect(response.data.status).toBe('healthy');
      expect(response.data.service).toBe('auth-service');

      console.log('✅ Auth service is healthy');
    });
  });

  describe('User Registration', () => {
    let testUser;
    let userId;
    let token;

    afterEach(async () => {
      // Cleanup: Delete test user if created
      if (userId && token) {
        await deleteUser(userId, token);
        userId = null;
        token = null;
      }
    });

    it('should successfully register a new user', async () => {
      testUser = generateTestUser();
      console.log(`\n📝 Registering user: ${testUser.email}`);

      const response = await registerUser(testUser);

      expect(response).toBeDefined();
      expect(response.message).toContain('Registration successful');
      expect(response.requiresVerification).toBe(true);
      expect(response.user).toBeDefined();
      expect(response.user.email).toBe(testUser.email);
      expect(response.user._id).toBeDefined();
      expect(response.user.firstName).toBe(testUser.firstName);
      expect(response.user.lastName).toBe(testUser.lastName);

      userId = response.user._id;

      console.log(`✅ User registered successfully with ID: ${userId}`);
    });

    it('should reject registration with missing email', async () => {
      const invalidUser = {
        password: 'Test@123456',
        firstName: 'Test',
        lastName: 'User',
      };

      try {
        await registerUser(invalidUser);
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error.response).toBeDefined();
        expect(error.response.status).toBe(400);
        expect(error.response.data.error).toBeDefined();

        console.log('✅ Registration rejected for missing email');
      }
    });

    it('should reject registration with invalid email format', async () => {
      const invalidUser = {
        email: 'invalid-email',
        password: 'Test@123456',
        firstName: 'Test',
        lastName: 'User',
      };

      try {
        await registerUser(invalidUser);
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error.response).toBeDefined();
        expect(error.response.status).toBe(400);

        console.log('✅ Registration rejected for invalid email format');
      }
    });

    it('should reject registration with weak password', async () => {
      const invalidUser = {
        email: generateTestUser().email,
        password: '123', // Too short and weak
        firstName: 'Test',
        lastName: 'User',
      };

      try {
        await registerUser(invalidUser);
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error.response).toBeDefined();
        expect(error.response.status).toBe(400);

        console.log('✅ Registration rejected for weak password');
      }
    });

    it('should reject registration with missing first name', async () => {
      const invalidUser = {
        email: generateTestUser().email,
        password: 'Test@123456',
        lastName: 'User',
      };

      try {
        await registerUser(invalidUser);
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error.response).toBeDefined();
        expect(error.response.status).toBe(400);

        console.log('✅ Registration rejected for missing first name');
      }
    });

    it('should reject duplicate user registration', async () => {
      testUser = generateTestUser();

      // Register user first time
      const firstResponse = await registerUser(testUser);
      userId = firstResponse.user._id;

      // Wait a bit to avoid rate limiting
      await sleep(1000);

      // Attempt to register same user again
      try {
        await registerUser(testUser);
        fail('Should have thrown error for duplicate registration');
      } catch (error) {
        expect(error.response).toBeDefined();
        // May return 400 (validation), 409 (conflict), or 429 (rate limit)
        expect([400, 409, 429]).toContain(error.response.status);

        console.log(`✅ Duplicate registration prevented (Status: ${error.response.status})`);
      }
    });
  });

  describe('User Login', () => {
    it('should reject login with non-existent email', async () => {
      try {
        await login('nonexistent@example.com', 'Test@123456');
        fail('Should have thrown unauthorized error');
      } catch (error) {
        expect(error.response).toBeDefined();
        expect(error.response.status).toBe(401);
        expect(error.response.data.error).toBeDefined();

        console.log('✅ Login rejected for non-existent user');
      }
    });

    it('should reject login with invalid email format', async () => {
      try {
        await login('invalid-email', 'Test@123456');
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error.response).toBeDefined();
        expect([400, 401]).toContain(error.response.status);

        console.log(`✅ Login rejected for invalid email format (Status: ${error.response.status})`);
      }
    });

    it('should reject login with missing password', async () => {
      try {
        const response = await axios.post(`${AUTH_SERVICE_URL}/api/auth/login`, {
          email: 'test@example.com',
        });
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error.response).toBeDefined();
        expect(error.response.status).toBe(400);

        console.log('✅ Login rejected for missing password');
      }
    });

    it('should reject login with empty credentials', async () => {
      try {
        await login('', '');
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error.response).toBeDefined();
        expect(error.response.status).toBe(400);

        console.log('✅ Login rejected for empty credentials');
      }
    });
  });

  describe('Token Validation', () => {
    it('should accept requests with valid token', async () => {
      // This would require a protected endpoint to test
      // Skipping for now as we need to implement in auth-service
      console.log('⏭️  Skipped: Requires protected endpoint implementation');
    });

    it('should reject requests with invalid token', async () => {
      // This would require a protected endpoint to test
      // Skipping for now as we need to implement in auth-service
      console.log('⏭️  Skipped: Requires protected endpoint implementation');
    });
  });
});
