/**
 * User Test Fixtures
 * Provides reusable user test data
 */

/**
 * Generate unique test email
 */
export function generateTestEmail(prefix = 'e2e-test') {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(7);
  return `${prefix}-${timestamp}-${random}@example.com`;
}

/**
 * Generate test user data
 */
export function generateTestUser(overrides = {}) {
  return {
    email: generateTestEmail(),
    password: 'Test@123456',
    firstName: 'TestUser',
    lastName: 'AutoTest',
    ...overrides,
  };
}

/**
 * Valid user data for registration
 */
export const validUser = {
  email: 'valid-user@example.com',
  password: 'Valid@123456',
  firstName: 'John',
  lastName: 'Doe',
};

/**
 * User with missing required fields
 */
export const incompleteUser = {
  email: 'incomplete@example.com',
  // Missing password, firstName, lastName
};

/**
 * User with invalid email format
 */
export const invalidEmailUser = {
  email: 'not-an-email',
  password: 'Test@123456',
  firstName: 'Test',
  lastName: 'User',
};

/**
 * User with weak password
 */
export const weakPasswordUser = {
  email: 'weak-password@example.com',
  password: '123',
  firstName: 'Test',
  lastName: 'User',
};

/**
 * User with invalid password (no special char)
 */
export const invalidPasswordUser = {
  email: 'invalid-password@example.com',
  password: 'NoSpecialChar123',
  firstName: 'Test',
  lastName: 'User',
};

/**
 * Admin user data
 */
export const adminUser = {
  email: 'admin@example.com',
  password: 'Admin@123456',
  firstName: 'Admin',
  lastName: 'User',
  role: 'admin',
};

/**
 * Generate batch of test users
 */
export function generateTestUsers(count = 5) {
  return Array.from({ length: count }, (_, i) => ({
    email: generateTestEmail(`batch-${i}`),
    password: 'Test@123456',
    firstName: `TestUser${i}`,
    lastName: `Batch${i}`,
  }));
}

export default {
  generateTestEmail,
  generateTestUser,
  validUser,
  incompleteUser,
  invalidEmailUser,
  weakPasswordUser,
  invalidPasswordUser,
  adminUser,
  generateTestUsers,
};
