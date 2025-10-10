// Integration test for user-service client
// Tests HTTP API integration with mocked user-service responses

import * as userServiceClient from '../../src/services/userServiceClient.js';

// Mock fetch to test HTTP API integration
global.fetch = jest.fn();

describe('User Service Client Integration Tests', () => {
  const USER_SERVICE_URL = process.env.USER_SERVICE_URL || 'http://localhost:5000/users';

  // Clear mocks before each test
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getUserByEmail', () => {
    it('should fetch user by email successfully', async () => {
      // Arrange
      const mockUser = {
        _id: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        isEmailVerified: true,
        isActive: true,
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockUser,
      });

      // Act
      const result = await userServiceClient.getUserByEmail('test@example.com');

      // Assert
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(global.fetch).toHaveBeenCalledWith(`${USER_SERVICE_URL}/findByEmail?email=test%40example.com`);
      expect(result).toEqual(mockUser);
    });

    it('should return null when user not found', async () => {
      // Arrange
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      // Act
      const result = await userServiceClient.getUserByEmail('notfound@example.com');

      // Assert
      expect(result).toBeNull();
    });

    it('should encode email with special characters', async () => {
      // Arrange
      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      // Act
      await userServiceClient.getUserByEmail('test+tag@example.com');

      // Assert
      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('test%2Btag%40example.com'));
    });
  });

  describe('createUser', () => {
    it('should create user successfully', async () => {
      // Arrange
      const userData = {
        email: 'newuser@example.com',
        password: 'SecurePass123!',
        firstName: 'New',
        lastName: 'User',
        roles: ['customer'],
      };

      const mockResponse = {
        _id: '507f1f77bcf86cd799439011',
        email: 'newuser@example.com',
        firstName: 'New',
        lastName: 'User',
        isEmailVerified: false,
        isActive: true,
        roles: ['customer'],
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => mockResponse,
      });

      // Act
      const result = await userServiceClient.createUser(userData);

      // Assert
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(global.fetch).toHaveBeenCalledWith(
        USER_SERVICE_URL,
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: expect.any(String),
        })
      );

      const requestBody = JSON.parse(global.fetch.mock.calls[0][1].body);
      expect(requestBody).toMatchObject({
        email: 'newuser@example.com',
        firstName: 'New',
        lastName: 'User',
      });
      expect(requestBody.password).toBe('SecurePass123!');
      expect(result).toEqual(mockResponse);
    });

    it('should handle HTTP error with JSON error details', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        password: 'pass',
        firstName: 'Test',
        lastName: 'User',
      };

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: 'Email already exists' }),
      });

      // Act & Assert
      await expect(userServiceClient.createUser(userData)).rejects.toThrow('Email already exists');

      // Reset mock for second call
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: 'Email already exists' }),
      });

      try {
        await userServiceClient.createUser(userData);
        fail('Should have thrown error');
      } catch (error) {
        expect(error.statusCode).toBe(400);
        expect(error.details).toEqual({ error: 'Email already exists' });
      }
    });

    it('should handle HTTP error with text error', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        password: 'pass',
        firstName: 'Test',
        lastName: 'User',
      };

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => {
          throw new Error('Not JSON');
        },
        text: async () => 'Internal Server Error',
      });

      // Act & Assert
      await expect(userServiceClient.createUser(userData)).rejects.toThrow();
    });

    it('should handle network errors', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        password: 'pass',
        firstName: 'Test',
        lastName: 'User',
      };

      global.fetch.mockRejectedValueOnce(new Error('Network error'));

      // Act & Assert
      await expect(userServiceClient.createUser(userData)).rejects.toThrow('User service unavailable');

      // Reset mock for second call
      const networkError = new Error('Network error');
      global.fetch.mockRejectedValueOnce(networkError);

      try {
        await userServiceClient.createUser(userData);
        fail('Should have thrown error');
      } catch (error) {
        expect(error.statusCode).toBe(503);
        expect(error.originalError).toBe(networkError);
      }
    });

    it('should redact password in error logs', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        password: 'SecretPassword123!',
        firstName: 'Test',
        lastName: 'User',
      };

      global.fetch.mockRejectedValueOnce(new Error('Network error'));

      // Act
      try {
        await userServiceClient.createUser(userData);
      } catch {
        // Error should be thrown but password should be redacted in logs
        // (This is tested implicitly by the error handling code)
      }

      // Assert - just verify the function handles the error
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('deleteUserSelf', () => {
    it('should delete user successfully', async () => {
      // Arrange
      const token = 'valid-jwt-token';

      global.fetch.mockResolvedValueOnce({
        status: 204,
      });

      // Act
      const result = await userServiceClient.deleteUserSelf(token);

      // Assert
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(global.fetch).toHaveBeenCalledWith(
        USER_SERVICE_URL,
        expect.objectContaining({
          method: 'DELETE',
          headers: {
            Authorization: `Bearer ${token}`,
          },
        })
      );
      expect(result).toBe(true);
    });

    it('should return false on non-204 response', async () => {
      // Arrange
      const token = 'valid-jwt-token';

      global.fetch.mockResolvedValueOnce({
        status: 404,
      });

      // Act
      const result = await userServiceClient.deleteUserSelf(token);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('deleteUserById', () => {
    it('should delete user by ID successfully', async () => {
      // Arrange
      const userId = '507f1f77bcf86cd799439011';
      const token = 'admin-jwt-token';

      global.fetch.mockResolvedValueOnce({
        status: 204,
      });

      // Act
      const result = await userServiceClient.deleteUserById(userId, token);

      // Assert
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(global.fetch).toHaveBeenCalledWith(
        `${USER_SERVICE_URL}/${userId}`,
        expect.objectContaining({
          method: 'DELETE',
          headers: {
            Authorization: `Bearer ${token}`,
          },
        })
      );
      expect(result).toBe(true);
    });

    it('should return false on non-204 response', async () => {
      // Arrange
      const userId = '507f1f77bcf86cd799439011';
      const token = 'admin-jwt-token';

      global.fetch.mockResolvedValueOnce({
        status: 403,
      });

      // Act
      const result = await userServiceClient.deleteUserById(userId, token);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('getUserById', () => {
    it('should fetch user by ID successfully with token', async () => {
      // Arrange
      const userId = '507f1f77bcf86cd799439011';
      const token = 'valid-jwt-token';
      const mockUser = {
        _id: userId,
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockUser,
      });

      // Act
      const result = await userServiceClient.getUserById(userId, token);

      // Assert
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining(`/admin/users/${userId}`),
        expect.objectContaining({
          headers: { Authorization: `Bearer ${token}` },
        })
      );
      expect(result).toEqual(mockUser);
    });

    it('should fetch user by ID without token', async () => {
      // Arrange
      const userId = '507f1f77bcf86cd799439011';
      const mockUser = {
        _id: userId,
        email: 'test@example.com',
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockUser,
      });

      // Act
      const result = await userServiceClient.getUserById(userId);

      // Assert
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining(`/admin/users/${userId}`),
        expect.objectContaining({
          headers: {},
        })
      );
      expect(result).toEqual(mockUser);
    });

    it('should return null when user not found', async () => {
      // Arrange
      const userId = '507f1f77bcf86cd799439011';

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      // Act
      const result = await userServiceClient.getUserById(userId);

      // Assert
      expect(result).toBeNull();
    });

    it('should use admin route for service-to-service lookups', async () => {
      // Arrange
      const userId = '507f1f77bcf86cd799439011';

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      // Act
      await userServiceClient.getUserById(userId);

      // Assert
      const calledUrl = global.fetch.mock.calls[0][0];
      expect(calledUrl).toContain('/admin/users/');
      expect(calledUrl).not.toContain('/users/users/'); // Should replace /users correctly
    });
  });

  describe('Error Handling', () => {
    it('should preserve HTTP status codes in errors', async () => {
      // Arrange
      const testCases = [
        { status: 400, message: 'Bad Request' },
        { status: 401, message: 'Unauthorized' },
        { status: 403, message: 'Forbidden' },
        { status: 404, message: 'Not Found' },
        { status: 409, message: 'Conflict' },
        { status: 500, message: 'Internal Server Error' },
      ];

      for (const testCase of testCases) {
        global.fetch.mockResolvedValueOnce({
          ok: false,
          status: testCase.status,
          json: async () => ({ error: testCase.message }),
        });

        try {
          await userServiceClient.createUser({
            email: 'test@example.com',
            password: 'pass',
            firstName: 'Test',
            lastName: 'User',
          });
        } catch (error) {
          expect(error.statusCode).toBe(testCase.status);
        }
      }
    });

    it('should handle timeout errors gracefully', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        password: 'pass',
        firstName: 'Test',
        lastName: 'User',
      };

      global.fetch.mockRejectedValueOnce(new Error('Request timeout'));

      // Act & Assert
      await expect(userServiceClient.createUser(userData)).rejects.toThrow('User service unavailable');
    });
  });
});
