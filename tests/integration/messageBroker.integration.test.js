// Integration test for auth-service with message broker service
// Tests that auth-service correctly calls message broker service HTTP API

import messageBrokerService from '../../src/services/messageBrokerServiceClient.js';

// Mock fetch to test HTTP API integration
global.fetch = jest.fn();

describe('Auth Service Message Broker Client Integration Tests', () => {
  // Clear mocks before each test
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('HTTP API Integration', () => {
    it('should call message broker service API with correct payload for auth.user.registered event', async () => {
      // Arrange
      const eventData = {
        userId: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        name: 'Test User',
        firstName: 'Test',
        lastName: 'User',
        registeredAt: new Date().toISOString(),
        correlationId: 'test-correlation-id',
        timestamp: new Date().toISOString(),
      };

      // Mock successful response from message broker service
      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          message_id: 'test-message-id-123',
        }),
      });

      // Act
      const result = await messageBrokerService.publishEvent('auth.user.registered', eventData);

      // Assert: Verify HTTP call was made correctly
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/publish'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            Authorization: expect.stringContaining('Bearer'),
          }),
          body: expect.any(String),
        })
      );

      // Verify the request body
      const callArgs = global.fetch.mock.calls[0];
      const requestBody = JSON.parse(callArgs[1].body);

      expect(requestBody).toMatchObject({
        topic: 'auth.user.registered',
        data: expect.objectContaining({
          eventType: 'auth.user.registered',
          source: 'auth-service',
          data: expect.objectContaining({
            userId: eventData.userId,
            email: eventData.email,
            name: eventData.name,
          }),
        }),
      });

      // Verify result
      expect(result).toEqual({
        success: true,
        message_id: 'test-message-id-123',
      });
    });

    it('should handle failed HTTP requests gracefully', async () => {
      // Arrange
      const eventData = {
        userId: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        timestamp: new Date().toISOString(),
      };

      // Mock failed response from message broker service
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      // Act
      const result = await messageBrokerService.publishEvent('auth.user.registered', eventData);

      // Assert: Should return null on failure (graceful degradation)
      expect(result).toBeNull();
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('should handle network errors gracefully', async () => {
      // Arrange
      const eventData = {
        userId: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        timestamp: new Date().toISOString(),
      };

      // Mock network error
      global.fetch.mockRejectedValueOnce(new Error('Network error'));

      // Act
      const result = await messageBrokerService.publishEvent('auth.user.registered', eventData);

      // Assert: Should return null on failure (graceful degradation)
      expect(result).toBeNull();
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('should include API key in authorization header', async () => {
      // Arrange
      const eventData = {
        userId: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        timestamp: new Date().toISOString(),
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true, message_id: 'test-123' }),
      });

      // Act
      await messageBrokerService.publishEvent('auth.user.registered', eventData);

      // Assert
      const callArgs = global.fetch.mock.calls[0];
      expect(callArgs[1].headers.Authorization).toMatch(/^Bearer /);
    });
  });

  describe('Event Payload Structure', () => {
    it('should wrap event data with proper structure', async () => {
      // Arrange
      const eventData = {
        userId: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        name: 'Test User',
        timestamp: new Date().toISOString(),
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true, message_id: 'test-123' }),
      });

      // Act
      await messageBrokerService.publishEvent('auth.user.registered', eventData);

      // Assert
      const callArgs = global.fetch.mock.calls[0];
      const requestBody = JSON.parse(callArgs[1].body);

      // Verify structure
      expect(requestBody).toHaveProperty('topic', 'auth.user.registered');
      expect(requestBody).toHaveProperty('data');
      expect(requestBody.data).toHaveProperty('eventId');
      expect(requestBody.data).toHaveProperty('eventType', 'auth.user.registered');
      expect(requestBody.data).toHaveProperty('timestamp');
      expect(requestBody.data).toHaveProperty('source', 'auth-service');
      expect(requestBody.data).toHaveProperty('data');
      expect(requestBody.data).toHaveProperty('metadata');
      expect(requestBody.data.metadata).toHaveProperty('correlationId');
      expect(requestBody.data.metadata).toHaveProperty('version', '1.0');
    });

    it('should generate unique event IDs', async () => {
      // Arrange
      const eventData = {
        userId: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        timestamp: new Date().toISOString(),
      };

      global.fetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true, message_id: 'test-123' }),
      });

      // Act
      await messageBrokerService.publishEvent('auth.user.registered', eventData);
      await messageBrokerService.publishEvent('auth.user.registered', eventData);

      // Assert
      const call1Body = JSON.parse(global.fetch.mock.calls[0][1].body);
      const call2Body = JSON.parse(global.fetch.mock.calls[1][1].body);

      expect(call1Body.data.eventId).not.toBe(call2Body.data.eventId);
    });

    it('should use provided correlationId or generate one', async () => {
      // Arrange
      const eventDataWithCorrelation = {
        userId: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        correlationId: 'my-correlation-id',
        timestamp: new Date().toISOString(),
      };

      const eventDataWithoutCorrelation = {
        userId: '507f1f77bcf86cd799439012',
        email: 'test2@example.com',
        timestamp: new Date().toISOString(),
      };

      global.fetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true, message_id: 'test-123' }),
      });

      // Act
      await messageBrokerService.publishEvent('auth.user.registered', eventDataWithCorrelation);
      await messageBrokerService.publishEvent('auth.user.registered', eventDataWithoutCorrelation);

      // Assert
      const call1Body = JSON.parse(global.fetch.mock.calls[0][1].body);
      const call2Body = JSON.parse(global.fetch.mock.calls[1][1].body);

      expect(call1Body.data.metadata.correlationId).toBe('my-correlation-id');
      expect(call2Body.data.metadata.correlationId).toBeDefined();
      expect(call2Body.data.metadata.correlationId).not.toBe('');
    });
  });
});
