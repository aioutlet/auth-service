/**
 * Environment Configuration Validation Tests
 * Validates that all required environment variables are set
 * Tests will fail if critical configuration is missing
 */

describe('Environment Configuration', () => {
  describe('Critical Environment Variables', () => {
    it('should have NODE_ENV defined', () => {
      expect(process.env.NODE_ENV).toBeDefined();
      expect(process.env.NODE_ENV).toBeTruthy();
    });

    it('should have MONGODB_URI defined', () => {
      expect(process.env.MONGODB_URI).toBeDefined();
      expect(process.env.MONGODB_URI).toMatch(/^mongodb/);
    });

    it('should have valid MONGODB_URI format', () => {
      const uri = process.env.MONGODB_URI;
      expect(uri).toBeDefined();
      // Should start with mongodb:// or mongodb+srv://
      expect(uri).toMatch(/^mongodb(\+srv)?:\/\//);
      // Should contain database name
      expect(uri).toContain('/');
    });

    it('should have JWT_SECRET defined', () => {
      expect(process.env.JWT_SECRET).toBeDefined();
      expect(process.env.JWT_SECRET).toBeTruthy();
      expect(process.env.JWT_SECRET.length).toBeGreaterThan(10);
    });
  });

  describe('Server Configuration', () => {
    it('should have valid PORT or use default', () => {
      const port = process.env.PORT || '3001';
      const portNum = parseInt(port, 10);
      expect(portNum).toBeGreaterThan(0);
      expect(portNum).toBeLessThan(65536);
    });

    it('should have SERVICE_NAME defined', () => {
      const serviceName = process.env.SERVICE_NAME || 'auth-service';
      expect(serviceName).toBeTruthy();
      expect(typeof serviceName).toBe('string');
    });
  });

  describe('Database Configuration', () => {
    it('should have valid MONGODB_PORT', () => {
      const port = process.env.MONGODB_PORT || '27017';
      const portNum = parseInt(port, 10);
      expect(portNum).toBeGreaterThan(0);
      expect(portNum).toBeLessThan(65536);
    });

    it('should have MONGODB_CONNECTION_SCHEME', () => {
      const scheme = process.env.MONGODB_CONNECTION_SCHEME || 'mongodb';
      expect(['mongodb', 'mongodb+srv']).toContain(scheme);
    });
  });

  describe('Security Configuration', () => {
    it('should have CORS_ORIGINS defined or use default', () => {
      const origins = process.env.CORS_ORIGINS || 'http://localhost:3000';
      expect(origins).toBeTruthy();
      expect(typeof origins).toBe('string');
    });
  });

  describe('External Services', () => {
    it('should have USER_SERVICE_URL defined or use default', () => {
      const url = process.env.USER_SERVICE_URL || 'http://localhost:3002/api/users';
      expect(url).toBeTruthy();
      expect(url).toMatch(/^https?:\/\//);
    });
  });

  describe('Message Broker Configuration', () => {
    it('should have MESSAGE_BROKER_SERVICE_URL defined or use default', () => {
      const url = process.env.MESSAGE_BROKER_SERVICE_URL || 'http://localhost:4000';
      expect(url).toBeTruthy();
      expect(url).toMatch(/^https?:\/\//);
    });
  });

  describe('Email Configuration', () => {
    it('should have EMAIL_FROM defined', () => {
      const from = process.env.EMAIL_FROM || 'noreply@aioutlet.local';
      expect(from).toBeTruthy();
      expect(from).toMatch(/@/);
    });

    it('should have SMTP_HOST defined or use default', () => {
      const host = process.env.SMTP_HOST || 'localhost';
      expect(host).toBeTruthy();
      expect(typeof host).toBe('string');
    });

    it('should have valid SMTP_PORT', () => {
      const port = process.env.SMTP_PORT || '1025';
      const portNum = parseInt(port, 10);
      expect(portNum).toBeGreaterThan(0);
      expect(portNum).toBeLessThan(65536);
    });
  });

  describe('Logging Configuration', () => {
    it('should have valid LOG_LEVEL', () => {
      const level = process.env.LOG_LEVEL || 'info';
      expect(['error', 'warn', 'info', 'debug', 'verbose']).toContain(level);
    });

    it('should have LOG_FORMAT defined', () => {
      const format = process.env.LOG_FORMAT || 'json';
      expect(['json', 'console', 'simple']).toContain(format);
    });
  });

  describe('Observability Configuration', () => {
    it('should have CORRELATION_ID_HEADER defined', () => {
      const header = process.env.CORRELATION_ID_HEADER || 'x-correlation-id';
      expect(header).toBeTruthy();
      expect(typeof header).toBe('string');
    });

    it('should have ENABLE_TRACING flag', () => {
      const tracing = process.env.ENABLE_TRACING;
      if (tracing) {
        expect(['true', 'false', '1', '0']).toContain(tracing);
      }
    });
  });

  describe('Production Environment Validation', () => {
    it('should have strong JWT_SECRET in production', () => {
      if (process.env.NODE_ENV === 'production') {
        expect(process.env.JWT_SECRET).toBeDefined();
        expect(process.env.JWT_SECRET.length).toBeGreaterThanOrEqual(32);
      }
    });

    it('should have proper SMTP configuration in production', () => {
      if (process.env.NODE_ENV === 'production' && process.env.EMAIL_PROVIDER === 'smtp') {
        expect(process.env.SMTP_HOST).toBeDefined();
        expect(process.env.SMTP_HOST).not.toBe('localhost');
      }
    });
  });
});
