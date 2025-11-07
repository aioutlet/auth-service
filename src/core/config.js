/**
 * Configuration module for auth-service
 * Centralizes all environment-based configuration (non-sensitive only)
 *
 * For sensitive secrets (JWT secrets), use:
 * - import { getJwtConfig } from '../services/dapr.secretManager.js'
 */

export default {
  service: {
    name: process.env.NAME || 'auth-service',
    version: process.env.VERSION || '1.0.0',
    port: parseInt(process.env.PORT, 10) || 3001,
    host: process.env.HOST || '0.0.0.0',
    nodeEnv: process.env.NODE_ENV || 'development',
  },

  cors: {
    origins: process.env.CORS_ORIGINS
      ? process.env.CORS_ORIGINS.split(',')
      : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3010'],
  },

  logging: {
    level: process.env.LOG_LEVEL || 'debug',
    format: process.env.LOG_FORMAT || 'console',
    toConsole: process.env.LOG_TO_CONSOLE === 'true',
    toFile: process.env.LOG_TO_FILE === 'true',
    filePath: process.env.LOG_FILE_PATH || './logs/auth-service.log',
  },

  observability: {
    correlationIdHeader: process.env.CORRELATION_ID_HEADER || 'x-correlation-id',
  },

  dapr: {
    enabled: process.env.DAPR_ENABLED === 'true',
    httpPort: parseInt(process.env.DAPR_HTTP_PORT, 10) || 3500,
    host: process.env.DAPR_HOST || 'localhost',
    pubsubName: process.env.DAPR_PUBSUB_NAME || 'auth-pubsub',
    appId: process.env.DAPR_APP_ID || 'auth-service',
  },

  services: {
    userService: {
      appId: process.env.USER_SERVICE_APP_ID || 'user-service',
    },
    webUI: {
      baseUrl: process.env.WEB_UI_BASE_URL || 'http://localhost:3000',
    },
  },
};
