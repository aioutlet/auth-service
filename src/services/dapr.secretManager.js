/**
 * Dapr Secret Management Service
 * Provides secret management using Dapr's secret store building block.
 * Falls back to environment variables if Dapr is not available.
 */

import { DaprClient } from '@dapr/dapr';
import logger from '../core/logger.js';

class DaprSecretManager {
  constructor() {
    this.daprEnabled = (process.env.DAPR_ENABLED || 'true').toLowerCase() === 'true';
    this.environment = process.env.NODE_ENV || 'development';
    this.daprHost = process.env.DAPR_HOST || '127.0.0.1';
    this.daprPort = process.env.DAPR_HTTP_PORT || '3500';

    // Use appropriate secret store based on environment
    if (this.environment === 'production') {
      this.secretStoreName = 'azure-keyvault-secret-store';
    } else {
      this.secretStoreName = 'local-secret-store';
    }

    logger.info('Secret manager initialized', {
      event: 'secret_manager_init',
      daprEnabled: this.daprEnabled,
      environment: this.environment,
      secretStore: this.secretStoreName,
    });
  }

  /**
   * Get a secret value
   * @param {string} secretName - Name of the secret to retrieve
   * @returns {Promise<string|null>} Secret value or null if not found
   *
   * Priority:
   * 1. Dapr secret store (if enabled and available)
   * 2. Environment variable (fallback)
   */
  async getSecret(secretName) {
    // If Dapr is disabled, use environment variables
    if (!this.daprEnabled) {
      const value = process.env[secretName];
      if (value) {
        logger.debug('Retrieved secret from environment', {
          event: 'secret_retrieved',
          secretName,
          source: 'env',
        });
      }
      return value || null;
    }

    // Try Dapr secret store
    try {
      const client = new DaprClient({
        daprHost: this.daprHost,
        daprPort: this.daprPort,
      });

      const response = await client.secret.get(this.secretStoreName, secretName);

      // Handle different response types
      if (response && typeof response === 'object') {
        // Response is typically an object like { secretName: 'value' }
        const value = response[secretName];
        if (value !== undefined && value !== null) {
          logger.debug('Retrieved secret from Dapr', {
            event: 'secret_retrieved',
            secretName,
            source: 'dapr',
            store: this.secretStoreName,
          });
          return String(value);
        }

        // If not found by key, try getting first value
        const values = Object.values(response);
        if (values.length > 0 && values[0] !== undefined) {
          logger.debug('Retrieved secret from Dapr (first value)', {
            event: 'secret_retrieved',
            secretName,
            source: 'dapr',
            store: this.secretStoreName,
          });
          return String(values[0]);
        }
      }

      // If we get here, no value was found in Dapr
      logger.warn('Secret not found in Dapr store', {
        event: 'secret_not_found',
        secretName,
        store: this.secretStoreName,
      });
    } catch (error) {
      logger.warn(`Failed to get secret from Dapr: ${error.message}`, {
        event: 'secret_retrieval_error',
        secretName,
        error: error.message,
        store: this.secretStoreName,
      });
    }

    // Fallback to environment variable
    const value = process.env[secretName];
    if (value) {
      logger.debug('Retrieved secret from environment (fallback)', {
        event: 'secret_retrieved',
        secretName,
        source: 'env_fallback',
      });
    }
    return value || null;
  }

  /**
   * Get multiple secrets at once
   * @param {string[]} secretNames - List of secret names to retrieve
   * @returns {Promise<Object>} Object mapping secret names to their values
   */
  async getMultipleSecrets(secretNames) {
    const secrets = {};
    for (const name of secretNames) {
      secrets[name] = await this.getSecret(name);
    }
    return secrets;
  }

  /**
   * Get JWT configuration from secrets or environment variables
   * @returns {Promise<Object>} JWT configuration parameters
   */
  async getJwtConfig() {
    const [secret, expire] = await Promise.all([this.getSecret('JWT_SECRET'), this.getSecret('JWT_EXPIRE')]);

    return {
      secret: secret || 'default-secret-key',
      expire: expire || '24h',
    };
  }
}

// Global instance
export const secretManager = new DaprSecretManager();

// Helper functions for easy access
export const getJwtConfig = () => secretManager.getJwtConfig();
