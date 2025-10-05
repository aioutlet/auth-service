/**
 * Environment Utility Module
 *
 * Centralized environment detection and configuration helpers.
 * This module provides consistent environment checking across the entire application,
 * following Node.js best practices and DRY principles.
 *
 * @module utils/environment
 */

/**
 * Valid environment types
 * @readonly
 * @enum {string}
 */
export const Environment = Object.freeze({
  LOCAL: 'local',
  DEVELOPMENT: 'development',
  STAGING: 'staging',
  PRODUCTION: 'production',
  TEST: 'test',
});

/**
 * Get the current environment
 * @returns {string} - Current environment (local, development, staging, production, test)
 */
export function getCurrentEnvironment() {
  const env = process.env.NODE_ENV || 'development';

  // Normalize environment names
  const normalized = env.toLowerCase().trim();

  // Map to valid environments
  if (normalized === 'test') {
    return Environment.TEST;
  }
  if (normalized === 'production' || normalized === 'prod') {
    return Environment.PRODUCTION;
  }
  if (normalized === 'staging' || normalized === 'stage') {
    return Environment.STAGING;
  }
  if (normalized === 'local') {
    return Environment.LOCAL;
  }

  return Environment.DEVELOPMENT;
}

/**
 * Check if running in production environment
 * @returns {boolean} - True if production
 */
export function isProduction() {
  return getCurrentEnvironment() === Environment.PRODUCTION;
}

/**
 * Check if running in development environment (includes local)
 * @returns {boolean} - True if development or local
 */
export function isDevelopment() {
  const env = getCurrentEnvironment();
  return env === Environment.DEVELOPMENT || env === Environment.LOCAL;
}

/**
 * Check if running in staging environment
 * @returns {boolean} - True if staging
 */
export function isStaging() {
  return getCurrentEnvironment() === Environment.STAGING;
}

/**
 * Check if running in local environment
 * @returns {boolean} - True if local
 */
export function isLocal() {
  return getCurrentEnvironment() === Environment.LOCAL;
}

/**
 * Check if running in test environment
 * @returns {boolean} - True if test
 */
export function isTest() {
  return getCurrentEnvironment() === Environment.TEST;
}

/**
 * Get environment-specific value
 * @param {Object} values - Object with environment keys and their values
 * @param {*} defaultValue - Default value if no match found
 * @returns {*} - Value for current environment
 *
 * @example
 * const maxRetries = getEnvironmentValue({
 *   production: 3,
 *   staging: 5,
 *   development: 10,
 *   local: 20
 * }, 5);
 */
export function getEnvironmentValue(values, defaultValue = null) {
  const env = getCurrentEnvironment();
  return values[env] !== undefined ? values[env] : defaultValue;
}

/**
 * Check if environment variable is enabled (true, 1, yes, on)
 * @param {string} varName - Environment variable name
 * @param {boolean} defaultValue - Default value if not set
 * @returns {boolean} - True if enabled
 */
export function isEnabled(varName, defaultValue = false) {
  const value = process.env[varName];
  if (value === undefined || value === null || value === '') {
    return defaultValue;
  }

  const normalized = value.toLowerCase().trim();
  return normalized === 'true' || normalized === '1' || normalized === 'yes' || normalized === 'on';
}

/**
 * Get required environment variable or throw error
 * @param {string} varName - Environment variable name
 * @param {string} errorMessage - Custom error message
 * @returns {string} - Environment variable value
 * @throws {Error} - If variable is not set
 */
export function requireEnv(varName, errorMessage = null) {
  const value = process.env[varName];
  if (!value) {
    throw new Error(errorMessage || `Required environment variable ${varName} is not set`);
  }
  return value;
}

/**
 * Get environment variable with default value
 * @param {string} varName - Environment variable name
 * @param {*} defaultValue - Default value if not set
 * @returns {*} - Environment variable value or default
 */
export function getEnv(varName, defaultValue = null) {
  const value = process.env[varName];
  return value !== undefined && value !== null && value !== '' ? value : defaultValue;
}

/**
 * Get environment variable as integer
 * @param {string} varName - Environment variable name
 * @param {number} defaultValue - Default value if not set or invalid
 * @returns {number} - Environment variable as integer
 */
export function getEnvInt(varName, defaultValue = 0) {
  const value = process.env[varName];
  if (!value) {
    return defaultValue;
  }

  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

/**
 * Get environment variable as float
 * @param {string} varName - Environment variable name
 * @param {number} defaultValue - Default value if not set or invalid
 * @returns {number} - Environment variable as float
 */
export function getEnvFloat(varName, defaultValue = 0.0) {
  const value = process.env[varName];
  if (!value) {
    return defaultValue;
  }

  const parsed = parseFloat(value);
  return isNaN(parsed) ? defaultValue : parsed;
}

/**
 * Get environment configuration summary
 * @returns {Object} - Environment configuration object
 */
export function getEnvironmentConfig() {
  return {
    current: getCurrentEnvironment(),
    nodeEnv: process.env.NODE_ENV,
    isProduction: isProduction(),
    isDevelopment: isDevelopment(),
    isStaging: isStaging(),
    isLocal: isLocal(),
    isTest: isTest(),
    serviceName: getEnv('SERVICE_NAME', 'auth-service'),
    serviceVersion: getEnv('SERVICE_VERSION', '1.0.0'),
  };
}

// Default export for convenience
export default {
  Environment,
  getCurrentEnvironment,
  isProduction,
  isDevelopment,
  isStaging,
  isLocal,
  isTest,
  getEnvironmentValue,
  isEnabled,
  requireEnv,
  getEnv,
  getEnvInt,
  getEnvFloat,
  getEnvironmentConfig,
};
