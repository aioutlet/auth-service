/**
 * Configuration Validator
 * Validates all required environment variables at application startup
 * Fails fast if any required configuration is missing or invalid
 *
 * NOTE: This module MUST NOT import logger, as the logger depends on validated config.
 * Use console.log for bootstrap messages - this is industry standard practice.
 */

/**
 * Validates a URL format
 * @param {string} url - The URL to validate
 * @returns {boolean} - True if valid, false otherwise
 */
const isValidUrl = (url) => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

/**
 * Validates MongoDB URI format
 * @param {string} uri - The MongoDB URI to validate
 * @returns {boolean} - True if valid, false otherwise
 */
const isValidMongoUri = (uri) => {
  if (!uri) {
    return false;
  }
  // MongoDB URI should start with mongodb:// or mongodb+srv://
  return /^mongodb(\+srv)?:\/\/.+/.test(uri);
};

/**
 * Validates a port number
 * @param {string|number} port - The port to validate
 * @returns {boolean} - True if valid, false otherwise
 */
const isValidPort = (port) => {
  const portNum = parseInt(port, 10);
  return !isNaN(portNum) && portNum > 0 && portNum <= 65535;
};

/**
 * Validates NODE_ENV
 * @param {string} env - The environment to validate
 * @returns {boolean} - True if valid, false otherwise
 */
const isValidNodeEnv = (env) => {
  const validEnvs = ['development', 'production', 'test', 'staging'];
  return validEnvs.includes(env?.toLowerCase());
};

/**
 * Configuration validation rules
 */
const validationRules = {
  // Server Configuration
  NODE_ENV: {
    required: true,
    validator: isValidNodeEnv,
    errorMessage: 'NODE_ENV must be one of: development, production, test, staging',
  },
  PORT: {
    required: true,
    validator: isValidPort,
    errorMessage: 'PORT must be a valid port number (1-65535)',
  },
  SERVICE_NAME: {
    required: true,
    validator: (value) => value && value.length > 0,
    errorMessage: 'SERVICE_NAME must be a non-empty string',
  },

  // Database Configuration
  MONGODB_URI: {
    required: true,
    validator: isValidMongoUri,
    errorMessage: 'MONGODB_URI must be a valid MongoDB connection string (mongodb:// or mongodb+srv://)',
  },

  // Security Configuration
  JWT_SECRET: {
    required: true,
    validator: (value) => value && value.length >= 32,
    errorMessage: 'JWT_SECRET must be at least 32 characters long',
  },

  // CORS Configuration
  CORS_ORIGINS: {
    required: true,
    validator: (value) => {
      if (!value) {
        return false;
      }
      const origins = value.split(',').map((o) => o.trim());
      return origins.every((origin) => origin === '*' || isValidUrl(origin));
    },
    errorMessage: 'CORS_ORIGINS must be a comma-separated list of valid URLs or *',
  },
};

/**
 * Validates all environment variables according to the rules
 * @throws {Error} - If any required variable is missing or invalid
 */
const validateConfig = () => {
  const errors = [];

  console.log('[CONFIG] Validating environment configuration...');

  // Validate each rule
  for (const [key, rule] of Object.entries(validationRules)) {
    const value = process.env[key];

    // Check if required variable is missing
    if (!value) {
      errors.push(`❌ ${key} is required but not set`);
      continue;
    }

    // Validate the value
    if (rule.validator && !rule.validator(value)) {
      errors.push(`❌ ${key}: ${rule.errorMessage}`);
      if (value.length > 100) {
        errors.push(`   Current value: ${value.substring(0, 100)}...`);
      } else {
        errors.push(`   Current value: ${value}`);
      }
    }
  }

  // If there are errors, log them and throw
  if (errors.length > 0) {
    console.error('[CONFIG] ❌ Configuration validation failed:');
    errors.forEach((error) => console.error(`[CONFIG] ${error}`));
    console.error('[CONFIG] 💡 Please check your .env file and ensure all required variables are set correctly.');
    throw new Error(`Configuration validation failed with ${errors.length} error(s)`);
  }

  console.log('[CONFIG] ✅ All required environment variables are valid');
};

/**
 * Gets a validated configuration value
 * Assumes validateConfig() has already been called
 * @param {string} key - The configuration key
 * @returns {string} - The configuration value
 */
const getConfig = (key) => {
  return process.env[key];
};

/**
 * Gets a validated configuration value as boolean
 * @param {string} key - The configuration key
 * @returns {boolean} - The configuration value as boolean
 */
const getConfigBoolean = (key) => {
  return process.env[key]?.toLowerCase() === 'true';
};

/**
 * Gets a validated configuration value as number
 * @param {string} key - The configuration key
 * @returns {number} - The configuration value as number
 */
const getConfigNumber = (key) => {
  return parseInt(process.env[key], 10);
};

/**
 * Gets a validated configuration value as array (comma-separated)
 * @param {string} key - The configuration key
 * @returns {string[]} - The configuration value as array
 */
const getConfigArray = (key) => {
  return process.env[key]?.split(',').map((item) => item.trim()) || [];
};

export default validateConfig;
export { getConfig, getConfigBoolean, getConfigNumber, getConfigArray };
