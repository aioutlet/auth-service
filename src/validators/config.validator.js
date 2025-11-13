/**
 * Configuration Validator
 * Validates all required environment variables at application startup
 * Fails fast if any required configuration is missing or invalid
 *
 * NOTE: This module MUST NOT import logger, as the logger depends on validated config.
 * Use console.log for bootstrap messages - this is industry standard practice.
 */

/**
 * Configuration validation rules
 */
const validationRules = {
  // Server Configuration
  NODE_ENV: {
    required: true,
    validator: (env) => ['development', 'production', 'test', 'staging'].includes(env?.toLowerCase()),
    errorMessage: 'NODE_ENV must be one of: development, production, test, staging',
  },
  PORT: {
    required: true,
    validator: (port) => {
      const portNum = parseInt(port, 10);
      return !isNaN(portNum) && portNum > 0 && portNum <= 65535;
    },
    errorMessage: 'PORT must be a valid port number (1-65535)',
  },
  NAME: {
    required: true,
    validator: (value) => value && value.length > 0,
    errorMessage: 'NAME must be a non-empty string',
  },
  VERSION: {
    required: true,
    validator: (value) => value && /^\d+\.\d+\.\d+/.test(value),
    errorMessage: 'VERSION must be in semantic version format (e.g., 1.0.0)',
  },

  // Security Configuration (JWT managed by Dapr Secret Manager)
  // JWT Configuration
  JWT_SECRET: {
    required: false, // Optional: Dapr Secret Manager handles this, falls back to env var
    validator: (value) => !value || value.length >= 32,
    errorMessage: 'JWT_SECRET must be at least 32 characters long if provided',
  },

  // Service Discovery (Dapr)
  DAPR_USER_SERVICE_APP_ID: {
    required: true,
    validator: (value) => value && value.length > 0,
    errorMessage: 'DAPR_USER_SERVICE_APP_ID must be a non-empty string',
  },

  // Logging Configuration
  LOG_LEVEL: {
    required: false,
    validator: (level) => ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'].includes(level?.toLowerCase()),
    errorMessage: 'LOG_LEVEL must be one of: error, warn, info, http, verbose, debug, silly',
    default: 'info',
  },
  LOG_FORMAT: {
    required: false,
    validator: (value) => !value || ['json', 'console'].includes(value?.toLowerCase()),
    errorMessage: 'LOG_FORMAT must be either json or console',
    default: 'console',
  },
  LOG_TO_CONSOLE: {
    required: false,
    validator: (value) => ['true', 'false'].includes(value?.toLowerCase()),
    errorMessage: 'LOG_TO_CONSOLE must be true or false',
    default: 'true',
  },
  LOG_TO_FILE: {
    required: false,
    validator: (value) => ['true', 'false'].includes(value?.toLowerCase()),
    errorMessage: 'LOG_TO_FILE must be true or false',
    default: 'false',
  },
  LOG_FILE_PATH: {
    required: false,
    validator: (value) => !value || (value.length > 0 && value.includes('.')),
    errorMessage: 'LOG_FILE_PATH must be a valid file path with extension',
    default: './logs/auth-service.log',
  },
};

/**
 * Validates all environment variables according to the rules
 * @throws {Error} - If any required variable is missing or invalid
 */
const validateConfig = () => {
  const errors = [];
  const warnings = [];

  console.log('[CONFIG] Validating environment configuration...');

  // Validate each rule
  for (const [key, rule] of Object.entries(validationRules)) {
    const value = process.env[key];

    // Check if required variable is missing
    if (rule.required && !value) {
      errors.push(`[ERROR] ${key} is required but not set`);
      continue;
    }

    // Skip validation if value is not set and not required
    if (!value && !rule.required) {
      if (rule.default) {
        warnings.push(`[WARN] ${key} not set, using default: ${rule.default}`);
        process.env[key] = rule.default;
      }
      continue;
    }

    // Validate the value
    if (value && rule.validator && !rule.validator(value)) {
      errors.push(`[ERROR] ${key}: ${rule.errorMessage}`);
      if (value.length > 100) {
        errors.push(`   Current value: ${value.substring(0, 100)}...`);
      } else {
        errors.push(`   Current value: ${value}`);
      }
    }
  }

  // Display warnings if any
  if (warnings.length > 0) {
    console.log('[CONFIG] Configuration warnings:');
    warnings.forEach((warning) => console.log(`[CONFIG] ${warning}`));
  }

  // If there are errors, log them and throw
  if (errors.length > 0) {
    console.error('[CONFIG] Configuration validation failed:');
    errors.forEach((error) => console.error(`[CONFIG] ${error}`));
    console.error('[CONFIG] Please check your .env file and ensure all required variables are set correctly.');
    throw new Error(`Configuration validation failed with ${errors.length} error(s)`);
  }

  console.log('[CONFIG] All required environment variables are valid');
};

// Export only the validation function
export { validateConfig };
