// Environment utility functions

export function getCurrentEnvironment() {
  const env = process.env.NODE_ENV || 'development';
  const normalizedEnv = env.toLowerCase().trim();

  switch (normalizedEnv) {
    case 'prod':
    case 'production':
      return 'production';
    case 'stage':
    case 'staging':
      return 'staging';
    case 'dev':
    case 'development':
      return 'development';
    case 'local':
      return 'local';
    case 'test':
    case 'testing':
      return 'test';
    default:
      return 'development';
  }
}

export function isProduction() {
  return getCurrentEnvironment() === 'production';
}

export function isDevelopment() {
  const env = getCurrentEnvironment();
  return env === 'development' || env === 'local';
}

export function isStaging() {
  return getCurrentEnvironment() === 'staging';
}

export function isTest() {
  return getCurrentEnvironment() === 'test';
}

export function isLocal() {
  return getCurrentEnvironment() === 'local';
}

export function getEnvValue(key, defaultValue = undefined) {
  const value = process.env[key];
  if (value === undefined || value === null || value === '') {
    return defaultValue;
  }
  return value;
}

export function getEnvBoolean(key, defaultValue = false) {
  const value = getEnvValue(key, String(defaultValue));
  return value === 'true' || value === '1' || value === 'yes';
}

export function getEnvNumber(key, defaultValue = 0) {
  const value = getEnvValue(key, String(defaultValue));
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

export function getEnvironmentInfo() {
  return {
    environment: getCurrentEnvironment(),
    nodeEnv: process.env.NODE_ENV,
    isProduction: isProduction(),
    isDevelopment: isDevelopment(),
    isStaging: isStaging(),
    isTest: isTest(),
    isLocal: isLocal(),
    nodeVersion: process.version,
    platform: process.platform,
    pid: process.pid,
  };
}
