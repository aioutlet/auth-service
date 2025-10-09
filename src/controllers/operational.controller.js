import mongoose from 'mongoose';
import { asyncHandler } from '../middlewares/asyncHandler.js';

/**
 * Operational/Infrastructure endpoints
 * These endpoints are used by monitoring systems, load balancers, and DevOps tools
 */

/**
 * Health check endpoint - Returns overall service health status
 */
export function health(req, res) {
  res.json({
    status: 'healthy',
    service: process.env.SERVICE_NAME || 'auth-service',
    version: process.env.SERVICE_VERSION || '1.0.0',
    timestamp: new Date().toISOString(),
  });
}

/**
 * Readiness probe - Checks if service is ready to receive traffic
 * Kubernetes uses this to determine if pod should receive traffic
 *
 * Performs actual dependency checks:
 * - Database connectivity (MongoDB)
 * - External service availability (optional)
 */
export const readiness = asyncHandler(async (req, res) => {
  const checks = {};
  let isReady = true;

  // 1. Check MongoDB connection
  try {
    const dbState = mongoose.connection.readyState;
    // readyState: 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting

    if (dbState === 1) {
      // Perform a simple ping to ensure DB is responsive
      await mongoose.connection.db.admin().ping();
      checks.database = {
        status: 'healthy',
        state: 'connected',
        host: mongoose.connection.host,
        name: mongoose.connection.name,
      };
    } else {
      checks.database = {
        status: 'unhealthy',
        state: getMongooseStateString(dbState),
        message: 'Database not ready',
      };
      isReady = false;
    }
  } catch (error) {
    checks.database = {
      status: 'unhealthy',
      state: 'error',
      message: error.message,
    };
    isReady = false;
  }

  // 2. Check external service dependencies
  checks.externalServices = {
    userService: checkServiceUrl(process.env.USER_SERVICE_URL, 'User Service'),
    adminService: checkServiceUrl(process.env.ADMIN_SERVICE_URL, 'Admin Service'),
    auditService: checkServiceUrl(process.env.AUDIT_SERVICE_URL, 'Audit Service'),
    messageBroker: checkServiceUrl(process.env.MESSAGE_BROKER_SERVICE_URL, 'Message Broker'),
  };

  // Check if any required external service is not configured
  const hasUnconfiguredServices = Object.values(checks.externalServices).some(
    (service) => service.status === 'not_configured'
  );

  if (hasUnconfiguredServices) {
    isReady = false;
  }

  // Determine overall readiness
  const status = isReady ? 'ready' : 'not_ready';
  const statusCode = isReady ? 200 : 503;

  res.status(statusCode).json({
    status,
    service: process.env.SERVICE_NAME || 'auth-service',
    timestamp: new Date().toISOString(),
    checks,
  });
});

/**
 * Helper function to convert mongoose readyState to string
 */
function getMongooseStateString(state) {
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting',
  };
  return states[state] || 'unknown';
}

/**
 * Helper function to check if service URL is configured
 * @param {string} url - The service URL to check
 * @param {string} serviceName - The name of the service for display
 * @returns {object} Service configuration status
 */
function checkServiceUrl(url, serviceName = 'Service') {
  if (!url) {
    return {
      status: 'not_configured',
      message: `${serviceName} URL not configured`,
      required: true,
    };
  }

  // Validate URL format
  try {
    const parsedUrl = new URL(url);
    return {
      status: 'configured',
      url: parsedUrl.origin + parsedUrl.pathname,
      protocol: parsedUrl.protocol,
    };
  } catch (error) {
    return {
      status: 'invalid',
      message: `${serviceName} URL is invalid: ${error.message}`,
      url,
    };
  }
}

/**
 * Liveness probe - Checks if service is alive (not deadlocked)
 * Kubernetes uses this to determine if pod should be restarted
 */
export function liveness(req, res) {
  res.json({
    status: 'alive',
    service: process.env.SERVICE_NAME || 'auth-service',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
}

/**
 * Metrics endpoint - Exposes service metrics for monitoring systems
 * Includes memory usage monitoring, uptime, and system information
 * Can be scraped by Prometheus or other monitoring tools
 */
export function metrics(req, res) {
  const memUsage = process.memoryUsage();
  const heapUsedPercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;

  res.json({
    service: process.env.SERVICE_NAME || 'auth-service',
    timestamp: new Date().toISOString(),
    uptime: {
      seconds: Math.floor(process.uptime()),
      formatted: formatUptime(process.uptime()),
    },
    memory: {
      heapUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024),
      heapTotalMB: Math.round(memUsage.heapTotal / 1024 / 1024),
      heapUsedPercent: Math.round(heapUsedPercent * 100) / 100,
      rssMB: Math.round(memUsage.rss / 1024 / 1024),
      externalMB: Math.round(memUsage.external / 1024 / 1024),
      status: heapUsedPercent < 90 ? 'healthy' : heapUsedPercent < 95 ? 'warning' : 'critical',
    },
    process: {
      pid: process.pid,
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    database: {
      state: getMongooseStateString(mongoose.connection.readyState),
    },
  });
}

/**
 * Helper function to format uptime in human-readable format
 */
function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  const parts = [];
  if (days > 0) {
    parts.push(`${days}d`);
  }
  if (hours > 0) {
    parts.push(`${hours}h`);
  }
  if (minutes > 0) {
    parts.push(`${minutes}m`);
  }
  parts.push(`${secs}s`);

  return parts.join(' ');
}
