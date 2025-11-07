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
    service: process.env.NAME || 'auth-service',
    version: process.env.VERSION || '1.0.0',
    timestamp: new Date().toISOString(),
  });
}

/**
 * Readiness probe - Checks if service is ready to receive traffic
 * Kubernetes uses this to determine if pod should receive traffic
 *
 * Auth service is stateless (JWT-based), no database dependencies
 */
export const readiness = asyncHandler(async (req, res) => {
  // Auth service is stateless and always ready if running
  res.json({
    status: 'ready',
    service: process.env.NAME || 'auth-service',
    timestamp: new Date().toISOString(),
  });
});

/**
 * Liveness probe - Checks if service is alive (not deadlocked)
 * Kubernetes uses this to determine if pod should be restarted
 */
export function liveness(req, res) {
  res.json({
    status: 'alive',
    service: process.env.NAME || 'auth-service',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
}

/**
 * Metrics endpoint - Exposes service metrics for monitoring systems
 * Includes memory usage monitoring, uptime, and system information
 */
export function metrics(req, res) {
  const memUsage = process.memoryUsage();
  const heapUsedPercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;

  res.json({
    service: process.env.NAME || 'auth-service',
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
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  parts.push(`${secs}s`);

  return parts.join(' ');
}
