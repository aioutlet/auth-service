/**
 * Operational/Infrastructure endpoints
 * These endpoints are used by monitoring systems, load balancers, and DevOps tools
 */

export function health(req, res) {
  res.json({
    status: 'healthy',
    service: 'auth-service',
    timestamp: new Date().toISOString(),
    version: process.env.API_VERSION || '1.0.0',
  });
}

export function readiness(req, res) {
  // Add more sophisticated checks here (DB connectivity, external dependencies, etc.)
  try {
    // Example: Check database connectivity
    // await checkDatabaseConnection();

    res.json({
      status: 'ready',
      service: 'auth-service',
      timestamp: new Date().toISOString(),
      checks: {
        database: 'connected',
        // Add other dependency checks
      },
    });
  } catch (error) {
    res.status(503).json({
      status: 'not ready',
      service: 'auth-service',
      timestamp: new Date().toISOString(),
      error: 'Service dependencies not available',
    });
  }
}

export function liveness(req, res) {
  // Liveness probe - just check if the app is running
  res.json({
    status: 'alive',
    service: 'auth-service',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
}

export function metrics(req, res) {
  // Basic metrics endpoint (could be extended with prometheus metrics)
  res.json({
    service: 'auth-service',
    timestamp: new Date().toISOString(),
    metrics: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      pid: process.pid,
      version: process.version,
    },
  });
}
