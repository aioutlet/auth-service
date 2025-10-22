/**
 * Dependency Health Checker
 * Validates external service availability without blocking startup
 * Provides visibility into dependency status through logging
 */

// Note: Using global fetch (available in Node.js 18+)
// If using older Node.js, install node-fetch: npm install node-fetch
// import fetch from 'node-fetch';

/**
 * Check health of service dependencies without blocking startup
 * @param {Object} dependencies - Object with service names as keys and URLs as values
 * @param {number} timeout - Timeout for each health check in ms
 * @returns {Promise<Array>} - Array of health check results
 */
export async function checkDependencyHealth(dependencies, timeout = 5000) {
  console.log('[DEPS] 🔍 Checking dependency health...');

  const healthChecks = Object.entries(dependencies).map(async ([serviceName, baseUrl]) => {
    try {
      const healthUrl = `${baseUrl}/health`;
      console.log(`[DEPS] Checking ${serviceName} health at ${healthUrl}`);

      // Create fetch with timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(healthUrl, {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
        method: 'GET',
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        console.log(`[DEPS] ✅ ${serviceName} is healthy`);
        return { service: serviceName, status: 'healthy', url: healthUrl };
      } else {
        console.log(`[DEPS] ⚠️ ${serviceName} returned status ${response.status}`);
        return { service: serviceName, status: 'unhealthy', url: healthUrl, statusCode: response.status };
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        console.log(`[DEPS] ⏰ ${serviceName} health check timed out after ${timeout}ms`);
        return { service: serviceName, status: 'timeout', error: 'timeout' };
      } else {
        console.log(`[DEPS] ❌ ${serviceName} is not reachable: ${error.message}`);
        return { service: serviceName, status: 'unreachable', error: error.message };
      }
    }
  });

  const results = await Promise.allSettled(healthChecks);

  // Summary logging
  const healthyServices = results.filter((r) => r.status === 'fulfilled' && r.value.status === 'healthy').length;
  const totalServices = results.length;

  if (healthyServices === totalServices) {
    console.log(`[DEPS] 🎉 All ${totalServices} dependencies are healthy`);
  } else {
    console.log(`[DEPS] ⚠️ ${healthyServices}/${totalServices} dependencies are healthy`);
  }

  return results.map((r) => (r.status === 'fulfilled' ? r.value : { error: r.reason }));
}

/**
 * Get dependency URLs from environment variables
 * Uses standardized _HEALTH_URL variables for service health endpoints
 * @returns {Object} - Object with service names as keys and health URLs as values
 */
export function getDependencies() {
  const dependencies = {};

  // Add user service if configured (for user management operations)
  if (process.env.USER_SERVICE_HEALTH_URL) {
    dependencies['user-service'] = process.env.USER_SERVICE_HEALTH_URL;
  }

  // Add message broker if configured (for publishing auth events)
  if (process.env.MESSAGE_BROKER_HEALTH_URL) {
    dependencies['message-broker'] = process.env.MESSAGE_BROKER_HEALTH_URL;
  }

  return dependencies;
}
