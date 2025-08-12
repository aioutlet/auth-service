export function getWelcomeMessage(req, res) {
  res.json({
    message: 'Welcome to the Auth Service',
    service: 'auth-service',
    description: 'Authentication and authorization service for AIOutlet platform',
  });
}

export function getVersion(req, res) {
  res.json({
    version: process.env.API_VERSION || '1.0.0',
    service: 'auth-service',
    environment: process.env.NODE_ENV || 'development',
  });
}
