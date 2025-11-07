export function info(req, res) {
  res.json({
    message: 'Welcome to the Auth Service',
    service: process.env.NAME || 'auth-service',
    description: 'Authentication and authorization service for AIOutlet platform',
    environment: process.env.NODE_ENV || 'development',
  });
}

export function version(req, res) {
  res.json({
    version: process.env.VERSION || '1.0.0',
  });
}
