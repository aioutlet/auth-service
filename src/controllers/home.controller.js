export function getWelcomeMessage(req, res) {
  res.json({ message: 'Welcome to the Auth Service' });
}

export function getVersion(req, res) {
  res.json({ version: process.env.API_VERSION || 'unknown' });
}

export function health(req, res) {
  res.json({ status: 'ok' });
}
