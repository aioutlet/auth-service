// CSRF middleware for web clients using cookies for JWT
// - Issues a CSRF token as a cookie and response header on login
// - Validates CSRF token on state-changing requests (POST, PUT, DELETE)
import crypto from 'crypto';

export function issueCsrfToken(req, res, next) {
  // Only issue if not present
  if (!req.cookies['csrfToken']) {
    const csrfToken = crypto.randomBytes(24).toString('hex');
    res.cookie('csrfToken', csrfToken, {
      httpOnly: false, // Must be readable by JS to send in header
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
    res.set('X-CSRF-Token', csrfToken);
    req.csrfToken = csrfToken;
  }
  next();
}

export function requireCsrfToken(req, res, next) {
  // Only check for browser clients (cookie-based JWT)
  const cookieToken = req.cookies['csrfToken'];
  const headerToken = req.get('X-CSRF-Token');
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }
  next();
}
