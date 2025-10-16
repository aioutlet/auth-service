import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import logger from '../observability/logging/index.js';

// --- Stateless JWT helpers ---
export function signToken(payload, expiresIn = '15m') {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

// --- Token issuing helpers ---
/**
 * Issues a JWT access token and sets it as an HTTP-only cookie.
 * Returns the token string.
 */
export function issueJwtToken(req, res, user) {
  logger.debug('Issuing JWT for user', req, { operation: 'issue_jwt', userId: user._id });
  const token = signToken(
    {
      id: user._id,
      username: user.name,
      email: user.email,
      roles: user.roles,
    },
    '15m'
  );
  res.cookie('jwt', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000, // 15 min
  });
  return token;
}

/**
 * Issues a stateless refresh token (JWT-based) and sets it as an HTTP-only cookie.
 * Returns a mock refresh token document for compatibility.
 */
export async function issueRefreshToken(req, res, user) {
  const refreshToken = signToken({ id: user._id, type: 'refresh' }, '7d');
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  // Return a mock document for compatibility
  return {
    _id: crypto.randomUUID(),
    user: user._id,
    token: refreshToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  };
}

/**
 * Issues a stateless CSRF token (JWT-based) and sets it as a cookie and response header.
 * Returns the token string.
 */
export async function issueCsrfToken(req, res, user) {
  const csrfToken = signToken(
    {
      userId: user._id,
      type: 'csrf',
    },
    '1h' // CSRF tokens should be short-lived
  );
  res.cookie('csrfToken', csrfToken, {
    httpOnly: false, // Must be readable by JS to send in header
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 1000, // 1 hour
  });
  res.set('X-CSRF-Token', csrfToken);
  req.csrfToken = csrfToken;
  return csrfToken;
}
