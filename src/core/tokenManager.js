import jwt from 'jsonwebtoken';
import logger from '../core/logger.js';
import { getJwtConfig } from '../services/dapr.secretManager.js';

// Cache JWT config to avoid repeated Dapr calls
let _jwtConfigCache = null;

async function getCachedJwtConfig() {
  if (_jwtConfigCache === null) {
    _jwtConfigCache = await getJwtConfig();
  }
  return _jwtConfigCache;
}

// --- Stateless JWT helpers ---
export async function signToken(payload, expiresIn = '15m') {
  const jwtConfig = await getCachedJwtConfig();
  return jwt.sign(payload, jwtConfig.secret, { expiresIn });
}

export async function verifyToken(token) {
  try {
    const jwtConfig = await getCachedJwtConfig();
    return jwt.verify(token, jwtConfig.secret);
  } catch {
    return null;
  }
}

// --- Token issuing helpers ---
/**
 * Issues a JWT access token following industry standards (RFC 7519)
 * Returns the token string.
 */
export async function issueJwtToken(req, res, user) {
  logger.debug('Issuing JWT for user', req, { operation: 'issue_jwt', userId: user._id });

  // Standard JWT claims (RFC 7519)
  const payload = {
    // Standard claims
    sub: user._id.toString(), // Subject (user ID)
    iss: 'auth-service', // Issuer
    aud: 'aioutlet-platform', // Audience
    iat: Math.floor(Date.now() / 1000), // Issued at
    exp: Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour

    // Custom claims
    email: user.email,
    name: user.name || `${user.firstName} ${user.lastName}`.trim(),
    roles: user.roles || ['customer'],
    emailVerified: user.isEmailVerified || false,
  };

  const token = await signToken(payload, '1h');

  // Set as HTTP-only cookie for web clients
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 1000, // 1 hour
  });

  return token;
}
