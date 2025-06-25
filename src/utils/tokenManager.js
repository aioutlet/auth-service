import jwt from 'jsonwebtoken';
import RefreshToken from '../models/refreshToken.model.js';
import crypto from 'crypto';
import CsrfToken from '../models/csrfToken.model.js';
import mongoose from 'mongoose';

// --- Stateless JWT helpers ---
export function signToken(payload, expiresIn = '15m') {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return null;
  }
}

// --- Token issuing helpers ---
/**
 * Issues a JWT access token and sets it as an HTTP-only cookie.
 * Returns the token string.
 */
export function issueJwtToken(req, res, user) {
  const token = signToken({ id: user._id, email: user.email, roles: user.roles }, '15m');
  res.cookie('jwt', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000, // 15 min
  });
  return token;
}

/**
 * Issues a refresh token, stores it in DB, and sets it as an HTTP-only cookie.
 * Returns the token string.
 */
export async function issueRefreshToken(req, res, user) {
  const refreshToken = signToken({ id: user._id }, '7d');
  await RefreshToken.create({
    user: user._id,
    token: refreshToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
  return refreshToken;
}

/**
 * Issues a CSRF token, stores it in DB, and sets it as a cookie and response header.
 * Returns the token string.
 */
export async function issueCsrfToken(req, res, user) {
  // if (!req.cookies['csrfToken']) {
    const csrfToken = crypto.randomBytes(24).toString('hex');
    let userId = user?._id || user?.id;
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      await CsrfToken.create({
        token: csrfToken,
        user: userId,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      });
    }
    res.cookie('csrfToken', csrfToken, {
      httpOnly: false, // Must be readable by JS to send in header
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000,
    });
    res.set('X-CSRF-Token', csrfToken);
    req.csrfToken = csrfToken;
    return csrfToken;
  // }
  // return req.cookies['csrfToken'];
}
