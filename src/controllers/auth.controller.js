import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import {
  signToken,
  issueJwtToken,
  issueRefreshToken,
  issueCsrfToken as issueCsrfTokenConsistent,
} from '../utils/tokenManager.js';
import RefreshToken from '../models/refreshToken.model.js';
import asyncHandler from '../middlewares/asyncHandler.js';
import { getUserByEmail, getUserById, createUser, getUserBySocial } from '../services/userServiceClient.js';
import { sendMail } from '../utils/email.js';
import logger from '../utils/logger.js';

/**
 * @desc    Log in a user with email and password
 * @route   POST /auth/login
 * @access  Public
 */
export const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    logger.warn('Login attempt missing credentials', { email });
    return res.status(400).json({ error: 'Email and password are required' });
  }
  const user = await getUserByEmail(email);
  logger.info('Fetched user in login', { user });
  if (!user) {
    logger.warn('Login failed: user not found', { email });
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.isActive === false) {
    logger.warn('Login failed: account deactivated', { email });
    return res.status(403).json({ error: 'Account is deactivated.' });
  }
  if (!user.isEmailVerified) {
    logger.warn('Login failed: email not verified', { email });
    return res.status(403).json({ error: 'Please verify your email before logging in.' });
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    logger.warn('Login failed: invalid password', { email });
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  logger.info('User logged in', { userId: user._id, email });

  // Issue tokens using consistent helpers
  const token = issueJwtToken(req, res, user);
  await issueRefreshToken(req, res, user);
  await issueCsrfTokenConsistent(req, res, user);

  res.json({ jwt: token, user });
});

/**
 * @desc    Log out the current user (clear cookies, revoke refresh token)
 * @route   POST /auth/logout
 * @access  Private
 * @role    User
 */
export const logout = asyncHandler(async (req, res) => {
  // Read refresh token from cookie
  const refreshToken = req.cookies?.refreshToken;
  // CSRF protection is now enforced at the route level, not here
  if (!refreshToken) {
    logger.warn('Logout attempt missing refresh token');
    return res.status(400).json({ error: 'Refresh token required' });
  }
  await RefreshToken.deleteOne({ token: refreshToken });
  // Clear the cookies
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.clearCookie('jwt', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.clearCookie('csrfToken', {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  logger.info('User logged out', { refreshToken });
  res.json({ message: 'Logged out successfully' });
});

/**
 * @desc    Issue a new JWT using a valid refresh token
 * @route   POST /auth/refreshToken
 * @access  Public
 */
export const refreshToken = asyncHandler(async (req, res) => {
  // Read refresh token from HTTP-only cookie
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    logger.warn('Refresh token missing');
    return res.status(400).json({ error: 'Refresh token required' });
  }
  const stored = await RefreshToken.findOne({ token: refreshToken });
  if (!stored || stored.expiresAt < new Date()) {
    logger.warn('Invalid or expired refresh token', { refreshToken });
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
  const userId = stored.user;
  const jwtToken = req.cookies?.jwt || null;
  const user = await getUserById(userId, jwtToken);
  if (!user) {
    logger.warn('Refresh token user not found', { refreshToken });
    return res.status(401).json({ error: 'User not found' });
  }
  logger.info('Refresh token used', { userId: user._id });
  const token = signToken({ id: user._id, email: user.email, roles: user.roles });
  // Rotate refresh token for extra security
  await issueRefreshToken(req, res, user);
  res.json({ jwt: token });
});

/**
 * @desc    Send password reset email
 * @route   POST /auth/password/forgot
 * @access  Public
 */
export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  const user = await getUserByEmail(email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const resetUrl = `${process.env.BASE_URL || 'http://localhost:4000'}/auth/password/reset?token=${resetToken}`;
  await sendMail({
    to: email,
    subject: 'Reset your password',
    text: `Reset your password: ${resetUrl}`,
    html: `<p>Reset your password: <a href="${resetUrl}">${resetUrl}</a></p>`,
  });
  res.json({ message: 'Password reset email sent' });
});

/**
 * @desc    Reset password using token from email
 * @route   POST /auth/password/reset
 * @access  Public
 */
export const resetPassword = asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password are required' });
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }
  const user = await getUserByEmail(payload.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  // Call user-service PATCH /users/ to update password (self-service endpoint)
  const resp = await fetch(`${process.env.USER_SERVICE_URL}/users/`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ newPassword, isReset: true }),
  });
  if (!resp.ok) {
    const errorBody = await resp.json().catch(() => ({}));
    return res.status(resp.status).json({
      error: errorBody.error || 'Failed to reset password',
      code: errorBody.code,
      details: errorBody.details,
    });
  }
  res.json({ message: 'Password reset successful' });
});

/**
 * @desc    Change password for authenticated user
 * @route   POST /auth/password/change
 * @access  Private
 * @role    User
 */
export const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  logger.info(`old password: ${oldPassword}, new password: ${newPassword}`);

  const userId = req.user?.id;
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

  const validation = authValidator.validatePasswordChange(oldPassword, newPassword);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  // Validate new password strength
  const passwordValidation = authValidator.isValidPassword(newPassword);
  if (!passwordValidation.valid) {
    return res.status(400).json({ error: passwordValidation.error });
  }

  // Extract JWT from cookie or Authorization header
  let jwtToken = null;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    jwtToken = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.jwt) {
    jwtToken = req.cookies.jwt;
  }
  if (!jwtToken) return res.status(401).json({ error: 'JWT missing' });

  // Forward password change to user service PATCH /users with { password }
  const resp = await fetch(`${process.env.USER_SERVICE_URL}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${jwtToken}`,
    },
    body: JSON.stringify({ password: newPassword }),
  });

  logger.info(resp);

  if (!resp.ok) {
    let err;
    try {
      err = await resp.json();
    } catch {
      err = { error: 'Unknown error from user service' };
    }
    return res.status(resp.status).json(err);
  }
  res.json({ message: 'Password changed successfully' });
});

/**
 * @desc    Verify email address using token
 * @route   GET /auth/email/verify?token=...
 * @access  Public
 */
export const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token is required' });
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }
  // Mark user as verified in user service
  const user = await getUserByEmail(payload.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.isEmailVerified) return res.json({ message: 'Email already verified' });
  // Issue a short-lived JWT for the user to authorize the PATCH
  const userJwt = signToken({ id: user._id, email: user.email, roles: user.roles }, '15m');
  const resp = await fetch(`${process.env.USER_SERVICE_URL}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${userJwt}`,
    },
    body: JSON.stringify({ isEmailVerified: true }),
  });
  if (!resp.ok) {
    const contentType = resp.headers.get('content-type');
    const text = await resp.text();
    if (contentType && contentType.includes('application/json')) {
      return res.status(resp.status).json(JSON.parse(text));
    } else {
      logger.error('User service error', { text });
      return res.status(resp.status).send(text);
    }
  }
  res.json({ message: 'Email verified successfully' });
});

/**
 * @desc    Social login callback (if present)
 * @route   GET /auth/social/callback
 * @access  Public
 */
export const socialCallback = asyncHandler(async (req, res) => {
  // req.user is set by passport strategy
  const { provider, id, email, name } = req.user || {};
  if (!req.user || !req.user._id) {
    return res.status(500).json({ error: 'User not found or missing _id after social login' });
  }
  let user = await getUserBySocial(provider, id);
  if (!user) {
    user = await createUser({ email, name, social: { [provider]: { id } }, isEmailVerified: true });
  }
  if (!user || !user._id) {
    return res.status(500).json({ error: 'User not found or missing _id after social login' });
  }

  // Issue tokens using consistent helpers
  const token = issueJwtToken(req, res, user);
  await issueRefreshToken(req, res, user);
  await issueCsrfTokenConsistent(req, res, user);

  res.json({ jwt: token, user });
});

/**
 * @desc    Get current authenticated user info
 * @route   GET /auth/me
 * @access  Private
 * @role    User
 */
export const me = asyncHandler((req, res) => {
  // Return current user info
  res.json({ user: req.user });
});

/**
 * @desc    Register a new user
 * @route   POST /auth/register
 * @access  Public
 */
export const register = asyncHandler(async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  // Check if user already exists
  const existing = await getUserByEmail(email);
  if (existing) {
    return res.status(409).json({ error: 'User already exists' });
  }
  // Do NOT hash password here; let user service handle hashing
  const user = await createUser({ email, password, name, isEmailVerified: false });
  if (!user) {
    return res.status(500).json({ error: 'Failed to create user' });
  }
  // Generate email verification token
  const verifyToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });
  const verifyUrl = `${process.env.BASE_URL || 'http://localhost:4000'}/auth/email/verify?token=${verifyToken}`;
  await sendMail({
    to: email,
    subject: 'Verify your email',
    text: `Please verify your email: ${verifyUrl}`,
    html: `<p>Please verify your email: <a href="${verifyUrl}">${verifyUrl}</a></p>`,
  });
  res.status(201).json({ message: 'Registration successful, please verify your email.' });
});

/**
 * @desc    Request account reactivation (send email link)
 * @route   POST /auth/account/reactivateRequest
 * @access  Public
 */
export const requestAccountReactivation = asyncHandler(async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  const user = await getUserByEmail(email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.isActive) return res.status(400).json({ error: 'Account is already active.' });
  // Generate a short-lived reactivation token
  const reactivateToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const reactivateUrl = `${process.env.BASE_URL || 'http://localhost:4000'}/auth/reactivate?token=${reactivateToken}`;
  await sendMail({
    to: email,
    subject: 'Reactivate your account',
    text: `Reactivate your account: ${reactivateUrl}`,
    html: `<p>Reactivate your account: <a href="${reactivateUrl}">${reactivateUrl}</a></p>`,
  });
  res.json({ message: 'Reactivation email sent.' });
});

/**
 * @desc    Reactivate account via email link
 * @route   GET /auth/account/reactivate
 * @access  Public
 */
export const reactivateAccount = asyncHandler(async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token is required' });
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }
  const user = await getUserByEmail(payload.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.isActive) return res.json({ message: 'Account is already active.' });
  // Issue a short-lived JWT for the user to authorize the PATCH
  const userJwt = signToken({ id: user._id, email: user.email, roles: user.roles }, '15m');
  const resp = await fetch(`${process.env.USER_SERVICE_URL}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${userJwt}`,
    },
    body: JSON.stringify({ isActive: true }),
  });
  if (!resp.ok) {
    const contentType = resp.headers.get('content-type');
    const text = await resp.text();
    if (contentType && contentType.includes('application/json')) {
      return res.status(resp.status).json(JSON.parse(text));
    } else {
      logger.error('User service error', { text });
      return res.status(resp.status).send(text);
    }
  }
  res.json({ message: 'Account reactivated successfully.' });
});

/**
 * @desc    Delete own account (self-service)
 * @route   DELETE /auth/account
 * @access  Private
 */
export const deleteAccount = asyncHandler(async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.jwt;
  const success = await import('../services/userServiceClient.js').then((m) => m.deleteUserSelf(token));
  if (!success) return res.status(404).json({ error: 'User not found' });
  res.status(204).send();
});

/**
 * @desc    Admin: delete any user by ID
 * @route   DELETE /auth/users/:id
 * @access  Admin only
 */
export const adminDeleteUser = asyncHandler(async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.jwt;
  const { id } = req.params;
  const success = await import('../services/userServiceClient.js').then((m) => m.deleteUserById(id, token));
  if (!success) return res.status(404).json({ error: 'User not found' });
  res.status(204).send();
});
