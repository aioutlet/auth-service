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
import authValidator from '../validators/auth.validator.js';
import logger from '../utils/logger.js';
import ErrorResponse from '../utils/ErrorResponse.js';

/**
 * @desc    Log in a user with email and password
 * @route   POST /auth/login
 * @access  Public
 */
export const login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    logger.warn('Login attempt missing credentials', { email });
    return next(new ErrorResponse('Email and password are required', 400));
  }
  const user = await getUserByEmail(email);
  logger.info('Fetched user in login', { user });
  if (!user) {
    logger.warn('Login failed: user not found', { email });
    return next(new ErrorResponse('Invalid credentials', 401));
  }
  if (user.isActive === false) {
    logger.warn('Login failed: account deactivated', { email });
    return next(new ErrorResponse('Account is deactivated', 403));
  }
  if (!user.isEmailVerified) {
    logger.warn('Login failed: email not verified', { email });
    return next(new ErrorResponse('Please verify your email before logging in', 403));
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    logger.warn('Login failed: invalid password', { email });
    return next(new ErrorResponse('Invalid credentials', 401));
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
export const logout = asyncHandler(async (req, res, next) => {
  // Read refresh token from cookie
  const refreshToken = req.cookies?.refreshToken;
  // CSRF protection is now enforced at the route level, not here
  if (!refreshToken) {
    logger.warn('Logout attempt missing refresh token');
    return next(new ErrorResponse('Refresh token required', 400));
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
export const refreshToken = asyncHandler(async (req, res, next) => {
  // Read refresh token from HTTP-only cookie
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    logger.warn('Refresh token missing');
    return next(new ErrorResponse('Refresh token required', 400));
  }
  const stored = await RefreshToken.findOne({ token: refreshToken });
  if (!stored || stored.expiresAt < new Date()) {
    logger.warn('Invalid or expired refresh token', { refreshToken });
    return next(new ErrorResponse('Invalid or expired refresh token', 401));
  }
  const userId = stored.user;
  const jwtToken = req.cookies?.jwt || null;
  const user = await getUserById(userId, jwtToken);
  if (!user) {
    logger.warn('Refresh token user not found', { refreshToken });
    return next(new ErrorResponse('User not found', 401));
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
export const forgotPassword = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  if (!email) return next(new ErrorResponse('Email is required', 400));
  const user = await getUserByEmail(email);
  if (!user) return next(new ErrorResponse('User not found', 404));
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
export const resetPassword = asyncHandler(async (req, res, next) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return next(new ErrorResponse('Token and new password are required', 400));
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return next(new ErrorResponse('Invalid or expired token', 400));
  }
  const user = await getUserByEmail(payload.email);
  if (!user) return next(new ErrorResponse('User not found', 404));
  // Call user-service PATCH /users/ to update password (self-service endpoint)
  const resp = await fetch(`${process.env.USER_SERVICE_URL}/users/`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ newPassword, isReset: true }),
  });
  if (!resp.ok) {
    const errorBody = await resp.json().catch(() => ({}));
    return next(new ErrorResponse(errorBody.error || 'Failed to reset password', resp.status));
  }
  res.json({ message: 'Password reset successful' });
});

/**
 * @desc    Change password for authenticated user
 * @route   POST /auth/password/change
 * @access  Private
 * @role    User
 */
export const changePassword = asyncHandler(async (req, res, next) => {
  const { oldPassword, newPassword } = req.body;
  logger.info(`old password: ${oldPassword}, new password: ${newPassword}`);

  const userId = req.user?.id;
  if (!userId) return next(new ErrorResponse('Unauthorized', 401));

  const validation = authValidator.validatePasswordChange(oldPassword, newPassword);
  if (!validation.valid) {
    return next(new ErrorResponse(validation.error, 400));
  }

  // Validate new password strength
  const passwordValidation = authValidator.isValidPassword(newPassword);
  if (!passwordValidation.valid) {
    return next(new ErrorResponse(passwordValidation.error, 400));
  }

  // Extract JWT from cookie or Authorization header
  let jwtToken = null;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    jwtToken = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.jwt) {
    jwtToken = req.cookies.jwt;
  }
  if (!jwtToken) return next(new ErrorResponse('JWT missing', 401));

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
    return next(new ErrorResponse(err.error || 'Password change failed', resp.status));
  }
  res.json({ message: 'Password changed successfully' });
});

/**
 * @desc    Verify email address using token
 * @route   GET /auth/email/verify?token=...
 * @access  Public
 */
export const verifyEmail = asyncHandler(async (req, res, next) => {
  const { token } = req.query;
  if (!token) return next(new ErrorResponse('Token is required', 400));
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return next(new ErrorResponse('Invalid or expired token', 400));
  }
  // Mark user as verified in user service
  const user = await getUserByEmail(payload.email);
  if (!user) return next(new ErrorResponse('User not found', 404));
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
      const errorData = JSON.parse(text);
      return next(new ErrorResponse(errorData.error || 'Email verification failed', resp.status));
    } else {
      logger.error('User service error', { text });
      return next(new ErrorResponse('Email verification failed', resp.status));
    }
  }
  res.json({ message: 'Email verified successfully' });
});

/**
 * @desc    Resend email verification
 * @route   POST /auth/email/resend
 * @access  Public
 */
export const resendVerificationEmail = asyncHandler(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return next(new ErrorResponse('Email is required', 400));
  }

  // Check if user exists
  const user = await getUserByEmail(email);
  if (!user) {
    return next(new ErrorResponse('User not found', 404));
  }

  // Check if already verified
  if (user.isEmailVerified) {
    return next(new ErrorResponse('Email is already verified', 400));
  }

  // Generate new verification token
  const verifyToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });
  const verifyUrl = `${process.env.BASE_URL || 'http://localhost:4000'}/api/auth/email/verify?token=${verifyToken}`;

  // Send verification email
  await sendMail({
    to: email,
    subject: 'Verify your email',
    text: `Please verify your email: ${verifyUrl}`,
    html: `<p>Please verify your email: <a href="${verifyUrl}">${verifyUrl}</a></p>`,
  });

  logger.info('Verification email resent', { email });
  res.json({ message: 'Verification email sent successfully' });
});

/**
 * @desc    Social login callback (if present)
 * @route   GET /auth/social/callback
 * @access  Public
 */
export const socialCallback = asyncHandler(async (req, res, next) => {
  // req.user is set by passport strategy
  const { provider, id, email, name, firstName, lastName, displayName } = req.user || {};
  if (!req.user || !req.user._id) {
    return next(new ErrorResponse('User not found or missing _id after social login', 500));
  }

  let user = await getUserBySocial(provider, id);
  if (!user) {
    // Create new user with social login data
    const userData = {
      email,
      social: { [provider]: { id } },
      isEmailVerified: true,
      roles: ['customer'],
    };

    // Handle name data from social provider
    if (firstName) userData.firstName = firstName;
    if (lastName) userData.lastName = lastName;
    if (displayName) userData.displayName = displayName;

    // Fallback: if we only have a single 'name' field, try to split it
    if (name && !firstName && !lastName) {
      const nameParts = name.split(' ');
      if (nameParts.length >= 2) {
        userData.firstName = nameParts[0];
        userData.lastName = nameParts.slice(1).join(' ');
      } else {
        userData.firstName = name;
      }
      userData.displayName = name;
    }

    user = await createUser(userData);
  }

  if (!user || !user._id) {
    return next(new ErrorResponse('User not found or missing _id after social login', 500));
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
export const register = asyncHandler(async (req, res, next) => {
  const { email, password, firstName, lastName, displayName, addresses, paymentMethods, wishlist, preferences } =
    req.body;

  // Basic validation
  if (!email || !password) {
    return next(new ErrorResponse('Email and password are required', 400));
  }

  // Validate password strength
  const passwordValidation = authValidator.isValidPassword(password);
  if (!passwordValidation.valid) {
    return next(new ErrorResponse(passwordValidation.error, 400));
  }

  // Check if user already exists
  const existing = await getUserByEmail(email);
  if (existing) {
    return next(new ErrorResponse('User already exists', 409));
  }

  // Prepare user data with new model structure
  const userData = {
    email,
    password,
    isEmailVerified: false,
    roles: ['customer'], // Set default role for new users
  };

  // Add name fields if provided
  if (firstName) userData.firstName = firstName;
  if (lastName) userData.lastName = lastName;
  if (displayName) userData.displayName = displayName;

  // Add multi-step wizard data if provided
  if (addresses && Array.isArray(addresses) && addresses.length > 0) {
    userData.addresses = addresses;
  }

  if (paymentMethods && Array.isArray(paymentMethods) && paymentMethods.length > 0) {
    userData.paymentMethods = paymentMethods;
  }

  if (wishlist && Array.isArray(wishlist) && wishlist.length > 0) {
    userData.wishlist = wishlist;
  }

  if (preferences && typeof preferences === 'object') {
    userData.preferences = preferences;
  }

  try {
    // Create user through user service (validation will be handled by the user service)
    const user = await createUser(userData);
    if (!user) {
      return next(new ErrorResponse('Failed to create user', 500));
    }

    // Generate email verification token
    const verifyToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    const verifyUrl = `${process.env.BASE_URL || 'http://localhost:4000'}/api/auth/email/verify?token=${verifyToken}`;

    await sendMail({
      to: email,
      subject: 'Verify your email',
      text: `Please verify your email: ${verifyUrl}`,
      html: `<p>Please verify your email: <a href="${verifyUrl}">${verifyUrl}</a></p>`,
    });

    logger.info('User registered successfully', {
      userId: user._id,
      email,
      hasAddresses: !!addresses?.length,
      hasPaymentMethods: !!paymentMethods?.length,
      hasWishlist: !!wishlist?.length,
      hasPreferences: !!preferences,
    });

    res.status(201).json({
      message: 'Registration successful, please verify your email.',
      user: {
        _id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        displayName: user.displayName,
        isEmailVerified: user.isEmailVerified,
        roles: user.roles,
        // Include counts of additional data for confirmation
        addressCount: user.addresses?.length || 0,
        paymentMethodCount: user.paymentMethods?.length || 0,
        wishlistCount: user.wishlist?.length || 0,
        hasPreferences: !!user.preferences,
      },
    });
  } catch (error) {
    logger.error('Registration failed', { email, error: error.message });

    // Check if it's a validation error from the user service
    if (error.message && error.message.includes('validation')) {
      return next(new ErrorResponse('Registration data validation failed. Please check your input data.', 400));
    }

    return next(new ErrorResponse('Registration failed. Please try again.', 500));
  }
});

/**
 * @desc    Request account reactivation (send email link)
 * @route   POST /auth/account/reactivateRequest
 * @access  Public
 */
export const requestAccountReactivation = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  if (!email) return next(new ErrorResponse('Email is required', 400));
  const user = await getUserByEmail(email);
  if (!user) return next(new ErrorResponse('User not found', 404));
  if (user.isActive) return next(new ErrorResponse('Account is already active.', 400));
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
export const reactivateAccount = asyncHandler(async (req, res, next) => {
  const { token } = req.query;
  if (!token) return next(new ErrorResponse('Token is required', 400));
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return next(new ErrorResponse('Invalid or expired token', 400));
  }
  const user = await getUserByEmail(payload.email);
  if (!user) return next(new ErrorResponse('User not found', 404));
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
      const errorData = JSON.parse(text);
      return next(new ErrorResponse(errorData.error || 'Account reactivation failed', resp.status));
    } else {
      logger.error('User service error', { text });
      return next(new ErrorResponse('Account reactivation failed', resp.status));
    }
  }
  res.json({ message: 'Account reactivated successfully.' });
});

/**
 * @desc    Delete own account (self-service)
 * @route   DELETE /auth/account
 * @access  Private
 */
export const deleteAccount = asyncHandler(async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.jwt;
  const success = await import('../services/userServiceClient.js').then((m) => m.deleteUserSelf(token));
  if (!success) return next(new ErrorResponse('User not found', 404));
  res.status(204).send();
});

/**
 * @desc    Admin: delete any user by ID
 * @route   DELETE /auth/users/:id
 * @access  Admin only
 */
export const adminDeleteUser = asyncHandler(async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.jwt;
  const { id } = req.params;
  const success = await import('../services/userServiceClient.js').then((m) => m.deleteUserById(id, token));
  if (!success) return next(new ErrorResponse('User not found', 404));
  res.status(204).send();
});
