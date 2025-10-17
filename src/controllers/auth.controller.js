import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import {
  signToken,
  issueJwtToken,
  issueRefreshToken,
  issueCsrfToken as issueCsrfTokenConsistent,
  verifyToken,
} from '../utils/tokenManager.js';
import { asyncHandler } from '../middlewares/asyncHandler.js';
import { getUserByEmail, getUserById, createUser } from '../services/userServiceClient.js';
import authValidator from '../validators/auth.validator.js';
import logger from '../observability/logging/index.js';
import ErrorResponse from '../utils/ErrorResponse.js';
import messageBrokerService from '../services/messageBrokerServiceClient.js';

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
  const refreshTokenDoc = await issueRefreshToken(req, res, user);
  await issueCsrfTokenConsistent(req, res, user);

  // Publish login event via Message Broker Service
  try {
    await messageBrokerService.publishEvent('auth.login', {
      userId: user._id.toString(),
      email: user.email,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      sessionId: refreshTokenDoc._id.toString(),
      correlationId: req.correlationId,
      timestamp: new Date().toISOString(),
      success: true,
    });
  } catch (error) {
    logger.error('Failed to publish login event', req, { operation: 'publish_login_event', error });
  }

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

  // For stateless tokens, we just clear the cookies (no database operation needed)
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
  logger.info('User logged out successfully');
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

  // Verify the refresh token (stateless)
  const decoded = verifyToken(refreshToken);
  if (!decoded || decoded.type !== 'refresh') {
    logger.warn('Invalid or expired refresh token');
    return next(new ErrorResponse('Invalid or expired refresh token', 401));
  }

  const userId = decoded.id;
  const jwtToken = req.cookies?.jwt || null;
  const user = await getUserById(userId, jwtToken);
  if (!user) {
    logger.warn('Refresh token user not found', { userId });
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
  if (!email) {
    return next(new ErrorResponse('Email is required', 400));
  }
  const user = await getUserByEmail(email);
  if (!user) {
    return next(new ErrorResponse('User not found', 404));
  }
  const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const resetUrl = `${process.env.BASE_URL || 'http://localhost:4000'}/auth/password/reset?token=${resetToken}`;

  // Publish event for notification-service to send email
  try {
    await messageBrokerService.publishEvent('auth.password.reset.requested', {
      userId: user._id.toString(),
      email: user.email,
      resetToken,
      resetUrl,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), // 1 hour
      requestIp: req.ip,
      correlationId: req.correlationId,
      timestamp: new Date().toISOString(),
    });
    logger.info('Password reset event published', { email, correlationId: req.correlationId });
  } catch (error) {
    logger.error('Failed to publish password reset event', { email, error: error.message });
    // Don't fail the request if event publishing fails
  }

  res.json({ message: 'Password reset email sent' });
});

/**
 * @desc    Reset password using token from email
 * @route   POST /auth/password/reset
 * @access  Public
 */
export const resetPassword = asyncHandler(async (req, res, next) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return next(new ErrorResponse('Token and new password are required', 400));
  }
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return next(new ErrorResponse('Invalid or expired token', 400));
  }
  const user = await getUserByEmail(payload.email);
  if (!user) {
    return next(new ErrorResponse('User not found', 404));
  }
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

  // Publish event for notification-service to send confirmation email
  try {
    await messageBrokerService.publishEvent('auth.password.reset.completed', {
      userId: user._id.toString(),
      email: user.email,
      changedAt: new Date().toISOString(),
      changedIp: req.ip,
      correlationId: req.correlationId,
      timestamp: new Date().toISOString(),
    });
    logger.info('Password reset completed event published', { email: user.email });
  } catch (error) {
    logger.error('Failed to publish password reset completed event', { error: error.message });
    // Don't fail the request if event publishing fails
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
  if (!userId) {
    return next(new ErrorResponse('Unauthorized', 401));
  }

  const validation = authValidator.validatePasswordChange(oldPassword, newPassword);
  if (!validation.valid) {
    return next(new ErrorResponse(validation.error, 400));
  }

  // Validate new password strength
  const passwordValidation = authValidator.isValidPassword(newPassword);
  if (!passwordValidation.valid) {
    // If validator provides details, use them; otherwise use the error message
    if (passwordValidation.details && passwordValidation.details.length > 0) {
      return next(
        new ErrorResponse(passwordValidation.error, 400, {
          field: 'password',
          requirements: passwordValidation.details,
        })
      );
    }
    return next(new ErrorResponse(passwordValidation.error, 400));
  }

  // Extract JWT from cookie or Authorization header
  let jwtToken = null;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    jwtToken = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.jwt) {
    jwtToken = req.cookies.jwt;
  }
  if (!jwtToken) {
    return next(new ErrorResponse('JWT missing', 401));
  }

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
  if (!token) {
    return next(new ErrorResponse('Token is required', 400));
  }
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return next(new ErrorResponse('Invalid or expired token', 400));
  }
  // Mark user as verified in user service
  const user = await getUserByEmail(payload.email);
  if (!user) {
    return next(new ErrorResponse('User not found', 404));
  }
  if (user.isEmailVerified) {
    return res.json({ message: 'Email already verified' });
  }
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

  // Publish event for notification-service to send verification email
  try {
    await messageBrokerService.publishEvent('auth.email.verification.requested', {
      userId: user._id.toString(),
      email: user.email,
      verificationToken: verifyToken,
      verificationUrl: verifyUrl,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 1 day
      correlationId: req.correlationId,
      timestamp: new Date().toISOString(),
    });
    logger.info('Email verification event published', { email, correlationId: req.correlationId });
  } catch (error) {
    logger.error('Failed to publish email verification event', { email, error: error.message });
    // Don't fail the request if event publishing fails
  }

  logger.info('Verification email resent', { email });
  res.json({ message: 'Verification email sent successfully' });
});

/**
 * @desc    Get current authenticated user info
 * @route   GET /auth/me
 * @access  Private
 * @role    User
 */
export const me = asyncHandler((req, res) => {
  res.json({ user: req.user });
});

/**
 * @desc    Verify JWT token
 * @route   GET /auth/verify
 * @access  Public (token verification only)
 */
export const verify = asyncHandler((req, res) => {
  // Token is already verified by authMiddleware, just return success with minimal info
  res.json({
    valid: true,
    userId: req.user.id,
    email: req.user.email,
    roles: req.user.roles,
  });
});

/**
 * @desc    Register a new user
 * @route   POST /auth/register
 * @access  Public
 */
export const register = asyncHandler(async (req, res, next) => {
  const { email, password, firstName, lastName, phoneNumber } = req.body;

  // Track operation start
  const operationStart = logger.operationStart('user_registration', req, {
    email,
    hasPhoneNumber: !!phoneNumber,
  });

  // Basic validation
  if (!email || !password) {
    return next(new ErrorResponse('Email and password are required', 400));
  }

  if (!firstName || !lastName) {
    return next(new ErrorResponse('First name and last name are required', 400));
  }

  // Validate password strength
  const passwordValidation = authValidator.isValidPassword(password);
  if (!passwordValidation.valid) {
    // If validator provides details, use them; otherwise use the error message
    if (passwordValidation.details && passwordValidation.details.length > 0) {
      return next(
        new ErrorResponse(passwordValidation.error, 400, {
          field: 'password',
          requirements: passwordValidation.details,
        })
      );
    }
    return next(new ErrorResponse(passwordValidation.error, 400));
  }

  // Check if user already exists
  const existing = await getUserByEmail(email);
  if (existing) {
    return next(new ErrorResponse('User already exists', 409));
  }

  // Prepare user data matching UI fields
  const userData = {
    email,
    password,
    firstName,
    lastName,
    isEmailVerified: false,
    roles: ['customer'], // Set default role for new users
  };

  // Add phone number if provided
  if (phoneNumber) {
    userData.phoneNumber = phoneNumber;
  }

  try {
    // Create user through user service (validation will be handled by the user service)
    const user = await createUser(userData);

    // Generate email verification token
    const verifyToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    const verifyUrl = `${process.env.BASE_URL || 'http://localhost:4000'}/api/auth/email/verify?token=${verifyToken}`;

    // Publish events for notification-service
    try {
      // User registered event
      await messageBrokerService.publishEvent('auth.user.registered', {
        userId: user._id.toString(),
        email: user.email,
        name: `${firstName} ${lastName}`,
        firstName,
        lastName,
        registeredAt: new Date().toISOString(),
        correlationId: req.correlationId,
        timestamp: new Date().toISOString(),
      });

      // Email verification event
      await messageBrokerService.publishEvent('auth.email.verification.requested', {
        userId: user._id.toString(),
        email: user.email,
        verificationToken: verifyToken,
        verificationUrl: verifyUrl,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 1 day
        correlationId: req.correlationId,
        timestamp: new Date().toISOString(),
      });

      logger.info('User registration and verification events published', req, {
        operation: 'publish_registration_events',
        email,
        userId: user._id,
      });
    } catch (eventError) {
      logger.warn('Failed to publish user registration events, but registration succeeded', req, {
        operation: 'publish_registration_events',
        email,
        userId: user._id,
        error: eventError,
      });
    }

    // Log as business event with duration
    logger.operationComplete('user_registration', operationStart, req, {
      userId: user._id,
      email,
    });

    logger.business('USER_REGISTERED', req, {
      userId: user._id,
      email,
      firstName,
      lastName,
      hasPhoneNumber: !!phoneNumber,
    });

    res.status(201).json({
      message: 'Registration successful, please verify your email.',
      requiresVerification: true,
      user: {
        _id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        isEmailVerified: user.isEmailVerified,
        roles: user.roles,
      },
    });
  } catch (error) {
    logger.operationFailed('user_registration', operationStart, error, req, {
      email,
      statusCode: error.statusCode,
      details: error.details,
    });

    logger.security('REGISTRATION_FAILED', req, {
      email,
      reason: error.message,
      statusCode: error.statusCode,
    });

    // Handle specific error types
    if (error.statusCode === 503) {
      return next(new ErrorResponse('User service is temporarily unavailable. Please try again later.', 503));
    }

    if (error.statusCode === 400 || (error.message && error.message.includes('validation'))) {
      // Extract error message, handling cases where error.details.error is an object
      let errorMsg = 'Registration data validation failed';
      if (error.details?.error) {
        if (typeof error.details.error === 'string') {
          errorMsg = error.details.error;
        } else if (error.details.error.message) {
          errorMsg = error.details.error.message;
        } else {
          errorMsg = JSON.stringify(error.details.error);
        }
      } else if (error.message) {
        errorMsg = error.message;
      }
      return next(new ErrorResponse(errorMsg, 400));
    }

    if (error.statusCode === 409 || error.message.includes('duplicate') || error.message.includes('already exists')) {
      return next(new ErrorResponse('A user with this email already exists', 409));
    }

    // Generic error with actual message for debugging in dev
    const errorMsg =
      process.env.NODE_ENV === 'development'
        ? `Registration failed: ${error.message}`
        : 'Registration failed. Please try again.';
    return next(new ErrorResponse(errorMsg, error.statusCode || 500));
  }
});

/**
 * @desc    Request account reactivation (send email link)
 * @route   POST /auth/account/reactivateRequest
 * @access  Public
 */
export const requestAccountReactivation = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  if (!email) {
    return next(new ErrorResponse('Email is required', 400));
  }
  const user = await getUserByEmail(email);
  if (!user) {
    return next(new ErrorResponse('User not found', 404));
  }
  if (user.isActive) {
    return next(new ErrorResponse('Account is already active.', 400));
  }
  // Generate a short-lived reactivation token
  const reactivateToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const reactivateUrl = `${process.env.BASE_URL || 'http://localhost:4000'}/auth/reactivate?token=${reactivateToken}`;

  // Publish event for notification-service to send reactivation email
  try {
    await messageBrokerService.publishEvent('auth.account.reactivation.requested', {
      userId: user._id.toString(),
      email: user.email,
      reactivationToken: reactivateToken,
      reactivationUrl: reactivateUrl,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), // 1 hour
      correlationId: req.correlationId,
      timestamp: new Date().toISOString(),
    });
    logger.info('Account reactivation event published', { email });
  } catch (error) {
    logger.error('Failed to publish account reactivation event', { error: error.message });
    // Don't fail the request if event publishing fails
  }

  res.json({ message: 'Reactivation email sent.' });
});

/**
 * @desc    Reactivate account via email link
 * @route   GET /auth/account/reactivate
 * @access  Public
 */
export const reactivateAccount = asyncHandler(async (req, res, next) => {
  const { token } = req.query;
  if (!token) {
    return next(new ErrorResponse('Token is required', 400));
  }
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return next(new ErrorResponse('Invalid or expired token', 400));
  }
  const user = await getUserByEmail(payload.email);
  if (!user) {
    return next(new ErrorResponse('User not found', 404));
  }
  if (user.isActive) {
    return res.json({ message: 'Account is already active.' });
  }
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
  if (!success) {
    return next(new ErrorResponse('User not found', 404));
  }
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
  if (!success) {
    return next(new ErrorResponse('User not found', 404));
  }
  res.status(204).send();
});
