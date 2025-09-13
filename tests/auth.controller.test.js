// Comprehensive tests for Auth Controller
import {
  login,
  logout,
  refreshToken,
  register,
  forgotPassword,
  resetPassword,
  changePassword,
  verifyEmail,
  resendVerificationEmail,
  socialCallback,
  me,
  requestAccountReactivation,
  reactivateAccount,
  deleteAccount,
  adminDeleteUser,
} from '../../src/controllers/auth.controller.js';
import { createMockReqRes, createMockNext, createMockUser, mockFetch } from '../utils/testHelpers.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import RefreshToken from '../../src/models/refreshToken.model.js';

// Mock all dependencies
jest.mock('bcrypt');
jest.mock('jsonwebtoken');
jest.mock('../../src/models/refreshToken.model.js');
jest.mock('../../src/services/userServiceClient.js');
jest.mock('../../src/utils/tokenManager.js');
jest.mock('../../src/utils/email.js');
jest.mock('../../src/validators/auth.validator.js');

describe('Auth Controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Set up fetch mock
    global.fetch = jest.fn();
  });

  describe('login', () => {
    it('should login user with valid credentials', async () => {
      const mockUser = createMockUser({ password: 'hashedPassword' });
      const { req, res } = createMockReqRes({
        body: { email: 'test@example.com', password: 'password123' },
      });
      const next = createMockNext();

      // Mock getUserByEmail
      const { getUserByEmail } = await import('../../src/services/userServiceClient.js');
      getUserByEmail.mockResolvedValue(mockUser);

      // Mock bcrypt.compare
      bcrypt.compare.mockResolvedValue(true);

      // Mock token utilities
      const { issueJwtToken, issueRefreshToken, issueCsrfToken } = await import(
        '../../src/utils/tokenManager.js'
      );
      issueJwtToken.mockReturnValue('jwt-token');
      issueRefreshToken.mockResolvedValue();
      issueCsrfToken.mockResolvedValue();

      await login(req, res, next);

      expect(getUserByEmail).toHaveBeenCalledWith('test@example.com');
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashedPassword');
      expect(issueJwtToken).toHaveBeenCalledWith(req, res, mockUser);
      expect(issueRefreshToken).toHaveBeenCalledWith(req, res, mockUser);
      expect(issueCsrfToken).toHaveBeenCalledWith(req, res, mockUser);
      expect(res.json).toHaveBeenCalledWith({
        jwt: 'jwt-token',
        user: mockUser,
      });
    });

    it('should return 400 when email is missing', async () => {
      const { req, res } = createMockReqRes({
        body: { password: 'password123' },
      });
      const next = createMockNext();

      await login(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Email and password are required',
          statusCode: 400,
        })
      );
    });

    it('should return 400 when password is missing', async () => {
      const { req, res } = createMockReqRes({
        body: { email: 'test@example.com' },
      });
      const next = createMockNext();

      await login(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Email and password are required',
          statusCode: 400,
        })
      );
    });

    it('should return 401 when user not found', async () => {
      const { req, res } = createMockReqRes({
        body: { email: 'test@example.com', password: 'password123' },
      });
      const next = createMockNext();

      const { getUserByEmail } = await import('../../src/services/userServiceClient.js');
      getUserByEmail.mockResolvedValue(null);

      await login(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Invalid credentials',
          statusCode: 401,
        })
      );
    });

    it('should return 403 when account is deactivated', async () => {
      const mockUser = createMockUser({ isActive: false });
      const { req, res } = createMockReqRes({
        body: { email: 'test@example.com', password: 'password123' },
      });
      const next = createMockNext();

      const { getUserByEmail } = await import('../../src/services/userServiceClient.js');
      getUserByEmail.mockResolvedValue(mockUser);

      await login(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Account is deactivated',
          statusCode: 403,
        })
      );
    });

    it('should return 403 when email is not verified', async () => {
      const mockUser = createMockUser({ isEmailVerified: false });
      const { req, res } = createMockReqRes({
        body: { email: 'test@example.com', password: 'password123' },
      });
      const next = createMockNext();

      const { getUserByEmail } = await import('../../src/services/userServiceClient.js');
      getUserByEmail.mockResolvedValue(mockUser);

      await login(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Please verify your email before logging in',
          statusCode: 403,
        })
      );
    });

    it('should return 401 when password is incorrect', async () => {
      const mockUser = createMockUser({ password: 'hashedPassword' });
      const { req, res } = createMockReqRes({
        body: { email: 'test@example.com', password: 'wrongpassword' },
      });
      const next = createMockNext();

      const { getUserByEmail } = await import('../../src/services/userServiceClient.js');
      getUserByEmail.mockResolvedValue(mockUser);
      bcrypt.compare.mockResolvedValue(false);

      await login(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Invalid credentials',
          statusCode: 401,
        })
      );
    });
  });

  describe('logout', () => {
    it('should logout user successfully', async () => {
      const { req, res } = createMockReqRes({
        cookies: { refreshToken: 'valid-refresh-token' },
      });
      const next = createMockNext();

      RefreshToken.deleteOne.mockResolvedValue({ deletedCount: 1 });

      await logout(req, res, next);

      expect(RefreshToken.deleteOne).toHaveBeenCalledWith({ token: 'valid-refresh-token' });
      expect(res.clearCookie).toHaveBeenCalledTimes(3);
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken', expect.any(Object));
      expect(res.clearCookie).toHaveBeenCalledWith('jwt', expect.any(Object));
      expect(res.clearCookie).toHaveBeenCalledWith('csrfToken', expect.any(Object));
      expect(res.json).toHaveBeenCalledWith({ message: 'Logged out successfully' });
    });

    it('should return 400 when refresh token is missing', async () => {
      const { req, res } = createMockReqRes();
      const next = createMockNext();

      await logout(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Refresh token required',
          statusCode: 400,
        })
      );
    });
  });

  describe('register', () => {
    it('should register new user successfully', async () => {
      const { req, res } = createMockReqRes({
        body: {
          email: 'newuser@example.com',
          password: 'password123',
          firstName: 'John',
          lastName: 'Doe',
        },
      });
      const next = createMockNext();
      const newUser = createMockUser({
        email: 'newuser@example.com',
        firstName: 'John',
        lastName: 'Doe',
        isEmailVerified: false,
      });

      // Mock validator
      const authValidator = await import('../../src/validators/auth.validator.js');
      authValidator.default.isValidPassword.mockReturnValue({ valid: true });

      // Mock user service
      const { getUserByEmail, createUser } = await import('../../src/services/userServiceClient.js');
      getUserByEmail.mockResolvedValue(null); // User doesn't exist
      createUser.mockResolvedValue(newUser);

      // Mock JWT and email
      jwt.sign.mockReturnValue('verification-token');
      const { sendMail } = await import('../../src/utils/email.js');
      sendMail.mockResolvedValue();

      await register(req, res, next);

      expect(authValidator.default.isValidPassword).toHaveBeenCalledWith('password123');
      expect(getUserByEmail).toHaveBeenCalledWith('newuser@example.com');
      expect(createUser).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'newuser@example.com',
          password: 'password123',
          firstName: 'John',
          lastName: 'Doe',
          isEmailVerified: false,
          roles: ['customer'],
        })
      );
      expect(sendMail).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Registration successful, please verify your email.',
          user: expect.objectContaining({
            email: 'newuser@example.com',
            firstName: 'John',
            lastName: 'Doe',
          }),
        })
      );
    });

    it('should return 400 when email is missing', async () => {
      const { req, res } = createMockReqRes({
        body: { password: 'password123' },
      });
      const next = createMockNext();

      await register(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Email and password are required',
          statusCode: 400,
        })
      );
    });

    it('should return 400 when password is invalid', async () => {
      const { req, res } = createMockReqRes({
        body: { email: 'test@example.com', password: 'weak' },
      });
      const next = createMockNext();

      const authValidator = await import('../../src/validators/auth.validator.js');
      authValidator.default.isValidPassword.mockReturnValue({
        valid: false,
        error: 'Password too weak',
      });

      await register(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Password too weak',
          statusCode: 400,
        })
      );
    });

    it('should return 409 when user already exists', async () => {
      const { req, res } = createMockReqRes({
        body: { email: 'existing@example.com', password: 'password123' },
      });
      const next = createMockNext();

      const authValidator = await import('../../src/validators/auth.validator.js');
      authValidator.default.isValidPassword.mockReturnValue({ valid: true });

      const { getUserByEmail } = await import('../../src/services/userServiceClient.js');
      getUserByEmail.mockResolvedValue(createMockUser());

      await register(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'User already exists',
          statusCode: 409,
        })
      );
    });
  });

  describe('me', () => {
    it('should return current user info', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });

      await me(req, res);

      expect(res.json).toHaveBeenCalledWith({ user });
    });
  });

  describe('forgotPassword', () => {
    it('should send password reset email', async () => {
      const { req, res } = createMockReqRes({
        body: { email: 'test@example.com' },
      });
      const next = createMockNext();
      const user = createMockUser();

      const { getUserByEmail } = await import('../../src/services/userServiceClient.js');
      getUserByEmail.mockResolvedValue(user);

      jwt.sign.mockReturnValue('reset-token');

      const { sendMail } = await import('../../src/utils/email.js');
      sendMail.mockResolvedValue();

      await forgotPassword(req, res, next);

      expect(getUserByEmail).toHaveBeenCalledWith('test@example.com');
      expect(jwt.sign).toHaveBeenCalled();
      expect(sendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'test@example.com',
          subject: 'Reset your password',
        })
      );
      expect(res.json).toHaveBeenCalledWith({
        message: 'Password reset email sent',
      });
    });

    it('should return 400 when email is missing', async () => {
      const { req, res } = createMockReqRes({ body: {} });
      const next = createMockNext();

      await forgotPassword(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Email is required',
          statusCode: 400,
        })
      );
    });

    it('should return 404 when user not found', async () => {
      const { req, res } = createMockReqRes({
        body: { email: 'nonexistent@example.com' },
      });
      const next = createMockNext();

      const { getUserByEmail } = await import('../../src/services/userServiceClient.js');
      getUserByEmail.mockResolvedValue(null);

      await forgotPassword(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'User not found',
          statusCode: 404,
        })
      );
    });
  });
});
