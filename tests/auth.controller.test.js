import * as authController from '../src/controllers/auth.controller.js';
import { getUserByEmail, createUser, getUserBySocial } from '../src/services/userServiceClient.js';
import RefreshToken from '../src/models/refreshToken.model.js';
import { sendMail } from '../src/utils/email.js';
import httpMocks from 'node-mocks-http';
import bcrypt from 'bcrypt';

jest.mock('../src/services/userServiceClient.js');
jest.mock('../src/models/refreshToken.model.js');
jest.mock('../src/utils/email.js');
jest.mock('../src/middlewares/csrf.middleware.js', () => ({
  issueCsrfToken: jest.fn((req, res, next) => (typeof next === 'function' ? next() : undefined)),
  requireCsrfToken: jest.fn((req, res, next) => (typeof next === 'function' ? next() : undefined)),
}));

// Helper to create mock req/res/next
function mockReqRes(body = {}, opts = {}) {
  const req = httpMocks.createRequest({
    method: opts.method || 'POST',
    url: opts.url || '/',
    body,
    cookies: opts.cookies || {},
    headers: opts.headers || {},
    query: opts.query || {},
    user: opts.user || undefined,
  });
  const res = httpMocks.createResponse();
  res.cookie = jest.fn(); // Mock cookie to no-op
  const next = jest.fn();
  return { req, res, next };
}

describe('auth.controller', () => {
  beforeAll(() => {
    process.env.JWT_SECRET = 'testsecret';
  });
  beforeEach(() => {
    jest.clearAllMocks();
    RefreshToken.create = jest.fn().mockResolvedValue({});
  });
  describe('login', () => {
    it('should login user with valid credentials', async () => {
      const password = await bcrypt.hash('password123', 10);
      getUserByEmail.mockResolvedValue({
        _id: 'user1',
        email: 'test@example.com',
        password,
        isActive: true,
        isEmailVerified: true,
        roles: ['user'],
      });
      const { req, res, next } = mockReqRes({ email: 'test@example.com', password: 'password123' });
      await authController.login(req, res, next);
      // Debug: log raw response
      // eslint-disable-next-line no-console
      console.log('RAW DATA:', res._getData());
      // eslint-disable-next-line no-console
      console.log('IS END CALLED:', res._isEndCalled());
      expect(res.statusCode).toBe(200);
      expect(() => res._getJSONData()).not.toThrow();
      expect(res._getJSONData()).toHaveProperty('jwt');
      expect(res._getJSONData().user.email).toBe('test@example.com');
    });
    it('should fail with missing credentials', async () => {
      const { req, res, next } = mockReqRes({ email: '' });
      await authController.login(req, res, next);
      expect(res.statusCode).toBe(400);
      expect(res._getJSONData().error).toMatch(/required/);
    });
    it('should fail with wrong password', async () => {
      const password = await bcrypt.hash('password123', 10);
      getUserByEmail.mockResolvedValue({
        _id: 'user1',
        email: 'test@example.com',
        password,
        isActive: true,
        isEmailVerified: true,
        roles: ['user'],
      });
      const { req, res, next } = mockReqRes({ email: 'test@example.com', password: 'wrongpass' });
      await authController.login(req, res, next);
      expect(res.statusCode).toBe(401);
      expect(res._getJSONData().error).toMatch(/Invalid credentials/);
    });
    it('should fail if user is not found', async () => {
      getUserByEmail.mockResolvedValue(null);
      const { req, res, next } = mockReqRes({ email: 'notfound@example.com', password: 'password123' });
      await authController.login(req, res, next);
      expect(res.statusCode).toBe(401);
      expect(res._getJSONData().error).toMatch(/Invalid credentials/);
    });
    it('should fail if account is deactivated', async () => {
      const password = await bcrypt.hash('password123', 10);
      getUserByEmail.mockResolvedValue({
        _id: 'user1',
        email: 'test@example.com',
        password,
        isActive: false,
        isEmailVerified: true,
        roles: ['user'],
      });
      const { req, res, next } = mockReqRes({ email: 'test@example.com', password: 'password123' });
      await authController.login(req, res, next);
      expect(res.statusCode).toBe(403);
      expect(res._getJSONData().error).toMatch(/deactivated/);
    });
    it('should fail if email is not verified', async () => {
      const password = await bcrypt.hash('password123', 10);
      getUserByEmail.mockResolvedValue({
        _id: 'user1',
        email: 'test@example.com',
        password,
        isActive: true,
        isEmailVerified: false,
        roles: ['user'],
      });
      const { req, res, next } = mockReqRes({ email: 'test@example.com', password: 'password123' });
      await authController.login(req, res, next);
      expect(res.statusCode).toBe(403);
      expect(res._getJSONData().error).toMatch(/verify/);
    });
  });
  describe('logout', () => {
    it('should logout and clear cookies if refresh token is present', async () => {
      RefreshToken.deleteOne.mockResolvedValue({ deletedCount: 1 });
      const { req, res, next } = mockReqRes(
        {},
        {
          cookies: { refreshToken: 'validtoken' },
        }
      );
      await authController.logout(req, res, next);
      expect(res.statusCode).toBe(200);
      expect(res._getJSONData().message).toMatch(/Logged out/);
    });
    it('should fail if refresh token is missing', async () => {
      const { req, res, next } = mockReqRes({}, { cookies: {} });
      await authController.logout(req, res, next);
      expect(res.statusCode).toBe(400);
      expect(res._getJSONData().error).toMatch(/Refresh token required/);
    });
  });

  describe('register', () => {
    it('should register a new user and send verification email', async () => {
      getUserByEmail.mockResolvedValue(null);
      createUser.mockResolvedValue({ _id: 'user2', email: 'new@example.com' });
      sendMail.mockResolvedValue(true);
      const { req, res, next } = mockReqRes({ email: 'new@example.com', password: 'Password1', name: 'New User' });
      await authController.register(req, res, next);
      expect(res.statusCode).toBe(201);
      expect(res._getJSONData().message).toMatch(/Registration successful/);
      expect(sendMail).toHaveBeenCalled();
    });
    it('should fail if user already exists', async () => {
      getUserByEmail.mockResolvedValue({ _id: 'user2', email: 'new@example.com' });
      const { req, res, next } = mockReqRes({ email: 'new@example.com', password: 'Password1', name: 'New User' });
      await authController.register(req, res, next);
      expect(res.statusCode).toBe(409);
      expect(res._getJSONData().error).toMatch(/already exists/);
    });
    it('should fail if email or password is missing', async () => {
      const { req, res, next } = mockReqRes({ email: '', password: '' });
      await authController.register(req, res, next);
      expect(res.statusCode).toBe(400);
      expect(res._getJSONData().error).toMatch(/required/);
    });
  });

  describe('refreshToken', () => {
    it('should issue new JWT if refresh token is valid', async () => {
      RefreshToken.findOne.mockResolvedValue({
        token: 'validtoken',
        expiresAt: new Date(Date.now() + 10000),
        user: { email: 'test@example.com', _id: 'user1', roles: ['user'] },
      });
      getUserByEmail.mockResolvedValue({ _id: 'user1', email: 'test@example.com', roles: ['user'] });
      const { req, res, next } = mockReqRes({ refreshToken: 'validtoken' });
      await authController.refreshToken(req, res, next);
      expect(res.statusCode).toBe(200);
      expect(res._getJSONData()).toHaveProperty('jwt');
    });
    it('should fail if refresh token is missing', async () => {
      const { req, res, next } = mockReqRes({});
      await authController.refreshToken(req, res, next);
      expect(res.statusCode).toBe(400);
      expect(res._getJSONData().error).toMatch(/required/);
    });
    it('should fail if refresh token is invalid or expired', async () => {
      RefreshToken.findOne.mockResolvedValue(null);
      const { req, res, next } = mockReqRes({ refreshToken: 'badtoken' });
      await authController.refreshToken(req, res, next);
      expect(res.statusCode).toBe(401);
      expect(res._getJSONData().error).toMatch(/Invalid/);
    });
  });
  // Add more describe blocks for other controllers as needed
});
