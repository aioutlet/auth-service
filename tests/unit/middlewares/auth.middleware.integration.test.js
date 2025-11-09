/**
 * Integration-style tests for auth middleware
 * Uses real JWT signing/verification instead of mocks
 */

import jwt from 'jsonwebtoken';

// Mock the logger module before any imports
jest.mock('../../../src/core/logger.js', () => ({
  default: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    withCorrelationId: jest.fn(function() { return this; }),
  },
}));

jest.mock('../../../src/services/dapr.secretManager.js', () => ({
  getJwtConfig: jest.fn().mockResolvedValue({
    secret: 'test-secret-key-for-testing',
    expire: '24h',
  }),
}));

import { authMiddleware, authorizeRoles, clearJwtConfigCache } from '../../../src/middlewares/auth.middleware.js';
import { createMockReqRes, createMockNext, createMockUser } from '../../shared/testHelpers.js';

describe('authMiddleware (Integration)', () => {
  const SECRET = 'test-secret-key-for-testing';

  beforeEach(() => {
    jest.clearAllMocks();
    // Clear the JWT config cache so it will call getJwtConfig again
    clearJwtConfigCache();
  });

  describe('JWT token verification', () => {
    it('should authenticate valid token from Authorization header', async () => {
      const mockUser = createMockUser();
      
      // Create a real JWT token
      const token = jwt.sign(
        {
          sub: mockUser._id,
          email: mockUser.email,
          roles: mockUser.roles,
          iss: 'auth-service',
          aud: 'auth-service',
        },
        SECRET,
        { expiresIn: '1h' }
      );

      const { req, res } = createMockReqRes({
        headers: {
          authorization: `Bearer ${token}`,
        },
      });
      const next = createMockNext();

      await authMiddleware(req, res, next).then(() => {
        console.log('Promise resolved');
      }).catch((err) => {
        console.log('Promise rejected:', err);
      });

      console.log('Test - req identity:', req === req); // Check if req is the same object
      console.log('Test - req.user:', req.user);
      console.log('Test - next calls:', next.mock.calls.length);

      expect(req.user).toMatchObject({
        id: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
      });
      expect(next).toHaveBeenCalledWith();
    });

    it('should authenticate valid token from cookies', async () => {
      const mockUser = createMockUser();
      
      const token = jwt.sign(
        {
          sub: mockUser._id,
          email: mockUser.email,
          roles: mockUser.roles,
          iss: 'auth-service',
          aud: 'auth-service',
        },
        SECRET,
        { expiresIn: '1h' }
      );

      const { req, res } = createMockReqRes({
        cookies: {
          token: token,
        },
      });
      const next = createMockNext();

      await authMiddleware(req, res, next);

      expect(req.user).toMatchObject({
        id: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
      });
      expect(next).toHaveBeenCalledWith();
    });

    it('should prioritize Authorization header over cookies', async () => {
      const mockUser = createMockUser();
      
      const headerToken = jwt.sign(
        {
          sub: mockUser._id,
          email: 'header@example.com',
          roles: mockUser.roles,
          iss: 'auth-service',
          aud: 'auth-service',
        },
        SECRET,
        { expiresIn: '1h' }
      );

      const cookieToken = jwt.sign(
        {
          sub: 'different-id',
          email: 'cookie@example.com',
          roles: ['guest'],
          iss: 'auth-service',
          aud: 'auth-service',
        },
        SECRET,
        { expiresIn: '1h' }
      );

      const { req, res } = createMockReqRes({
        headers: {
          authorization: `Bearer ${headerToken}`,
        },
        cookies: {
          token: cookieToken,
        },
      });
      const next = createMockNext();

      await authMiddleware(req, res, next);

      // Should use the header token
      expect(req.user.email).toBe('header@example.com');
      expect(next).toHaveBeenCalledWith();
    });

    it('should return 401 when no token is provided', async () => {
      const { req, res } = createMockReqRes();
      const next = createMockNext();

      await authMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Not authorized to access this route',
          statusCode: 401,
        })
      );
    });

    it('should return 401 when Authorization header is malformed', async () => {
      const { req, res } = createMockReqRes({
        headers: {
          authorization: 'Invalid format',
        },
      });
      const next = createMockNext();

      await authMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Not authorized to access this route',
          statusCode: 401,
        })
      );
    });

    it('should handle invalid token', async () => {
      const { req, res } = createMockReqRes({
        headers: {
          authorization: 'Bearer invalid-token',
        },
      });
      const next = createMockNext();

      await authMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(Error));
      const error = next.mock.calls[0][0];
      expect(error.name).toBe('JsonWebTokenError');
    });

    it('should handle expired token', async () => {
      const mockUser = createMockUser();
      
      // Create an expired token
      const expiredToken = jwt.sign(
        {
          sub: mockUser._id,
          email: mockUser.email,
          roles: mockUser.roles,
          iss: 'auth-service',
          aud: 'auth-service',
        },
        SECRET,
        { expiresIn: '-1h' } // Already expired
      );

      const { req, res } = createMockReqRes({
        headers: {
          authorization: `Bearer ${expiredToken}`,
        },
      });
      const next = createMockNext();

      await authMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(Error));
      const error = next.mock.calls[0][0];
      expect(error.name).toBe('TokenExpiredError');
    });

    it('should handle token without required claims', async () => {
      // Token missing sub, iss, aud claims
      const invalidToken = jwt.sign(
        {
          email: 'test@example.com',
          roles: ['user'],
        },
        SECRET,
        { expiresIn: '1h' }
      );

      const { req, res } = createMockReqRes({
        headers: {
          authorization: `Bearer ${invalidToken}`,
        },
      });
      const next = createMockNext();

      await authMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(Error));
    });

    it('should handle user without roles', async () => {
      const token = jwt.sign(
        {
          sub: '123',
          email: 'test@example.com',
          iss: 'auth-service',
          aud: 'auth-service',
          // no roles property
        },
        SECRET,
        { expiresIn: '1h' }
      );

      const { req, res } = createMockReqRes({
        headers: {
          authorization: `Bearer ${token}`,
        },
      });
      const next = createMockNext();

      await authMiddleware(req, res, next);

      expect(req.user).toMatchObject({
        id: '123',
        email: 'test@example.com',
        roles: [],
      });
      expect(next).toHaveBeenCalledWith();
    });
  });
});

describe('authorizeRoles (Integration)', () => {
  it('should allow access when user has required role', () => {
    const { req, res } = createMockReqRes({
      user: createMockUser({ roles: ['admin', 'user'] }),
    });
    const next = createMockNext();

    const middleware = authorizeRoles('admin');
    middleware(req, res, next);

    expect(next).toHaveBeenCalledWith();
  });

  it('should allow access when user has one of multiple required roles', () => {
    const { req, res } = createMockReqRes({
      user: createMockUser({ roles: ['user'] }),
    });
    const next = createMockNext();

    const middleware = authorizeRoles('admin', 'user', 'moderator');
    middleware(req, res, next);

    expect(next).toHaveBeenCalledWith();
  });

  it('should deny access when user does not have required role', () => {
    const { req, res } = createMockReqRes({
      user: createMockUser({ roles: ['user'] }),
    });
    const next = createMockNext();

    const middleware = authorizeRoles('admin');
    middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Forbidden: insufficient role',
        statusCode: 403,
      })
    );
  });

  it('should deny access when user has no roles', () => {
    const { req, res } = createMockReqRes({
      user: createMockUser({ roles: [] }),
    });
    const next = createMockNext();

    const middleware = authorizeRoles('admin');
    middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Forbidden: insufficient role',
        statusCode: 403,
      })
    );
  });

  it('should deny access when user roles is undefined', () => {
    const { req, res } = createMockReqRes({
      user: createMockUser({ roles: undefined }),
    });
    const next = createMockNext();

    const middleware = authorizeRoles('admin');
    middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Forbidden: insufficient role',
        statusCode: 403,
      })
    );
  });

  it('should deny access when user is not present', () => {
    const { req, res } = createMockReqRes();
    const next = createMockNext();

    const middleware = authorizeRoles('admin');
    middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Forbidden: insufficient role',
        statusCode: 403,
      })
    );
  });

  it('should handle multiple roles requirement correctly', () => {
    const { req, res } = createMockReqRes({
      user: createMockUser({ roles: ['moderator'] }),
    });
    const next = createMockNext();

    const middleware = authorizeRoles('admin', 'super-admin');
    middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Forbidden: insufficient role',
        statusCode: 403,
      })
    );
  });

  it('should handle empty roles requirement', () => {
    const { req, res } = createMockReqRes({
      user: createMockUser({ roles: ['admin'] }),
    });
    const next = createMockNext();

    const middleware = authorizeRoles();
    middleware(req, res, next);

    // Should deny access when no roles are specified
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Forbidden: insufficient role',
        statusCode: 403,
      })
    );
  });

  it('should handle case-sensitive role matching', () => {
    const { req, res } = createMockReqRes({
      user: createMockUser({ roles: ['Admin'] }),
    });
    const next = createMockNext();

    const middleware = authorizeRoles('admin');
    middleware(req, res, next);

    // Should be case-sensitive
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Forbidden: insufficient role',
        statusCode: 403,
      })
    );
  });
});
