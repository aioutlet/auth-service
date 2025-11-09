// Mock dependencies before importing
jest.mock('jsonwebtoken');
jest.mock('../../../src/core/logger.js', () => ({
  default: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));
jest.mock('../../../src/services/dapr.secretManager.js', () => ({
  getJwtConfig: jest.fn().mockResolvedValue({
    secret: 'test-secret',
    expire: '24h',
  }),
}));

import { authMiddleware, authorizeRoles } from '../../../src/middlewares/auth.middleware.js';
import { createMockReqRes, createMockNext, createMockUser } from '../../shared/testHelpers.js';
import ErrorResponse from '../../../src/core/errors.js';
import jwt from 'jsonwebtoken';

describe('authMiddleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.JWT_SECRET = 'test-secret';
  });

  describe('JWT token verification', () => {
    it('should authenticate valid token from Authorization header', async () => {
      const { req, res } = createMockReqRes({
        headers: {
          authorization: 'Bearer valid-token',
        },
      });
      const next = createMockNext();
      const mockUser = createMockUser();

      jwt.verify.mockReturnValue({
        sub: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
        iss: 'auth-service',
        aud: 'auth-service',
      });

      await authMiddleware(req, res, next);

      // Check if next was called with an error
      if (next.mock.calls.length > 0 && next.mock.calls[0][0]) {
        console.log('Next called with error:', next.mock.calls[0][0]);
      }

      expect(jwt.verify).toHaveBeenCalledWith('valid-token', 'test-secret');
      expect(req.user).toEqual({
        id: mockUser._id,
        email: mockUser.email,
        name: undefined,
        roles: mockUser.roles,
        emailVerified: false,
      });
      expect(next).toHaveBeenCalledWith();
    });

    it('should authenticate valid token from cookies', async () => {
      const { req, res } = createMockReqRes({
        cookies: {
          token: 'valid-cookie-token',
        },
      });
      const next = createMockNext();
      const mockUser = createMockUser();

      jwt.verify.mockReturnValue({
        sub: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
        iss: 'auth-service',
        aud: 'auth-service',
      });

      await authMiddleware(req, res, next);

      expect(jwt.verify).toHaveBeenCalledWith('valid-cookie-token', 'test-secret');
      expect(req.user).toEqual({
        id: mockUser._id,
        email: mockUser.email,
        name: undefined,
        roles: mockUser.roles,
        emailVerified: false,
      });
      expect(next).toHaveBeenCalledWith();
    });

    it('should prioritize Authorization header over cookies', async () => {
      const { req, res } = createMockReqRes({
        headers: {
          authorization: 'Bearer header-token',
        },
        cookies: {
          token: 'cookie-token',
        },
      });
      const next = createMockNext();
      const mockUser = createMockUser();

      jwt.verify.mockReturnValue({
        sub: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
        iss: 'auth-service',
        aud: 'auth-service',
      });

      await authMiddleware(req, res, next);

      expect(jwt.verify).toHaveBeenCalledWith('header-token', 'test-secret');
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

    it('should pass JWT error to error handler when token verification fails', async () => {
      const { req, res } = createMockReqRes({
        headers: {
          authorization: 'Bearer invalid-token',
        },
      });
      const next = createMockNext();
      const jwtError = new Error('Invalid token');

      jwt.verify.mockImplementation(() => {
        throw jwtError;
      });

      await authMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(jwtError);
    });

    it('should handle TokenExpiredError', async () => {
      const { req, res } = createMockReqRes({
        headers: {
          authorization: 'Bearer expired-token',
        },
      });
      const next = createMockNext();
      const expiredError = new Error('jwt expired');
      expiredError.name = 'TokenExpiredError';

      jwt.verify.mockImplementation(() => {
        throw expiredError;
      });

      await authMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expiredError);
    });

    it('should handle JsonWebTokenError', async () => {
      const { req, res } = createMockReqRes({
        headers: {
          authorization: 'Bearer malformed-token',
        },
      });
      const next = createMockNext();
      const jwtError = new Error('invalid token');
      jwtError.name = 'JsonWebTokenError';

      jwt.verify.mockImplementation(() => {
        throw jwtError;
      });

      await authMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(jwtError);
    });

    it('should handle empty cookies object', async () => {
      const { req, res } = createMockReqRes({
        cookies: {},
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

    it('should handle user without roles', async () => {
      const { req, res } = createMockReqRes({
        headers: {
          authorization: 'Bearer valid-token',
        },
      });
      const next = createMockNext();

      jwt.verify.mockReturnValue({
        sub: '123',
        email: 'test@example.com',
        iss: 'auth-service',
        aud: 'auth-service',
        // no roles property
      });

      await authMiddleware(req, res, next);

      expect(req.user).toEqual({
        id: '123',
        email: 'test@example.com',
        name: undefined,
        roles: [],
        emailVerified: false,
      });
      expect(next).toHaveBeenCalledWith();
    });
  });
});

describe('authorizeRoles', () => {
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
