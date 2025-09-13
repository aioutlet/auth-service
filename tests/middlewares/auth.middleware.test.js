import authMiddleware, { authorizeRoles } from '../../src/middlewares/auth.middleware.js';
import { createMockReqRes, createMockNext, createMockUser } from '../utils/testHelpers.js';
import ErrorResponse from '../../src/utils/ErrorResponse.js';
import jwt from 'jsonwebtoken';

// Mock JWT for testing
jest.mock('jsonwebtoken');

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
        id: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
      });

      await authMiddleware(req, res, next);

      expect(jwt.verify).toHaveBeenCalledWith('valid-token', 'test-secret');
      expect(req.user).toEqual({
        id: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
      });
      expect(next).toHaveBeenCalledWith();
    });

    it('should authenticate valid token from cookies', async () => {
      const { req, res } = createMockReqRes({
        cookies: {
          jwt: 'valid-cookie-token',
        },
      });
      const next = createMockNext();
      const mockUser = createMockUser();

      jwt.verify.mockReturnValue({
        id: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
      });

      await authMiddleware(req, res, next);

      expect(jwt.verify).toHaveBeenCalledWith('valid-cookie-token', 'test-secret');
      expect(req.user).toEqual({
        id: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
      });
      expect(next).toHaveBeenCalledWith();
    });

    it('should prioritize Authorization header over cookies', async () => {
      const { req, res } = createMockReqRes({
        headers: {
          authorization: 'Bearer header-token',
        },
        cookies: {
          jwt: 'cookie-token',
        },
      });
      const next = createMockNext();
      const mockUser = createMockUser();

      jwt.verify.mockReturnValue({
        id: mockUser._id,
        email: mockUser.email,
        roles: mockUser.roles,
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
        id: '123',
        email: 'test@example.com',
        // no roles property
      });

      await authMiddleware(req, res, next);

      expect(req.user).toEqual({
        id: '123',
        email: 'test@example.com',
        roles: undefined,
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