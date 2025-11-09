/**
 * Simplified tests for auth middleware
 * These tests focus on the authorizeRoles middleware which doesn't require complex mocking
 */

import { authorizeRoles } from '../../../src/middlewares/auth.middleware.js';
import { createMockReqRes, createMockNext, createMockUser } from '../../shared/testHelpers.js';

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
