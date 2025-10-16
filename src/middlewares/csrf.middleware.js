import jwt from 'jsonwebtoken';
import ErrorResponse from '../utils/ErrorResponse.js';

async function requireCsrfToken(req, res, next) {
  try {
    // Only check for browser clients (cookie-based JWT)
    const cookieToken = req.cookies['csrfToken'];
    const headerToken = req.get('X-CSRF-Token');

    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return next(new ErrorResponse('Invalid or missing CSRF token', 403));
    }

    // Validate CSRF token as JWT (stateless approach)
    try {
      const decoded = jwt.verify(cookieToken, process.env.JWT_SECRET);

      // Check if token is for the same user and hasn't expired
      const userId = req.user?.id;
      if (!userId || decoded.userId !== userId) {
        return next(new ErrorResponse('CSRF token user mismatch', 403));
      }

      // Check token expiration (CSRF tokens should be short-lived)
      if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
        return next(new ErrorResponse('Expired CSRF token', 403));
      }
    } catch {
      return next(new ErrorResponse('Invalid CSRF token format', 403));
    }

    next();
  } catch (err) {
    next(err);
  }
}

// Export all functions
export { requireCsrfToken };
