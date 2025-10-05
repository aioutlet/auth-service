import ErrorResponse from '../utils/ErrorResponse.js';
import CsrfToken from '../models/csrfToken.model.js';
import mongoose from 'mongoose';

async function requireCsrfToken(req, res, next) {
  try {
    // Only check for browser clients (cookie-based JWT)
    const cookieToken = req.cookies['csrfToken'];
    const headerToken = req.get('X-CSRF-Token');
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return next(new ErrorResponse('Invalid or missing CSRF token', 403));
    }
    // Validate token in DB (optional, for advanced security)
    const userId = req.user?._id || req.user?.id;
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      const csrfDoc = await CsrfToken.findOne({ token: cookieToken, user: userId });
      if (!csrfDoc || csrfDoc.expiresAt < new Date()) {
        return next(new ErrorResponse('Expired or invalid CSRF token', 403));
      }
    }
    next();
  } catch (err) {
    next(err);
  }
}

// Export all functions
export { requireCsrfToken };
