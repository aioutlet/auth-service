import CsrfToken from '../models/csrfToken.model.js';
import mongoose from 'mongoose';

export async function requireCsrfToken(req, res, next) {
  try {
    // Only check for browser clients (cookie-based JWT)
    const cookieToken = req.cookies['csrfToken'];
    const headerToken = req.get('X-CSRF-Token');
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
    // Validate token in DB (optional, for advanced security)
    let userId = req.user?._id || req.user?.id;
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      const csrfDoc = await CsrfToken.findOne({ token: cookieToken, user: userId });
      if (!csrfDoc || csrfDoc.expiresAt < new Date()) {
        return res.status(403).json({ error: 'Expired or invalid CSRF token' });
      }
    }
    next();
  } catch (err) {
    next(err);
  }
}
