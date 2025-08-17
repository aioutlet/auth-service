import express from 'express';
import passport from 'passport';
import * as authController from '../controllers/auth.controller.js';
import authMiddleware, { authorizeRoles } from '../middlewares/auth.middleware.js';
import { requireCsrfToken } from '../middlewares/csrf.middleware.js'; // add import
import {
  authRateLimit,
  passwordRateLimit,
  registrationRateLimit,
  emailActionsRateLimit,
  tokenRefreshRateLimit,
  authSlowDown,
} from '../middlewares/rateLimit.middleware.js';

const router = express.Router();

// Local login - Apply strict rate limiting with progressive delay
router.post('/login', authSlowDown, authRateLimit, authController.login);
router.post('/logout', authMiddleware, requireCsrfToken, authController.logout);
router.post('/token/refresh', tokenRefreshRateLimit, authController.refreshToken);

// Password operations - Apply strict rate limiting
router.post('/password/forgot', passwordRateLimit, authController.forgotPassword);
router.post('/password/reset', passwordRateLimit, authController.resetPassword);
router.post('/password/change', passwordRateLimit, authMiddleware, authController.changePassword);

// Email operations - Apply moderate rate limiting
router.get('/email/verify', emailActionsRateLimit, authController.verifyEmail);
router.post('/email/resend', emailActionsRateLimit, authController.resendVerificationEmail);

router.get('/me', authMiddleware, authorizeRoles('customer', 'admin'), authController.me);
router.post('/register', registrationRateLimit, authController.register);
router
  .route('/reactivate')
  .post(emailActionsRateLimit, authController.requestAccountReactivation)
  .get(emailActionsRateLimit, authController.reactivateAccount);
router.delete('/account', authMiddleware, authController.deleteAccount);
router.delete('/users/:id', authMiddleware, authorizeRoles('admin'), authController.adminDeleteUser);

// Social login
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { session: false }), authController.socialCallback);
router.get('/facebook', passport.authenticate('facebook', { scope: ['email'] }));
router.get('/facebook/callback', passport.authenticate('facebook', { session: false }), authController.socialCallback);
router.get('/twitter', passport.authenticate('twitter'));
router.get('/twitter/callback', passport.authenticate('twitter', { session: false }), authController.socialCallback);

export default router;
