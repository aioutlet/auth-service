import express from 'express';
import passport from 'passport';
import * as authController from '../controllers/auth.controller.js';
import refreshTokenMiddleware from '../middlewares/refreshToken.middleware.js';
import authMiddleware, { authorizeRoles } from '../middlewares/auth.middleware.js';
import { requireCsrfToken } from '../middlewares/csrf.middleware.js'; // add import

const router = express.Router();

// Local login
router.post('/login', authController.login);
// Protected logout with CSRF protection
router.post('/logout', authMiddleware, requireCsrfToken, authController.logout);
// Token refresh
router.post('/token/refresh', refreshTokenMiddleware, authController.refreshToken);
// Unprotected forgot/reset password
router.post('/password/forgot', authController.forgotPassword);
router.post('/password/reset', authController.resetPassword);
// Protected change password (renamed to password/change)
router.post('/password/change', authMiddleware, authController.changePassword);
// Email verification
router.get('/email/verify', authController.verifyEmail);

// Social login
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { session: false }), authController.socialCallback);
router.get('/facebook', passport.authenticate('facebook', { scope: ['email'] }));
router.get('/facebook/callback', passport.authenticate('facebook', { session: false }), authController.socialCallback);
router.get('/twitter', passport.authenticate('twitter'));
router.get('/twitter/callback', passport.authenticate('twitter', { session: false }), authController.socialCallback);

// Protect /auth/me for 'user' and 'admin' roles
router.get('/me', authMiddleware, authorizeRoles('user', 'admin'), authController.me);
// Registration endpoint
router.post('/register', authController.register);
// Account reactivation (POST to request, GET to activate)
router.route('/reactivate').post(authController.requestAccountReactivation).get(authController.reactivateAccount);
// Self-service account deletion
router.delete('/account', authMiddleware, authController.deleteAccount);
// Admin: delete any user by ID
router.delete('/users/:id', authMiddleware, authorizeRoles('admin'), authController.adminDeleteUser);

export default router;
