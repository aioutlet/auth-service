import express from 'express';
import passport from 'passport';
import * as authController from '../controllers/auth.controller.js';
import authMiddleware, { authorizeRoles } from '../middlewares/auth.middleware.js';
import { requireCsrfToken } from '../middlewares/csrf.middleware.js'; // add import

const router = express.Router();

// Local login
router.post('/login', authController.login);
router.post('/logout', authMiddleware, requireCsrfToken, authController.logout);
router.post('/token/refresh', authController.refreshToken);

router.post('/password/forgot', authController.forgotPassword);
router.post('/password/reset', authController.resetPassword);
router.post('/password/change', authMiddleware, authController.changePassword);

router.get('/email/verify', authController.verifyEmail);
router.post('/email/resend', authController.resendVerificationEmail);

router.get('/me', authMiddleware, authorizeRoles('customer', 'admin'), authController.me);
router.post('/register', authController.register);
router.route('/reactivate').post(authController.requestAccountReactivation).get(authController.reactivateAccount);
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
