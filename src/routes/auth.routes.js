import express from 'express';
import * as authController from '../controllers/auth.controller.js';
import { authMiddleware, authorizeRoles } from '../middlewares/auth.middleware.js';

const router = express.Router();

// Local login
router.post('/login', authController.login);
router.post('/logout', authMiddleware, authController.logout);

// Password operations
router.post('/password/forgot', authController.forgotPassword);
router.post('/password/reset', authController.resetPassword);
router.post('/password/change', authMiddleware, authController.changePassword);

// Email operations
router.get('/email/verify', authController.verifyEmail);
router.post('/email/resend', authController.resendVerificationEmail);

// Token verification
router.get('/verify', authMiddleware, authController.verify);
router.get('/me', authMiddleware, authorizeRoles('customer', 'admin'), authController.me);
router.post('/register', authController.register);
router.route('/reactivate').post(authController.requestAccountReactivation).get(authController.reactivateAccount);
router.delete('/account', authMiddleware, authController.deleteAccount);
router.delete('/users/:id', authMiddleware, authorizeRoles('admin'), authController.adminDeleteUser);

export default router;
