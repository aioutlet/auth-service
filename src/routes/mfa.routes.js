import express from 'express';
import * as mfaController from '../controllers/mfa.controller.js';
import authMiddleware from '../middlewares/auth.middleware.js';
import mfaMiddleware from '../middlewares/mfa.middleware.js';
import { authRateLimit } from '../middlewares/rateLimit.middleware.js';

const router = express.Router();

// MFA endpoints - Apply authentication rate limiting since these are sensitive operations
router.post('/mfa/enable', authRateLimit, authMiddleware, mfaController.enableMFA);
router.post('/mfa/verify', authRateLimit, authMiddleware, mfaMiddleware, mfaController.verifyMFA);
router.post('/mfa/disable', authRateLimit, authMiddleware, mfaController.disableMFA);

export default router;
