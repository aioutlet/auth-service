import express from 'express';
import * as mfaController from '../controllers/mfa.controller.js';
import authMiddleware from '../middlewares/auth.middleware.js';
import mfaMiddleware from '../middlewares/mfa.middleware.js';

const router = express.Router();

// MFA endpoints (placeholders)
router.post('/mfa/enable', authMiddleware, mfaController.enableMFA);
router.post('/mfa/verify', authMiddleware, mfaMiddleware, mfaController.verifyMFA);
router.post('/mfa/disable', authMiddleware, mfaController.disableMFA);

export default router;
