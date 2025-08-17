import express from 'express';
import * as accountLinkController from '../controllers/accountLink.controller.js';
import authMiddleware from '../middlewares/auth.middleware.js';
import { authRateLimit } from '../middlewares/rateLimit.middleware.js';

const router = express.Router();

// Account linking endpoints - Apply authentication rate limiting
router.post('/link', authRateLimit, authMiddleware, accountLinkController.linkAccount);
router.post('/unlink', authRateLimit, authMiddleware, accountLinkController.unlinkAccount);

export default router;
