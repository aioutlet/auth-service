import express from 'express';
import * as accountLinkController from '../controllers/accountLink.controller.js';
import authMiddleware from '../middlewares/auth.middleware.js';
const router = express.Router();

// Account linking endpoints (placeholders)
router.post('/link', authMiddleware, accountLinkController.linkAccount);
router.post('/unlink', authMiddleware, accountLinkController.unlinkAccount);

export default router;
