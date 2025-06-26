import express from 'express';
import { getVersion, health, getWelcomeMessage } from '../controllers/home.controller.js';

const router = express.Router();

// Home route
router.get('/', getWelcomeMessage);
router.get('/health', health);
router.get('/version', getVersion);

export default router;
