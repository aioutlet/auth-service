import express from 'express';
import { info, version } from '../controllers/home.controller.js';

const router = express.Router();

// Home route
router.get('/', info);
router.get('/version', version);

export default router;
