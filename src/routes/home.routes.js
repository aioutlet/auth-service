import express from 'express';

const router = express.Router();

// Home route
router.get('/', (req, res) => {
  res.json({ message: 'Welcome to the Auth Service API' });
});

// Health check route
router.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

export default router;
