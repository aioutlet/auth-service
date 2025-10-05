import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import connectDB from './config/db.js';
import authRoutes from './routes/auth.routes.js';
import homeRoutes from './routes/home.routes.js';
import cookieParser from 'cookie-parser';
import logger from './utils/logger.js';
import { errorHandler } from './middlewares/errorHandler.js';
import { correlationIdMiddleware } from './middlewares/correlationId.middleware.js';
import { createRateLimiter } from './middlewares/rateLimit.middleware.js';
import { health, readiness, liveness, metrics } from './controllers/operational.controller.js';

const app = express();

// Middleware
app.use(correlationIdMiddleware); // Add correlation ID middleware first
app.use(createRateLimiter()); // Apply general rate limiting to all endpoints
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(morgan('dev'));
app.use(cookieParser());

// Connect to MongoDB
await connectDB();

// Routes
app.use('/api/home', homeRoutes);
app.use('/api/auth', authRoutes);

// Operational endpoints (for monitoring, load balancers, K8s probes)
app.get('/health', health); // Main health check
app.get('/health/ready', readiness); // Readiness probe
app.get('/health/live', liveness); // Liveness probe
app.get('/metrics', metrics); // Basic metrics

// Error handler
app.use(errorHandler);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => logger.info(`Auth service running on port ${PORT}`));
