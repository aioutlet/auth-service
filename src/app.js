import dotenv from 'dotenv';
dotenv.config({ quiet: true });

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import validateConfig, { getConfig, getConfigArray } from './validators/config.validator.js';
import logger from './core/logger.js';
import authRoutes from './routes/auth.routes.js';
import homeRoutes from './routes/home.routes.js';
import operationalRoutes from './routes/operational.routes.js';
import { correlationIdMiddleware } from './middlewares/correlationId.middleware.js';

validateConfig();

const app = express();

// Trust proxy for accurate IP address extraction
app.set('trust proxy', true);

// Middleware
app.use(correlationIdMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS configuration
const corsOrigins = getConfigArray('CORS_ORIGINS');
app.use(
  cors({
    origin: corsOrigins.includes('*') ? true : corsOrigins,
    credentials: true,
  })
);

// Routes
app.use('/', operationalRoutes);
app.use('/api/home', homeRoutes);
app.use('/api/auth', authRoutes);

// Centralized error handler for consistent error responses
app.use((err, req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  const correlationId = req.correlationId || 'no-correlation';

  // Log the error with full details
  logger.error(`Request failed: ${req.method} ${req.originalUrl} - ${err.message || 'Unknown error'}`, req, {
    correlationId,
    method: req.method,
    url: req.originalUrl,
    status,
    errorCode: err.code || 'INTERNAL_ERROR',
    errorMessage: err.message,
    errorStack: err.stack,
    userId: req.user?.id,
  });

  res.status(status).json({
    error: {
      code: err.code || 'INTERNAL_ERROR',
      message: err.message || 'Internal server error',
      details: err.details || null,
      traceId: req.traceId || null,
    },
  });
});

// Start server
const PORT = getConfig('PORT') || 3001;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
  logger.info(`Auth service running on ${HOST}:${PORT} in ${getConfig('NODE_ENV')} mode`, {
    service: getConfig('NAME'),
    version: getConfig('VERSION'),
  });
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
