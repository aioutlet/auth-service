import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import { validateConfig } from './validators/config.validator.js';
import config from './core/config.js';
import logger from './core/logger.js';
import authRoutes from './routes/auth.routes.js';
import homeRoutes from './routes/home.routes.js';
import operationalRoutes from './routes/operational.routes.js';
import { traceContextMiddleware } from './middlewares/traceContext.middleware.js';
import { errorHandler } from './middlewares/errorHandler.middleware.js';

// Validate all required environment variables exist
validateConfig();

const app = express();

// Trust proxy for accurate IP address extraction
app.set('trust proxy', true);

// Middleware
app.use(traceContextMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS configuration
app.use(
  cors({
    origin: config.cors.origins.includes('*') ? true : config.cors.origins,
    credentials: true,
  })
);

// Routes
app.use('/', operationalRoutes);
app.use('/api/home', homeRoutes);
app.use('/api/auth', authRoutes);

// Centralized error handler (must be last)
app.use(errorHandler);

// Start server
app.listen(config.service.port, config.service.host, () => {
  const { host, port, nodeEnv, name, version } = config.service;
  logger.info(`Auth service running on ${host}:${port} in ${nodeEnv} mode`, {
    service: name,
    version,
  });
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
