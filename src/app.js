import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import authRoutes from './routes/auth.routes.js';
import homeRoutes from './routes/home.routes.js';
import operationalRoutes from './routes/operational.routes.js';
import cookieParser from 'cookie-parser';
import logger from './observability/logging/index.js';
import { errorHandler } from './middlewares/errorHandler.js';
import { correlationIdMiddleware } from './middlewares/correlationId.middleware.js';
import { getConfig, getConfigArray } from './validators/config.validator.js';

const app = express();

// Middleware
app.use(correlationIdMiddleware); // Add correlation ID middleware first
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS configuration
const corsOrigins = getConfigArray('CORS_ORIGINS');
app.use(
  cors({
    origin: corsOrigins.includes('*') ? true : corsOrigins,
    credentials: true,
  })
);

app.use(morgan('dev'));
app.use(cookieParser());

// Routes
app.use('/api/home', homeRoutes);
app.use('/api/auth', authRoutes);
app.use('/', operationalRoutes);

// Error handler
app.use(errorHandler);

const PORT = getConfig('PORT') || 3001;
const HOST = process.env.HOST || '0.0.0.0';

const server = app.listen(PORT, HOST, () => {
  logger.info(`✅ Auth Service started successfully`, {
    host: HOST,
    port: PORT,
    environment: getConfig('NODE_ENV'),
    serviceName: getConfig('SERVICE_NAME'),
    nodeVersion: process.version,
    corsOrigins: corsOrigins,
  });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});
