import express from 'express';
import passport from 'passport';
import session from 'express-session';
import cors from 'cors';
import morgan from 'morgan';
import MongoStore from 'connect-mongo';
import connectDB from './config/db.js';
import passportConfig from './config/passport.js';
import authRoutes from './routes/auth.routes.js';
import mfaRoutes from './routes/mfa.routes.js';
import accountLinkRoutes from './routes/accountLink.routes.js';
import homeRoutes from './routes/home.routes.js';
import cookieParser from 'cookie-parser';
import logger from './utils/logger.js';
import errorHandler from './middlewares/errorHandler.js';
import correlationIdMiddleware from './middlewares/correlationId.middleware.js';
import { health, readiness, liveness, metrics } from './controllers/operational.controller.js';

const app = express();

// Middleware
app.use(correlationIdMiddleware); // Add correlation ID middleware first
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(morgan('dev'));
app.use(cookieParser());

// Connect to MongoDB
await connectDB();

// Session
if (!global.mongoUrl) {
  throw new Error(
    'MongoDB URI is not set. Make sure connectDB() sets global.mongoUrl before initializing session store.'
  );
}
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: global.mongoUrl,
    }),
    cookie: { secure: false, httpOnly: true },
  })
);

// Passport config
passportConfig(passport);
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/api/home', homeRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/auth', mfaRoutes);
app.use('/api/auth', accountLinkRoutes);

// Operational endpoints (for monitoring, load balancers, K8s probes)
app.get('/health', health); // Main health check
app.get('/health/ready', readiness); // Readiness probe
app.get('/health/live', liveness); // Liveness probe
app.get('/metrics', metrics); // Basic metrics

// Error handler
app.use(errorHandler);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => logger.info(`Auth service running on port ${PORT}`));
