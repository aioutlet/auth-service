import dotenv from 'dotenv';
dotenv.config({ quiet: true });

// Industry-standard initialization pattern:
// 1. Load environment variables
// 2. Validate configuration (uses console.log - standard for bootstrap)
// 3. Initialize observability modules (logger, tracing)
// 4. Start application

import validateConfig from './validators/config.validator.js';
validateConfig();

import './observability/logging/logger.js';
import './observability/tracing/setup.js';

await import('./app.js');
