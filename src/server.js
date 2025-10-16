import dotenv from 'dotenv';
dotenv.config({ quiet: true });

// Industry-standard initialization pattern:
// 1. Load environment variables
// 2. Validate configuration (blocking - must pass)
// 3. Check dependency health (non-blocking - log only)
// 4. Initialize observability modules (logger, tracing)
// 5. Start application

import validateConfig from './validators/config.validator.js';
import { checkDependencyHealth, getDependencies } from './utils/dependencyHealthChecker.js';

async function startServer() {
  try {
    // 🔧 STEP 1: Validate configuration (BLOCKING - must pass)
    console.log('🔧 Step 1: Validating configuration...');
    validateConfig();

    // 🔍 STEP 2: Check dependency health (NON-BLOCKING - log only)
    console.log('🔍 Step 2: Checking dependency health...');
    const dependencies = getDependencies();
    const dependencyCount = Object.keys(dependencies).length;

    if (dependencyCount > 0) {
      console.log(`[DEPS] Found ${dependencyCount} dependencies to check`);
      // Don't await - let it run in background
      checkDependencyHealth(dependencies).catch((error) =>
        console.log(`[DEPS] ⚠️ Dependency health check failed: ${error.message}`)
      );
    } else {
      console.log('[DEPS] 📝 No dependencies configured for health checking');
    }

    // 📊 STEP 3: Initialize observability
    console.log('📊 Step 3: Initializing observability...');
    await import('./observability/logging/logger.js');
    await import('./observability/tracing/setup.js');

    // 🚀 STEP 4: Start the application
    console.log('🚀 Step 4: Starting auth service...');
    await import('./app.js');
  } catch (error) {
    console.error('❌ Failed to start auth service:', error.message);
    process.exit(1);
  }
}

startServer();
