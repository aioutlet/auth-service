import dotenv from 'dotenv';
dotenv.config({ quiet: true });

async function testImports() {
  try {
    console.log('Testing validators/config.validator.js...');
    await import('./src/validators/config.validator.js');
    console.log('✓ validators/config.validator.js OK');

    console.log('Testing core/config.js...');
    await import('./src/core/config.js');
    console.log('✓ core/config.js OK');

    console.log('Testing core/logger.js...');
    await import('./src/core/logger.js');
    console.log('✓ core/logger.js OK');

    console.log('Testing routes/auth.routes.js...');
    await import('./src/routes/auth.routes.js');
    console.log('✓ routes/auth.routes.js OK');

    console.log('Testing routes/home.routes.js...');
    await import('./src/routes/home.routes.js');
    console.log('✓ routes/home.routes.js OK');

    console.log('Testing routes/operational.routes.js...');
    await import('./src/routes/operational.routes.js');
    console.log('✓ routes/operational.routes.js OK');

    console.log('Testing middlewares/traceContext.middleware.js...');
    await import('./src/middlewares/traceContext.middleware.js');
    console.log('✓ middlewares/traceContext.middleware.js OK');

    console.log('Testing middlewares/errorHandler.middleware.js...');
    await import('./src/middlewares/errorHandler.middleware.js');
    console.log('✓ middlewares/errorHandler.middleware.js OK');

    console.log('Testing app.js...');
    await import('./src/app.js');
    console.log('✓ app.js OK');

    console.log('\nAll imports successful!');
  } catch (error) {
    console.error('\n❌ Error importing module:');
    console.error('Message:', error.message);
    console.error('Stack:', error.stack);
    process.exit(1);
  }
}

testImports();
