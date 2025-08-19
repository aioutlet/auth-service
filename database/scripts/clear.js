const { Pool } = require('pg');

class AuthDatabaseCleaner {
  constructor() {
    this.pool = new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 5432,
      database: process.env.DB_NAME || 'aioutlet_auth',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'password',
    });
  }

  async clearAllData() {
    console.log('Clearing all auth service data...');

    try {
      const clearQueries = [
        'DELETE FROM auth.user_oauth;',
        'DELETE FROM auth.login_attempts;',
        'DELETE FROM auth.sessions;',
        'DELETE FROM auth.tokens;',
        'DELETE FROM auth.users;',
        'DELETE FROM auth.oauth_providers;',
      ];

      for (const query of clearQueries) {
        await this.pool.query(query);
        console.log(`Executed: ${query}`);
      }

      console.log('All auth service data cleared successfully!');
    } catch (error) {
      console.error('Error clearing auth data:', error);
      throw error;
    }
  }

  async dropAllTables() {
    console.log('Dropping all auth service tables...');

    try {
      const dropQueries = [
        'DROP TABLE IF EXISTS auth.user_oauth CASCADE;',
        'DROP TABLE IF EXISTS auth.login_attempts CASCADE;',
        'DROP TABLE IF EXISTS auth.sessions CASCADE;',
        'DROP TABLE IF EXISTS auth.tokens CASCADE;',
        'DROP TABLE IF EXISTS auth.users CASCADE;',
        'DROP TABLE IF EXISTS auth.oauth_providers CASCADE;',
        'DROP SCHEMA IF EXISTS auth CASCADE;',
      ];

      for (const query of dropQueries) {
        await this.pool.query(query);
        console.log(`Executed: ${query}`);
      }

      console.log('All auth service tables dropped successfully!');
    } catch (error) {
      console.error('Error dropping auth tables:', error);
      throw error;
    }
  }

  async close() {
    await this.pool.end();
  }
}

// Run cleaner if called directly
if (require.main === module) {
  const cleaner = new AuthDatabaseCleaner();
  const operation = process.argv[2] || 'clear';

  const runOperation = operation === 'drop' ? cleaner.dropAllTables() : cleaner.clearAllData();

  runOperation
    .then(() => {
      console.log(`Auth database ${operation} completed!`);
      return cleaner.close();
    })
    .catch((error) => {
      console.error(`Auth database ${operation} failed:`, error);
      return cleaner.close().then(() => process.exit(1));
    });
}

module.exports = AuthDatabaseCleaner;
