const { Pool } = require('pg');
const fs = require('fs').promises;
const path = require('path');

class AuthDatabaseSeeder {
  constructor() {
    this.pool = new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 5432,
      database: process.env.DB_NAME || 'aioutlet_auth',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'password',
    });
  }

  async runMigrations() {
    console.log('Running auth service migrations...');

    const migrationFiles = ['001_create_auth_tables.sql', '002_add_oauth_support.sql'];

    for (const file of migrationFiles) {
      const migrationPath = path.join(__dirname, '..', 'migrations', file);
      const migration = await fs.readFile(migrationPath, 'utf8');

      console.log(`Running migration: ${file}`);
      await this.pool.query(migration);
    }
  }

  async seedData() {
    console.log('Seeding auth service data...');

    try {
      // Clear existing data
      await this.clearData();

      // Seed OAuth providers first
      await this.seedOAuthProviders();

      // Seed auth users
      await this.seedAuthUsers();

      // Seed user OAuth connections
      await this.seedUserOAuth();

      console.log('Auth service data seeding completed successfully!');
    } catch (error) {
      console.error('Error seeding auth data:', error);
      throw error;
    }
  }

  async clearData() {
    console.log('Clearing existing auth data...');

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
    }
  }

  async seedOAuthProviders() {
    const providersPath = path.join(__dirname, '..', 'seeds', 'oauth_providers.json');
    const providers = JSON.parse(await fs.readFile(providersPath, 'utf8'));

    for (const provider of providers) {
      await this.pool.query(
        `
                INSERT INTO auth.oauth_providers (
                    id, provider_name, client_id, client_secret,
                    authorization_url, token_url, user_info_url,
                    scope, is_active, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            `,
        [
          provider.id,
          provider.provider_name,
          provider.client_id,
          provider.client_secret,
          provider.authorization_url,
          provider.token_url,
          provider.user_info_url,
          provider.scope,
          provider.is_active,
          provider.created_at,
          provider.updated_at,
        ]
      );
    }
    console.log(`Seeded ${providers.length} OAuth providers`);
  }

  async seedAuthUsers() {
    const usersPath = path.join(__dirname, '..', 'seeds', 'auth_users.json');
    const users = JSON.parse(await fs.readFile(usersPath, 'utf8'));

    for (const user of users) {
      await this.pool.query(
        `
                INSERT INTO auth.users (
                    id, user_id, email, password_hash, salt,
                    is_verified, is_active, failed_login_attempts,
                    locked_until, password_reset_token, password_reset_expires,
                    verification_token, verification_expires, two_factor_enabled,
                    two_factor_secret, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            `,
        [
          user.id,
          user.user_id,
          user.email,
          user.password_hash,
          user.salt,
          user.is_verified,
          user.is_active,
          user.failed_login_attempts,
          user.locked_until,
          user.password_reset_token,
          user.password_reset_expires,
          user.verification_token,
          user.verification_expires,
          user.two_factor_enabled,
          user.two_factor_secret,
          user.created_at,
          user.updated_at,
        ]
      );
    }
    console.log(`Seeded ${users.length} auth users`);
  }

  async seedUserOAuth() {
    const oauthPath = path.join(__dirname, '..', 'seeds', 'user_oauth.json');
    const connections = JSON.parse(await fs.readFile(oauthPath, 'utf8'));

    for (const connection of connections) {
      await this.pool.query(
        `
                INSERT INTO auth.user_oauth (
                    id, user_id, provider_id, provider_user_id,
                    access_token, refresh_token, expires_at,
                    created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            `,
        [
          connection.id,
          connection.user_id,
          connection.provider_id,
          connection.provider_user_id,
          connection.access_token,
          connection.refresh_token,
          connection.expires_at,
          connection.created_at,
          connection.updated_at,
        ]
      );
    }
    console.log(`Seeded ${connections.length} OAuth connections`);
  }

  async close() {
    await this.pool.end();
  }
}

// Run seeder if called directly
if (require.main === module) {
  const seeder = new AuthDatabaseSeeder();

  seeder
    .runMigrations()
    .then(() => seeder.seedData())
    .then(() => {
      console.log('Auth database setup completed!');
      return seeder.close();
    })
    .catch((error) => {
      console.error('Auth database setup failed:', error);
      return seeder.close().then(() => process.exit(1));
    });
}

module.exports = AuthDatabaseSeeder;
