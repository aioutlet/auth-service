import mongoose from 'mongoose';
import logger from '../observability/logging/index.js';

const connectDB = async () => {
  try {
    // Construct MongoDB URI from environment variables
    const mongoHost = process.env.MONGODB_HOST || 'localhost';
    const mongoPort = process.env.MONGODB_PORT || '27017';
    const mongoUsername = process.env.MONGO_INITDB_ROOT_USERNAME;
    const mongoPassword = process.env.MONGO_INITDB_ROOT_PASSWORD;
    const mongoDatabase = process.env.MONGO_INITDB_DATABASE;
    const mongoAuthSource = process.env.MONGODB_AUTH_SOURCE || 'admin';

    let mongodb_uri;
    if (mongoUsername && mongoPassword) {
      mongodb_uri = `mongodb://${mongoUsername}:${mongoPassword}@${mongoHost}:${mongoPort}/${mongoDatabase}?authSource=${mongoAuthSource}`;
    } else {
      mongodb_uri = `mongodb://${mongoHost}:${mongoPort}/${mongoDatabase}`;
    }

    logger.info(`Connecting to MongoDB: ${mongoHost}:${mongoPort}/${mongoDatabase}`);

    // Set global promise library
    mongoose.Promise = global.Promise;

    // Connect to MongoDB with connection options
    const conn = await mongoose.connect(mongodb_uri, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });

    logger.info(`MongoDB connected: ${conn.connection.host}:${conn.connection.port}/${conn.connection.name}`);

    // Handle connection events
    mongoose.connection.on('error', (err) => {
      logger.error(`MongoDB connection error: ${err.message}`);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      try {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed due to application termination');
        process.exit(0);
      } catch (error) {
        logger.error(`Error during MongoDB disconnection: ${error.message}`);
        process.exit(1);
      }
    });

    return conn;
  } catch (error) {
    logger.error(`Error occurred while connecting to MongoDB: ${error.message}`);
    throw error;
  }
};

export default connectDB;
