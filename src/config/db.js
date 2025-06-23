import mongoose from 'mongoose';
import 'colors'; // Import colors for colored console output
import logger from '../utils/logger.js';

const connectDB = async () => {
  try {
    const {
      MONGODB_CONNECTION_SCHEME = '',
      MONGODB_HOST = '',
      MONGODB_PORT = '',
      MONGODB_USERNAME = '',
      MONGODB_PASSWORD = '',
      MONGODB_DB_NAME = '',
      MONGODB_DB_PARAMS = '',
    } = process.env;

    // Log environment variables for debugging
    logger.info('Environment variables:', {
      MONGODB_CONNECTION_SCHEME,
      MONGODB_HOST,
      MONGODB_PORT,
      MONGODB_USERNAME,
      MONGODB_PASSWORD,
      MONGODB_DB_NAME,
      MONGODB_DB_PARAMS,
    });

    if (!MONGODB_HOST || !MONGODB_DB_NAME) {
      throw new Error('MONGODB_HOST and MONGODB_DB_NAME must be defined');
    }

    let mongodb_uri = `${MONGODB_CONNECTION_SCHEME}://`;

    if (MONGODB_USERNAME) {
      mongodb_uri += `${MONGODB_USERNAME}:${MONGODB_PASSWORD}@`;
    }

    mongodb_uri += `${MONGODB_HOST}:${MONGODB_PORT}/${MONGODB_DB_NAME}`;

    if (MONGODB_DB_PARAMS) {
      mongodb_uri += `?${MONGODB_DB_PARAMS}`;
    }

    logger.info(`Connecting to MongoDB: ${mongodb_uri}`);
    global.mongoUrl = mongodb_uri;
    await mongoose.connect(mongodb_uri);
    logger.info('Connected to MongoDB');
  } catch (error) {
    logger.error(`Error occurred while connecting to MongoDB: ${error.message}`);
    process.exit(1);
  }
};

export default connectDB;
