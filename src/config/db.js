import mongoose from 'mongoose';
import logger from '../observability/logging/index.js';

const connectDB = async () => {
  try {
    const mongodb_uri = process.env.MONGODB_URI;

    if (!mongodb_uri) {
      throw new Error('MONGODB_URI must be defined in environment variables');
    }

    // Validate URI format
    try {
      new URL(mongodb_uri);
    } catch (urlError) {
      throw new Error(`Invalid MONGODB_URI format: ${urlError.message}`);
    }

    global.mongoUrl = mongodb_uri;
    await mongoose.connect(mongodb_uri);
    logger.info('Connected to MongoDB');
  } catch (error) {
    logger.error(`Error occurred while connecting to MongoDB: ${error.message}`);
    process.exit(1);
  }
};

export default connectDB;
