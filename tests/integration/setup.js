// Integration test setup
// Handles MongoDB Memory Server and RabbitMQ Testcontainer lifecycle

import { MongoMemoryServer } from 'mongodb-memory-server';
import { GenericContainer } from 'testcontainers';
import mongoose from 'mongoose';
import amqp from 'amqplib';

let mongoServer;
let rabbitmqContainer;
let rabbitmqConnection;
let rabbitmqChannel;

// Global setup - runs once before all tests
export async function setupTestEnvironment() {
  try {
    console.log('🔧 Setting up test environment...');

    // Start MongoDB in-memory server
    console.log('📦 Starting MongoDB Memory Server...');
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    process.env.MONGODB_URI = mongoUri;

    await mongoose.connect(mongoUri);
    console.log('✅ MongoDB Memory Server ready');

    // Start RabbitMQ container
    console.log('🐰 Starting RabbitMQ container...');
    rabbitmqContainer = await new GenericContainer('rabbitmq:3-management')
      .withExposedPorts(5672, 15672)
      .withStartupTimeout(120000) // 2 minutes timeout
      .start();

    const rabbitmqPort = rabbitmqContainer.getMappedPort(5672);
    const rabbitmqUrl = `amqp://guest:guest@localhost:${rabbitmqPort}`;
    process.env.RABBITMQ_URL = rabbitmqUrl;

    // Connect to RabbitMQ
    rabbitmqConnection = await amqp.connect(rabbitmqUrl);
    rabbitmqChannel = await rabbitmqConnection.createChannel();

    // Setup test exchange and queue
    await rabbitmqChannel.assertExchange('aioutlet.events', 'topic', { durable: true });
    await rabbitmqChannel.assertQueue('test-notification-queue', { exclusive: false, durable: false });
    await rabbitmqChannel.bindQueue('test-notification-queue', 'aioutlet.events', 'auth.*');

    console.log('✅ RabbitMQ container ready');
    console.log('🎉 Test environment ready!\n');

    return {
      mongoServer,
      rabbitmqContainer,
      rabbitmqConnection,
      rabbitmqChannel,
      mongoUri,
      rabbitmqUrl,
    };
  } catch (error) {
    console.error('❌ Failed to setup test environment:', error);
    throw error;
  }
}

// Global teardown - runs once after all tests
export async function teardownTestEnvironment() {
  try {
    console.log('\n🧹 Cleaning up test environment...');

    if (mongoose.connection.readyState === 1) {
      await mongoose.disconnect();
      console.log('✅ Disconnected from MongoDB');
    }

    if (mongoServer) {
      await mongoServer.stop();
      console.log('✅ MongoDB Memory Server stopped');
    }

    if (rabbitmqChannel) {
      await rabbitmqChannel.close();
      console.log('✅ RabbitMQ channel closed');
    }

    if (rabbitmqConnection) {
      await rabbitmqConnection.close();
      console.log('✅ RabbitMQ connection closed');
    }

    if (rabbitmqContainer) {
      await rabbitmqContainer.stop();
      console.log('✅ RabbitMQ container stopped');
    }

    console.log('🎉 Test environment cleaned up!\n');
  } catch (error) {
    console.error('❌ Error during cleanup:', error);
  }
}

// Helper to clear database between tests
export async function clearDatabase() {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany({});
  }
}

// Helper to consume messages from test queue
export async function consumeTestMessage(timeout = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Timeout waiting for message'));
    }, timeout);

    rabbitmqChannel.consume(
      'test-notification-queue',
      (msg) => {
        if (msg) {
          clearTimeout(timer);
          const content = JSON.parse(msg.content.toString());
          rabbitmqChannel.ack(msg);
          resolve(content);
        }
      },
      { noAck: false }
    );
  });
}

// Helper to purge test queue
export async function purgeTestQueue() {
  if (rabbitmqChannel) {
    await rabbitmqChannel.purgeQueue('test-notification-queue');
  }
}

// Export instances for use in tests
export function getTestInstances() {
  return {
    mongoServer,
    rabbitmqContainer,
    rabbitmqConnection,
    rabbitmqChannel,
  };
}
