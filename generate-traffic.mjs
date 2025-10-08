#!/usr/bin/env node

/**
 * Test script to generate traffic to Message Broker Service
 * Publishes 10 test messages to verify integration
 */

import axios from 'axios';

const MESSAGE_BROKER_URL = process.env.MESSAGE_BROKER_SERVICE_URL || 'http://localhost:4000';
const API_KEY = process.env.MESSAGE_BROKER_API_KEY || 'your-secret-api-key-here';
const NUM_MESSAGES = 15;

const client = axios.create({
  baseURL: MESSAGE_BROKER_URL,
  timeout: 5000,
  headers: {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${API_KEY}`,
    'X-Service-Name': 'test-traffic-generator',
  },
});

// Test events to publish
const testEvents = [
  {
    topic: 'auth.login',
    data: {
      userId: '507f1f77bcf86cd799439011',
      email: 'user1@test.com',
      ipAddress: '192.168.1.100',
      success: true,
    },
  },
  {
    topic: 'auth.logout',
    data: {
      userId: '507f1f77bcf86cd799439012',
      email: 'user2@test.com',
      sessionId: '507f1f77bcf86cd799439013',
    },
  },
  {
    topic: 'auth.registered',
    data: {
      userId: '507f1f77bcf86cd799439014',
      email: 'newuser@test.com',
      role: 'customer',
    },
  },
  {
    topic: 'auth.password.changed',
    data: {
      userId: '507f1f77bcf86cd799439015',
      email: 'user3@test.com',
      changedAt: new Date().toISOString(),
    },
  },
  {
    topic: 'auth.email.verified',
    data: {
      userId: '507f1f77bcf86cd799439016',
      email: 'user4@test.com',
      verifiedAt: new Date().toISOString(),
    },
  },
];

async function publishMessage(topic, data, index) {
  try {
    const payload = {
      topic,
      data: {
        ...data,
        messageNumber: index + 1,
        timestamp: new Date().toISOString(),
        testRun: true,
      },
    };

    const response = await client.post('/api/v1/publish', payload);

    if (response.data && response.data.success) {
      console.log(`✅ [${index + 1}/${NUM_MESSAGES}] Published to ${topic} - Message ID: ${response.data.messageId}`);
      return true;
    } else {
      console.error(`❌ [${index + 1}/${NUM_MESSAGES}] Failed to publish to ${topic}`);
      return false;
    }
  } catch (error) {
    console.error(`❌ [${index + 1}/${NUM_MESSAGES}] Error publishing to ${topic}:`, error.message);
    return false;
  }
}

async function generateTraffic() {
  console.log('🚀 Starting Message Broker Traffic Generator\n');
  console.log(`Target: ${MESSAGE_BROKER_URL}`);
  console.log(`Messages to publish: ${NUM_MESSAGES}\n`);

  // Check if service is available
  try {
    const healthResponse = await client.get('/api/v1/health');
    console.log(`✅ Message Broker Service is healthy`);
    console.log(`   Broker Type: ${healthResponse.data.broker?.broker_type}`);
    console.log(`   Connected: ${healthResponse.data.broker?.connected}\n`);
  } catch (error) {
    console.error('❌ Message Broker Service is not available:', error.message);
    process.exit(1);
  }

  // Get initial stats
  let initialStats;
  try {
    const statsResponse = await client.get('/api/v1/stats');
    initialStats = statsResponse.data.data;
    console.log(`📊 Initial Stats:`);
    console.log(`   Messages Published: ${initialStats.messages_published}`);
    console.log(`   Messages Failed: ${initialStats.messages_failed}\n`);
  } catch (error) {
    console.error('⚠️  Could not get initial stats');
  }

  console.log('📨 Publishing messages...\n');

  // Publish messages
  let successCount = 0;
  let failCount = 0;

  for (let i = 0; i < NUM_MESSAGES; i++) {
    // Rotate through different event types
    const eventIndex = i % testEvents.length;
    const event = testEvents[eventIndex];

    const success = await publishMessage(event.topic, event.data, i);

    if (success) {
      successCount++;
    } else {
      failCount++;
    }

    // Small delay between messages
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  console.log('\n📊 Publishing Complete!\n');
  console.log(`✅ Successful: ${successCount}`);
  console.log(`❌ Failed: ${failCount}`);
  console.log(`📈 Success Rate: ${((successCount / NUM_MESSAGES) * 100).toFixed(1)}%\n`);

  // Get final stats
  try {
    const statsResponse = await client.get('/api/v1/stats');
    const finalStats = statsResponse.data.data;
    const newMessages = finalStats.messages_published - (initialStats?.messages_published || 0);

    console.log(`📊 Final Stats:`);
    console.log(`   Messages Published: ${finalStats.messages_published} (+${newMessages})`);
    console.log(`   Messages Failed: ${finalStats.messages_failed}`);
    console.log(`   Last Published: ${finalStats.last_published_at}\n`);
  } catch (error) {
    console.error('⚠️  Could not get final stats');
  }

  console.log('🎉 Traffic generation complete!');
  console.log('\n💡 View messages in RabbitMQ Management UI:');
  console.log('   URL: http://localhost:15672');
  console.log('   Username: admin');
  console.log('   Password: admin');
  console.log('   Navigate to: Exchanges → aioutlet.events → Publish message\n');
}

// Run the traffic generator
generateTraffic()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('💥 Fatal error:', error);
    process.exit(1);
  });
