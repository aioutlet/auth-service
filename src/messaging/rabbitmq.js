import amqp from 'amqplib';
import dotenv from 'dotenv';

dotenv.config();

class RabbitMQService {
    constructor() {
        this.connection = null;
        this.channel = null;
        this.isConnected = false;
    }

    async connect() {
        try {
            const rabbitUrl = process.env.RABBITMQ_URL || 'amqp://admin:admin123@localhost:5672/';
            console.log('� Connecting to RabbitMQ:', rabbitUrl.replace(/\/\/.*@/, '//***@'));
            
            this.connection = await amqp.connect(rabbitUrl);
            this.channel = await this.connection.createChannel();
            
            // Setup connection error handlers
            this.connection.on('error', (err) => {
                console.error('❌ RabbitMQ connection error:', err);
                this.isConnected = false;
            });
            
            this.connection.on('close', () => {
                console.log('� RabbitMQ connection closed');
                this.isConnected = false;
            });
            
            this.isConnected = true;
            console.log('✅ Connected to RabbitMQ successfully');
            
            // Ensure exchanges exist
            await this.setupExchanges();
            
        } catch (error) {
            console.error('❌ Failed to connect to RabbitMQ:', error);
            this.isConnected = false;
            throw error;
        }
    }

    async setupExchanges() {
        try {
            // Ensure the events exchange exists
            await this.channel.assertExchange('aioutlet.events', 'topic', { durable: true });
            console.log('✅ Events exchange ready');
        } catch (error) {
            console.error('❌ Failed to setup exchanges:', error);
            throw error;
        }
    }

    async publishEvent(routingKey, eventData) {
        if (!this.isConnected || !this.channel) {
            throw new Error('RabbitMQ not connected');
        }

        try {
            const event = {
                eventId: this.generateEventId(),
                eventType: routingKey,
                timestamp: new Date().toISOString(),
                source: 'auth-service',
                data: eventData,
                metadata: {
                    correlationId: eventData.correlationId || this.generateEventId(),
                    version: '1.0'
                }
            };

            const message = Buffer.from(JSON.stringify(event));
            const published = this.channel.publish('aioutlet.events', routingKey, message, {
                persistent: true,
                timestamp: Date.now(),
                contentType: 'application/json'
            });

            if (published) {
                console.log(`� Event published: ${routingKey}`, {
                    eventId: event.eventId,
                    timestamp: event.timestamp
                });
            }

            return published;
        } catch (error) {
            console.error('❌ Failed to publish event:', error);
            throw error;
        }
    }

    async close() {
        try {
            if (this.channel) {
                await this.channel.close();
            }
            if (this.connection) {
                await this.connection.close();
            }
            this.isConnected = false;
            console.log('� RabbitMQ connection closed gracefully');
        } catch (error) {
            console.error('❌ Error closing RabbitMQ connection:', error);
        }
    }

    generateEventId() {
        return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    isHealthy() {
        return this.isConnected && this.channel && !this.channel.closing;
    }
}

// Create singleton instance
const rabbitMQService = new RabbitMQService();

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('� Received SIGINT, closing RabbitMQ connection...');
    await rabbitMQService.close();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('� Received SIGTERM, closing RabbitMQ connection...');
    await rabbitMQService.close();
    process.exit(0);
});

export default rabbitMQService;
