import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { createServer } from 'http';
import { PrismaClient } from '@prisma/client';
import { RedisClientType, createClient } from 'redis';

// Import route handlers
import { authRoutes } from './routes/auth';
import { adminRoutes } from './routes/admin';
import { reservationRoutes } from './routes/reservations';
import { guestServiceRoutes } from './routes/guest-services';
import { systemRoutes } from './routes/system';
import { webhookRoutes } from './routes/webhooks';
import { contactRoutes } from './routes/contact';
import { complianceRoutes } from './routes/compliance';
import { forecastingRoutes } from './routes/forecasting';
import { apiKeyRoutes } from './routes/api-keys';
import { healthRoutes } from './routes/health';

// Import middleware
import { authMiddleware } from './middleware/auth';
import { errorHandler } from './middleware/error';
import { requestLogger } from './middleware/logger';

// Environment configuration
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';
const DATABASE_URL = process.env.DATABASE_URL;
const REDIS_URL = process.env.REDIS_URL;

// Initialize clients
const prisma = new PrismaClient();
let redisClient: RedisClientType;

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Initialize Express app
const app = express();
const server = createServer(app);

// Global middleware
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: CORS_ORIGIN.split(',').map(origin => origin.trim()),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(requestLogger);
app.use('/api/', limiter);

// Health check endpoint (no auth required)
app.use('/health', healthRoutes);
app.use('/api/health', healthRoutes);

// Public routes (no auth required)
app.use('/api/auth', authRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/webhooks', webhookRoutes);

// Protected routes (auth required)
app.use('/api/admin', authMiddleware, adminRoutes);
app.use('/api/reservations', authMiddleware, reservationRoutes);
app.use('/api/guest-services', authMiddleware, guestServiceRoutes);
app.use('/api/system', authMiddleware, systemRoutes);
app.use('/api/compliance', authMiddleware, complianceRoutes);
app.use('/api/forecasting', authMiddleware, forecastingRoutes);
app.use('/api/api-keys', authMiddleware, apiKeyRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'PMS Backend API',
    version: '2.0.0',
    environment: NODE_ENV,
    status: 'running',
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/health',
      auth: '/api/auth',
      admin: '/api/admin',
      reservations: '/api/reservations',
      'guest-services': '/api/guest-services',
      system: '/api/system',
      compliance: '/api/compliance',
      forecasting: '/api/forecasting',
      'api-keys': '/api/api-keys',
      contact: '/api/contact',
      webhooks: '/api/webhooks'
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl,
    timestamp: new Date().toISOString()
  });
});

// Global error handler
app.use(errorHandler);

// Initialize Redis connection
async function initializeRedis() {
  if (!REDIS_URL) {
    console.warn('REDIS_URL not provided, running without Redis cache');
    return;
  }

  try {
    redisClient = createClient({ url: REDIS_URL });
    redisClient.on('error', (err) => console.error('Redis Client Error:', err));
    redisClient.on('connect', () => console.log('Redis connected'));
    await redisClient.connect();
  } catch (error) {
    console.error('Failed to connect to Redis:', error);
  }
}

// Database connection test
async function testDatabase() {
  try {
    await prisma.$queryRaw`SELECT 1`;
    console.log('✅ Database connected successfully');
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  
  server.close(() => {
    console.log('HTTP server closed.');
  });
  
  if (redisClient) {
    await redisClient.disconnect();
    console.log('Redis connection closed.');
  }
  
  await prisma.$disconnect();
  console.log('Database connection closed.');
  
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully...');
  
  server.close(() => {
    console.log('HTTP server closed.');
  });
  
  if (redisClient) {
    await redisClient.disconnect();
    console.log('Redis connection closed.');
  }
  
  await prisma.$disconnect();
  console.log('Database connection closed.');
  
  process.exit(0);
});

// Start server
async function startServer() {
  try {
    await testDatabase();
    await initializeRedis();
    
    server.listen(PORT, () => {
      console.log(`🚀 PMS Backend API running on port ${PORT}`);
      console.log(`📚 Environment: ${NODE_ENV}`);
      console.log(`🔗 Health check: http://localhost:${PORT}/health`);
      console.log(`📋 API Documentation: http://localhost:${PORT}/`);
      
      if (NODE_ENV === 'development') {
        console.log(`🎯 Local API: http://localhost:${PORT}/api`);
      }
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Export for testing
export { app, prisma, redisClient };

// Start the server if this file is run directly
if (require.main === module) {
  startServer();
}
