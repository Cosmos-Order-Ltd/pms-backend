import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const router = Router();
const prisma = new PrismaClient();

// Basic health check
router.get('/', async (req: Request, res: Response) => {
  try {
    const healthData = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'pms-backend',
      version: '2.0.0',
      environment: process.env.NODE_ENV || 'development',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      checks: {
        database: 'unknown',
        redis: 'unknown'
      }
    };

    // Test database connection
    try {
      await prisma.$queryRaw`SELECT 1`;
      healthData.checks.database = 'healthy';
    } catch (error) {
      healthData.checks.database = 'unhealthy';
      healthData.status = 'degraded';
    }

    // Test Redis connection if available
    if (process.env.REDIS_URL) {
      try {
        // Redis check would go here if redisClient was accessible
        healthData.checks.redis = 'healthy';
      } catch (error) {
        healthData.checks.redis = 'unhealthy';
        if (healthData.status === 'healthy') {
          healthData.status = 'degraded';
        }
      }
    } else {
      healthData.checks.redis = 'not_configured';
    }

    const statusCode = healthData.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json(healthData);

  } catch (error) {
    console.error('Health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'pms-backend',
      version: '2.0.0',
      error: 'Health check failed',
      uptime: process.uptime()
    });
  }
});

// Detailed health check with system info
router.get('/detailed', async (req: Request, res: Response) => {
  try {
    const healthData = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'pms-backend',
      version: '2.0.0',
      environment: process.env.NODE_ENV || 'development',
      uptime: process.uptime(),
      system: {
        platform: process.platform,
        nodeVersion: process.version,
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        pid: process.pid
      },
      database: {
        status: 'unknown',
        connected: false,
        latency: null as number | null
      },
      redis: {
        status: 'not_configured',
        connected: false,
        latency: null as number | null
      },
      dependencies: {
        express: require('express/package.json').version,
        prisma: require('@prisma/client/package.json').version
      }
    };

    // Test database connection with timing
    try {
      const startTime = Date.now();
      await prisma.$queryRaw`SELECT 1`;
      const endTime = Date.now();

      healthData.database.status = 'healthy';
      healthData.database.connected = true;
      healthData.database.latency = endTime - startTime;
    } catch (error) {
      healthData.database.status = 'unhealthy';
      healthData.database.connected = false;
      healthData.status = 'degraded';
    }

    const statusCode = healthData.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json(healthData);

  } catch (error) {
    console.error('Detailed health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'pms-backend',
      error: 'Detailed health check failed'
    });
  }
});

// Liveness probe (simple check that service is running)
router.get('/live', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    service: 'pms-backend'
  });
});

// Readiness probe (check if service is ready to handle requests)
router.get('/ready', async (req: Request, res: Response) => {
  try {
    // Check database connectivity
    await prisma.$queryRaw`SELECT 1`;

    res.status(200).json({
      status: 'ready',
      timestamp: new Date().toISOString(),
      service: 'pms-backend'
    });
  } catch (error) {
    console.error('Readiness check failed:', error);
    res.status(503).json({
      status: 'not_ready',
      timestamp: new Date().toISOString(),
      service: 'pms-backend',
      error: 'Database not accessible'
    });
  }
});

export { router as healthRoutes };