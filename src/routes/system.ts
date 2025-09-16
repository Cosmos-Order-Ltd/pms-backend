import { Router, Request, Response } from 'express';
import { asyncHandler } from '../middleware/error';
import { AuthenticatedRequest, requireRole } from '../middleware/auth';

const router = Router();

// System health (requires admin role)
router.get('/health', requireRole(['admin']), asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const systemHealth = {
    status: 'operational',
    timestamp: new Date().toISOString(),
    services: {
      database: 'operational',
      redis: process.env.REDIS_URL ? 'operational' : 'not_configured',
      email: 'operational',
      storage: 'operational'
    },
    metrics: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      activeConnections: 0 // Would be tracked in real implementation
    }
  };

  res.json(systemHealth);
}));

// System information
router.get('/info', requireRole(['admin']), asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const systemInfo = {
    application: {
      name: 'PMS Backend',
      version: '2.0.0',
      environment: process.env.NODE_ENV || 'development'
    },
    runtime: {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      pid: process.pid
    },
    configuration: {
      port: process.env.PORT || 5000,
      database: !!process.env.DATABASE_URL,
      redis: !!process.env.REDIS_URL,
      jwtConfigured: !!process.env.JWT_SECRET
    }
  };

  res.json(systemInfo);
}));

// System statistics
router.get('/stats', requireRole(['admin']), asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  // In a real implementation, these would be actual database queries
  const stats = {
    users: {
      total: 0,
      active: 0,
      byRole: {
        admin: 0,
        staff: 0,
        guest: 0
      }
    },
    reservations: {
      total: 0,
      pending: 0,
      confirmed: 0,
      cancelled: 0
    },
    rooms: {
      total: 0,
      occupied: 0,
      available: 0,
      maintenance: 0
    }
  };

  res.json(stats);
}));

export { router as systemRoutes };