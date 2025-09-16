import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { asyncHandler } from '../middleware/error';
import { AuthenticatedRequest, requireRole } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();

// Apply admin role requirement to all routes
router.use(requireRole(['admin']));

// Get all users
router.get('/users', asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const users = await prisma.user.findMany({
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      isActive: true,
      createdAt: true,
      lastLoginAt: true
    },
    orderBy: { createdAt: 'desc' }
  });

  res.json({ users });
}));

// Get user by ID
router.get('/users/:id', asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const user = await prisma.user.findUnique({
    where: { id: req.params.id },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      isActive: true,
      createdAt: true,
      lastLoginAt: true,
      permissions: true
    }
  });

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ user });
}));

// Update user
router.patch('/users/:id', asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const updateSchema = z.object({
    name: z.string().min(1).optional(),
    role: z.enum(['admin', 'staff', 'guest']).optional(),
    isActive: z.boolean().optional(),
    permissions: z.array(z.string()).optional()
  });

  const data = updateSchema.parse(req.body);

  const user = await prisma.user.update({
    where: { id: req.params.id },
    data,
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      isActive: true,
      permissions: true,
      updatedAt: true
    }
  });

  res.json({ user });
}));

// Get audit logs
router.get('/audit', asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  // This would typically fetch from an audit log table
  res.json({
    message: 'Audit endpoint - implementation pending',
    logs: []
  });
}));

// Get system properties/settings
router.get('/properties', asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  // This would fetch system properties
  res.json({
    message: 'Properties endpoint - implementation pending',
    properties: {}
  });
}));

// Get roles and permissions
router.get('/roles', asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const roles = [
    {
      name: 'admin',
      permissions: ['*'],
      description: 'Full system access'
    },
    {
      name: 'staff',
      permissions: ['reservations.read', 'reservations.write', 'guests.read'],
      description: 'Staff operations'
    },
    {
      name: 'guest',
      permissions: ['profile.read', 'profile.write'],
      description: 'Guest access'
    }
  ];

  res.json({ roles });
}));

export { router as adminRoutes };