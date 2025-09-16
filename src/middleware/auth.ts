import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
    permissions?: string[];
  };
}

export const authMiddleware = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'] as string;

    // Check for API key authentication
    if (apiKey) {
      const key = await prisma.apiKey.findUnique({
        where: { key: apiKey, isActive: true },
        include: { user: true }
      });

      if (!key || new Date() > key.expiresAt) {
        res.status(401).json({ error: 'Invalid or expired API key' });
        return;
      }

      // Update last used timestamp
      await prisma.apiKey.update({
        where: { id: key.id },
        data: { lastUsedAt: new Date() }
      });

      req.user = {
        id: key.user.id,
        email: key.user.email,
        role: key.user.role,
        permissions: key.permissions
      };

      return next();
    }

    // Check for JWT authentication
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Authorization header required' });
      return;
    }

    const token = authHeader.substring(7);

    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET not configured');
      res.status(500).json({ error: 'Authentication configuration error' });
      return;
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET) as {
        userId: string;
        email: string;
        role: string;
        iat: number;
        exp: number;
      };

      // Fetch user to ensure they still exist and are active
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: {
          id: true,
          email: true,
          role: true,
          isActive: true,
          permissions: true
        }
      });

      if (!user || !user.isActive) {
        res.status(401).json({ error: 'User not found or inactive' });
        return;
      }

      req.user = {
        id: user.id,
        email: user.email,
        role: user.role,
        permissions: user.permissions || []
      };

      next();
    } catch (jwtError) {
      if (jwtError instanceof jwt.TokenExpiredError) {
        res.status(401).json({ error: 'Token expired' });
      } else if (jwtError instanceof jwt.JsonWebTokenError) {
        res.status(401).json({ error: 'Invalid token' });
      } else {
        console.error('JWT verification error:', jwtError);
        res.status(401).json({ error: 'Authentication failed' });
      }
      return;
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Authentication service error' });
    return;
  }
};

export const requireRole = (allowedRoles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: 'Insufficient permissions',
        required: allowedRoles,
        current: req.user.role
      });
      return;
    }

    next();
  };
};

export const requirePermission = (requiredPermissions: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const userPermissions = req.user.permissions || [];
    const hasPermission = requiredPermissions.some(permission =>
      userPermissions.includes(permission) || req.user?.role === 'admin'
    );

    if (!hasPermission) {
      res.status(403).json({
        error: 'Insufficient permissions',
        required: requiredPermissions,
        current: userPermissions
      });
      return;
    }

    next();
  };
};