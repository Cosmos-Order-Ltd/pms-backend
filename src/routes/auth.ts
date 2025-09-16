import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { asyncHandler } from '../middleware/error';

const router = Router();
const prisma = new PrismaClient();

// Validation schemas
const signInSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required')
});

const signUpSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().min(1, 'Name is required'),
  role: z.enum(['admin', 'staff', 'guest']).optional().default('guest')
});

const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email format')
});

const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  password: z.string().min(8, 'Password must be at least 8 characters')
});

// Sign in
router.post('/signin', asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = signInSchema.parse(req.body);

  // Find user
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
    select: {
      id: true,
      email: true,
      password: true,
      name: true,
      role: true,
      isActive: true,
      lastLoginAt: true
    }
  });

  if (!user || !user.isActive) {
    return res.status(401).json({
      error: 'Invalid credentials or account inactive'
    });
  }

  // Verify password
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(401).json({
      error: 'Invalid credentials'
    });
  }

  // Generate JWT token
  const token = jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role
    },
    process.env.JWT_SECRET!,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '7d'
    }
  );

  // Update last login
  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() }
  });

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      lastLoginAt: user.lastLoginAt
    }
  });
}));

// Sign up
router.post('/signup', asyncHandler(async (req: Request, res: Response) => {
  const { email, password, name, role } = signUpSchema.parse(req.body);

  // Check if user already exists
  const existingUser = await prisma.user.findUnique({
    where: { email: email.toLowerCase() }
  });

  if (existingUser) {
    return res.status(409).json({
      error: 'User already exists with this email'
    });
  }

  // Hash password
  const saltRounds = 12;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // Create user
  const user = await prisma.user.create({
    data: {
      email: email.toLowerCase(),
      password: hashedPassword,
      name,
      role,
      isActive: true
    },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      createdAt: true
    }
  });

  // Generate JWT token
  const token = jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role
    },
    process.env.JWT_SECRET!,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '7d'
    }
  );

  res.status(201).json({
    token,
    user
  });
}));

// Forgot password
router.post('/forgot-password', asyncHandler(async (req: Request, res: Response) => {
  const { email } = forgotPasswordSchema.parse(req.body);

  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() }
  });

  if (!user) {
    // Don't reveal if email exists or not
    return res.json({
      message: 'If an account with that email exists, a password reset link has been sent'
    });
  }

  // Generate reset token
  const resetToken = jwt.sign(
    { userId: user.id, type: 'password_reset' },
    process.env.JWT_SECRET!,
    { expiresIn: '1h' }
  );

  // Store reset token (in production, you'd send this via email)
  await prisma.user.update({
    where: { id: user.id },
    data: {
      resetToken,
      resetTokenExpiresAt: new Date(Date.now() + 3600000) // 1 hour
    }
  });

  // In development, return the token. In production, send email
  if (process.env.NODE_ENV === 'development') {
    res.json({
      message: 'Password reset token generated',
      resetToken // Remove this in production
    });
  } else {
    // TODO: Send email with reset link
    res.json({
      message: 'If an account with that email exists, a password reset link has been sent'
    });
  }
}));

// Reset password
router.post('/reset-password', asyncHandler(async (req: Request, res: Response) => {
  const { token, password } = resetPasswordSchema.parse(req.body);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as {
      userId: string;
      type: string;
    };

    if (decoded.type !== 'password_reset') {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId }
    });

    if (!user || !user.resetToken || user.resetToken !== token) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    if (user.resetTokenExpiresAt && new Date() > user.resetTokenExpiresAt) {
      return res.status(400).json({ error: 'Reset token has expired' });
    }

    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Update password and clear reset token
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiresAt: null
      }
    });

    res.json({
      message: 'Password has been reset successfully'
    });

  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(400).json({ error: 'Invalid reset token' });
    }
    throw error;
  }
}));

// Verify token
router.get('/verify', asyncHandler(async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as {
      userId: string;
      email: string;
      role: string;
    };

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isActive: true
      }
    });

    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid token or user inactive' });
    }

    res.json({
      valid: true,
      user
    });

  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    throw error;
  }
}));

export { router as authRoutes };