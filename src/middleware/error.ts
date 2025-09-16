import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { Prisma } from '@prisma/client';

export interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
}

export class ValidationError extends Error {
  statusCode = 400;
  isOperational = true;

  constructor(message: string, public field?: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class NotFoundError extends Error {
  statusCode = 404;
  isOperational = true;

  constructor(resource: string = 'Resource') {
    super(`${resource} not found`);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends Error {
  statusCode = 409;
  isOperational = true;

  constructor(message: string = 'Resource already exists') {
    super(message);
    this.name = 'ConflictError';
  }
}

export class ForbiddenError extends Error {
  statusCode = 403;
  isOperational = true;

  constructor(message: string = 'Access forbidden') {
    super(message);
    this.name = 'ForbiddenError';
  }
}

export class UnauthorizedError extends Error {
  statusCode = 401;
  isOperational = true;

  constructor(message: string = 'Authentication required') {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

export const errorHandler = (
  error: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let statusCode = 500;
  let message = 'Internal server error';
  let details: any = undefined;

  // Log the error
  console.error('Error:', {
    name: error.name,
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  // Handle different error types
  if (error instanceof ZodError) {
    statusCode = 400;
    message = 'Validation error';
    details = error.errors.map(err => ({
      field: err.path.join('.'),
      message: err.message,
      code: err.code
    }));
  } else if (error instanceof Prisma.PrismaClientKnownRequestError) {
    statusCode = 400;

    switch (error.code) {
      case 'P2002':
        statusCode = 409;
        message = 'Resource already exists';
        details = {
          field: error.meta?.target,
          constraint: 'unique_violation'
        };
        break;
      case 'P2025':
        statusCode = 404;
        message = 'Resource not found';
        break;
      case 'P2003':
        statusCode = 400;
        message = 'Foreign key constraint failed';
        details = {
          field: error.meta?.field_name,
          constraint: 'foreign_key_violation'
        };
        break;
      case 'P2014':
        statusCode = 400;
        message = 'Invalid relation';
        break;
      default:
        message = 'Database operation failed';
    }
  } else if (error instanceof Prisma.PrismaClientValidationError) {
    statusCode = 400;
    message = 'Invalid query parameters';
  } else if ('statusCode' in error && error.statusCode) {
    statusCode = error.statusCode;
    message = error.message;
  }

  // Don't expose internal errors in production
  if (process.env.NODE_ENV === 'production' && statusCode === 500) {
    message = 'Internal server error';
    details = undefined;
  }

  // Construct error response
  const errorResponse: any = {
    error: message,
    statusCode,
    timestamp: new Date().toISOString(),
    path: req.url,
    method: req.method
  };

  if (details) {
    errorResponse.details = details;
  }

  // Include request ID if available
  if (req.headers['x-request-id']) {
    errorResponse.requestId = req.headers['x-request-id'];
  }

  // Include stack trace in development
  if (process.env.NODE_ENV === 'development') {
    errorResponse.stack = error.stack;
  }

  res.status(statusCode).json(errorResponse);
};

// Async error wrapper to catch async route handler errors
export const asyncHandler = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Handle 404 for unmatched routes
export const notFoundHandler = (req: Request, res: Response): void => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.url,
    method: req.method,
    timestamp: new Date().toISOString(),
    availableEndpoints: [
      'GET /health',
      'POST /api/auth/signin',
      'POST /api/auth/signup',
      'GET /api/admin/users',
      'POST /api/reservations',
      'GET /api/system/health'
    ]
  });
};