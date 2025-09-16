import { Request, Response, NextFunction } from 'express';
import winston from 'winston';
import morgan from 'morgan';

// Configure Winston logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.colorize({ all: true }),
    winston.format.printf(({ timestamp, level, message, stack }) => {
      return `${timestamp} [${level}]: ${message}${stack ? `\n${stack}` : ''}`;
    })
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Add file transport in production
if (process.env.NODE_ENV === 'production') {
  logger.add(new winston.transports.File({
    filename: 'logs/error.log',
    level: 'error',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    )
  }));

  logger.add(new winston.transports.File({
    filename: 'logs/combined.log',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    )
  }));
}

// Create request logger middleware using Morgan
export const requestLogger = morgan(
  ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" - :response-time ms',
  {
    stream: {
      write: (message: string) => {
        logger.info(message.trim());
      }
    },
    skip: (req: Request) => {
      // Skip logging for health check endpoints in production
      return process.env.NODE_ENV === 'production' &&
             (req.url.includes('/health') || req.url.includes('/ping'));
    }
  }
);

// Request ID middleware
export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const requestId = req.headers['x-request-id'] as string ||
                   `req_${Date.now()}_${Math.random().toString(36).substring(7)}`;

  req.headers['x-request-id'] = requestId;
  res.setHeader('X-Request-ID', requestId);

  next();
};

// Enhanced request logging with structured data
export const structuredLogger = (req: Request, res: Response, next: NextFunction): void => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;

    logger.info('Request completed', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      requestId: req.headers['x-request-id'],
      timestamp: new Date().toISOString()
    });
  });

  next();
};

// API request/response logger for debugging
export const apiLogger = (req: Request, res: Response, next: NextFunction): void => {
  if (process.env.NODE_ENV === 'development') {
    logger.debug('API Request', {
      method: req.method,
      url: req.url,
      headers: req.headers,
      query: req.query,
      body: req.method !== 'GET' ? req.body : undefined,
      timestamp: new Date().toISOString()
    });
  }

  next();
};

// Export the Winston logger for use in other parts of the application
export { logger };

// Utility functions for logging
export const logInfo = (message: string, meta?: any) => {
  logger.info(message, meta);
};

export const logError = (message: string, error?: Error, meta?: any) => {
  logger.error(message, {
    error: error?.message,
    stack: error?.stack,
    ...meta
  });
};

export const logWarn = (message: string, meta?: any) => {
  logger.warn(message, meta);
};

export const logDebug = (message: string, meta?: any) => {
  logger.debug(message, meta);
};