import { Router, Request, Response } from 'express';
import { asyncHandler } from '../middleware/error';
import { AuthenticatedRequest } from '../middleware/auth';

const router = Router();

router.get('/', asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  res.json({
    message: 'Guest services endpoint - implementation pending',
    services: []
  });
}));

export { router as guestServiceRoutes };