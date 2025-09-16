import { Router, Request, Response } from 'express';
import { asyncHandler } from '../middleware/error';

const router = Router();

router.post('/', asyncHandler(async (req: Request, res: Response) => {
  res.json({
    message: 'Webhook endpoint - implementation pending',
    received: true
  });
}));

export { router as webhookRoutes };