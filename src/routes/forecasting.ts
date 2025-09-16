import { Router, Request, Response } from 'express';
import { asyncHandler } from '../middleware/error';
import { AuthenticatedRequest, requireRole } from '../middleware/auth';

const router = Router();

router.get('/export', requireRole(['admin']), asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  res.json({
    message: 'Forecasting export endpoint - implementation pending'
  });
}));

export { router as forecastingRoutes };