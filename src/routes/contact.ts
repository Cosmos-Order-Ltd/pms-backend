import { Router, Request, Response } from 'express';
import { asyncHandler } from '../middleware/error';
import { z } from 'zod';

const router = Router();

const contactSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  subject: z.string().min(1),
  message: z.string().min(1)
});

router.post('/', asyncHandler(async (req: Request, res: Response) => {
  const contactData = contactSchema.parse(req.body);
  
  // TODO: Send email or save to database
  res.json({
    message: 'Contact form submitted successfully',
    data: contactData
  });
}));

export { router as contactRoutes };