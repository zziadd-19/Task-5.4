import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { maintenanceLimiter } from '../middleware/rateLimit.js';
import {
  getAllRequests,
  getRequest,
  createRequest,
  updateRequest,
  deleteRequest
} from '../controllers/maintenanceController.js';

const router = Router();

// Reading is public; writing requires a logged-in user.
//
// Throttled as a whole so one client cannot flood the feature. The writes are
// additionally protected against CSRF by the app-wide doubleCsrfProtection.
router.use(maintenanceLimiter);

router.get('/', getAllRequests);
router.get('/:id', getRequest);
router.post('/', requireAuth, createRequest);
router.patch('/:id', requireAuth, updateRequest);
router.delete('/:id', requireAuth, deleteRequest);

export default router;
