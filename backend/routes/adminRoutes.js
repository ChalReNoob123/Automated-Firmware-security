import express from 'express';
import * as adminController from '../controllers/adminController.js';
import { authenticate, authorize } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { killProcessSchema } from '../schemas/index.js';

const router = express.Router();

router.use(authenticate);

router.post('/kill-process', authorize('exec:kill'), validate(killProcessSchema), adminController.killProcess);
router.post('/auth/admin/reset-totp', authorize('manage:users'), adminController.resetTOTP);

export default router;
