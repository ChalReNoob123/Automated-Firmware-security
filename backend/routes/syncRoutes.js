import express from 'express';
import { authenticate, authorize } from '../middleware/auth.js';
import * as syncController from '../controllers/syncController.js';

const router = express.Router();

router.use(authenticate);

router.get('/changes', authorize('read:telemetry'), syncController.getChanges);
router.post('/upload', authorize('write:logs'), syncController.uploadChanges);
router.get('/status', authorize('read:telemetry'), syncController.getStatus);

export default router;
