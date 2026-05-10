import express from 'express';
import { authenticate, authorize } from '../middleware/auth.js';
import * as securityController from '../controllers/securityController.js';

const router = express.Router();

router.use(authenticate);

router.get('/audit', authorize('read:all'), securityController.getAuditLogs);
router.get('/ddos-stats', authorize('read:telemetry'), securityController.getDdosStats);

export default router;
