import express from 'express';
import * as telemetryController from '../controllers/telemetryController.js';
import { authenticate, authorize } from '../middleware/auth.js';

const router = express.Router();

router.use(authenticate);

router.get('/os-info', authorize('read:telemetry'), telemetryController.getSystemInfo);
router.get('/stats', authorize('read:telemetry'), telemetryController.getStats);
router.get('/analyze', authorize('read:all'), telemetryController.getAnalyze);
router.get('/logs', authorize('read:all'), telemetryController.getLiveLogs);
router.get('/database/logs', authorize('read:all'), telemetryController.getDatabaseLogs);
router.get('/insights', authorize('read:all'), telemetryController.getInsights);
router.get('/system/stats', authorize('read:telemetry'), telemetryController.getStats);
router.get('/system/permissions', telemetryController.getSystemPermissions);

export default router;
