import express from 'express';
import { authenticate, authorize } from '../middleware/auth.js';
import * as analyticsController from '../controllers/analyticsController.js';

const router = express.Router();

router.use(authenticate);

router.get('/global', authorize('read:telemetry'), analyticsController.getGlobal);
router.get('/segments', authorize('read:telemetry'), analyticsController.getSegments);
router.get('/segments/:id', authorize('read:telemetry'), analyticsController.getSegmentDetails);
router.get('/segments/:id/timeseries', authorize('read:telemetry'), analyticsController.getSegmentTimeseries);
router.get('/segments/:id/compare', authorize('read:telemetry'), analyticsController.getSegmentComparison);
router.get('/alerts', authorize('read:telemetry'), analyticsController.getAlerts);
router.post('/alerts/:id/ack', authorize('write:logs'), analyticsController.ackAlert);
router.get('/thresholds', authorize('read:telemetry'), analyticsController.getThresholds);
router.put('/thresholds', authorize('write:logs'), analyticsController.updateThresholds);
router.post('/engage', authorize('exec:kill'), analyticsController.engageMitigation);
router.get('/snapshots/:id', authorize('read:telemetry'), analyticsController.getSnapshot);
router.get('/benchmarks', authorize('read:telemetry'), analyticsController.getBenchmarks);

export default router;
