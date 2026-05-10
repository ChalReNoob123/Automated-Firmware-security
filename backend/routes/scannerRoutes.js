import express from 'express';
import { authenticate, authorize } from '../middleware/auth.js';
import * as scannerController from '../controllers/scannerController.js';
import { validate } from '../middleware/validate.js';
import { scanStartSchema } from '../schemas/index.js';

const router = express.Router();

router.use(authenticate);

router.get('/targets', authorize('read:telemetry'), scannerController.getTargets);
router.get('/status', authorize('read:telemetry'), scannerController.getStatus);
router.post('/start', authorize('write:all'), validate(scanStartSchema), scannerController.startScan);
router.post('/stop', authorize('write:all'), scannerController.stopScan);
router.get('/sessions', authorize('read:telemetry'), scannerController.getSessions);
router.get('/sessions/:id', authorize('read:telemetry'), scannerController.getSessionDetails);
router.get('/sessions/:id/findings', authorize('read:telemetry'), scannerController.getSessionFindings);
router.get('/export/:sessionId/:format', authorize('read:telemetry'), scannerController.exportFindings);

export default router;
