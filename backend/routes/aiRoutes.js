import express from 'express';
import { authenticate, authorize } from '../middleware/auth.js';
import * as aiController from '../controllers/aiController.js';

const router = express.Router();

router.use(authenticate);

router.post('/analyze', authorize('read:all'), aiController.analyze);
router.post('/chat', authorize('read:all'), aiController.chat);
router.get('/metrics', authorize('read:telemetry'), aiController.getMetrics);

export default router;
