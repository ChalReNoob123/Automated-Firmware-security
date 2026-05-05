import express from 'express';
import * as threatIntelController from '../controllers/threatIntelController.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

router.use(authenticate);

router.get('/virustotal', threatIntelController.getVirusTotal);
router.get('/otx', threatIntelController.getOTX);

export default router;
