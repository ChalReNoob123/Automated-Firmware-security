import { z } from 'zod';
import logger from '../utils/logger.js';

export const validate = (schema) => (req, res, next) => {
  try {
    schema.parse(req.body);
    next();
  } catch (err) {
    if (err instanceof z.ZodError) {
      logger.warn({ path: req.path, issues: err.errors }, 'Schema validation failed');
      return res.status(400).json({ error: 'Invalid request payload', details: err.errors });
    }
    next(err);
  }
};
