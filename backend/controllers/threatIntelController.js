import * as threatIntelService from '../services/threatIntelService.js';
import logger from '../utils/logger.js';

export const getVirusTotal = async (req, res) => {
  const { indicator, type } = req.query;
  try {
    const result = await threatIntelService.queryVirusTotal(indicator, type);
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(err.message.includes('not configured') ? 503 : 400).json({ error: err.message });
  }
};

export const getOTX = async (req, res) => {
  const { ip } = req.query;
  try {
    const result = await threatIntelService.queryOTX(ip);
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(err.message.includes('not configured') ? 503 : 400).json({ error: err.message });
  }
};
