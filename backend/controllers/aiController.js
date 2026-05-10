import logger from '../utils/logger.js';
import * as geminiService from '../../services/geminiService.js'; // Existing service

export const analyze = async (req, res) => {
  const body = req.body;
  if (!geminiService.isConfigured() && body.apiKey) geminiService.setApiKey(body.apiKey);
  if (!geminiService.isConfigured()) return res.status(400).json({ error: 'Gemini API key not configured. Set GEMINI_API_KEY env var or provide apiKey in request.' });
  try {
    const result = await geminiService.analyzeTelemetry(body);
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: err.message });
  }
};

export const chat = async (req, res) => {
  const body = req.body;
  if (!geminiService.isConfigured() && body.apiKey) geminiService.setApiKey(body.apiKey);
  if (!geminiService.isConfigured()) return res.status(400).json({ error: 'AI not configured' });
  try {
    const result = await geminiService.chat(body);
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: err.message });
  }
};

export const getMetrics = (req, res) => {
  try {
    res.json(geminiService.getMetrics());
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch metrics' });
  }
};
