import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import authRoutes from './routes/authRoutes.js';
import telemetryRoutes from './routes/telemetryRoutes.js';
import threatIntelRoutes from './routes/threatIntelRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import { getSystemHealth } from './services/supervisorService.js';
import { apiLimiter, authLimiter } from './middleware/rateLimiter.js';
import logger from './utils/logger.js';

dotenv.config();

const app = express();

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "connect-src": ["'self'", "http://localhost:*", "ws://localhost:*", "https://generativelanguage.googleapis.com", "https://www.virustotal.com", "https://mb-api.abuse.ch", "https://otx.alienvault.com"],
    },
  },
}));

// Global Rate Limiter
app.use('/api', apiLimiter);

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173,http://localhost:4173,http://127.0.0.1:5173,http://127.0.0.1:4173')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  logger.info({ method: req.method, url: req.url, origin: req.headers.origin }, 'Incoming Request');
  next();
});

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.indexOf(origin) !== -1 || origin.includes('localhost') || origin.includes('127.0.0.1')) {
      callback(null, true);
    } else {
      logger.warn({ origin }, 'CORS Blocked');
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(morgan('dev'));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Routes
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/threat-intel', threatIntelRoutes);
app.use('/api', telemetryRoutes);

// Health Check
app.get('/health', (req, res) => {
  const supervisorHealth = getSystemHealth();
  res.json({ 
    status: 'ok', 
    uptime: process.uptime(), 
    ts: Date.now(),
    supervisor: supervisorHealth 
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handling
app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

export default app;
