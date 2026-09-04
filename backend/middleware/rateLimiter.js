import rateLimit, { ipKeyGenerator } from 'express-rate-limit';

const safeIpKey = (req) => ipKeyGenerator(req.ip || 'unknown');

export const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  keyGenerator: safeIpKey
});

export const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minute window
  max: 15, // 15 attempts per 5 minutes
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'Too many authentication attempts. Please wait 5 minutes before trying again.' },
  keyGenerator: safeIpKey
});

export const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 signups per hour per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many accounts created from this IP. Try again in an hour.' },
  keyGenerator: safeIpKey
});
