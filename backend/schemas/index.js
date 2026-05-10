import { z } from 'zod';

export const signupSchema = z.object({
  username: z.string().min(3).max(32),
  email: z.string().email(),
  password: z.string().min(8)
});

export const loginSchema = z.object({
  identifier: z.string().min(3),
  password: z.string(),
  rememberMe: z.boolean().optional()
});

export const verify2FASchema = z.object({
  tempToken: z.string(),
  code: z.string().length(6),
  rememberMe: z.boolean().optional()
});

export const killProcessSchema = z.object({
  pid: z.union([z.string(), z.number()]).refine(val => /^\d+$/.test(String(val)), { message: "Valid PID required" })
});

export const scanStartSchema = z.object({
  targets: z.array(z.string()).optional(),
  options: z.object({
    maxDepth: z.number().optional(),
    checkSignatures: z.boolean().optional(),
    checkADS: z.boolean().optional(),
    maxFileSizeMB: z.number().optional()
  }).optional()
});
