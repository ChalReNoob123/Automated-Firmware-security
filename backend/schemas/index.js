import { z } from 'zod';

export const signupSchema = z.object({
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_.-]+$/, 'Username may only contain letters, numbers, underscores, dots, or hyphens'),
  email: z.string().email(),
  password: z.string()
    .min(10, 'Password must be at least 10 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/\d/, 'Password must contain at least one digit')
    .regex(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/, 'Password must contain at least one special character')
});

export const loginSchema = z.object({
  identifier: z.string().min(3).max(128),
  password: z.string().max(256),
  rememberMe: z.boolean().optional()
});

export const verify2FASchema = z.object({
  tempToken: z.string(),
  code: z.string().length(6).regex(/^\d{6}$/, 'Code must be 6 digits'),
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
