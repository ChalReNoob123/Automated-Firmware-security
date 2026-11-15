/** @type {import('next').NextConfig} */
// Security headers at the web tier — the API sets its own via helmet middleware;
// previously the Next pages served ZERO CSP / nosniff / frame protections (found
// in the live security audit). connect-src includes the API origin because the
// browser calls it directly with credentials. Dev exceptions (unsafe-eval for
// the Turbopack runtime, ws:// for HMR) are noted and must be dropped for a
// hardened production allowlist — the API tier CSP stays strict already.
const API_ORIGIN = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // dev: turbopack runtime needs eval
  "style-src 'self' 'unsafe-inline'", // the design system styles elements inline
  "img-src 'self' data: blob:",
  "connect-src 'self' " + API_ORIGIN + " ws://localhost:3005 ws://127.0.0.1:3005", // dev: HMR websockets
  "font-src 'self' data:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: csp },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
