import type { MiddlewareHandler } from 'hono';

export const securityHeaders = (): MiddlewareHandler => {
  return async (c, next) => {
    await next();
    c.header('Cross-Origin-Opener-Policy', 'same-origin');
    c.header('Cross-Origin-Embedder-Policy', 'require-corp');
    c.header('Cross-Origin-Resource-Policy', 'same-origin');
    c.header('Referrer-Policy', 'no-referrer');
    c.header('X-Frame-Options', 'DENY');
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('Content-Security-Policy', "default-src 'self'; style-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'");
  };
};
