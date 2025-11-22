import { isDevelopment } from '../config/env.js';

const rateLimitMap = new Map();
const RATE_LIMIT = {
  windowMs: 15 * 60 * 1000,
  maxRequests: isDevelopment ? 10000 : 100
};

setInterval(() => {
  const now = Date.now();
  for (const [ip, limit] of rateLimitMap.entries()) {
    if (now > limit.resetTime) {
      rateLimitMap.delete(ip);
    }
  }
}, 60 * 60 * 1000);

function rateLimit(req, res, next) {
  const ip = req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || '';
  const ipStr = String(ip).toLowerCase();
  const isLocalhost = ipStr.includes('127.0.0.1') ||
    ipStr.includes('::1') ||
    ipStr.includes('localhost') ||
    ipStr.includes('::ffff:127.0.0.1') ||
    ipStr === '';

  if (isDevelopment && (isLocalhost || !ip)) {
    return next();
  }

  const now = Date.now();

  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT.windowMs });
    return next();
  }

  const limit = rateLimitMap.get(ip);

  if (now > limit.resetTime) {
    limit.count = 1;
    limit.resetTime = now + RATE_LIMIT.windowMs;
    return next();
  }

  if (limit.count >= RATE_LIMIT.maxRequests) {
    return res.status(429).send('Quá nhiều requests. Vui lòng thử lại sau.');
  }

  limit.count++;
  next();
}

export { rateLimit };



