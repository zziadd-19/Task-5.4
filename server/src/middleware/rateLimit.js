import rateLimit from 'express-rate-limit';

// Caps how much work one client can demand of the maintenance feature in a
// given window. Without this, a single page can flood the endpoint and exhaust
// the server's CPU, memory and database connections.
export const maintenanceLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' }
});
