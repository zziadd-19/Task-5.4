import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { generateCsrfToken, doubleCsrfProtection } from './middleware/csrf.js';
import authRoutes from './routes/auth.js';
import bookingRoutes from './routes/bookings.js';
import userRoutes from './routes/users.js';
import maintenanceRoutes from './routes/maintenance.js';

const app = express();

app.use(morgan('dev'));
// CORS is locked to the client origin with credentials enabled so the browser
// may send the auth cookie on cross-origin XHR. (CORS alone does NOT stop CSRF.)
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
// Parse urlencoded bodies so a bare HTML <form> POST (the classic CSRF vector,
// which needs no JavaScript and triggers no CORS preflight) is understood.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/health', (req, res) => res.json({ ok: true }));

// The client reads its token from here. The attacker's page cannot: a
// cross-origin GET is blocked by CORS from reading the response body, and the
// matching cookie is httpOnly.
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

// Every state-changing request from here on must echo the token. Safe methods
// and the pre-auth routes are exempt (see middleware/csrf.js).
app.use(doubleCsrfProtection);

app.use('/api/auth', authRoutes);
app.use('/api/bookings', bookingRoutes);
app.use('/api/users', userRoutes);
app.use('/api/maintenance', maintenanceRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// A failed CSRF check is reported with a code so the client can tell it apart
// from an ownership 403 and retry once with a fresh token.
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid CSRF token', code: 'EBADCSRFTOKEN' });
  }
  next(err);
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
