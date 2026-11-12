import { doubleCsrf } from 'csrf-csrf';
import jwt from 'jsonwebtoken';

// Login and register run before a session exists, so they cannot carry a
// session-bound token. Everything else that changes state must.
const PRE_AUTH_PATHS = new Set(['/api/auth/register', '/api/auth/login']);

// Binds every token to one session. The token's HMAC is computed over this
// value, so a token minted for one login cannot be replayed against another —
// and an anonymous token stops working the moment the user logs in.
function getSessionIdentifier(req) {
  const token = req.cookies?.token;
  if (!token) return '';
  try {
    return jwt.verify(token, process.env.JWT_SECRET).id;
  } catch {
    return '';
  }
}

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  getSessionIdentifier,
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    path: '/',
    secure: false, // true in production (HTTPS only)
    // The attacker must not be able to read this cookie, and our own client
    // does not need to: it reads the token from GET /api/csrf-token's body.
    httpOnly: true
  },
  // GET/HEAD/OPTIONS are exempt by default — they are supposed to be safe.
  skipCsrfProtection: (req) => PRE_AUTH_PATHS.has(req.path)
});
