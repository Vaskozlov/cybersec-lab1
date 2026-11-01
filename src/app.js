import express from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { SignJWT, jwtVerify } from 'jose';
import { randomUUID } from 'node:crypto';
import { hashPassword, verifyPassword } from './passwords.js';

export const ISSUER = 'cybersec-lab1';
export const AUDIENCE = 'cybersec-lab1-client';
export const TOKEN_SECONDS = 900;

// The lab explicitly requires HTML escaping of strings returned in JSON.
// This is HTML text encoding, not a sanitizer for scripts, URLs or attributes.
export function escapeHtml(value) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

export async function createApp({ db, jwtSecret, loginLimit = 5 }) {
  if (!(jwtSecret instanceof Uint8Array) || jwtSecret.byteLength < 32) {
    throw new Error('JWT signing key must contain at least 32 random bytes');
  }
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  app.use(express.json({ limit: '16kb', strict: true }));
  const dummyHash = await hashPassword(randomUUID());
  const findUser = db.prepare('SELECT id, password_hash FROM users WHERE username = ?');
  const userExists = db.prepare('SELECT id FROM users WHERE id = ?');
  const listNotes = db.prepare(
    'SELECT id, title, body FROM notes WHERE owner_id = ? ORDER BY id DESC LIMIT 100',
  );
  const insertNote = db.prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)');
  const encodeNote = (row) => ({
    id: row.id, title: escapeHtml(row.title), body: escapeHtml(row.body),
  });
  const loginLimiter = rateLimit({
    windowMs: 60_000, limit: loginLimit,
    standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: 'Too many login attempts; retry later' },
  });

  app.post('/auth/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body ?? {};
    if (typeof username !== 'string' || username.length < 1 || username.length > 64
        || typeof password !== 'string' || password.length < 1
        || Buffer.byteLength(password) > 128) {
      return res.status(400).json({ error: 'Invalid login payload' });
    }
    const user = findUser.get(username);
    const valid = await verifyPassword(password, user?.password_hash ?? dummyHash);
    if (!user || !valid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject(String(user.id)).setIssuer(ISSUER).setAudience(AUDIENCE)
      .setIssuedAt().setExpirationTime(`${TOKEN_SECONDS}s`).setJti(randomUUID())
      .sign(jwtSecret);
    return res.json({ access_token: token, token_type: 'Bearer', expires_in: TOKEN_SECONDS });
  });

  // Every route below /api requires this middleware, including future routes.
  app.use('/api', async (req, res, next) => {
    const match = /^Bearer ([A-Za-z0-9_.-]+)$/i.exec(req.get('Authorization') ?? '');
    if (!match || match[1].length > 4096) {
      res.set('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ error: 'Authentication required' });
    }
    try {
      const { payload } = await jwtVerify(match[1], jwtSecret, {
        algorithms: ['HS256'], issuer: ISSUER, audience: AUDIENCE, typ: 'JWT',
        requiredClaims: ['sub', 'iat', 'exp', 'iss', 'aud', 'jti'],
        maxTokenAge: `${TOKEN_SECONDS}s`,
      });
      if (!/^[1-9][0-9]*$/.test(payload.sub ?? '')
          || !userExists.get(payload.sub)) throw new Error('Unknown user');
      res.locals.userId = payload.sub;
      return next();
    } catch {
      res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  });

  app.get('/api/data', (_req, res) => {
    res.json({ data: listNotes.all(res.locals.userId).map(encodeNote) });
  });

  app.post('/api/data', (req, res) => {
    const { title, body } = req.body ?? {};
    if (typeof title !== 'string' || title.trim().length < 1 || title.length > 120
        || typeof body !== 'string' || body.length > 2000) {
      return res.status(400).json({ error: 'title: 1-120 characters; body: 0-2000 characters' });
    }
    const result = insertNote.run(res.locals.userId, title, body);
    return res.status(201).json({ data: encodeNote({ id: Number(result.lastInsertRowid), title, body }) });
  });

  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  app.use((err, _req, res, _next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
    return res.status(500).json({ error: 'Internal server error' });
  });
  return app;
}
