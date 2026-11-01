import { openDatabase } from './database.js';
import { createApp } from './app.js';

const secret = process.env.JWT_SECRET ?? '';
const key = Buffer.from(secret, 'base64');
if (!secret || key.length < 32 || key.toString('base64') !== secret) {
  throw new Error('Set JWT_SECRET to a base64-encoded random key of at least 32 bytes');
}
const db = openDatabase(process.env.DB_PATH ?? 'lab1.db');
const app = await createApp({ db, jwtSecret: key });
const port = Number(process.env.PORT ?? 3001);
const server = app.listen(port, '127.0.0.1', () => {
  console.log(`Secure notes API: http://127.0.0.1:${port}`);
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => { db.close(); process.exit(0); }));
}
