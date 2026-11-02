import { openDatabase } from '../src/database.js';
import { hashPassword } from '../src/passwords.js';
import { randomUUID } from 'node:crypto';

const username = process.argv[2] ?? '';
const password = process.env.LAB_PASSWORD ?? '';
if (!/^[A-Za-z0-9_.-]{3,64}$/.test(username)
    || Buffer.byteLength(password) < 12 || Buffer.byteLength(password) > 128) {
  console.error('Usage: LAB_PASSWORD=<12-128 bytes> npm run create-user -- <username: 3-64 letters/digits/_.->');
  process.exitCode = 1;
} else {
  const db = openDatabase(process.env.DB_PATH ?? 'lab1.db');
  try {
    db.prepare('INSERT INTO users (account_id, username, password_hash) VALUES (?, ?, ?)')
      .run(randomUUID(), username, await hashPassword(password));
    console.log(`Created user ${username}; only a salted scrypt hash was stored.`);
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      console.error('Username already exists');
      process.exitCode = 1;
    } else throw err;
  } finally { db.close(); }
}
