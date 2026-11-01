import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(scrypt);
// One of OWASP's scrypt configurations: N=2^15, r=8, p=3 (32 MiB).
const parameters = { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 };

export async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const key = await derive(password, salt, 64, parameters);
  return `scrypt$32768$8$3$${salt}$${key.toString('hex')}`;
}

export async function verifyPassword(password, encoded) {
  const [name, n, r, p, salt, digest] = encoded.split('$');
  if (name !== 'scrypt' || n !== '32768' || r !== '8' || p !== '3'
      || !/^[a-f0-9]{32}$/.test(salt ?? '')
      || !/^[a-f0-9]{128}$/.test(digest ?? '')) return false;
  const expected = Buffer.from(digest, 'hex');
  const actual = await derive(password, salt, 64, parameters);
  return timingSafeEqual(actual, expected);
}
