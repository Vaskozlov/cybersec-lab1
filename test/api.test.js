import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { SignJWT } from 'jose';
import { openDatabase } from '../src/database.js';
import { hashPassword, verifyPassword } from '../src/passwords.js';
import { createApp, ISSUER, AUDIENCE } from '../src/app.js';

const secret = randomBytes(32);
const password = randomBytes(18).toString('base64url');
const db = openDatabase(':memory:');
let server, base, aliceToken, bobToken, passwordHash;
async function request(path, { token, method = 'GET', body, raw } = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined || raw !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: raw ?? (body === undefined ? undefined : JSON.stringify(body)),
  });
  return { status: response.status, headers: response.headers, json: await response.json() };
}
const login = (username, suppliedPassword = password) => request('/auth/login', {
  method: 'POST', body: { username, password: suppliedPassword },
});
async function customToken({ key = secret, algorithm = 'HS256', claims = {}, omitExp = false } = {}) {
  const jwt = new SignJWT({ sub: '1', iss: ISSUER, aud: AUDIENCE, jti: 'test', ...claims })
    .setProtectedHeader({ alg: algorithm, typ: 'JWT' }).setIssuedAt();
  if (!omitExp) jwt.setExpirationTime(claims.exp ?? '15m');
  return jwt.sign(key);
}

before(async () => {
  passwordHash = await hashPassword(password);
  const insert = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
  insert.run('alice', passwordHash);
  insert.run('bob', await hashPassword(password));
  const app = await createApp({ db, jwtSecret: secret, loginLimit: 100 });
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${server.address().port}`;
  aliceToken = (await login('alice')).json.access_token;
  bobToken = (await login('bob')).json.access_token;
});
after(async () => { await new Promise((resolve) => server.close(resolve)); db.close(); });

test('passwords use salted scrypt; correct/wrong password verification', async () => {
  assert.match(passwordHash, /^scrypt\$32768\$8\$3\$/);
  assert.ok(!passwordHash.includes(password));
  assert.notEqual(passwordHash, await hashPassword(password));
  assert.equal(await verifyPassword(password, passwordHash), true);
  assert.equal(await verifyPassword('wrong-password', passwordHash), false);
});
test('valid login returns a Bearer token with a 15 minute lifetime', async () => {
  const result = await login('alice');
  assert.equal(result.status, 200);
  assert.equal(result.json.token_type, 'Bearer');
  assert.equal(result.json.expires_in, 900);
  assert.equal(result.json.access_token.split('.').length, 3);
});
test('wrong password and unknown username return identical 401 responses', async () => {
  const wrong = await login('alice', 'incorrect');
  const unknown = await login('unknown');
  assert.equal(wrong.status, 401);
  assert.equal(unknown.status, 401);
  assert.deepEqual(wrong.json, unknown.json);
});
test('both data methods deny access without a token', async () => {
  for (const method of ['GET', 'POST']) {
    const result = await request('/api/data', { method, ...(method === 'POST' ? { body: {} } : {}) });
    assert.equal(result.status, 401);
    assert.equal(result.headers.get('www-authenticate'), 'Bearer');
  }
});
test('SQL injection in login cannot bypass authentication', async () => {
  for (const username of ["' OR 1=1 --", "alice' --", "'; DROP TABLE users; --"]) {
    assert.equal((await login(username)).status, 401);
  }
  assert.equal((await login('alice')).status, 200);
});
test('create and retrieve notes; SQL-looking text remains literal data', async () => {
  const title = "x'); DROP TABLE notes; --";
  const created = await request('/api/data', { token: aliceToken, method: 'POST', body: { title, body: 'Hello' } });
  assert.equal(created.status, 201);
  const rows = db.prepare('SELECT title FROM notes WHERE owner_id = ?').all(1);
  assert.ok(rows.some((row) => row.title === title));
  const listed = await request('/api/data', { token: aliceToken });
  assert.equal(listed.status, 200);
  assert.ok(listed.json.data.some((row) => row.id === created.json.data.id));
});
test('XSS payload is escaped on both creation and retrieval, exactly once', async () => {
  const body = '<script>alert("XSS")</script> &';
  const expected = '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt; &amp;';
  const created = await request('/api/data', { token: aliceToken, method: 'POST', body: { title: '<img src=x>', body } });
  assert.equal(created.status, 201);
  assert.equal(created.json.data.body, expected);
  const listed = await request('/api/data', { token: aliceToken });
  assert.equal(listed.json.data.find((row) => row.id === created.json.data.id).body, expected);
  assert.equal(db.prepare('SELECT body FROM notes WHERE id = ?').get(created.json.data.id).body, body);
});
test('one user cannot read another user notes or assign their owner', async () => {
  assert.deepEqual((await request('/api/data', { token: bobToken })).json.data, []);
  await request('/api/data', { token: bobToken, method: 'POST', body: { title: 'Bob only', body: '', owner_id: 1 } });
  assert.equal((await request('/api/data', { token: bobToken })).json.data.length, 1);
  assert.ok(!(await request('/api/data', { token: aliceToken })).json.data.some((row) => row.title === 'Bob only'));
});
test('malformed, forged, expired and wrong-algorithm tokens are rejected', async () => {
  const tokens = [
    'not.a.jwt',
    await customToken({ key: randomBytes(32) }),
    await customToken({ claims: { exp: Math.floor(Date.now() / 1000) - 10 } }),
    await customToken({ algorithm: 'HS384', key: randomBytes(48) }),
  ];
  for (const token of tokens) assert.equal((await request('/api/data', { token })).status, 401);
});
test('wrong issuer/audience, missing expiry and nonexistent user are rejected', async () => {
  for (const options of [
    { claims: { iss: 'another-service' } }, { claims: { aud: 'another-client' } },
    { omitExp: true }, { claims: { sub: '99999' } },
  ]) assert.equal((await request('/api/data', { token: await customToken(options) })).status, 401);
});
test('unsigned alg=none tokens are rejected', async () => {
  const part = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const token = `${part({ alg: 'none' })}.${part({ sub: '1' })}.`;
  assert.equal((await request('/api/data', { token })).status, 401);
});
test('invalid JSON, types and oversized payloads produce bounded JSON errors', async () => {
  assert.equal((await request('/auth/login', { method: 'POST', raw: '{' })).status, 400);
  assert.equal((await request('/auth/login', { method: 'POST', body: { username: {}, password } })).status, 400);
  assert.equal((await request('/api/data', { method: 'POST', token: aliceToken, body: { title: '', body: '' } })).status, 400);
  assert.equal((await request('/api/data', { method: 'POST', token: aliceToken, body: { title: 'Title', body: 'a'.repeat(17000) } })).status, 413);
});
test('security response headers and JSON content type are present', async () => {
  const { headers } = await request('/api/data', { token: aliceToken });
  assert.match(headers.get('content-type'), /^application\/json/);
  assert.equal(headers.get('x-content-type-options'), 'nosniff');
  assert.equal(headers.get('cache-control'), 'no-store');
  assert.equal(headers.get('x-powered-by'), null);
  assert.ok(headers.get('content-security-policy'));
});
test('login rate limiter returns 429 when the attempt budget is exhausted', async () => {
  const app = await createApp({ db, jwtSecret: secret, loginLimit: 2 });
  const limitedServer = app.listen(0, '127.0.0.1');
  await once(limitedServer, 'listening');
  try {
    const url = `http://127.0.0.1:${limitedServer.address().port}/auth/login`;
    for (let n = 0; n < 2; n++) {
      const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      assert.equal(response.status, 400);
      await response.text();
    }
    const denied = await fetch(url, { method: 'POST' });
    assert.equal(denied.status, 429);
    assert.ok(denied.headers.get('retry-after'));
    await denied.text();
  } finally { await new Promise((resolve) => limitedServer.close(resolve)); }
});
test('application refuses a missing or short signing key', async () => {
  await assert.rejects(createApp({ db, jwtSecret: Buffer.alloc(8) }), /32 random bytes/);
});
