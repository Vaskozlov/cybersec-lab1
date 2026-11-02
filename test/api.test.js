import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SignJWT, jwtVerify } from 'jose';
import { openDatabase } from '../src/database.js';
import { hashPassword, verifyPassword } from '../src/passwords.js';
import { createApp, ISSUER, AUDIENCE } from '../src/app.js';

const secret = randomBytes(32);
const password = randomBytes(18).toString('base64url');
const aliceAccountId = randomUUID();
const db = openDatabase(':memory:');
let server, base, aliceToken, bobToken, passwordHash;
async function request(path, { token, method = 'GET', body, raw, headers = {}, origin = base } = {}) {
  const response = await fetch(`${origin}${path}`, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined || raw !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: raw ?? (body === undefined ? undefined : JSON.stringify(body)),
  });
  return { status: response.status, headers: response.headers, json: await response.json() };
}
const login = (username, suppliedPassword = password, origin = base) => request('/auth/login', {
  method: 'POST', body: { username, password: suppliedPassword }, origin,
});
async function customToken({ key = secret, algorithm = 'HS256', claims = {}, omitExp = false } = {}) {
  const jwt = new SignJWT({ sub: aliceAccountId, iss: ISSUER, aud: AUDIENCE, jti: 'test', ...claims })
    .setProtectedHeader({ alg: algorithm, typ: 'JWT' }).setIssuedAt();
  if (!omitExp) jwt.setExpirationTime(claims.exp ?? '15m');
  return jwt.sign(key);
}

before(async () => {
  passwordHash = await hashPassword(password);
  const insert = db.prepare('INSERT INTO users (account_id, username, password_hash) VALUES (?, ?, ?)');
  insert.run(aliceAccountId, 'alice', passwordHash);
  insert.run(randomUUID(), 'bob', await hashPassword(password));
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
  const { payload } = await jwtVerify(result.json.access_token, secret, { algorithms: ['HS256'] });
  assert.equal(payload.sub, aliceAccountId);
  assert.equal(payload.exp - payload.iat, 900);
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
    { omitExp: true }, { claims: { sub: randomUUID() } }, { claims: { sub: '1' } },
  ]) assert.equal((await request('/api/data', { token: await customToken(options) })).status, 401);
});
test('unsigned alg=none tokens are rejected', async () => {
  const part = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const token = `${part({ alg: 'none' })}.${part({ sub: aliceAccountId })}.`;
  assert.equal((await request('/api/data', { token })).status, 401);
});
test('invalid JSON, types and oversized payloads produce bounded JSON errors', async () => {
  assert.equal((await request('/auth/login', { method: 'POST', raw: '{' })).status, 400);
  assert.equal((await request('/auth/login', { method: 'POST', body: { username: {}, password } })).status, 400);
  assert.equal((await request('/api/data', { method: 'POST', token: aliceToken, body: { title: '', body: '' } })).status, 400);
  assert.equal((await request('/api/data', { method: 'POST', token: aliceToken, body: { title: 'Title', body: 'a'.repeat(17000) } })).status, 413);
});
test('unsupported JSON charset and content encoding return sanitized 415 errors', async () => {
  for (const [headers, error] of [
    [{ 'Content-Type': 'application/json; charset=iso-8859-1' }, 'Unsupported JSON charset'],
    [{ 'Content-Encoding': 'unsupported' }, 'Unsupported content encoding'],
  ]) {
    const result = await request('/auth/login', { method: 'POST', raw: '{}', headers });
    assert.equal(result.status, 415);
    assert.deepEqual(result.json, { error });
    assert.match(result.headers.get('content-type'), /^application\/json/);
  }
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
test('deleted account tokens stay invalid when a new account reuses its numeric ID', async () => {
  const insert = db.prepare('INSERT INTO users (account_id, username, password_hash) VALUES (?, ?, ?)');
  const formerAccountId = randomUUID();
  const formerId = Number(insert.run(formerAccountId, 'former-user', passwordHash).lastInsertRowid);
  try {
    const formerToken = (await login('former-user')).json.access_token;
    db.prepare('DELETE FROM users WHERE id = ?').run(formerId);
    assert.equal((await request('/api/data', { token: formerToken })).status, 401);
    const replacementPassword = randomBytes(18).toString('base64url');
    const replacementAccountId = randomUUID();
    const replacementId = Number(insert.run(
      replacementAccountId, 'replacement-user', await hashPassword(replacementPassword),
    ).lastInsertRowid);
    assert.equal(replacementId, formerId);
    assert.notEqual(replacementAccountId, formerAccountId);
    const replacementToken = (await login('replacement-user', replacementPassword)).json.access_token;
    const created = await request('/api/data', {
      method: 'POST', token: replacementToken, body: { title: 'Private replacement note', body: 'Secret' },
    });
    assert.equal(created.status, 201);
    assert.equal((await request('/api/data', { token: formerToken })).status, 401);
    assert.equal((await request('/api/data', {
      method: 'POST', token: formerToken, body: { title: 'Forbidden', body: '' },
    })).status, 401);
    assert.deepEqual((await request('/api/data', { token: replacementToken })).json.data, [created.json.data]);
  } finally {
    db.prepare('DELETE FROM notes WHERE owner_id = ?').run(formerId);
    db.prepare('DELETE FROM users WHERE id = ?').run(formerId);
  }
});
test('legacy databases migrate accounts atomically while preserving notes and login', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cybersec-lab1-migration-'));
  const path = join(directory, 'legacy.db');
  let migratedDb, migratedServer;
  try {
    const legacy = new DatabaseSync(path);
    try {
      legacy.exec(`
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL) STRICT;
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, body TEXT NOT NULL) STRICT;
      `);
      const insert = legacy.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)');
      insert.run(7, 'legacy-user', passwordHash);
      insert.run(9, 'other-legacy-user', passwordHash);
      legacy.prepare('INSERT INTO notes (id, owner_id, title, body) VALUES (?, ?, ?, ?)')
        .run(21, 7, 'Legacy title', '<legacy>');
      legacy.prepare('INSERT INTO notes (id, owner_id, title, body) VALUES (?, ?, ?, ?)')
        .run(22, 9, 'Another user', 'Private');
    } finally { legacy.close(); }
    migratedDb = openDatabase(path);
    const users = migratedDb.prepare('SELECT id, account_id, username, password_hash FROM users ORDER BY id').all();
    assert.deepEqual(users.map((user) => user.id), [7, 9]);
    assert.notEqual(users[0].account_id, users[1].account_id);
    for (const user of users) {
      assert.match(user.account_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      assert.equal(user.password_hash, passwordHash);
    }
    assert.equal(migratedDb.prepare('PRAGMA foreign_keys').get().foreign_keys, 1);
    assert.equal(migratedDb.prepare('PRAGMA foreign_key_list(notes)').get().table, 'users');
    assert.deepEqual(migratedDb.prepare('PRAGMA foreign_key_check').all(), []);
    assert.throws(() => migratedDb.prepare('UPDATE users SET account_id = ? WHERE id = ?').run(randomUUID(), 7), /immutable/);
    assert.throws(() => migratedDb.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('missing-id', passwordHash), /NOT NULL/);
    assert.throws(() => migratedDb.prepare('INSERT INTO users (account_id, username, password_hash) VALUES (?, ?, ?)')
      .run(users[0].account_id, 'duplicate-id', passwordHash), /UNIQUE/);
    const app = await createApp({ db: migratedDb, jwtSecret: secret });
    migratedServer = app.listen(0, '127.0.0.1');
    await once(migratedServer, 'listening');
    const origin = `http://127.0.0.1:${migratedServer.address().port}`;
    const oldNumericToken = await customToken({ claims: { sub: '7' } });
    assert.equal((await request('/api/data', { origin, token: oldNumericToken })).status, 401);
    const loginResult = await login('legacy-user', password, origin);
    assert.equal(loginResult.status, 200);
    const token = loginResult.json.access_token;
    const { payload } = await jwtVerify(token, secret, { algorithms: ['HS256'] });
    assert.equal(payload.sub, users[0].account_id);
    assert.deepEqual((await request('/api/data', { origin, token })).json.data, [
      { id: 21, title: 'Legacy title', body: '&lt;legacy&gt;' },
    ]);
    const created = await request('/api/data', { origin, token, method: 'POST', body: { title: 'After migration', body: '' } });
    assert.equal(created.status, 201);
    assert.equal(migratedDb.prepare('SELECT owner_id FROM notes WHERE id = ?').get(created.json.data.id).owner_id, 7);
    await new Promise((resolve) => migratedServer.close(resolve));
    migratedServer = undefined;
    migratedDb.close();
    migratedDb = undefined;
    migratedDb = openDatabase(path);
    assert.deepEqual(migratedDb.prepare('SELECT id, account_id, username, password_hash FROM users ORDER BY id').all(), users);
    assert.equal(migratedDb.prepare('SELECT count(*) AS total FROM notes').get().total, 3);
  } finally {
    if (migratedServer) await new Promise((resolve) => migratedServer.close(resolve));
    if (migratedDb) migratedDb.close();
    await rm(directory, { recursive: true, force: true });
  }
});
test('a failed legacy migration rolls back the schema and original data', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cybersec-lab1-rollback-'));
  const path = join(directory, 'legacy.db');
  try {
    const legacy = new DatabaseSync(path);
    try {
      legacy.exec(`
        PRAGMA foreign_keys = OFF;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL) STRICT;
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, body TEXT NOT NULL) STRICT;
        INSERT INTO notes (owner_id, title, body) VALUES (999, 'Orphan', 'Existing invalid reference');
      `);
      legacy.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('original-user', passwordHash);
    } finally { legacy.close(); }
    assert.throws(() => openDatabase(path), /invalid foreign keys/);
    const unchanged = new DatabaseSync(path);
    try {
      assert.ok(!unchanged.prepare('PRAGMA table_info(users)').all().some((column) => column.name === 'account_id'));
      assert.equal(unchanged.prepare('PRAGMA user_version').get().user_version, 0);
      assert.equal(unchanged.prepare('SELECT username FROM users').get().username, 'original-user');
      assert.equal(unchanged.prepare('SELECT owner_id FROM notes').get().owner_id, 999);
      assert.equal(unchanged.prepare("SELECT count(*) AS total FROM sqlite_schema WHERE name = 'users_migrating'").get().total, 0);
      unchanged.exec("ALTER TABLE users ADD COLUMN custom_data TEXT; UPDATE users SET custom_data = 'Preserve me';");
    } finally { unchanged.close(); }
    assert.throws(() => openDatabase(path), /Unsupported legacy users schema/);
    const extended = new DatabaseSync(path);
    try {
      assert.equal(extended.prepare('SELECT custom_data FROM users').get().custom_data, 'Preserve me');
      assert.ok(!extended.prepare('PRAGMA table_info(users)').all().some((column) => column.name === 'account_id'));
    } finally { extended.close(); }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
