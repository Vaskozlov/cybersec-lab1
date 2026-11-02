import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';

export function openDatabase(path) {
  const db = new DatabaseSync(path);
  let transaction = false;
  try {
    db.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = OFF;
      BEGIN IMMEDIATE;
    `);
    transaction = true;
    const { user_version: version } = db.prepare('PRAGMA user_version').get();
    if (version > 1) throw new Error('Unsupported database schema version');
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        account_id TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
      ) STRICT;
    `);
    const columns = db.prepare('PRAGMA table_info(users)').all();
    if (!columns.some((column) => column.name === 'account_id')) {
      const legacyColumns = ['id', 'username', 'password_hash'];
      const customObjects = db.prepare(
        "SELECT name FROM sqlite_schema WHERE tbl_name = 'users' AND type IN ('index', 'trigger') AND sql IS NOT NULL",
      ).all();
      if (columns.length !== legacyColumns.length
          || columns.some((column) => !legacyColumns.includes(column.name))
          || customObjects.length > 0) {
        throw new Error('Unsupported legacy users schema; migrate custom extensions explicitly');
      }
      // Rebuild the legacy table without renaming it first: notes must keep
      // referencing users(id), and existing numeric IDs must remain unchanged.
      db.exec(`
        CREATE TABLE users_migrating (
          id INTEGER PRIMARY KEY,
          account_id TEXT UNIQUE NOT NULL,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL
        ) STRICT;
      `);
      const insert = db.prepare(
        'INSERT INTO users_migrating (id, account_id, username, password_hash) VALUES (?, ?, ?, ?)',
      );
      for (const user of db.prepare('SELECT id, username, password_hash FROM users').all()) {
        insert.run(user.id, randomUUID(), user.username, user.password_hash);
      }
      db.exec('DROP TABLE users; ALTER TABLE users_migrating RENAME TO users;');
    }
    db.exec(`
      CREATE TRIGGER IF NOT EXISTS users_account_id_immutable
      BEFORE UPDATE OF account_id ON users
      WHEN NEW.account_id IS NOT OLD.account_id
      BEGIN
        SELECT RAISE(ABORT, 'account_id is immutable');
      END;
      CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY,
        owner_id INTEGER NOT NULL REFERENCES users(id),
        title TEXT NOT NULL,
        body TEXT NOT NULL
      ) STRICT;
    `);
    if (db.prepare('PRAGMA foreign_key_check').all().length > 0) {
      throw new Error('Database migration would leave invalid foreign keys');
    }
    db.exec('PRAGMA user_version = 1; COMMIT;');
    transaction = false;
    db.exec('PRAGMA foreign_keys = ON;');
    return db;
  } catch (err) {
    if (transaction) db.exec('ROLLBACK;');
    db.close();
    throw err;
  }
}
