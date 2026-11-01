import { DatabaseSync } from 'node:sqlite';

export function openDatabase(path) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY,
      owner_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      body TEXT NOT NULL
    ) STRICT;
  `);
  return db;
}
