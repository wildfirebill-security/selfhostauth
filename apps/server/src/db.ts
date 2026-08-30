import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { VaultItem, EncryptedVaultItem, TOTPParams, TOTPAlgorithm } from "@selfhostauth/core";

export interface UserRow {
  id: string;
  username: string;
  password_hash: string;
  totp_secret_enc: string | null;
  totp_enabled: number;
  revision: number;
  created_at: number;
}

export interface ItemRow {
  id: string;
  user_id: string;
  type: string;
  name: string;
  issuer: string | null;
  account: string | null;
  secret_enc: string;
  algorithm: string;
  digits: number;
  period: number;
  icon: string | null;
  note: string | null;
  created_at: number;
  updated_at: number;
  deleted_at: number | null;
  rev: number;
  last_modified_by: string | null;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  totp_secret_enc TEXT,
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  revision INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  issuer TEXT,
  account TEXT,
  secret_enc TEXT NOT NULL,
  algorithm TEXT NOT NULL DEFAULT 'SHA1',
  digits INTEGER NOT NULL DEFAULT 6,
  period INTEGER NOT NULL DEFAULT 30,
  icon TEXT,
  note TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER,
  rev INTEGER NOT NULL,
  last_modified_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_items_user_rev ON items(user_id, rev);
`;

export class Db {
  private db: DatabaseSync;

  constructor(dbPath: string) {
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA foreign_keys = ON");
    this.db.exec(SCHEMA);
  }

  /** Cast a node:sqlite row to a typed shape. */
  private row<T>(r: unknown): T | null {
    return r === undefined ? null : (r as unknown as T);
  }

  private rows<T>(r: unknown): T[] {
    return r as unknown as T[];
  }

  // ------------------------------------------------------------- users

  createUser(username: string, passwordHash: string): UserRow {
    const id = randomUUID();
    const now = Date.now();
    this.db
      .prepare("INSERT INTO users (id, username, password_hash, revision, created_at) VALUES (?, ?, ?, 0, ?)")
      .run(id, username, passwordHash, now);
    return this.getUserById(id)!;
  }

  getUserByUsername(username: string): UserRow | null {
    return this.row<UserRow>(this.db.prepare("SELECT * FROM users WHERE username = ?").get(username));
  }

  getUserById(id: string): UserRow | null {
    return this.row<UserRow>(this.db.prepare("SELECT * FROM users WHERE id = ?").get(id));
  }

  setUserTotp(userId: string, secretEnc: string | null, enabled: boolean): void {
    this.db
      .prepare("UPDATE users SET totp_secret_enc = ?, totp_enabled = ? WHERE id = ?")
      .run(secretEnc, enabled ? 1 : 0, userId);
  }

  // ---------------------------------------------------------- sessions

  createSession(tokenHash: string, userId: string, ttlDays: number): void {
    const now = Date.now();
    this.db
      .prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
      .run(tokenHash, userId, now, now + ttlDays * 24 * 60 * 60 * 1000);
  }

  getUserBySession(tokenHash: string): UserRow | null {
    const row = this.row<UserRow>(
      this.db
        .prepare(
          `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > ?`,
        )
        .get(tokenHash, Date.now()),
    );
    if (row) {
      // sliding expiration
      this.db
        .prepare("UPDATE sessions SET expires_at = ? WHERE token_hash = ?")
        .run(Date.now() + 30 * 24 * 60 * 60 * 1000, tokenHash);
    }
    return row;
  }

  deleteSession(tokenHash: string): void {
    this.db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
  }

  // ------------------------------------------------------------- items

  getItem(userId: string, id: string): ItemRow | null {
    return this.row<ItemRow>(
      this.db.prepare("SELECT * FROM items WHERE user_id = ? AND id = ?").get(userId, id),
    );
  }

  /** All items (incl. tombstones) with rev > since, ordered by rev. */
  getItemsSince(userId: string, sinceRev: number): ItemRow[] {
    return this.rows<ItemRow>(
      this.db.prepare("SELECT * FROM items WHERE user_id = ? AND rev > ? ORDER BY rev ASC").all(userId, sinceRev),
    );
  }

  upsertItem(userId: string, item: VaultItem, secretEnc: string, rev: number): void {
    this.db
      .prepare(
        `INSERT INTO items (id, user_id, type, name, issuer, account, secret_enc, algorithm, digits, period, icon, note, created_at, updated_at, deleted_at, rev, last_modified_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           type = excluded.type,
           name = excluded.name,
           issuer = excluded.issuer,
           account = excluded.account,
           secret_enc = excluded.secret_enc,
           algorithm = excluded.algorithm,
           digits = excluded.digits,
           period = excluded.period,
           icon = excluded.icon,
           note = excluded.note,
           updated_at = excluded.updated_at,
           deleted_at = excluded.deleted_at,
           rev = excluded.rev,
           last_modified_by = excluded.last_modified_by`,
      )
      .run(
        item.id,
        userId,
        item.type,
        item.name,
        item.issuer ?? null,
        item.account ?? null,
        secretEnc,
        item.params.algorithm ?? "SHA1",
        item.params.digits ?? 6,
        item.params.period ?? 30,
        item.icon ?? null,
        item.note ?? null,
        item.createdAt,
        item.updatedAt,
        item.deletedAt ?? null,
        rev,
        item.lastModifiedBy ?? null,
      );
  }

  /** Max rev across a user's items (0 if none). */
  maxItemRev(userId: string): number {
    const raw = this.db
      .prepare("SELECT MAX(rev) AS max_rev FROM items WHERE user_id = ?")
      .get(userId) as unknown as { max_rev: number | null };
    return raw.max_rev ?? 0;
  }

  bumpUserRevision(userId: string): number {
    const user = this.getUserById(userId)!;
    const next = user.revision + 1;
    this.db.prepare("UPDATE users SET revision = ? WHERE id = ?").run(next, userId);
    return next;
  }

  close(): void {
    this.db.close();
  }
}

// ------------------------------------------------------------ mappers

export function itemRowToEncrypted(row: ItemRow): EncryptedVaultItem {
  return {
    id: row.id,
    type: row.type as VaultItem["type"],
    name: row.name,
    issuer: row.issuer ?? undefined,
    account: row.account ?? undefined,
    icon: row.icon ?? undefined,
    note: row.note ?? undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    deletedAt: row.deleted_at ?? undefined,
    lastModifiedBy: row.last_modified_by ?? undefined,
    params: {
      secret: row.secret_enc,
      algorithm: row.algorithm as TOTPAlgorithm,
      digits: row.digits,
      period: row.period,
    },
  };
}

export function itemRowToPlain(row: ItemRow, decryptedParams: TOTPParams): VaultItem {
  return {
    id: row.id,
    type: row.type as VaultItem["type"],
    name: row.name,
    issuer: row.issuer ?? undefined,
    account: row.account ?? undefined,
    icon: row.icon ?? undefined,
    note: row.note ?? undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    deletedAt: row.deleted_at ?? undefined,
    lastModifiedBy: row.last_modified_by ?? undefined,
    params: decryptedParams,
  };
}

export function openDb(dataDir: string): Db {
  return new Db(join(dataDir, "vault.db"));
}