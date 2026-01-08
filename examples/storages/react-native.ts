// storage/SQLiteStorageAdapter.ts
import * as SQLite from "expo-sqlite";
import type { StorageAdapter, Identity, Session } from "../../src/types"; // or @immahq/aegis/aegis.d.ts

const DB_NAME = "aegis_e2ee.db";
const TABLE_NAME = "aegis_storage";

// Singleton DB instance
let dbInstance: SQLite.SQLiteDatabase | null = null;

/**
 * Opens encrypted database using SQLCipher.
 * Assumes encryption key is provided via environment or secure setup.
 * In practice, you'd pass a key from expo-secure-store.
 */
async function getDb(encryptionKey?: string): Promise<SQLite.SQLiteDatabase> {
  if (dbInstance) return dbInstance;

  const db = await SQLite.openDatabaseAsync(DB_Name, {
    // 🔑 Critical: Provide encryptionKey from secure source (e.g., expo-secure-store)
    ...(encryptionKey ? { encryptionKey } : {}),
    enableChangeListener: false,
    location: "default",
  });

  // Initialize table with WAL mode for durability
  await db.execAsync(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
      key TEXT PRIMARY KEY NOT NULL,
      value TEXT NOT NULL
    );
  `);

  dbInstance = db;
  return db;
}

/**
 * Deep-clones session objects to prevent mutation of stored state.
 * Handles special types like Map/Set/Uint8Array.
 */
function deepCloneSession(session: Session): Session {
  return {
    ...session,
    skippedMessageKeys: session.skippedMessageKeys
      ? new Map(session.skippedMessageKeys)
      : new Map(),
    receivedMessageIds: session.receivedMessageIds
      ? new Set(session.receivedMessageIds)
      : new Set(),
    // Add other structured types if needed (e.g., Uint8Array in keys)
  };
}

/**
 * Serializes values for SQLite storage.
 * Converts non-JSON-friendly types to serializable format.
 */
function serialize(value: any): string {
  return JSON.stringify(value, (key, val) => {
    if (val instanceof Uint8Array) {
      return { _type: "Uint8Array", data: Array.from(val) };
    }
    if (val instanceof Map) {
      return { _type: "Map", data: Array.from(val.entries()) };
    }
    if (val instanceof Set) {
      return { _type: "Set", data: Array.from(val) };
    }
    return val;
  });
}

/**
 * Deserializes values from SQLite.
 */
function deserialize(text: string): any {
  return JSON.parse(text, (key, val) => {
    if (val && typeof val === "object") {
      if (val._type === "Uint8Array") {
        return new Uint8Array(val.data);
      }
      if (val._type === "Map") {
        return new Map(val.data);
      }
      if (val._type === "Set") {
        return new Set(val.data);
      }
    }
    return val;
  });
}

export class SQLiteStorageAdapter implements StorageAdapter {
  private encryptionKey?: string;

  constructor(encryptionKey?: string) {
    this.encryptionKey = encryptionKey;
  }

  private async withDb<T>(
    fn: (db: SQLite.SQLiteDatabase) => Promise<T>,
  ): Promise<T> {
    const db = await getDb(this.encryptionKey);
    return fn(db);
  }

  async saveIdentity(identity: Identity): Promise<void> {
    await this.withDb(async (db) => {
      const stmt = await db.prepareAsync(
        `INSERT OR REPLACE INTO ${TABLE_NAME} (key, value) VALUES ($key, $value)`,
      );
      try {
        await stmt.executeAsync({
          $key: "identity",
          $value: serialize(identity),
        });
      } finally {
        await stmt.finalizeAsync();
      }
    });
  }

  async getIdentity(): Promise<Identity | null> {
    return this.withDb(async (db) => {
      const stmt = await db.prepareAsync(
        `SELECT value FROM ${TABLE_NAME} WHERE key = $key`,
      );
      try {
        const result = await stmt.executeAsync({ $key: "identity" });
        const row = await result.getFirstAsync<{ value: string }>();
        return row ? deserialize(row.value) : null;
      } finally {
        await stmt.finalizeAsync();
      }
    });
  }

  async deleteIdentity(): Promise<void> {
    await this.withDb(async (db) =>
      db.runAsync(`DELETE FROM ${TABLE_NAME} WHERE key = 'identity'`),
    );
  }

  async saveSession(sessionId: string, session: Session): Promise<void> {
    await this.withDb(async (db) => {
      // Clone to avoid external mutations
      const clonedSession = deepCloneSession(session);

      const stmt = await db.prepareAsync(
        `INSERT OR REPLACE INTO ${TABLE_NAME} (key, value) VALUES ($key, $value)`,
      );
      try {
        await stmt.executeAsync({
          $key: `session_${sessionId}`,
          $value: serialize(clonedSession),
        });
      } finally {
        await stmt.finalizeAsync();
      }

      // Update session list
      const list = await this.listSessions();
      if (!list.includes(sessionId)) {
        list.push(sessionId);
        await this.saveSessionList(list);
      }
    });
  }

  async getSession(sessionId: string): Promise<Session | null> {
    return this.withDb(async (db) => {
      const stmt = await db.prepareAsync(
        `SELECT value FROM ${TABLE_NAME} WHERE key = $key`,
      );
      try {
        const result = await stmt.executeAsync({
          $key: `session_${sessionId}`,
        });
        const row = await result.getFirstAsync<{ value: string }>();
        if (!row) return null;

        const session = deserialize(row.value);
        return deepCloneSession(session); // Return immutable copy
      } finally {
        await stmt.finalizeAsync();
      }
    });
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.withDb(async (db) => {
      await db.runAsync(`DELETE FROM ${TABLE_NAME} WHERE key = $key`, {
        $key: `session_${sessionId}`,
      });

      // Update session list
      const list = (await this.listSessions()).filter((id) => id !== sessionId);
      await this.saveSessionList(list);
    });
  }

  async listSessions(): Promise<string[]> {
    return this.withDb(async (db) => {
      const stmt = await db.prepareAsync(
        `SELECT value FROM ${TABLE_NAME} WHERE key = '_sessions_list'`,
      );
      try {
        const result = await stmt.executeAsync();
        const row = await result.getFirstAsync<{ value: string }>();
        return row ? deserialize(row.value) : [];
      } finally {
        await stmt.finalizeAsync();
      }
    });
  }

  private async saveSessionList(list: string[]): Promise<void> {
    await this.withDb(async (db) => {
      const stmt = await db.prepareAsync(
        `INSERT OR REPLACE INTO ${TABLE_NAME} (key, value) VALUES ($key, $value)`,
      );
      try {
        await stmt.executeAsync({
          $key: "_sessions_list",
          $value: serialize(list),
        });
      } finally {
        await stmt.finalizeAsync();
      }
    });
  }

  async deleteAllSessions(): Promise<void> {
    const sessions = await this.listSessions();
    await this.withDb(async (db) => {
      for (const sessionId of sessions) {
        await db.runAsync(`DELETE FROM ${TABLE_NAME} WHERE key = $key`, {
          $key: `session_${sessionId}`,
        });
      }
      await db.runAsync(
        `DELETE FROM ${TABLE_NAME} WHERE key = '_sessions_list'`,
      );
    });
  }
}
