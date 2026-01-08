// electron.ts
import type { StorageAdapter, Identity, Session } from "./types";
import Database from "better-sqlite3";
import * as keytar from "keytar";
import { app } from "electron";
import * as path from "path";
import { randomBytes } from "crypto";

// --- Secure Key Management ---
const SERVICE = "com.yourapp.aegis";
const ACCOUNT = "sqlcipher_key";

async function getOrCreateDbKey(): Promise<string> {
  let key = await keytar.getPassword(SERVICE, ACCOUNT);
  if (!key) {
    key = randomBytes(32).toString("hex");
    await keytar.setPassword(SERVICE, ACCOUNT, key);
  }
  return key;
}

// --- Database Setup ---
const userDataPath = app.getPath("userData");
const DB_PATH = path.join(userDataPath, "aegis_e2ee.db");

let dbInstance: Database | null = null;

async function getDb(): Promise<Database> {
  if (dbInstance) return dbInstance;

  const key = await getOrCreateDbKey();
  const db = new Database(DB_PATH, {
    timeout: 30000,
    cipher: "sqlcipher",
    key,
  });

  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS aegis_storage (
      key TEXT PRIMARY KEY NOT NULL,
      value TEXT NOT NULL
    );
  `);

  dbInstance = db;
  return db;
}

// --- Serialization ---
function serialize(value: any): string {
  return JSON.stringify(value, (k, v) => {
    if (v instanceof Uint8Array)
      return { _type: "Uint8Array", data: Array.from(v) };
    if (v instanceof Map)
      return { _type: "Map", data: Array.from(v.entries()) };
    if (v instanceof Set) return { _type: "Set", data: Array.from(v) };
    return v;
  });
}

function deserialize(text: string): any {
  return JSON.parse(text, (k, v) => {
    if (v && typeof v === "object") {
      if (v._type === "Uint8Array") return new Uint8Array(v.data);
      if (v._type === "Map") return new Map(v.data);
      if (v._type === "Set") return new Set(v.data);
    }
    return v;
  });
}

// --- Deep Clone ---
function deepCloneSession(session: Session): Session {
  return {
    ...session,
    skippedMessageKeys: new Map(session.skippedMessageKeys),
    receivedMessageIds: new Set(session.receivedMessageIds),
  };
}

// --- Storage Adapter ---
export class ElectronStorageAdapter implements StorageAdapter {
  async saveIdentity(identity: Identity): Promise<void> {
    const db = await getDb();
    db.prepare(
      "INSERT OR REPLACE INTO aegis_storage (key, value) VALUES (?, ?)",
    ).run("identity", serialize(identity));
  }

  async getIdentity(): Promise<Identity | null> {
    const db = await getDb();
    const row = db
      .prepare("SELECT value FROM aegis_storage WHERE key = ?")
      .get("identity");
    return row ? deserialize(row.value) : null;
  }

  async deleteIdentity(): Promise<void> {
    const db = await getDb();
    db.prepare("DELETE FROM aegis_storage WHERE key = ?").run("identity");
  }

  async saveSession(sessionId: string, session: Session): Promise<void> {
    const db = await getDb();
    db.prepare(
      "INSERT OR REPLACE INTO aegis_storage (key, value) VALUES (?, ?)",
    ).run(`session_${sessionId}`, serialize(deepCloneSession(session)));

    const list = await this.listSessions();
    if (!list.includes(sessionId)) {
      db.prepare(
        "INSERT OR REPLACE INTO aegis_storage (key, value) VALUES (?, ?)",
      ).run("_sessions_list", serialize([...list, sessionId]));
    }
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const db = await getDb();
    const row = db
      .prepare("SELECT value FROM aegis_storage WHERE key = ?")
      .get(`session_${sessionId}`);
    return row ? deepCloneSession(deserialize(row.value)) : null;
  }

  async deleteSession(sessionId: string): Promise<void> {
    const db = await getDb();
    db.prepare("DELETE FROM aegis_storage WHERE key = ?").run(
      `session_${sessionId}`,
    );

    const list = (await this.listSessions()).filter((id) => id !== sessionId);
    db.prepare(
      "INSERT OR REPLACE INTO aegis_storage (key, value) VALUES (?, ?)",
    ).run("_sessions_list", serialize(list));
  }

  async listSessions(): Promise<string[]> {
    const db = await getDb();
    const row = db
      .prepare("SELECT value FROM aegis_storage WHERE key = ?")
      .get("_sessions_list");
    return row ? deserialize(row.value) : [];
  }

  async deleteAllSessions(): Promise<void> {
    const db = await getDb();
    const list = await this.listSessions();
    const deleteStmt = db.prepare("DELETE FROM aegis_storage WHERE key = ?");
    for (const id of list) {
      deleteStmt.run(`session_${id}`);
    }
    db.prepare("DELETE FROM aegis_storage WHERE key = ?").run("_sessions_list");
  }
}
