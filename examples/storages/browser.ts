// storage/BrowserStorageAdapter.ts
import type { StorageAdapter, Identity, Session } from "../../src/types"; // or @immahq/aegis/aegis.d.ts

const DB_NAME = "aegis";
const STORE_NAME = "e2ee";

async function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);

    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
  });
}

function withStore<T>(
  mode: IDBTransactionMode,
  callback: (store: IDBObjectStore) => Promise<T>,
): Promise<T> {
  return new Promise(async (resolve, reject) => {
    const db = await openDb();
    const tx = db.transaction(STORE_NAME, mode);
    tx.onerror = () => reject(tx.error);
    tx.oncomplete = () => resolve(undefined as any);

    const result = await callback(tx.objectStore(STORE_NAME));
    // If callback returns a value, resolve with it
    if (result !== undefined) resolve(result);
  });
}

// Deep clone helper (same as MemoryStorage)
function deepCloneSession(session: Session): Session {
  return {
    ...session,
    skippedMessageKeys: new Map(session.skippedMessageKeys),
    receivedMessageIds: new Set(session.receivedMessageIds),
  };
}

export class BrowserStorageAdapter implements StorageAdapter {
  async saveIdentity(identity: Identity): Promise<void> {
    await withStore("readwrite", async (store) => {
      store.put(identity, "identity");
    });
  }

  async getIdentity(): Promise<Identity | null> {
    return withStore("readonly", async (store) => {
      return (await store.get("identity")) || null;
    });
  }

  async deleteIdentity(): Promise<void> {
    await withStore("readwrite", async (store) => {
      store.delete("identity");
    });
  }

  async saveSession(sessionId: string, session: Session): Promise<void> {
    await withStore("readwrite", async (store) => {
      store.put(deepCloneSession(session), `session_${sessionId}`);

      // Update session list
      const list = (await store.get("_sessions_list")) || [];
      if (!list.includes(sessionId)) {
        store.put([...list, sessionId], "_sessions_list");
      }
    });
  }

  async getSession(sessionId: string): Promise<Session | null> {
    return withStore("readonly", async (store) => {
      const session = await store.get(`session_${sessionId}`);
      return session ? deepCloneSession(session) : null;
    });
  }

  async deleteSession(sessionId: string): Promise<void> {
    await withStore("readwrite", async (store) => {
      store.delete(`session_${sessionId}`);
      const list: string[] = (await store.get("_sessions_list")) || [];
      store.put(
        list.filter((id) => id !== sessionId),
        "_sessions_list",
      );
    });
  }

  async listSessions(): Promise<string[]> {
    return withStore("readonly", async (store) => {
      return (await store.get("_sessions_list")) || [];
    });
  }

  async deleteAllSessions(): Promise<void> {
    await withStore("readwrite", async (store) => {
      const list: string[] = (await store.get("_sessions_list")) || [];
      for (const id of list) {
        store.delete(`session_${id}`);
      }
      store.delete("_sessions_list");
    });
  }
}
