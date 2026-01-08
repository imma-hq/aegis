import type { StorageAdapter, Identity, Session } from "../../../src/types"; // or @immahq/aegis/aegis.d.ts

// Deep clone helper
function deepCloneSession(session: Session): Session {
  return {
    ...session,
    skippedMessageKeys: new Map(session.skippedMessageKeys),
    receivedMessageIds: new Set(session.receivedMessageIds),
  };
}

// Serialize/deserialize
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

export class TauriStorageAdapter implements StorageAdapter {
  async saveIdentity(identity: Identity): Promise<void> {
    await window.__TAURI__.invoke("save_identity", {
      identity: serialize(identity),
    });
  }

  async getIdentity(): Promise<Identity | null> {
    const raw = await window.__TAURI__.invoke<string | null>("get_identity");
    return raw ? deserialize(raw) : null;
  }

  async deleteIdentity(): Promise<void> {
    await window.__TAURI__.invoke("delete_identity");
  }

  async saveSession(sessionId: string, session: Session): Promise<void> {
    await window.__TAURI__.invoke("save_session", {
      sessionId,
      session: serialize(deepCloneSession(session)),
    });
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const raw = await window.__TAURI__.invoke<string | null>("get_session", {
      sessionId,
    });
    return raw ? deepCloneSession(deserialize(raw)) : null;
  }

  async deleteSession(sessionId: string): Promise<void> {
    await window.__TAURI__.invoke("delete_session", { sessionId });
  }

  async listSessions(): Promise<string[]> {
    return await window.__TAURI__.invoke("list_sessions");
  }

  async deleteAllSessions(): Promise<void> {
    await window.__TAURI__.invoke("delete_all_sessions");
  }
}
