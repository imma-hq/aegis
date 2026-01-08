import type { StorageAdapter, Identity, Session } from "./types";

//Default storage adapter for the SDK. Stores data in memory.
export class MemoryStorage implements StorageAdapter {
  private identity: Identity | null = null;
  private sessions = new Map<string, Session>();

  async saveIdentity(identity: Identity): Promise<void> {
    this.identity = identity;
  }

  async getIdentity(): Promise<Identity | null> {
    return this.identity;
  }

  async deleteIdentity(): Promise<void> {
    this.identity = null;
  }

  async saveSession(sessionId: string, session: Session): Promise<void> {
    // Deep clone to avoid reference issues
    const sessionCopy: Session = {
      ...session,
      skippedMessageKeys: new Map(session.skippedMessageKeys),
      receivedMessageIds: new Set(session.receivedMessageIds),
    };
    this.sessions.set(sessionId, sessionCopy);
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    // Return a deep clone
    return {
      ...session,
      skippedMessageKeys: new Map(session.skippedMessageKeys),
      receivedMessageIds: new Set(session.receivedMessageIds),
    };
  }

  async deleteSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  async listSessions(): Promise<string[]> {
    return Array.from(this.sessions.keys());
  }

  async deleteAllSessions(): Promise<void> {
    this.sessions.clear();
  }
}
