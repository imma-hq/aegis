export class MemoryStorage {
    constructor() {
        Object.defineProperty(this, "identity", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        Object.defineProperty(this, "sessions", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Map()
        });
    }
    async saveIdentity(identity) {
        this.identity = identity;
    }
    async getIdentity() {
        return this.identity;
    }
    async deleteIdentity() {
        this.identity = null;
    }
    async saveSession(sessionId, session) {
        // Deep clone to avoid reference issues
        const sessionCopy = {
            ...session,
            skippedMessageKeys: new Map(session.skippedMessageKeys),
            receivedMessageIds: new Set(session.receivedMessageIds),
        };
        this.sessions.set(sessionId, sessionCopy);
    }
    async getSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session)
            return null;
        // Return a deep clone
        return {
            ...session,
            skippedMessageKeys: new Map(session.skippedMessageKeys),
            receivedMessageIds: new Set(session.receivedMessageIds),
        };
    }
    async deleteSession(sessionId) {
        this.sessions.delete(sessionId);
    }
    async listSessions() {
        return Array.from(this.sessions.keys());
    }
    async deleteAllSessions() {
        this.sessions.clear();
    }
}
