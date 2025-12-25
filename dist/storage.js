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
// Example: IndexedDB storage adapter for browsers
export class IndexedDBStorage {
    constructor() {
        Object.defineProperty(this, "dbName", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: "e2ee_storage"
        });
        Object.defineProperty(this, "version", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 2
        }); // Incremented version for new schema
        Object.defineProperty(this, "db", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
    }
    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                resolve();
            };
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains("identity")) {
                    db.createObjectStore("identity");
                }
                if (!db.objectStoreNames.contains("sessions")) {
                    db.createObjectStore("sessions");
                }
            };
        });
    }
    async ensureDB() {
        if (!this.db) {
            await this.init();
        }
        return this.db;
    }
    async saveIdentity(identity) {
        const db = await this.ensureDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("identity", "readwrite");
            const store = tx.objectStore("identity");
            const request = store.put(this.serializeIdentity(identity), "current");
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
    async getIdentity() {
        const db = await this.ensureDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("identity", "readonly");
            const store = tx.objectStore("identity");
            const request = store.get("current");
            request.onsuccess = () => {
                const data = request.result;
                resolve(data ? this.deserializeIdentity(data) : null);
            };
            request.onerror = () => reject(request.error);
        });
    }
    async deleteIdentity() {
        const db = await this.ensureDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("identity", "readwrite");
            const store = tx.objectStore("identity");
            const request = store.delete("current");
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
    async saveSession(sessionId, session) {
        const db = await this.ensureDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("sessions", "readwrite");
            const store = tx.objectStore("sessions");
            const request = store.put(this.serializeSession(session), sessionId);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
    async getSession(sessionId) {
        const db = await this.ensureDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("sessions", "readonly");
            const store = tx.objectStore("sessions");
            const request = store.get(sessionId);
            request.onsuccess = () => {
                const data = request.result;
                resolve(data ? this.deserializeSession(data) : null);
            };
            request.onerror = () => reject(request.error);
        });
    }
    async deleteSession(sessionId) {
        const db = await this.ensureDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("sessions", "readwrite");
            const store = tx.objectStore("sessions");
            const request = store.delete(sessionId);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
    async listSessions() {
        const db = await this.ensureDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("sessions", "readonly");
            const store = tx.objectStore("sessions");
            const request = store.getAllKeys();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }
    async deleteAllSessions() {
        const db = await this.ensureDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction("sessions", "readwrite");
            const store = tx.objectStore("sessions");
            const request = store.clear();
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
    // Serialization helpers for IndexedDB
    serializeIdentity(identity) {
        return {
            ...identity,
            kemKeyPair: {
                publicKey: Array.from(identity.kemKeyPair.publicKey),
                secretKey: Array.from(identity.kemKeyPair.secretKey),
            },
            dsaKeyPair: {
                publicKey: Array.from(identity.dsaKeyPair.publicKey),
                secretKey: Array.from(identity.dsaKeyPair.secretKey),
            },
            preKeySecret: identity.preKeySecret
                ? Array.from(identity.preKeySecret)
                : undefined,
        };
    }
    deserializeIdentity(data) {
        return {
            ...data,
            kemKeyPair: {
                publicKey: new Uint8Array(data.kemKeyPair.publicKey),
                secretKey: new Uint8Array(data.kemKeyPair.secretKey),
            },
            dsaKeyPair: {
                publicKey: new Uint8Array(data.dsaKeyPair.publicKey),
                secretKey: new Uint8Array(data.dsaKeyPair.secretKey),
            },
            preKeySecret: data.preKeySecret
                ? new Uint8Array(data.preKeySecret)
                : undefined,
        };
    }
    serializeSession(session) {
        return {
            ...session,
            rootKey: Array.from(session.rootKey),
            peerDsaPublicKey: Array.from(session.peerDsaPublicKey),
            currentRatchetKeyPair: session.currentRatchetKeyPair
                ? {
                    publicKey: Array.from(session.currentRatchetKeyPair.publicKey),
                    secretKey: Array.from(session.currentRatchetKeyPair.secretKey),
                }
                : null,
            peerRatchetPublicKey: session.peerRatchetPublicKey
                ? Array.from(session.peerRatchetPublicKey)
                : null,
            sendingChain: session.sendingChain
                ? {
                    chainKey: Array.from(session.sendingChain.chainKey),
                    messageNumber: session.sendingChain.messageNumber,
                }
                : null,
            receivingChain: session.receivingChain
                ? {
                    chainKey: Array.from(session.receivingChain.chainKey),
                    messageNumber: session.receivingChain.messageNumber,
                }
                : null,
            previousSendingChainLength: session.previousSendingChainLength,
            highestReceivedMessageNumber: session.highestReceivedMessageNumber,
            maxSkippedMessages: session.maxSkippedMessages,
            createdAt: session.createdAt,
            lastUsed: session.lastUsed,
            isInitiator: session.isInitiator,
            ratchetCount: session.ratchetCount,
            state: session.state,
            confirmed: session.confirmed,
            replayWindowSize: session.replayWindowSize,
            lastProcessedTimestamp: session.lastProcessedTimestamp,
            confirmationMac: session.confirmationMac
                ? Array.from(session.confirmationMac)
                : undefined,
            pendingRatchetCiphertext: session.pendingRatchetCiphertext
                ? Array.from(session.pendingRatchetCiphertext)
                : undefined,
            skippedMessageKeys: Array.from(session.skippedMessageKeys.entries()).map(([key, value]) => [
                key,
                {
                    messageKey: Array.from(value.messageKey),
                    timestamp: value.timestamp,
                },
            ]),
            // Serialize Set as Array
            receivedMessageIds: Array.from(session.receivedMessageIds),
        };
    }
    deserializeSession(data) {
        return {
            ...data,
            rootKey: new Uint8Array(data.rootKey),
            peerDsaPublicKey: new Uint8Array(data.peerDsaPublicKey),
            currentRatchetKeyPair: data.currentRatchetKeyPair
                ? {
                    publicKey: new Uint8Array(data.currentRatchetKeyPair.publicKey),
                    secretKey: new Uint8Array(data.currentRatchetKeyPair.secretKey),
                }
                : null,
            peerRatchetPublicKey: data.peerRatchetPublicKey
                ? new Uint8Array(data.peerRatchetPublicKey)
                : null,
            sendingChain: data.sendingChain
                ? {
                    chainKey: new Uint8Array(data.sendingChain.chainKey),
                    messageNumber: data.sendingChain.messageNumber,
                }
                : null,
            receivingChain: data.receivingChain
                ? {
                    chainKey: new Uint8Array(data.receivingChain.chainKey),
                    messageNumber: data.receivingChain.messageNumber,
                }
                : null,
            skippedMessageKeys: new Map((data.skippedMessageKeys || []).map(([key, value]) => [
                key,
                {
                    messageKey: new Uint8Array(value.messageKey),
                    timestamp: value.timestamp,
                },
            ])),
            // Deserialize Array back to Set
            receivedMessageIds: new Set(data.receivedMessageIds || []),
            confirmationMac: data.confirmationMac
                ? new Uint8Array(data.confirmationMac)
                : undefined,
            pendingRatchetCiphertext: data.pendingRatchetCiphertext
                ? new Uint8Array(data.pendingRatchetCiphertext)
                : undefined,
        };
    }
}
