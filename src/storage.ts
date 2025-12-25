// src/adapters/storage.ts
import type { StorageAdapter, Identity, Session } from "./types";

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

// Example: IndexedDB storage adapter for browsers
export class IndexedDBStorage implements StorageAdapter {
  private dbName = "e2ee_storage";
  private version = 2; // Incremented version for new schema
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        if (!db.objectStoreNames.contains("identity")) {
          db.createObjectStore("identity");
        }

        if (!db.objectStoreNames.contains("sessions")) {
          db.createObjectStore("sessions");
        }
      };
    });
  }

  private async ensureDB(): Promise<IDBDatabase> {
    if (!this.db) {
      await this.init();
    }
    return this.db!;
  }

  async saveIdentity(identity: Identity): Promise<void> {
    const db = await this.ensureDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("identity", "readwrite");
      const store = tx.objectStore("identity");
      const request = store.put(this.serializeIdentity(identity), "current");

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async getIdentity(): Promise<Identity | null> {
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

  async deleteIdentity(): Promise<void> {
    const db = await this.ensureDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("identity", "readwrite");
      const store = tx.objectStore("identity");
      const request = store.delete("current");

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async saveSession(sessionId: string, session: Session): Promise<void> {
    const db = await this.ensureDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("sessions", "readwrite");
      const store = tx.objectStore("sessions");
      const request = store.put(this.serializeSession(session), sessionId);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async getSession(sessionId: string): Promise<Session | null> {
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

  async deleteSession(sessionId: string): Promise<void> {
    const db = await this.ensureDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("sessions", "readwrite");
      const store = tx.objectStore("sessions");
      const request = store.delete(sessionId);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async listSessions(): Promise<string[]> {
    const db = await this.ensureDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("sessions", "readonly");
      const store = tx.objectStore("sessions");
      const request = store.getAllKeys();

      request.onsuccess = () => resolve(request.result as string[]);
      request.onerror = () => reject(request.error);
    });
  }

  async deleteAllSessions(): Promise<void> {
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
  private serializeIdentity(identity: Identity): any {
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

  private deserializeIdentity(data: any): Identity {
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

  private serializeSession(session: Session): any {
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
      skippedMessageKeys: Array.from(session.skippedMessageKeys.entries()).map(
        ([key, value]) => [
          key,
          {
            messageKey: Array.from(value.messageKey),
            timestamp: value.timestamp,
          },
        ],
      ),
      // Serialize Set as Array
      receivedMessageIds: Array.from(session.receivedMessageIds),
    };
  }

  private deserializeSession(data: any): Session {
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
      skippedMessageKeys: new Map(
        (data.skippedMessageKeys || []).map(([key, value]: [string, any]) => [
          key,
          {
            messageKey: new Uint8Array(value.messageKey),
            timestamp: value.timestamp,
          },
        ]),
      ),
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
