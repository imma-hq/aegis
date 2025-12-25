import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../src/storage";
import type { Identity, Session } from "../src/types";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

describe("MemoryStorage", () => {
  let storage: MemoryStorage;
  let mockIdentity: Identity;
  let mockSession: Session;

  beforeEach(() => {
    storage = new MemoryStorage();

    const kemKeyPair = ml_kem768.keygen();
    const dsaKeyPair = ml_dsa65.keygen();

    mockIdentity = {
      kemKeyPair,
      dsaKeyPair,
      userId: "test-user-id",
      createdAt: Date.now(),
      preKeySecret: kemKeyPair.secretKey,
    };

    mockSession = {
      sessionId: "test-session-id",
      peerUserId: "peer-user-id",
      peerDsaPublicKey: new Uint8Array(32),
      rootKey: new Uint8Array(32),
      currentRatchetKeyPair: ml_kem768.keygen(),
      peerRatchetPublicKey: null,
      sendingChain: {
        chainKey: new Uint8Array(32),
        messageNumber: 0,
      },
      receivingChain: null,
      previousSendingChainLength: 0,
      skippedMessageKeys: new Map(),
      highestReceivedMessageNumber: -1,
      maxSkippedMessages: 100,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      isInitiator: true,
      ratchetCount: 0,
      state: "CREATED",
      confirmed: false,
      receivedMessageIds: new Set(),
      replayWindowSize: 100,
      lastProcessedTimestamp: Date.now(),
    };
  });

  describe("Identity Management", () => {
    it("should save and retrieve identity", async () => {
      await storage.saveIdentity(mockIdentity);
      const retrieved = await storage.getIdentity();

      expect(retrieved).not.toBeNull();
      expect(retrieved!.userId).toBe(mockIdentity.userId);
      expect(retrieved!.kemKeyPair.publicKey).toEqual(
        mockIdentity.kemKeyPair.publicKey,
      );
    });

    it("should return null when no identity exists", async () => {
      const retrieved = await storage.getIdentity();
      expect(retrieved).toBeNull();
    });

    it("should delete identity", async () => {
      await storage.saveIdentity(mockIdentity);
      await storage.deleteIdentity();

      const retrieved = await storage.getIdentity();
      expect(retrieved).toBeNull();
    });

    it("should overwrite existing identity", async () => {
      await storage.saveIdentity(mockIdentity);

      const newIdentity = { ...mockIdentity, userId: "new-user-id" };
      await storage.saveIdentity(newIdentity);

      const retrieved = await storage.getIdentity();
      expect(retrieved!.userId).toBe("new-user-id");
    });
  });

  describe("Session Management", () => {
    it("should save and retrieve session", async () => {
      await storage.saveSession(mockSession.sessionId, mockSession);
      const retrieved = await storage.getSession(mockSession.sessionId);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.sessionId).toBe(mockSession.sessionId);
      expect(retrieved!.peerUserId).toBe(mockSession.peerUserId);
    });

    it("should return null for non-existent session", async () => {
      const retrieved = await storage.getSession("non-existent");
      expect(retrieved).toBeNull();
    });

    it("should delete session", async () => {
      await storage.saveSession(mockSession.sessionId, mockSession);
      await storage.deleteSession(mockSession.sessionId);

      const retrieved = await storage.getSession(mockSession.sessionId);
      expect(retrieved).toBeNull();
    });

    it("should list all session IDs", async () => {
      await storage.saveSession("session-1", mockSession);
      await storage.saveSession("session-2", {
        ...mockSession,
        sessionId: "session-2",
      });
      await storage.saveSession("session-3", {
        ...mockSession,
        sessionId: "session-3",
      });

      const sessionIds = await storage.listSessions();
      expect(sessionIds).toHaveLength(3);
      expect(sessionIds).toContain("session-1");
      expect(sessionIds).toContain("session-2");
      expect(sessionIds).toContain("session-3");
    });

    it("should delete all sessions", async () => {
      await storage.saveSession("session-1", mockSession);
      await storage.saveSession("session-2", {
        ...mockSession,
        sessionId: "session-2",
      });

      await storage.deleteAllSessions();

      const sessionIds = await storage.listSessions();
      expect(sessionIds).toHaveLength(0);
    });

    it("should handle skipped message keys in sessions", async () => {
      mockSession.skippedMessageKeys.set("key-1", {
        messageKey: new Uint8Array(32).fill(1),
        timestamp: Date.now(),
      });
      mockSession.skippedMessageKeys.set("key-2", {
        messageKey: new Uint8Array(32).fill(2),
        timestamp: Date.now(),
      });

      await storage.saveSession(mockSession.sessionId, mockSession);
      const retrieved = await storage.getSession(mockSession.sessionId);

      expect(retrieved!.skippedMessageKeys.size).toBe(2);
      expect(retrieved!.skippedMessageKeys.has("key-1")).toBe(true);
      expect(retrieved!.skippedMessageKeys.has("key-2")).toBe(true);
    });

    it("should handle received message IDs in sessions", async () => {
      mockSession.receivedMessageIds.add("msg-1");
      mockSession.receivedMessageIds.add("msg-2");
      mockSession.receivedMessageIds.add("msg-3");

      await storage.saveSession(mockSession.sessionId, mockSession);
      const retrieved = await storage.getSession(mockSession.sessionId);

      expect(retrieved!.receivedMessageIds.size).toBe(3);
      expect(retrieved!.receivedMessageIds.has("msg-1")).toBe(true);
      expect(retrieved!.receivedMessageIds.has("msg-2")).toBe(true);
      expect(retrieved!.receivedMessageIds.has("msg-3")).toBe(true);
    });

    it("should deep clone sessions to prevent reference issues", async () => {
      await storage.saveSession(mockSession.sessionId, mockSession);
      const retrieved = await storage.getSession(mockSession.sessionId);

      // Modify retrieved session
      retrieved!.peerUserId = "modified-peer-id";
      retrieved!.skippedMessageKeys.set("new-key", {
        messageKey: new Uint8Array(32),
        timestamp: Date.now(),
      });

      // Original should be unchanged
      const original = await storage.getSession(mockSession.sessionId);
      expect(original!.peerUserId).toBe("peer-user-id");
      expect(original!.skippedMessageKeys.has("new-key")).toBe(false);
    });
  });

  describe("Data Integrity", () => {
    it("should preserve Uint8Array data", async () => {
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      mockIdentity.kemKeyPair.publicKey = testData;

      await storage.saveIdentity(mockIdentity);
      const retrieved = await storage.getIdentity();

      expect(retrieved!.kemKeyPair.publicKey).toEqual(testData);
      expect(retrieved!.kemKeyPair.publicKey).toBeInstanceOf(Uint8Array);
    });

    it("should preserve null values", async () => {
      mockSession.peerRatchetPublicKey = null;
      mockSession.receivingChain = null;

      await storage.saveSession(mockSession.sessionId, mockSession);
      const retrieved = await storage.getSession(mockSession.sessionId);

      expect(retrieved!.peerRatchetPublicKey).toBeNull();
      expect(retrieved!.receivingChain).toBeNull();
    });

    it("should preserve timestamps", async () => {
      const now = Date.now();
      mockSession.createdAt = now;
      mockSession.lastUsed = now;

      await storage.saveSession(mockSession.sessionId, mockSession);
      const retrieved = await storage.getSession(mockSession.sessionId);

      expect(retrieved!.createdAt).toBe(now);
      expect(retrieved!.lastUsed).toBe(now);
    });
  });
});

// Note: IndexedDB tests would require a browser environment or jsdom
// These can be added if you need to test IndexedDBStorage specifically
describe("IndexedDBStorage", () => {
  it("should be tested in browser environment", () => {
    // Placeholder for browser-based tests
    expect(true).toBe(true);
  });
});
