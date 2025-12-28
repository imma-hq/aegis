import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../src/storage";
import { Identity, Session } from "../src/types";

describe("MemoryStorage", () => {
  let storage: MemoryStorage;

  beforeEach(() => {
    storage = new MemoryStorage();
  });

  it("should save and retrieve identity", async () => {
    const identity: Identity = {
      kemKeyPair: {
        publicKey: new Uint8Array([1, 2, 3]),
        secretKey: new Uint8Array([4, 5, 6]),
      },
      dsaKeyPair: {
        publicKey: new Uint8Array([7, 8, 9]),
        secretKey: new Uint8Array([10, 11, 12]),
      },
      userId: "test-user",
      createdAt: Date.now(),
    };

    await storage.saveIdentity(identity);
    const retrieved = await storage.getIdentity();

    expect(retrieved).toBeDefined();
    expect(retrieved?.userId).toBe(identity.userId);
    expect(retrieved?.kemKeyPair.publicKey).toEqual(
      identity.kemKeyPair.publicKey,
    );
    expect(retrieved?.kemKeyPair.secretKey).toEqual(
      identity.kemKeyPair.secretKey,
    );
    expect(retrieved?.dsaKeyPair.publicKey).toEqual(
      identity.dsaKeyPair.publicKey,
    );
    expect(retrieved?.dsaKeyPair.secretKey).toEqual(
      identity.dsaKeyPair.secretKey,
    );
  });

  it("should delete identity", async () => {
    const identity: Identity = {
      kemKeyPair: {
        publicKey: new Uint8Array([1, 2, 3]),
        secretKey: new Uint8Array([4, 5, 6]),
      },
      dsaKeyPair: {
        publicKey: new Uint8Array([7, 8, 9]),
        secretKey: new Uint8Array([10, 11, 12]),
      },
      userId: "test-user",
      createdAt: Date.now(),
    };

    await storage.saveIdentity(identity);
    let retrieved = await storage.getIdentity();
    expect(retrieved).toBeDefined();

    await storage.deleteIdentity();
    retrieved = await storage.getIdentity();
    expect(retrieved).toBeNull();
  });

  it("should save and retrieve session", async () => {
    const sessionId = "test-session";
    const session: Session = {
      sessionId,
      peerUserId: "peer-user",
      peerDsaPublicKey: new Uint8Array([1, 2, 3]),
      rootKey: new Uint8Array([4, 5, 6]),
      currentRatchetKeyPair: {
        publicKey: new Uint8Array([7, 8, 9]),
        secretKey: new Uint8Array([10, 11, 12]),
      },
      peerRatchetPublicKey: new Uint8Array([13, 14, 15]),
      sendingChain: {
        chainKey: new Uint8Array([16, 17, 18]),
        messageNumber: 0,
      },
      receivingChain: {
        chainKey: new Uint8Array([19, 20, 21]),
        messageNumber: 0,
      },
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
      replayWindowSize: 100,
      lastProcessedTimestamp: Date.now(),
      receivedMessageIds: new Set(),
    };

    await storage.saveSession(sessionId, session);
    const retrieved = await storage.getSession(sessionId);

    expect(retrieved).toBeDefined();
    expect(retrieved?.sessionId).toBe(sessionId);
    expect(retrieved?.peerUserId).toBe(session.peerUserId);
    expect(retrieved?.rootKey).toEqual(session.rootKey);
    expect(retrieved?.currentRatchetKeyPair?.publicKey).toEqual(
      session.currentRatchetKeyPair?.publicKey,
    );
    expect(retrieved?.currentRatchetKeyPair?.secretKey).toEqual(
      session.currentRatchetKeyPair?.secretKey,
    );
    expect(retrieved?.receivingChain?.chainKey).toEqual(
      session.receivingChain?.chainKey,
    );
    expect(retrieved?.receivingChain?.messageNumber).toEqual(
      session.receivingChain?.messageNumber,
    );
    expect(retrieved?.skippedMessageKeys).toEqual(session.skippedMessageKeys);
    expect(retrieved?.receivedMessageIds).toEqual(session.receivedMessageIds);
  });

  it("should delete session", async () => {
    const sessionId = "test-session";
    const session: Session = {
      sessionId,
      peerUserId: "peer-user",
      peerDsaPublicKey: new Uint8Array([1, 2, 3]),
      rootKey: new Uint8Array([4, 5, 6]),
      currentRatchetKeyPair: {
        publicKey: new Uint8Array([7, 8, 9]),
        secretKey: new Uint8Array([10, 11, 12]),
      },
      peerRatchetPublicKey: new Uint8Array([13, 14, 15]),
      sendingChain: {
        chainKey: new Uint8Array([16, 17, 18]),
        messageNumber: 0,
      },
      receivingChain: {
        chainKey: new Uint8Array([19, 20, 21]),
        messageNumber: 0,
      },
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
      replayWindowSize: 100,
      lastProcessedTimestamp: Date.now(),
      receivedMessageIds: new Set(),
    };

    await storage.saveSession(sessionId, session);
    let retrieved = await storage.getSession(sessionId);
    expect(retrieved).toBeDefined();

    await storage.deleteSession(sessionId);
    retrieved = await storage.getSession(sessionId);
    expect(retrieved).toBeNull();
  });

  it("should list sessions", async () => {
    const session1: Session = {
      sessionId: "session-1",
      peerUserId: "peer-user-1",
      peerDsaPublicKey: new Uint8Array([1, 2, 3]),
      rootKey: new Uint8Array([4, 5, 6]),
      currentRatchetKeyPair: {
        publicKey: new Uint8Array([7, 8, 9]),
        secretKey: new Uint8Array([10, 11, 12]),
      },
      peerRatchetPublicKey: new Uint8Array([13, 14, 15]),
      sendingChain: {
        chainKey: new Uint8Array([16, 17, 18]),
        messageNumber: 0,
      },
      receivingChain: {
        chainKey: new Uint8Array([19, 20, 21]),
        messageNumber: 0,
      },
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
      replayWindowSize: 100,
      lastProcessedTimestamp: Date.now(),
      receivedMessageIds: new Set(),
    };

    const session2: Session = {
      ...session1,
      sessionId: "session-2",
      peerUserId: "peer-user-2",
    };

    await storage.saveSession("session-1", session1);
    await storage.saveSession("session-2", session2);

    const sessionIds = await storage.listSessions();
    expect(sessionIds).toContain("session-1");
    expect(sessionIds).toContain("session-2");
    expect(sessionIds.length).toBe(2);
  });

  it("should delete all sessions", async () => {
    const session1: Session = {
      sessionId: "session-1",
      peerUserId: "peer-user-1",
      peerDsaPublicKey: new Uint8Array([1, 2, 3]),
      rootKey: new Uint8Array([4, 5, 6]),
      currentRatchetKeyPair: {
        publicKey: new Uint8Array([7, 8, 9]),
        secretKey: new Uint8Array([10, 11, 12]),
      },
      peerRatchetPublicKey: new Uint8Array([13, 14, 15]),
      sendingChain: {
        chainKey: new Uint8Array([16, 17, 18]),
        messageNumber: 0,
      },
      receivingChain: {
        chainKey: new Uint8Array([19, 20, 21]),
        messageNumber: 0,
      },
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
      replayWindowSize: 100,
      lastProcessedTimestamp: Date.now(),
      receivedMessageIds: new Set(),
    };

    const session2: Session = {
      ...session1,
      sessionId: "session-2",
      peerUserId: "peer-user-2",
    };

    await storage.saveSession("session-1", session1);
    await storage.saveSession("session-2", session2);

    let sessionIds = await storage.listSessions();
    expect(sessionIds.length).toBe(2);

    await storage.deleteAllSessions();
    sessionIds = await storage.listSessions();
    expect(sessionIds.length).toBe(0);
  });

  it("should handle deep cloning of session objects", async () => {
    const sessionId = "test-session";
    const session: Session = {
      sessionId,
      peerUserId: "peer-user",
      peerDsaPublicKey: new Uint8Array([1, 2, 3]),
      rootKey: new Uint8Array([4, 5, 6]),
      currentRatchetKeyPair: {
        publicKey: new Uint8Array([7, 8, 9]),
        secretKey: new Uint8Array([10, 11, 12]),
      },
      peerRatchetPublicKey: new Uint8Array([13, 14, 15]),
      sendingChain: {
        chainKey: new Uint8Array([16, 17, 18]),
        messageNumber: 0,
      },
      receivingChain: {
        chainKey: new Uint8Array([19, 20, 21]),
        messageNumber: 0,
      },
      previousSendingChainLength: 0,
      skippedMessageKeys: new Map([
        [
          "key1",
          { messageKey: new Uint8Array([1, 2, 3]), timestamp: Date.now() },
        ],
      ]),
      highestReceivedMessageNumber: -1,
      maxSkippedMessages: 100,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      isInitiator: true,
      ratchetCount: 0,
      state: "CREATED",
      confirmed: false,
      replayWindowSize: 100,
      lastProcessedTimestamp: Date.now(),
      receivedMessageIds: new Set(["msg1", "msg2"]),
    };

    await storage.saveSession(sessionId, session);
    const retrieved = await storage.getSession(sessionId);

    // Verify that the retrieved object is a deep clone
    expect(retrieved).not.toBe(session);
    expect(retrieved?.skippedMessageKeys).not.toBe(session.skippedMessageKeys);
    expect(retrieved?.receivedMessageIds).not.toBe(session.receivedMessageIds);

    // Verify that changes to the retrieved object don't affect the original
    retrieved!.skippedMessageKeys.set("newKey", {
      messageKey: new Uint8Array([4, 5, 6]),
      timestamp: Date.now(),
    });
    retrieved!.receivedMessageIds.add("newMsg");

    expect(session.skippedMessageKeys.has("newKey")).toBe(false);
    expect(session.receivedMessageIds.has("newMsg")).toBe(false);
  });
});
