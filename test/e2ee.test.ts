import { describe, it, expect, beforeEach } from "vitest";
import { Aegis, MemoryStorage } from "../src/index";
import {
  ERRORS,
  RATCHET_AFTER_MESSAGES,
  RATCHET_INTERVAL,
} from "../src/constants";

describe("E2EE", () => {
  let alice: Aegis;
  let bob: Aegis;

  beforeEach(() => {
    alice = new Aegis(new MemoryStorage());
    bob = new Aegis(new MemoryStorage());
  });

  it("should initialize correctly with storage adapter", async () => {
    expect(alice).toBeDefined();
    expect(bob).toBeDefined();
  });

  describe("Identity Management", () => {
    it("should create a new identity", async () => {
      const result = await alice.createIdentity();

      expect(result).toBeDefined();
      expect(result.identity).toBeDefined();
      expect(result.publicBundle).toBeDefined();
      expect(result.identity.userId).toBeDefined();
      expect(result.identity.kemKeyPair).toBeDefined();
      expect(result.identity.dsaKeyPair).toBeDefined();
      expect(result.publicBundle.userId).toEqual(result.identity.userId);
      expect(result.publicBundle.kemPublicKey).toEqual(
        result.identity.kemKeyPair.publicKey,
      );
      expect(result.publicBundle.dsaPublicKey).toEqual(
        result.identity.dsaKeyPair.publicKey,
      );
    });

    it("should retrieve public bundle", async () => {
      const { publicBundle } = await alice.createIdentity();
      const retrievedBundle = await alice.getPublicBundle();

      expect(retrievedBundle).toEqual(publicBundle);
    });

    it("should rotate identity with new userId", async () => {
      const initialIdentity = await alice.createIdentity();
      const rotatedResult = await alice.rotateIdentity("new-user-id");

      expect(rotatedResult.identity.userId).not.toEqual(
        initialIdentity.identity.userId,
      );
      expect(rotatedResult.publicBundle.userId).not.toEqual(
        initialIdentity.publicBundle.userId,
      );
    });

    it("should rotate identity with same userId", async () => {
      const initialIdentity = await alice.createIdentity();
      const initialUserId = initialIdentity.identity.userId;
      const rotatedResult = await alice.rotateIdentity(initialUserId);

      expect(rotatedResult.identity.userId).toEqual(initialUserId);
      expect(rotatedResult.publicBundle.userId).toEqual(initialUserId);
    });
  });

  describe("Session Management", () => {
    it("should create and establish a session between two parties", async () => {
      const aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      // Alice creates session with Bob's public bundle
      const aliceSession = await alice.createSession(bobIdentity.publicBundle);

      // Bob creates responder session
      const bobSession = await bob.createResponderSession(
        aliceIdentity.publicBundle,
        aliceSession.ciphertext,
        aliceSession.confirmationMac,
      );

      // Alice confirms session
      const isConfirmed = await alice.confirmSession(
        aliceSession.sessionId,
        bobSession.confirmationMac,
      );

      expect(aliceSession.sessionId).toBeDefined();
      expect(aliceSession.ciphertext).toBeDefined();
      expect(aliceSession.confirmationMac).toBeDefined();
      expect(bobSession.sessionId).toBeDefined();
      expect(bobSession.confirmationMac).toBeDefined();
      expect(bobSession.isValid).toBe(true);
      expect(isConfirmed).toBe(true);
    });

    it("should fail to create session with invalid prekey signature", async () => {
      const _aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      // Modify the prekey signature to make it invalid
      const invalidBundle = {
        ...bobIdentity.publicBundle,
        preKey: {
          ...bobIdentity.publicBundle.preKey,
          signature: new Uint8Array(32).fill(1), // Invalid signature
        },
      };

      await expect(alice.createSession(invalidBundle)).rejects.toThrow(
        ERRORS.INVALID_PREKEY_SIGNATURE,
      );
    });

    it("should fail to create responder session with invalid prekey signature", async () => {
      const aliceIdentity = await alice.createIdentity();
      const _bobIdentity = await bob.createIdentity();

      // Modify the prekey signature to make it invalid
      const invalidBundle = {
        ...aliceIdentity.publicBundle,
        preKey: {
          ...aliceIdentity.publicBundle.preKey,
          signature: new Uint8Array(32).fill(1), // Invalid signature
        },
      };

      await expect(
        bob.createResponderSession(
          invalidBundle,
          new Uint8Array(1088), // Valid ciphertext size
        ),
      ).rejects.toThrow(ERRORS.INVALID_PREKEY_SIGNATURE);
    });

    it("should handle key confirmation failures", async () => {
      const aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      const aliceSession = await alice.createSession(bobIdentity.publicBundle);

      // Create an invalid confirmation MAC
      const invalidConfirmationMac = new Uint8Array(32).fill(1);

      await expect(
        bob.createResponderSession(
          aliceIdentity.publicBundle,
          aliceSession.ciphertext,
          invalidConfirmationMac,
        ),
      ).rejects.toThrow(ERRORS.KEY_CONFIRMATION_FAILED);
    });
  });

  describe("Message Encryption/Decryption", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      const aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      const aliceSession = await alice.createSession(bobIdentity.publicBundle);
      const bobSession = await bob.createResponderSession(
        aliceIdentity.publicBundle,
        aliceSession.ciphertext,
        aliceSession.confirmationMac,
      );

      await alice.confirmSession(
        aliceSession.sessionId,
        bobSession.confirmationMac,
      );

      aliceSessionId = aliceSession.sessionId;
      bobSessionId = bobSession.sessionId;
    });

    it("should encrypt and decrypt a message successfully", async () => {
      const originalMessage = "Hello, Bob!";
      const encrypted = await alice.encryptMessage(
        aliceSessionId,
        originalMessage,
      );
      const decrypted = await bob.decryptMessage(bobSessionId, encrypted);

      const decryptedText = new TextDecoder().decode(decrypted.plaintext);
      expect(decryptedText).toEqual(originalMessage);
    });

    it("should handle Uint8Array plaintext", async () => {
      const originalBytes = new TextEncoder().encode("Hello, Bob!");
      const encrypted = await alice.encryptMessage(
        aliceSessionId,
        originalBytes,
      );
      const decrypted = await bob.decryptMessage(bobSessionId, encrypted);

      expect(decrypted.plaintext).toEqual(originalBytes);
    });

    it("should maintain message order and sequence numbers", async () => {
      const message1 = await alice.encryptMessage(
        aliceSessionId,
        "First message",
      );
      const message2 = await alice.encryptMessage(
        aliceSessionId,
        "Second message",
      );

      // Check that message numbers are sequential
      expect(message1.header.messageNumber).toBe(0);
      expect(message2.header.messageNumber).toBe(1);

      const decrypted1 = await bob.decryptMessage(bobSessionId, message1);
      const decrypted2 = await bob.decryptMessage(bobSessionId, message2);

      expect(new TextDecoder().decode(decrypted1.plaintext)).toBe(
        "First message",
      );
      expect(new TextDecoder().decode(decrypted2.plaintext)).toBe(
        "Second message",
      );
    });

    it("should reject invalid signatures", async () => {
      const originalMessage = "Hello, Bob!";
      const encrypted = await alice.encryptMessage(
        aliceSessionId,
        originalMessage,
      );

      // Modify the signature to make it invalid
      const invalidEncrypted = {
        ...encrypted,
        signature: new Uint8Array(64).fill(1),
      };

      await expect(
        bob.decryptMessage(bobSessionId, invalidEncrypted),
      ).rejects.toThrow(ERRORS.INVALID_MESSAGE_SIGNATURE);
    });

    it("should round-trip a message once the session is confirmed", async () => {
      // Create a new session and confirm it properly
      const aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      const aliceSession = await alice.createSession(bobIdentity.publicBundle);
      const bobSession = await bob.createResponderSession(
        aliceIdentity.publicBundle,
        aliceSession.ciphertext,
        aliceSession.confirmationMac,
      );

      await alice.confirmSession(
        aliceSession.sessionId,
        bobSession.confirmationMac,
      );

      // Now encrypting should work, and the ciphertext must decrypt back
      const encrypted = await alice.encryptMessage(
        aliceSession.sessionId,
        "Test message",
      );
      const decrypted = await bob.decryptMessage(
        bobSession.sessionId,
        encrypted,
      );
      expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
        "Test message",
      );
    });
  });

  describe("Replay Protection", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      const aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      const aliceSession = await alice.createSession(bobIdentity.publicBundle);
      const bobSession = await bob.createResponderSession(
        aliceIdentity.publicBundle,
        aliceSession.ciphertext,
        aliceSession.confirmationMac,
      );

      await alice.confirmSession(
        aliceSession.sessionId,
        bobSession.confirmationMac,
      );

      aliceSessionId = aliceSession.sessionId;
      bobSessionId = bobSession.sessionId;
    });

    it("should prevent message replay attacks", async () => {
      const originalMessage = "Test message";
      const encrypted = await alice.encryptMessage(
        aliceSessionId,
        originalMessage,
      );

      // First decryption should succeed
      const decrypted = await bob.decryptMessage(bobSessionId, encrypted);
      const decryptedText = new TextDecoder().decode(decrypted.plaintext);
      expect(decryptedText).toEqual(originalMessage);

      // Second decryption of the same message should fail due to replay protection
      await expect(bob.decryptMessage(bobSessionId, encrypted)).rejects.toThrow(
        ERRORS.DUPLICATE_MESSAGE,
      );
    });

    it("should track replay protection status", async () => {
      const statusBefore = await bob.getReplayProtectionStatus(bobSessionId);
      expect(statusBefore.storedMessageIds).toBe(0);

      const encrypted = await alice.encryptMessage(
        aliceSessionId,
        "Test message",
      );
      await bob.decryptMessage(bobSessionId, encrypted);

      const statusAfter = await bob.getReplayProtectionStatus(bobSessionId);
      expect(statusAfter.storedMessageIds).toBe(1);
    });
  });

  describe("Ratchet Functionality", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      const aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      const aliceSession = await alice.createSession(bobIdentity.publicBundle);
      const bobSession = await bob.createResponderSession(
        aliceIdentity.publicBundle,
        aliceSession.ciphertext,
        aliceSession.confirmationMac,
      );

      await alice.confirmSession(
        aliceSession.sessionId,
        bobSession.confirmationMac,
      );

      aliceSessionId = aliceSession.sessionId;
      bobSessionId = bobSession.sessionId;
    });

    it("should handle manual ratchet triggering", async () => {
      // First, send a message to establish the session properly and ensure peer ratchet key is available
      const establishmentMsg = await alice.encryptMessage(
        aliceSessionId,
        "establish session",
      );
      await bob.decryptMessage(bobSessionId, establishmentMsg);

      // Send a reply from bob to alice to ensure both sides have each other's ratchet keys
      const replyMsg = await bob.encryptMessage(
        bobSessionId,
        "reply to establish ratchet keys",
      );
      await alice.decryptMessage(aliceSessionId, replyMsg);

      // Now both sides should have each other's ratchet public keys
      // Try triggering ratchet on alice side
      await alice.triggerRatchet(aliceSessionId);

      // After ratcheting, send a new message from alice
      const encryptedAfterRatchet = await alice.encryptMessage(
        aliceSessionId,
        "Message after ratchet",
      );
      const decryptedAfterRatchet = await bob.decryptMessage(
        bobSessionId,
        encryptedAfterRatchet,
      );

      const decryptedText = new TextDecoder().decode(
        decryptedAfterRatchet.plaintext,
      );

      expect(decryptedText).toBe("Message after ratchet");

      // Also trigger ratchet on bob side and send a message
      await bob.triggerRatchet(bobSessionId);
      const bobEncryptedAfterRatchet = await bob.encryptMessage(
        bobSessionId,
        "Bob's message after ratchet",
      );

      const bobDecryptedAfterRatchet = await alice.decryptMessage(
        aliceSessionId,
        bobEncryptedAfterRatchet,
      );

      const bobDecryptedText = new TextDecoder().decode(
        bobDecryptedAfterRatchet.plaintext,
      );
      expect(bobDecryptedText).toBe("Bob's message after ratchet");
    });
  });

  describe("Session Management", () => {
    it("should list all sessions", async () => {
      const aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      const aliceSession = await alice.createSession(bobIdentity.publicBundle);
      const bobSession = await bob.createResponderSession(
        aliceIdentity.publicBundle,
        aliceSession.ciphertext,
        aliceSession.confirmationMac,
      );

      await alice.confirmSession(
        aliceSession.sessionId,
        bobSession.confirmationMac,
      );

      const aliceSessions = await alice.getSessions();
      const bobSessions = await bob.getSessions();

      expect(aliceSessions.length).toBe(1);
      expect(bobSessions.length).toBe(1);
      expect(aliceSessions[0].sessionId).toBe(aliceSession.sessionId);
      expect(bobSessions[0].sessionId).toBe(bobSession.sessionId);
    });
  });

  describe("Out-of-order Delivery", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      const aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      const aliceSession = await alice.createSession(bobIdentity.publicBundle);
      const bobSession = await bob.createResponderSession(
        aliceIdentity.publicBundle,
        aliceSession.ciphertext,
        aliceSession.confirmationMac,
      );

      await alice.confirmSession(
        aliceSession.sessionId,
        bobSession.confirmationMac,
      );

      aliceSessionId = aliceSession.sessionId;
      bobSessionId = bobSession.sessionId;
    });

    it("should decrypt messages delivered as 2, 0, 1", async () => {
      const m0 = await alice.encryptMessage(aliceSessionId, "zero");
      const m1 = await alice.encryptMessage(aliceSessionId, "one");
      const m2 = await alice.encryptMessage(aliceSessionId, "two");

      // Delivered in the order 2, 0, 1
      const d2 = await bob.decryptMessage(bobSessionId, m2);
      const d0 = await bob.decryptMessage(bobSessionId, m0);
      const d1 = await bob.decryptMessage(bobSessionId, m1);

      expect(new TextDecoder().decode(d2.plaintext)).toBe("two");
      expect(new TextDecoder().decode(d0.plaintext)).toBe("zero");
      expect(new TextDecoder().decode(d1.plaintext)).toBe("one");
    });

    it("should decrypt a large gap (5 delivered before 0-4)", async () => {
      const messages = [];
      for (let i = 0; i < 6; i++) {
        messages.push(
          await alice.encryptMessage(aliceSessionId, `message-${i}`),
        );
      }

      // Deliver 5 first, then the earlier ones
      const first = await bob.decryptMessage(bobSessionId, messages[5]);
      expect(new TextDecoder().decode(first.plaintext)).toBe("message-5");

      for (let i = 0; i < 5; i++) {
        const decrypted = await bob.decryptMessage(bobSessionId, messages[i]);
        expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
          `message-${i}`,
        );
      }
    });

    it("should decrypt a pre-ratchet message delivered after a post-ratchet one", async () => {
      // Exchange a round trip so both sides hold each other's ratchet keys
      const establish = await alice.encryptMessage(aliceSessionId, "establish");
      await bob.decryptMessage(bobSessionId, establish);
      const reply = await bob.encryptMessage(bobSessionId, "reply");
      await alice.decryptMessage(aliceSessionId, reply);

      // A normal message that is delayed in transit
      const preRatchet = await alice.encryptMessage(
        aliceSessionId,
        "pre-ratchet",
      );

      // Force an automatic ratchet, then send a message that carries it
      const session = await alice.getStorage().getSession(aliceSessionId);
      await alice.getStorage().saveSession(aliceSessionId, {
        ...session!,
        lastRatchetAt: Date.now() - RATCHET_INTERVAL - 1000,
      });
      const postRatchet = await alice.encryptMessage(
        aliceSessionId,
        "post-ratchet",
      );

      // The post-ratchet message arrives first...
      const dPost = await bob.decryptMessage(bobSessionId, postRatchet);
      expect(new TextDecoder().decode(dPost.plaintext)).toBe("post-ratchet");

      // ...and the delayed pre-ratchet message still decrypts from a skipped key
      const dPre = await bob.decryptMessage(bobSessionId, preRatchet);
      expect(new TextDecoder().decode(dPre.plaintext)).toBe("pre-ratchet");
    });
  });

  describe("Automatic Ratcheting", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      const aliceIdentity = await alice.createIdentity();
      const bobIdentity = await bob.createIdentity();

      const aliceSession = await alice.createSession(bobIdentity.publicBundle);
      const bobSession = await bob.createResponderSession(
        aliceIdentity.publicBundle,
        aliceSession.ciphertext,
        aliceSession.confirmationMac,
      );

      await alice.confirmSession(
        aliceSession.sessionId,
        bobSession.confirmationMac,
      );

      // Exchange a round trip so both sides know each other's ratchet keys
      const establish = await alice.encryptMessage(
        aliceSession.sessionId,
        "hi",
      );
      await bob.decryptMessage(bobSession.sessionId, establish);
      const reply = await bob.encryptMessage(bobSession.sessionId, "hello");
      await alice.decryptMessage(aliceSession.sessionId, reply);

      aliceSessionId = aliceSession.sessionId;
      bobSessionId = bobSession.sessionId;
    });

    it("should ratchet automatically after RATCHET_AFTER_MESSAGES messages", async () => {
      const before = await alice.getStorage().getSession(aliceSessionId);
      expect(before?.ratchetCount).toBe(0);

      let last: Awaited<ReturnType<typeof alice.encryptMessage>> | undefined;
      for (let i = 0; i < RATCHET_AFTER_MESSAGES; i++) {
        last = await alice.encryptMessage(aliceSessionId, `bulk-${i}`);
      }
      expect(last).toBeDefined();
      // The message carrying the automatic ratchet must still decrypt
      const decrypted = await bob.decryptMessage(bobSessionId, last!);
      expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
        `bulk-${RATCHET_AFTER_MESSAGES - 1}`,
      );

      const after = await alice.getStorage().getSession(aliceSessionId);
      expect(after?.ratchetCount).toBeGreaterThan(0);
      expect(after?.lastRatchetAt).toBeDefined();
    });

    it("should ratchet automatically once the chain ages past RATCHET_INTERVAL", async () => {
      const session = await alice.getStorage().getSession(aliceSessionId);
      expect(session).toBeDefined();

      // Simulate a long idle period since the last ratchet
      await alice.getStorage().saveSession(aliceSessionId, {
        ...session!,
        lastRatchetAt: Date.now() - RATCHET_INTERVAL - 1000,
      });
      const beforeCount = session!.ratchetCount;

      const encrypted = await alice.encryptMessage(
        aliceSessionId,
        "after idle",
      );
      const decrypted = await bob.decryptMessage(bobSessionId, encrypted);
      expect(new TextDecoder().decode(decrypted.plaintext)).toBe("after idle");

      const after = await alice.getStorage().getSession(aliceSessionId);
      expect(after?.ratchetCount).toBeGreaterThan(beforeCount);
    });
  });
});
