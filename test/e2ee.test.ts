// tests/e2ee.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { E2EE } from "../src/core";
import { MemoryStorage } from "../src/storage";
import { ERRORS } from "../src/constants";
import type { EncryptedMessage, PublicBundle } from "../src/types";

describe("E2EE Core Functionality", () => {
  let aliceStorage: MemoryStorage;
  let bobStorage: MemoryStorage;
  let aliceE2EE: E2EE;
  let bobE2EE: E2EE;

  beforeEach(() => {
    aliceStorage = new MemoryStorage();
    bobStorage = new MemoryStorage();
    aliceE2EE = new E2EE(aliceStorage);
    bobE2EE = new E2EE(bobStorage);
  });

  describe("Identity Creation", () => {
    it("should create a valid identity", async () => {
      const { identity, publicBundle } = await aliceE2EE.createIdentity();

      expect(identity.userId).toBeDefined();
      expect(identity.userId).toHaveLength(64); // 32 bytes hex
      expect(identity.kemKeyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(identity.dsaKeyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(identity.createdAt).toBeGreaterThan(0);
      expect(publicBundle.userId).toBe(identity.userId);
    });

    it("should create unique identities", async () => {
      const { identity: id1 } = await aliceE2EE.createIdentity();
      const bobE2EE2 = new E2EE(new MemoryStorage());
      const { identity: id2 } = await bobE2EE2.createIdentity();

      expect(id1.userId).not.toBe(id2.userId);
    });

    it("should store identity in storage", async () => {
      await aliceE2EE.createIdentity();
      const stored = await aliceStorage.getIdentity();

      expect(stored).not.toBeNull();
      expect(stored!.userId).toBeDefined();
    });

    it("should include prekey in public bundle", async () => {
      const { publicBundle } = await aliceE2EE.createIdentity();

      expect(publicBundle.preKey).toBeDefined();
      expect(publicBundle.preKey.id).toBe(1);
      expect(publicBundle.preKey.key).toBeInstanceOf(Uint8Array);
      expect(publicBundle.preKey.signature).toBeInstanceOf(Uint8Array);
    });
  });

  describe("Session Creation", () => {
    let aliceBundle: PublicBundle;
    let bobBundle: PublicBundle;

    beforeEach(async () => {
      const alice = await aliceE2EE.createIdentity();
      const bob = await bobE2EE.createIdentity();
      aliceBundle = alice.publicBundle;
      bobBundle = bob.publicBundle;
    });

    it("should create initiator session successfully", async () => {
      const { sessionId, ciphertext, confirmationMac } =
        await aliceE2EE.createSession(bobBundle);

      expect(sessionId).toBeDefined();
      expect(sessionId).toHaveLength(64);
      expect(ciphertext).toBeInstanceOf(Uint8Array);
      expect(ciphertext.length).toBeGreaterThan(0);
      expect(confirmationMac).toBeInstanceOf(Uint8Array);
    });

    it("should create responder session successfully", async () => {
      const {
        sessionId: aliceSessionId,
        ciphertext,
        confirmationMac: aliceMac,
      } = await aliceE2EE.createSession(bobBundle);

      const {
        sessionId: bobSessionId,
        confirmationMac: bobMac,
        isValid,
      } = await bobE2EE.createResponderSession(
        aliceBundle,
        ciphertext,
        aliceMac,
      );

      expect(bobSessionId).toBe(aliceSessionId);
      expect(isValid).toBe(true);
      expect(bobMac).toBeInstanceOf(Uint8Array);
    });

    it("should reject invalid prekey signature", async () => {
      const invalidBundle = { ...bobBundle };
      invalidBundle.preKey.signature = new Uint8Array(32).fill(0);

      await expect(aliceE2EE.createSession(invalidBundle)).rejects.toThrow(
        ERRORS.INVALID_PREKEY_SIGNATURE,
      );
    });

    it("should create deterministic session IDs", async () => {
      const { sessionId: sid1 } = await aliceE2EE.createSession(bobBundle);

      // Reset and recreate
      aliceStorage = new MemoryStorage();
      bobStorage = new MemoryStorage();
      aliceE2EE = new E2EE(aliceStorage);
      bobE2EE = new E2EE(bobStorage);

      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const alice2 = await aliceStorage.getIdentity();
      const bob2 = await bobStorage.getIdentity();

      // Should be different because identities are different
      const { sessionId: sid2 } = await aliceE2EE.createSession(
        await bobE2EE.getPublicBundle(),
      );

      expect(sid1).not.toBe(sid2);
    });

    it("should mark session as unconfirmed initially", async () => {
      const { sessionId } = await aliceE2EE.createSession(bobBundle);
      const session = await aliceStorage.getSession(sessionId);

      expect(session).not.toBeNull();
      expect(session!.confirmed).toBe(false);
      expect(session!.state).toBe("CREATED");
    });
  });

  describe("Key Confirmation", () => {
    let sessionId: string;
    let bobConfirmationMac: Uint8Array;

    beforeEach(async () => {
      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const bobBundle = await bobE2EE.getPublicBundle();
      const {
        sessionId: sid,
        ciphertext,
        confirmationMac,
      } = await aliceE2EE.createSession(bobBundle);

      sessionId = sid;

      const aliceBundle = await aliceE2EE.getPublicBundle();
      const result = await bobE2EE.createResponderSession(
        aliceBundle,
        ciphertext,
        confirmationMac,
      );

      bobConfirmationMac = result.confirmationMac;
    });

    it("should confirm session with valid MAC", async () => {
      const isValid = await aliceE2EE.confirmSession(
        sessionId,
        bobConfirmationMac,
      );
      expect(isValid).toBe(true);

      const session = await aliceStorage.getSession(sessionId);
      expect(session!.confirmed).toBe(true);
      expect(session!.state).toBe("KEY_CONFIRMED");
    });

    it("should reject invalid confirmation MAC", async () => {
      const invalidMac = new Uint8Array(32).fill(0);
      const isValid = await aliceE2EE.confirmSession(sessionId, invalidMac);

      expect(isValid).toBe(false);

      const session = await aliceStorage.getSession(sessionId);
      expect(session!.confirmed).toBe(false);
      expect(session!.state).toBe("ERROR");
    });
  });

  describe("Message Encryption and Decryption", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const bobBundle = await bobE2EE.getPublicBundle();
      const { sessionId, ciphertext, confirmationMac } =
        await aliceE2EE.createSession(bobBundle);

      aliceSessionId = sessionId;

      const aliceBundle = await aliceE2EE.getPublicBundle();
      const { sessionId: bobSid, confirmationMac: bobMac } =
        await bobE2EE.createResponderSession(
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      bobSessionId = bobSid;

      await aliceE2EE.confirmSession(aliceSessionId, bobMac);
    });

    it("should encrypt and decrypt a simple message", async () => {
      const plaintext = "Hello, Bob!";
      const encrypted = await aliceE2EE.encryptMessage(
        aliceSessionId,
        plaintext,
      );

      expect(encrypted.ciphertext).toBeInstanceOf(Uint8Array);
      expect(encrypted.header).toBeDefined();
      expect(encrypted.signature).toBeInstanceOf(Uint8Array);

      const { plaintext: decrypted } = await bobE2EE.decryptMessage(
        bobSessionId,
        encrypted,
      );
      expect(new TextDecoder().decode(decrypted)).toBe(plaintext);
    });

    it("should encrypt and decrypt binary data", async () => {
      const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
      const encrypted = await aliceE2EE.encryptMessage(
        aliceSessionId,
        plaintext,
      );

      const { plaintext: decrypted } = await bobE2EE.decryptMessage(
        bobSessionId,
        encrypted,
      );
      expect(decrypted).toEqual(plaintext);
    });

    it("should handle multiple messages in sequence", async () => {
      const messages = ["Message 1", "Message 2", "Message 3"];

      for (const msg of messages) {
        const encrypted = await aliceE2EE.encryptMessage(aliceSessionId, msg);
        const { plaintext } = await bobE2EE.decryptMessage(
          bobSessionId,
          encrypted,
        );
        expect(new TextDecoder().decode(plaintext)).toBe(msg);
      }
    });

    it("should handle bidirectional messaging", async () => {
      // Alice to Bob
      const msg1 = "Hello from Alice";
      const enc1 = await aliceE2EE.encryptMessage(aliceSessionId, msg1);
      const { plaintext: dec1 } = await bobE2EE.decryptMessage(
        bobSessionId,
        enc1,
      );
      expect(new TextDecoder().decode(dec1)).toBe(msg1);

      // Bob to Alice
      const msg2 = "Hello from Bob";
      const enc2 = await bobE2EE.encryptMessage(bobSessionId, msg2);
      const { plaintext: dec2 } = await aliceE2EE.decryptMessage(
        aliceSessionId,
        enc2,
      );
      expect(new TextDecoder().decode(dec2)).toBe(msg2);
    });

    it("should reject messages with invalid signatures", async () => {
      const encrypted = await aliceE2EE.encryptMessage(aliceSessionId, "Test");

      // Corrupt signature
      encrypted.signature[0] ^= 0xff;

      await expect(
        bobE2EE.decryptMessage(bobSessionId, encrypted),
      ).rejects.toThrow(ERRORS.INVALID_MESSAGE_SIGNATURE);
    });

    it("should increment message numbers", async () => {
      const enc1 = await aliceE2EE.encryptMessage(aliceSessionId, "Msg 1");
      expect(enc1.header.messageNumber).toBe(0);

      const enc2 = await aliceE2EE.encryptMessage(aliceSessionId, "Msg 2");
      expect(enc2.header.messageNumber).toBe(1);

      const enc3 = await aliceE2EE.encryptMessage(aliceSessionId, "Msg 3");
      expect(enc3.header.messageNumber).toBe(2);
    });
  });

  describe("Out-of-Order Message Handling", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const bobBundle = await bobE2EE.getPublicBundle();
      const { sessionId, ciphertext, confirmationMac } =
        await aliceE2EE.createSession(bobBundle);

      aliceSessionId = sessionId;

      const aliceBundle = await aliceE2EE.getPublicBundle();
      const { sessionId: bobSid, confirmationMac: bobMac } =
        await bobE2EE.createResponderSession(
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      bobSessionId = bobSid;
      await aliceE2EE.confirmSession(aliceSessionId, bobMac);
    });

    it("should handle out-of-order messages", async () => {
      // Encrypt 3 messages
      const enc1 = await aliceE2EE.encryptMessage(aliceSessionId, "Message 1");
      const enc2 = await aliceE2EE.encryptMessage(aliceSessionId, "Message 2");
      const enc3 = await aliceE2EE.encryptMessage(aliceSessionId, "Message 3");

      // Decrypt in wrong order: 3, 1, 2
      const { plaintext: dec3 } = await bobE2EE.decryptMessage(
        bobSessionId,
        enc3,
      );
      expect(new TextDecoder().decode(dec3)).toBe("Message 3");

      const { plaintext: dec1 } = await bobE2EE.decryptMessage(
        bobSessionId,
        enc1,
      );
      expect(new TextDecoder().decode(dec1)).toBe("Message 1");

      const { plaintext: dec2 } = await bobE2EE.decryptMessage(
        bobSessionId,
        enc2,
      );
      expect(new TextDecoder().decode(dec2)).toBe("Message 2");
    });

    it("should skip keys for missing messages", async () => {
      const enc1 = await aliceE2EE.encryptMessage(aliceSessionId, "Message 1");
      const enc2 = await aliceE2EE.encryptMessage(aliceSessionId, "Message 2");
      const enc3 = await aliceE2EE.encryptMessage(aliceSessionId, "Message 3");
      const enc4 = await aliceE2EE.encryptMessage(aliceSessionId, "Message 4");

      // Skip message 2 and 3, decrypt 4 first
      const { plaintext: dec4 } = await bobE2EE.decryptMessage(
        bobSessionId,
        enc4,
      );
      expect(new TextDecoder().decode(dec4)).toBe("Message 4");

      // Now decrypt the skipped messages
      const { plaintext: dec2 } = await bobE2EE.decryptMessage(
        bobSessionId,
        enc2,
      );
      expect(new TextDecoder().decode(dec2)).toBe("Message 2");

      const { plaintext: dec3 } = await bobE2EE.decryptMessage(
        bobSessionId,
        enc3,
      );
      expect(new TextDecoder().decode(dec3)).toBe("Message 3");
    });

    it("should reject skipping too many messages", async () => {
      // Encrypt 101 messages (max is 100)
      const messages: EncryptedMessage[] = [];
      for (let i = 0; i < 101; i++) {
        messages.push(
          await aliceE2EE.encryptMessage(aliceSessionId, `Message ${i}`),
        );
      }

      // Try to decrypt the last one (would need to skip 100)
      await expect(
        bobE2EE.decryptMessage(bobSessionId, messages[100]),
      ).rejects.toThrow();
    });
  });

  describe("KEM Ratcheting", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const bobBundle = await bobE2EE.getPublicBundle();
      const { sessionId, ciphertext, confirmationMac } =
        await aliceE2EE.createSession(bobBundle);

      aliceSessionId = sessionId;

      const aliceBundle = await aliceE2EE.getPublicBundle();
      const { sessionId: bobSid, confirmationMac: bobMac } =
        await bobE2EE.createResponderSession(
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      bobSessionId = bobSid;
      await aliceE2EE.confirmSession(aliceSessionId, bobMac);
    });

    it("should perform KEM ratchet after 50 messages", async () => {
      // Send 49 messages - no ratchet yet
      for (let i = 0; i < 49; i++) {
        const enc = await aliceE2EE.encryptMessage(
          aliceSessionId,
          `Message ${i}`,
        );
        await bobE2EE.decryptMessage(bobSessionId, enc);
      }

      let aliceSession = await aliceStorage.getSession(aliceSessionId);
      expect(aliceSession!.ratchetCount).toBe(0);

      // 50th message should trigger ratchet
      const enc50 = await aliceE2EE.encryptMessage(
        aliceSessionId,
        "Message 50",
      );
      expect(enc50.header.isRatchetMessage).toBe(true);
      expect(enc50.header.kemCiphertext).toBeDefined();

      await bobE2EE.decryptMessage(bobSessionId, enc50);

      aliceSession = await aliceStorage.getSession(aliceSessionId);
      const bobSession = await bobStorage.getSession(bobSessionId);

      expect(aliceSession!.ratchetCount).toBe(1);
      expect(bobSession!.ratchetCount).toBe(1);
    });

    it("should handle manual ratchet trigger", async () => {
      // First establish peer ratchet key
      const enc1 = await aliceE2EE.encryptMessage(aliceSessionId, "Init");
      await bobE2EE.decryptMessage(bobSessionId, enc1);

      const enc2 = await bobE2EE.encryptMessage(bobSessionId, "Response");
      await aliceE2EE.decryptMessage(aliceSessionId, enc2);

      // Now trigger manual ratchet
      await aliceE2EE.triggerRatchet(aliceSessionId);

      const session = await aliceStorage.getSession(aliceSessionId);
      expect(session!.ratchetCount).toBe(1);
      expect(session!.state).toBe("RATCHET_PENDING");
    });

    it("should continue messaging after ratchet", async () => {
      // Trigger ratchet by sending 50 messages
      for (let i = 0; i < 51; i++) {
        const enc = await aliceE2EE.encryptMessage(
          aliceSessionId,
          `Message ${i}`,
        );
        await bobE2EE.decryptMessage(bobSessionId, enc);
      }

      // Continue messaging after ratchet
      const enc = await aliceE2EE.encryptMessage(
        aliceSessionId,
        "After ratchet",
      );
      const { plaintext } = await bobE2EE.decryptMessage(bobSessionId, enc);
      expect(new TextDecoder().decode(plaintext)).toBe("After ratchet");

      // Bob can reply
      const reply = await bobE2EE.encryptMessage(bobSessionId, "Bob replies");
      const { plaintext: dec } = await aliceE2EE.decryptMessage(
        aliceSessionId,
        reply,
      );
      expect(new TextDecoder().decode(dec)).toBe("Bob replies");
    });
  });

  describe("Replay Protection", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const bobBundle = await bobE2EE.getPublicBundle();
      const { sessionId, ciphertext, confirmationMac } =
        await aliceE2EE.createSession(bobBundle);

      aliceSessionId = sessionId;

      const aliceBundle = await aliceE2EE.getPublicBundle();
      const { sessionId: bobSid, confirmationMac: bobMac } =
        await bobE2EE.createResponderSession(
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      bobSessionId = bobSid;
      await aliceE2EE.confirmSession(aliceSessionId, bobMac);
    });

    it("should reject duplicate messages", async () => {
      const encrypted = await aliceE2EE.encryptMessage(aliceSessionId, "Test");

      // First decryption should succeed
      await bobE2EE.decryptMessage(bobSessionId, encrypted);

      // Second decryption of same message should fail
      await expect(
        bobE2EE.decryptMessage(bobSessionId, encrypted),
      ).rejects.toThrow(ERRORS.DUPLICATE_MESSAGE);
    });

    it("should reject messages that are too old", async () => {
      const encrypted = await aliceE2EE.encryptMessage(aliceSessionId, "Test");

      // Manipulate timestamp to be 10 minutes old
      encrypted.header.timestamp = Date.now() - 10 * 60 * 1000;

      await expect(
        bobE2EE.decryptMessage(bobSessionId, encrypted),
      ).rejects.toThrow(ERRORS.MESSAGE_TOO_OLD_TIMESTAMP);
    });

    it("should track received message IDs", async () => {
      const messages = ["Msg1", "Msg2", "Msg3"];

      for (const msg of messages) {
        const enc = await aliceE2EE.encryptMessage(aliceSessionId, msg);
        await bobE2EE.decryptMessage(bobSessionId, enc);
      }

      const status = await bobE2EE.getReplayProtectionStatus(bobSessionId);
      expect(status.storedMessageIds).toBe(3);
    });
  });

  describe("Session Management", () => {
    it("should list all sessions", async () => {
      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const bobBundle = await bobE2EE.getPublicBundle();

      // Create multiple sessions
      await aliceE2EE.createSession(bobBundle);
      await aliceE2EE.createSession(bobBundle);

      const sessions = await aliceE2EE.getSessions();
      expect(sessions).toHaveLength(2);
    });

    it("should cleanup old sessions", async () => {
      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const bobBundle = await bobE2EE.getPublicBundle();
      const { sessionId } = await aliceE2EE.createSession(bobBundle);

      // Manually set lastUsed to 40 days ago
      const session = await aliceStorage.getSession(sessionId);
      session!.lastUsed = Date.now() - 40 * 24 * 60 * 60 * 1000;
      await aliceStorage.saveSession(sessionId, session!);

      // Cleanup sessions older than 30 days
      await aliceE2EE.cleanupOldSessions(30 * 24 * 60 * 60 * 1000);

      const remainingSessions = await aliceE2EE.getSessions();
      expect(remainingSessions).toHaveLength(0);
    });

    it("should rotate identity and clear sessions", async () => {
      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const bobBundle = await bobE2EE.getPublicBundle();
      await aliceE2EE.createSession(bobBundle);

      const oldIdentity = await aliceStorage.getIdentity();

      // Rotate identity
      const { identity: newIdentity } = await aliceE2EE.rotateIdentity();

      expect(newIdentity.userId).not.toBe(oldIdentity!.userId);

      const sessions = await aliceE2EE.getSessions();
      expect(sessions).toHaveLength(0);
    });
  });

  describe("Error Handling", () => {
    it("should throw error when encrypting without identity", async () => {
      const storage = new MemoryStorage();
      const e2ee = new E2EE(storage);

      await expect(e2ee.encryptMessage("fake-session", "test")).rejects.toThrow(
        ERRORS.IDENTITY_NOT_FOUND,
      );
    });

    it("should throw error when encrypting to non-existent session", async () => {
      await aliceE2EE.createIdentity();

      await expect(
        aliceE2EE.encryptMessage("fake-session-id", "test"),
      ).rejects.toThrow(ERRORS.SESSION_NOT_FOUND);
    });

    it("should throw error when decrypting from non-existent session", async () => {
      await bobE2EE.createIdentity();

      const fakeMessage: EncryptedMessage = {
        ciphertext: new Uint8Array(32),
        header: {
          messageId: "fake",
          ratchetPublicKey: new Uint8Array(1184),
          messageNumber: 0,
          previousChainLength: 0,
          timestamp: Date.now(),
        },
        signature: new Uint8Array(32),
      };

      await expect(
        bobE2EE.decryptMessage("fake-session", fakeMessage),
      ).rejects.toThrow(ERRORS.SESSION_NOT_FOUND);
    });

    it("should handle invalid peer bundle", async () => {
      await aliceE2EE.createIdentity();

      const invalidBundle = {
        userId: "invalid",
        kemPublicKey: null,
        dsaPublicKey: null,
        preKey: null,
        createdAt: Date.now(),
      } as any;

      await expect(aliceE2EE.createSession(invalidBundle)).rejects.toThrow();
    });
  });

  describe("Public Bundle", () => {
    it("should get public bundle after identity creation", async () => {
      await aliceE2EE.createIdentity();
      const bundle = await aliceE2EE.getPublicBundle();

      expect(bundle.userId).toBeDefined();
      expect(bundle.kemPublicKey).toBeInstanceOf(Uint8Array);
      expect(bundle.dsaPublicKey).toBeInstanceOf(Uint8Array);
      expect(bundle.preKey).toBeDefined();
    });

    it("should fail to get bundle without identity", async () => {
      await expect(aliceE2EE.getPublicBundle()).rejects.toThrow(
        ERRORS.IDENTITY_NOT_FOUND,
      );
    });
  });

  describe("Stress Testing", () => {
    let aliceSessionId: string;
    let bobSessionId: string;

    beforeEach(async () => {
      await aliceE2EE.createIdentity();
      await bobE2EE.createIdentity();

      const bobBundle = await bobE2EE.getPublicBundle();
      const { sessionId, ciphertext, confirmationMac } =
        await aliceE2EE.createSession(bobBundle);

      aliceSessionId = sessionId;

      const aliceBundle = await aliceE2EE.getPublicBundle();
      const { sessionId: bobSid, confirmationMac: bobMac } =
        await bobE2EE.createResponderSession(
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      bobSessionId = bobSid;
      await aliceE2EE.confirmSession(aliceSessionId, bobMac);
    });

    it("should handle 200 sequential messages", async () => {
      for (let i = 0; i < 200; i++) {
        const encrypted = await aliceE2EE.encryptMessage(
          aliceSessionId,
          `Message ${i}`,
        );
        const { plaintext } = await bobE2EE.decryptMessage(
          bobSessionId,
          encrypted,
        );
        expect(new TextDecoder().decode(plaintext)).toBe(`Message ${i}`);
      }
    });

    it("should handle large messages (1MB)", async () => {
      const largeData = new Uint8Array(1024 * 1024).fill(42);
      const encrypted = await aliceE2EE.encryptMessage(
        aliceSessionId,
        largeData,
      );
      const { plaintext } = await bobE2EE.decryptMessage(
        bobSessionId,
        encrypted,
      );

      expect(plaintext).toEqual(largeData);
    });

    it("should handle rapid bidirectional exchange", async () => {
      for (let i = 0; i < 50; i++) {
        // Alice sends
        const aliceMsg = await aliceE2EE.encryptMessage(
          aliceSessionId,
          `Alice ${i}`,
        );
        await bobE2EE.decryptMessage(bobSessionId, aliceMsg);

        // Bob replies
        const bobMsg = await bobE2EE.encryptMessage(bobSessionId, `Bob ${i}`);
        await aliceE2EE.decryptMessage(aliceSessionId, bobMsg);
      }

      const aliceSession = await aliceStorage.getSession(aliceSessionId);
      const bobSession = await bobStorage.getSession(bobSessionId);

      expect(aliceSession!.sendingChain!.messageNumber).toBe(50);
      expect(bobSession!.sendingChain!.messageNumber).toBe(50);
    });
  });
});
