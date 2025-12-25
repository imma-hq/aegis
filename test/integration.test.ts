import { describe, it, expect, beforeEach } from "vitest";
import {
  createIdentity,
  getPublicBundle,
  createSession,
  createResponderSession,
  confirmSession,
  encryptMessage,
  decryptMessage,
  getSessions,
  cleanupOldSessions,
  triggerRatchet,
} from "../src/index";
import { MemoryStorage } from "../src/storage";

describe("E2EE Integration Tests", () => {
  let aliceStorage: MemoryStorage;
  let bobStorage: MemoryStorage;

  beforeEach(() => {
    aliceStorage = new MemoryStorage();
    bobStorage = new MemoryStorage();
  });

  describe("Complete Communication Flow", () => {
    it("should establish secure communication between Alice and Bob", async () => {
      // 1. Both parties create identities
      const aliceIdentity = await createIdentity(aliceStorage);
      const bobIdentity = await createIdentity(bobStorage);

      expect(aliceIdentity.identity.userId).toBeDefined();
      expect(bobIdentity.identity.userId).toBeDefined();

      // 2. Exchange public bundles
      const aliceBundle = await getPublicBundle(aliceStorage);
      const bobBundle = await getPublicBundle(bobStorage);

      expect(aliceBundle.preKey).toBeDefined();
      expect(bobBundle.preKey).toBeDefined();

      // 3. Alice initiates session with Bob
      const {
        sessionId: aliceSessionId,
        ciphertext,
        confirmationMac,
      } = await createSession(aliceStorage, bobBundle);

      expect(aliceSessionId).toBeDefined();

      // 4. Bob creates responder session
      const {
        sessionId: bobSessionId,
        confirmationMac: bobMac,
        isValid,
      } = await createResponderSession(
        bobStorage,
        aliceBundle,
        ciphertext,
        confirmationMac,
      );

      expect(bobSessionId).toBe(aliceSessionId);
      expect(isValid).toBe(true);

      // 5. Alice confirms session
      const confirmed = await confirmSession(
        aliceStorage,
        aliceSessionId,
        bobMac,
      );
      expect(confirmed).toBe(true);

      // 6. Exchange messages
      const msg1 = "Hello from Alice!";
      const encrypted1 = await encryptMessage(
        aliceStorage,
        aliceSessionId,
        msg1,
      );
      const { plaintext: decrypted1 } = await decryptMessage(
        bobStorage,
        bobSessionId,
        encrypted1,
      );
      expect(new TextDecoder().decode(decrypted1)).toBe(msg1);

      const msg2 = "Hello from Bob!";
      const encrypted2 = await encryptMessage(bobStorage, bobSessionId, msg2);
      const { plaintext: decrypted2 } = await decryptMessage(
        aliceStorage,
        aliceSessionId,
        encrypted2,
      );
      expect(new TextDecoder().decode(decrypted2)).toBe(msg2);
    });

    it("should handle multi-party communication", async () => {
      // Create Charlie
      const charlieStorage = new MemoryStorage();
      await createIdentity(charlieStorage);

      // Alice creates identity
      await createIdentity(aliceStorage);
      const aliceBundle = await getPublicBundle(aliceStorage);

      // Bob and Charlie both establish sessions with Alice
      await createIdentity(bobStorage);
      const bobBundle = await getPublicBundle(bobStorage);

      const charlieBundle = await getPublicBundle(charlieStorage);

      // Alice -> Bob session
      const {
        sessionId: aliceBobSession,
        ciphertext: ct1,
        confirmationMac: cm1,
      } = await createSession(aliceStorage, bobBundle);

      const { confirmationMac: bobMac } = await createResponderSession(
        bobStorage,
        aliceBundle,
        ct1,
        cm1,
      );
      await confirmSession(aliceStorage, aliceBobSession, bobMac);

      // Alice -> Charlie session
      const {
        sessionId: aliceCharlieSession,
        ciphertext: ct2,
        confirmationMac: cm2,
      } = await createSession(aliceStorage, charlieBundle);

      const { confirmationMac: charlieMac } = await createResponderSession(
        charlieStorage,
        aliceBundle,
        ct2,
        cm2,
      );
      await confirmSession(aliceStorage, aliceCharlieSession, charlieMac);

      // Alice sends different messages to Bob and Charlie
      const msgToBob = "Private message to Bob";
      const encToBob = await encryptMessage(
        aliceStorage,
        aliceBobSession,
        msgToBob,
      );
      const { plaintext: decByBob } = await decryptMessage(
        bobStorage,
        aliceBobSession,
        encToBob,
      );
      expect(new TextDecoder().decode(decByBob)).toBe(msgToBob);

      const msgToCharlie = "Private message to Charlie";
      const encToCharlie = await encryptMessage(
        aliceStorage,
        aliceCharlieSession,
        msgToCharlie,
      );
      const { plaintext: decByCharlie } = await decryptMessage(
        charlieStorage,
        aliceCharlieSession,
        encToCharlie,
      );
      expect(new TextDecoder().decode(decByCharlie)).toBe(msgToCharlie);

      // Verify Alice has 2 sessions
      const aliceSessions = await getSessions(aliceStorage);
      expect(aliceSessions).toHaveLength(2);
    });
  });

  describe("Real-world Scenarios", () => {
    it("should handle message loss and recovery", async () => {
      // Setup
      await createIdentity(aliceStorage);
      await createIdentity(bobStorage);

      const aliceBundle = await getPublicBundle(aliceStorage);
      const bobBundle = await getPublicBundle(bobStorage);

      const {
        sessionId: aliceSessionId,
        ciphertext,
        confirmationMac,
      } = await createSession(aliceStorage, bobBundle);

      const { sessionId: bobSessionId, confirmationMac: bobMac } =
        await createResponderSession(
          bobStorage,
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      await confirmSession(aliceStorage, aliceSessionId, bobMac);

      // Alice sends 5 messages
      const messages = [];
      for (let i = 0; i < 5; i++) {
        let data = await encryptMessage(
          aliceStorage,
          aliceSessionId,
          `Message ${i}`,
        );
        messages.push(data);
      }

      // Bob only receives messages 0, 2, and 4 (1 and 3 are lost)
      await decryptMessage(bobStorage, bobSessionId, messages[0]);
      await decryptMessage(bobStorage, bobSessionId, messages[2]);
      await decryptMessage(bobStorage, bobSessionId, messages[4]);

      // Now messages 1 and 3 arrive late
      const { plaintext: p1 } = await decryptMessage(
        bobStorage,
        bobSessionId,
        messages[1],
      );
      expect(new TextDecoder().decode(p1)).toBe("Message 1");

      const { plaintext: p3 } = await decryptMessage(
        bobStorage,
        bobSessionId,
        messages[3],
      );
      expect(new TextDecoder().decode(p3)).toBe("Message 3");
    });

    it("should handle connection interruption and resumption", async () => {
      // Setup
      await createIdentity(aliceStorage);
      await createIdentity(bobStorage);

      const aliceBundle = await getPublicBundle(aliceStorage);
      const bobBundle = await getPublicBundle(bobStorage);

      const {
        sessionId: aliceSessionId,
        ciphertext,
        confirmationMac,
      } = await createSession(aliceStorage, bobBundle);

      const { sessionId: bobSessionId, confirmationMac: bobMac } =
        await createResponderSession(
          bobStorage,
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      await confirmSession(aliceStorage, aliceSessionId, bobMac);

      // Exchange some messages
      for (let i = 0; i < 10; i++) {
        const enc = await encryptMessage(
          aliceStorage,
          aliceSessionId,
          `Msg ${i}`,
        );
        await decryptMessage(bobStorage, bobSessionId, enc);
      }

      // Simulate connection break - sessions persist in storage
      // ... time passes ...

      // Resume communication
      const resumeMsg = await encryptMessage(
        aliceStorage,
        aliceSessionId,
        "Resumed message",
      );
      const { plaintext } = await decryptMessage(
        bobStorage,
        bobSessionId,
        resumeMsg,
      );
      expect(new TextDecoder().decode(plaintext)).toBe("Resumed message");
    });

    it("should handle rapid back-and-forth conversation", async () => {
      // Setup
      await createIdentity(aliceStorage);
      await createIdentity(bobStorage);

      const aliceBundle = await getPublicBundle(aliceStorage);
      const bobBundle = await getPublicBundle(bobStorage);

      const {
        sessionId: aliceSessionId,
        ciphertext,
        confirmationMac,
      } = await createSession(aliceStorage, bobBundle);

      const { sessionId: bobSessionId, confirmationMac: bobMac } =
        await createResponderSession(
          bobStorage,
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      await confirmSession(aliceStorage, aliceSessionId, bobMac);

      // Rapid exchange
      for (let i = 0; i < 25; i++) {
        // Alice sends
        const aliceMsg = await encryptMessage(
          aliceStorage,
          aliceSessionId,
          `Alice: ${i}`,
        );
        const { plaintext: bobReceives } = await decryptMessage(
          bobStorage,
          bobSessionId,
          aliceMsg,
        );
        expect(new TextDecoder().decode(bobReceives)).toBe(`Alice: ${i}`);

        // Bob replies immediately
        const bobMsg = await encryptMessage(
          bobStorage,
          bobSessionId,
          `Bob: ${i}`,
        );
        const { plaintext: aliceReceives } = await decryptMessage(
          aliceStorage,
          aliceSessionId,
          bobMsg,
        );
        expect(new TextDecoder().decode(aliceReceives)).toBe(`Bob: ${i}`);
      }
    });

    it("should handle session cleanup", async () => {
      // Create multiple sessions
      await createIdentity(aliceStorage);

      for (let i = 0; i < 5; i++) {
        const tempStorage = new MemoryStorage();
        await createIdentity(tempStorage);
        const bundle = await getPublicBundle(tempStorage);
        await createSession(aliceStorage, bundle);
      }

      let sessions = await getSessions(aliceStorage);
      expect(sessions).toHaveLength(5);

      // Manually age some sessions
      const allSessions = await getSessions(aliceStorage);
      for (let i = 0; i < 3; i++) {
        const session = allSessions[i];
        session.lastUsed = Date.now() - 40 * 24 * 60 * 60 * 1000; // 40 days ago
        await aliceStorage.saveSession(session.sessionId, session);
      }

      // Clean up sessions older than 30 days
      await cleanupOldSessions(aliceStorage, 30 * 24 * 60 * 60 * 1000);

      sessions = await getSessions(aliceStorage);
      expect(sessions).toHaveLength(2);
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty messages", async () => {
      await createIdentity(aliceStorage);
      await createIdentity(bobStorage);

      const aliceBundle = await getPublicBundle(aliceStorage);
      const bobBundle = await getPublicBundle(bobStorage);

      const {
        sessionId: aliceSessionId,
        ciphertext,
        confirmationMac,
      } = await createSession(aliceStorage, bobBundle);

      const { sessionId: bobSessionId, confirmationMac: bobMac } =
        await createResponderSession(
          bobStorage,
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      await confirmSession(aliceStorage, aliceSessionId, bobMac);

      const emptyMsg = "";
      const encrypted = await encryptMessage(
        aliceStorage,
        aliceSessionId,
        emptyMsg,
      );
      const { plaintext } = await decryptMessage(
        bobStorage,
        bobSessionId,
        encrypted,
      );

      expect(new TextDecoder().decode(plaintext)).toBe("");
    });

    it("should handle very large messages", async () => {
      await createIdentity(aliceStorage);
      await createIdentity(bobStorage);

      const aliceBundle = await getPublicBundle(aliceStorage);
      const bobBundle = await getPublicBundle(bobStorage);

      const {
        sessionId: aliceSessionId,
        ciphertext,
        confirmationMac,
      } = await createSession(aliceStorage, bobBundle);

      const { sessionId: bobSessionId, confirmationMac: bobMac } =
        await createResponderSession(
          bobStorage,
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      await confirmSession(aliceStorage, aliceSessionId, bobMac);

      // 10MB message
      const largeMsg = new Uint8Array(10 * 1024 * 1024).fill(123);
      const encrypted = await encryptMessage(
        aliceStorage,
        aliceSessionId,
        largeMsg,
      );
      const { plaintext } = await decryptMessage(
        bobStorage,
        bobSessionId,
        encrypted,
      );

      expect(plaintext).toEqual(largeMsg);
    });

    it("should handle ratchet during active conversation", async () => {
      await createIdentity(aliceStorage);
      await createIdentity(bobStorage);

      const aliceBundle = await getPublicBundle(aliceStorage);
      const bobBundle = await getPublicBundle(bobStorage);

      const {
        sessionId: aliceSessionId,
        ciphertext,
        confirmationMac,
      } = await createSession(aliceStorage, bobBundle);

      const { sessionId: bobSessionId, confirmationMac: bobMac } =
        await createResponderSession(
          bobStorage,
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      await confirmSession(aliceStorage, aliceSessionId, bobMac);

      // Exchange messages to establish peer ratchet keys
      const init1 = await encryptMessage(
        aliceStorage,
        aliceSessionId,
        "Init 1",
      );
      await decryptMessage(bobStorage, bobSessionId, init1);

      const init2 = await encryptMessage(bobStorage, bobSessionId, "Init 2");
      await decryptMessage(aliceStorage, aliceSessionId, init2);

      // Trigger manual ratchet
      await triggerRatchet(aliceStorage, aliceSessionId);

      // Continue communication
      const afterRatchet = await encryptMessage(
        aliceStorage,
        aliceSessionId,
        "After ratchet",
      );
      const { plaintext } = await decryptMessage(
        bobStorage,
        bobSessionId,
        afterRatchet,
      );

      expect(new TextDecoder().decode(plaintext)).toBe("After ratchet");
    });

    it("should handle Unicode and special characters", async () => {
      await createIdentity(aliceStorage);
      await createIdentity(bobStorage);

      const aliceBundle = await getPublicBundle(aliceStorage);
      const bobBundle = await getPublicBundle(bobStorage);

      const {
        sessionId: aliceSessionId,
        ciphertext,
        confirmationMac,
      } = await createSession(aliceStorage, bobBundle);

      const { sessionId: bobSessionId, confirmationMac: bobMac } =
        await createResponderSession(
          bobStorage,
          aliceBundle,
          ciphertext,
          confirmationMac,
        );

      await confirmSession(aliceStorage, aliceSessionId, bobMac);

      const specialMsg = "你好世界 🌍 Hello مرحبا Привет 🚀";
      const encrypted = await encryptMessage(
        aliceStorage,
        aliceSessionId,
        specialMsg,
      );
      const { plaintext } = await decryptMessage(
        bobStorage,
        bobSessionId,
        encrypted,
      );

      expect(new TextDecoder().decode(plaintext)).toBe(specialMsg);
    });
  });
});
