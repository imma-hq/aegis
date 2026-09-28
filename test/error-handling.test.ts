import { describe, it, expect, beforeEach } from "vitest";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { Aegis, MemoryStorage } from "../src/index";
import { ERRORS } from "../src/constants";
import { serializeHeader } from "../src/utils";

describe("Error Handling", () => {
  let alice: Aegis;
  let bob: Aegis;

  beforeEach(() => {
    alice = new Aegis(new MemoryStorage());
    bob = new Aegis(new MemoryStorage());
  });

  it("should handle missing identity error", async () => {
    await expect(alice.getPublicBundle()).rejects.toThrow(
      ERRORS.IDENTITY_NOT_FOUND,
    );
    await expect(alice.createSession({} as any)).rejects.toThrow(
      ERRORS.IDENTITY_NOT_FOUND,
    );
  });

  it("should handle invalid public bundle validation", async () => {
    await alice.createIdentity();

    // A bundle without a pre-key fails up-front validation
    const missingPreKey = {
      userId: "test-user",
      kemPublicKey: new Uint8Array(1184),
      dsaPublicKey: new Uint8Array(1952),
      createdAt: Date.now(),
    } as any;

    await expect(alice.createSession(missingPreKey)).rejects.toThrow(
      ERRORS.INVALID_PEER_BUNDLE,
    );

    // A correctly-sized but zeroed pre-key signature fails verification
    const bobIdentity = await bob.createIdentity();
    const tamperedBundle = {
      ...bobIdentity.publicBundle,
      preKey: {
        ...bobIdentity.publicBundle.preKey,
        signature: new Uint8Array(
          bobIdentity.publicBundle.preKey.signature.length,
        ),
      },
    };

    await expect(alice.createSession(tamperedBundle)).rejects.toThrow(
      ERRORS.INVALID_PREKEY_SIGNATURE,
    );
  });

  it("should handle session not found error", async () => {
    await expect(
      alice.encryptMessage("non-existent-session", "test"),
    ).rejects.toThrow(ERRORS.SESSION_NOT_FOUND);
    await expect(
      alice.decryptMessage("non-existent-session", {} as any),
    ).rejects.toThrow(ERRORS.SESSION_NOT_FOUND);
    await expect(
      alice.confirmSession("non-existent-session", new Uint8Array()),
    ).rejects.toThrow(ERRORS.SESSION_NOT_FOUND);
  });

  it("should reject a correctly signed but too-old message", async () => {
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

    // First, send a normal message to establish the session
    const normalMessage = await alice.encryptMessage(
      aliceSession.sessionId,
      "normal message",
    );
    await bob.decryptMessage(bobSession.sessionId, normalMessage);

    // Create a valid message and then age its timestamp, re-signing the header
    // so the signature stays valid and the age check is what rejects it
    const validMessage = await alice.encryptMessage(
      aliceSession.sessionId,
      "test message",
    );
    const staleHeader = {
      ...validMessage.header,
      timestamp: Date.now() - 10 * 60 * 1000, // 10 minutes old
    };
    const staleMessage = {
      ...validMessage,
      header: staleHeader,
      signature: ml_dsa65.sign(
        concatBytes(serializeHeader(staleHeader), validMessage.ciphertext),
        aliceIdentity.identity.dsaKeyPair.secretKey,
      ),
    };

    await expect(
      bob.decryptMessage(bobSession.sessionId, staleMessage),
    ).rejects.toThrow(ERRORS.MESSAGE_TOO_OLD_TIMESTAMP);
  });

  it("should reject a ratchet message with no KEM ciphertext", async () => {
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

    // First, send a normal message to establish the session
    const normalMessage = await alice.encryptMessage(
      aliceSession.sessionId,
      "normal message",
    );
    await bob.decryptMessage(bobSession.sessionId, normalMessage);

    const validMessage = await alice.encryptMessage(
      aliceSession.sessionId,
      "ratchet test",
    );

    // Flag the message as a ratchet message without a KEM ciphertext, then
    // re-sign so signature verification passes and the ratchet check fires
    const ratchetHeader = {
      ...validMessage.header,
      isRatchetMessage: true,
      kemCiphertext: undefined,
    };
    const invalidRatchetMessage = {
      ...validMessage,
      header: ratchetHeader,
      signature: ml_dsa65.sign(
        concatBytes(serializeHeader(ratchetHeader), validMessage.ciphertext),
        aliceIdentity.identity.dsaKeyPair.secretKey,
      ),
    };

    await expect(
      bob.decryptMessage(bobSession.sessionId, invalidRatchetMessage),
    ).rejects.toThrow(ERRORS.RATCHET_CIPHERTEXT_MISSING);
  });

  it("should encrypt/decrypt on a confirmed session and reject unknown sessions", async () => {
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

    // A confirmed session must round-trip a real message
    const encrypted = await alice.encryptMessage(
      aliceSession.sessionId,
      "Test message",
    );
    const decrypted = await bob.decryptMessage(bobSession.sessionId, encrypted);
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe("Test message");

    // And unknown sessions must be rejected
    await expect(
      alice.encryptMessage("non-existent-session", "Test message"),
    ).rejects.toThrow(ERRORS.SESSION_NOT_FOUND);
  });

  it("should handle out-of-order messages within limits", async () => {
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

    // Send multiple messages out of order
    const msg1 = await alice.encryptMessage(
      aliceSession.sessionId,
      "Message 1",
    );
    const msg3 = await alice.encryptMessage(
      aliceSession.sessionId,
      "Message 3",
    );
    const msg2 = await alice.encryptMessage(
      aliceSession.sessionId,
      "Message 2",
    );

    // Decrypt in order: 1, 3, 2 (out of sequence)
    const dec1 = await bob.decryptMessage(bobSession.sessionId, msg1);
    const dec3 = await bob.decryptMessage(bobSession.sessionId, msg3);
    const dec2 = await bob.decryptMessage(bobSession.sessionId, msg2);

    expect(new TextDecoder().decode(dec1.plaintext)).toBe("Message 1");
    expect(new TextDecoder().decode(dec3.plaintext)).toBe("Message 3");
    expect(new TextDecoder().decode(dec2.plaintext)).toBe("Message 2");
  });

  it("should reject a message that skips beyond the allowed window", async () => {
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

    // Send first message to establish session
    const firstMsg = await alice.encryptMessage(
      aliceSession.sessionId,
      "First message",
    );
    await bob.decryptMessage(bobSession.sessionId, firstMsg);

    const validEncrypted = await alice.encryptMessage(
      aliceSession.sessionId,
      "Test message",
    );

    // Jump the message number far past maxSkippedMessages and re-sign so the
    // signature is valid and the skip-window check is what rejects it
    const farAheadHeader = {
      ...validEncrypted.header,
      messageNumber: validEncrypted.header.messageNumber + 200,
    };
    const invalidMessage = {
      ...validEncrypted,
      header: farAheadHeader,
      signature: ml_dsa65.sign(
        concatBytes(serializeHeader(farAheadHeader), validEncrypted.ciphertext),
        aliceIdentity.identity.dsaKeyPair.secretKey,
      ),
    };

    await expect(
      bob.decryptMessage(bobSession.sessionId, invalidMessage),
    ).rejects.toThrow(/Cannot skip \d+ messages, max is 100/);
  });

  it("should remove sessions older than the supplied max age", async () => {
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

    expect(await alice.getSessions()).toHaveLength(1);

    // A max age far in the future keeps recently-used sessions
    await alice.cleanupOldSessions(60 * 60 * 1000);
    expect(await alice.getSessions()).toHaveLength(1);

    // A tiny max age removes sessions that have not been used recently
    await new Promise((resolve) => setTimeout(resolve, 5));
    await alice.cleanupOldSessions(1);
    expect(await alice.getSessions()).toHaveLength(0);
  });

  it("should handle manual ratchet trigger on non-existent session", async () => {
    await expect(alice.triggerRatchet("non-existent-session")).rejects.toThrow(
      ERRORS.SESSION_NOT_FOUND,
    );
  });

  it("should handle manual ratchet trigger", async () => {
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

    // First, exchange messages to establish the ratchet keys properly
    const establishmentMsg = await alice.encryptMessage(
      aliceSession.sessionId,
      "establish session",
    );
    await bob.decryptMessage(bobSession.sessionId, establishmentMsg);

    // Send a reply from bob to alice to ensure both sides have each other's ratchet keys
    const replyMsg = await bob.encryptMessage(
      bobSession.sessionId,
      "reply to establish ratchet keys",
    );
    await alice.decryptMessage(aliceSession.sessionId, replyMsg);

    // Now both sides should have each other's ratchet public keys
    // Try triggering ratchet on alice side
    await alice.triggerRatchet(aliceSession.sessionId);

    // After ratcheting, send a new message from alice
    const encrypted = await alice.encryptMessage(
      aliceSession.sessionId,
      "Message after ratchet",
    );
    const decrypted = await bob.decryptMessage(bobSession.sessionId, encrypted);

    const decryptedText = new TextDecoder().decode(decrypted.plaintext);
    expect(decryptedText).toBe("Message after ratchet");

    // Now trigger ratchet on bob side
    await bob.triggerRatchet(bobSession.sessionId);

    // Send a message after ratchet from bob
    const encrypted2 = await bob.encryptMessage(
      bobSession.sessionId,
      "Bob's message after ratchet",
    );
    const decrypted2 = await alice.decryptMessage(
      aliceSession.sessionId,
      encrypted2,
    );

    const decryptedText2 = new TextDecoder().decode(decrypted2.plaintext);
    expect(decryptedText2).toBe("Bob's message after ratchet");
  });
});
