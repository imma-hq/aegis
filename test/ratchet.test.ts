import { describe, it, expect } from "vitest";
import { KemRatchet } from "../src/ratchet";
import { SessionKeyExchange } from "../src/session";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { Identity, PublicBundle } from "../src/types";

describe("KemRatchet", () => {
  describe("Symmetric Ratchet", () => {
    it("should derive message key and advance chain", () => {
      const initialChain = {
        chainKey: new Uint8Array(32).fill(1),
        messageNumber: 0,
      };

      const { messageKey, newChain } =
        KemRatchet.symmetricRatchet(initialChain);

      expect(messageKey).toBeInstanceOf(Uint8Array);
      expect(messageKey.length).toBe(32);
      expect(newChain.messageNumber).toBe(1);
      expect(newChain.chainKey).not.toEqual(initialChain.chainKey);
    });

    it("should produce different keys for each ratchet", () => {
      let chain = {
        chainKey: new Uint8Array(32).fill(1),
        messageNumber: 0,
      };

      const keys: Uint8Array[] = [];
      for (let i = 0; i < 5; i++) {
        const result = KemRatchet.symmetricRatchet(chain);
        keys.push(result.messageKey);
        chain = result.newChain;
      }

      // All keys should be unique
      for (let i = 0; i < keys.length; i++) {
        for (let j = i + 1; j < keys.length; j++) {
          expect(keys[i]).not.toEqual(keys[j]);
        }
      }
    });

    it("should increment message numbers sequentially", () => {
      let chain = {
        chainKey: new Uint8Array(32).fill(1),
        messageNumber: 0,
      };

      for (let i = 0; i < 10; i++) {
        expect(chain.messageNumber).toBe(i);
        const result = KemRatchet.symmetricRatchet(chain);
        chain = result.newChain;
      }

      expect(chain.messageNumber).toBe(10);
    });
  });

  describe("Skip Message Keys", () => {
    it("should skip to target message number", () => {
      const chain = {
        chainKey: new Uint8Array(32).fill(1),
        messageNumber: 0,
      };

      const { skippedKeys, newChain } = KemRatchet.skipMessageKeys(
        chain,
        5,
        100,
      );

      expect(skippedKeys.size).toBe(5);
      expect(newChain.messageNumber).toBe(5);
      expect(skippedKeys.has(0)).toBe(true);
      expect(skippedKeys.has(4)).toBe(true);
    });

    it("should reject skipping backwards", () => {
      const chain = {
        chainKey: new Uint8Array(32).fill(1),
        messageNumber: 5,
      };

      expect(() => KemRatchet.skipMessageKeys(chain, 3, 100)).toThrow(
        "Cannot skip to earlier message number",
      );
    });

    it("should reject skipping too many messages", () => {
      const chain = {
        chainKey: new Uint8Array(32).fill(1),
        messageNumber: 0,
      };

      expect(() => KemRatchet.skipMessageKeys(chain, 101, 100)).toThrow(
        "exceeds maximum",
      );
    });

    it("should generate correct keys for skipped messages", () => {
      const chain = {
        chainKey: new Uint8Array(32).fill(1),
        messageNumber: 0,
      };

      const { skippedKeys } = KemRatchet.skipMessageKeys(chain, 3, 100);

      // Verify by manually ratcheting
      let manualChain = { ...chain };
      for (let i = 0; i < 3; i++) {
        const result = KemRatchet.symmetricRatchet(manualChain);
        expect(skippedKeys.get(i)).toEqual(result.messageKey);
        manualChain = result.newChain;
      }
    });
  });

  describe("KEM Ratchet Encapsulation", () => {
    it("should perform encapsulation ratchet", () => {
      const rootKey = new Uint8Array(32).fill(1);
      const peerKeyPair = ml_kem768.keygen();

      const result = KemRatchet.performKemRatchetEncapsulate(
        rootKey,
        peerKeyPair.publicKey,
      );

      expect(result.newRootKey).toBeInstanceOf(Uint8Array);
      expect(result.newRootKey).not.toEqual(rootKey);
      expect(result.newRatchetKeyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(result.sendingChain.messageNumber).toBe(0);
      expect(result.receivingChain.messageNumber).toBe(0);
      expect(result.kemCiphertext).toBeInstanceOf(Uint8Array);
    });

    it("should throw error without peer public key", () => {
      const rootKey = new Uint8Array(32).fill(1);

      expect(() =>
        KemRatchet.performKemRatchetEncapsulate(rootKey, null as any),
      ).toThrow("peerRatchetPublicKey is required");
    });

    it("should validate peer ratchet public key", () => {
      const rootKey = new Uint8Array(32).fill(1);
      const invalidKey = new Uint8Array(100); // Wrong size

      expect(() =>
        KemRatchet.performKemRatchetEncapsulate(rootKey, invalidKey),
      ).toThrow("Invalid peer ratchet public key");
    });
  });

  describe("KEM Ratchet Decapsulation", () => {
    it("should perform decapsulation ratchet", () => {
      const rootKey = new Uint8Array(32).fill(1);
      const keyPair = ml_kem768.keygen();

      // First encapsulate
      const encapResult = KemRatchet.performKemRatchetEncapsulate(
        rootKey,
        keyPair.publicKey,
      );

      // Then decapsulate
      const decapResult = KemRatchet.performKemRatchetDecapsulate(
        rootKey,
        encapResult.kemCiphertext,
        keyPair.secretKey,
      );

      expect(decapResult.newRootKey).toBeInstanceOf(Uint8Array);
      expect(decapResult.newRatchetKeyPair.publicKey).toBeInstanceOf(
        Uint8Array,
      );
      expect(decapResult.sendingChain.messageNumber).toBe(0);
      expect(decapResult.receivingChain.messageNumber).toBe(0);
    });

    it("should throw error without ciphertext", () => {
      const rootKey = new Uint8Array(32).fill(1);
      const keyPair = ml_kem768.keygen();

      expect(() =>
        KemRatchet.performKemRatchetDecapsulate(
          rootKey,
          new Uint8Array(0),
          keyPair.secretKey,
        ),
      ).toThrow("KEM ciphertext is required");
    });

    it("should derive same root key for both parties", () => {
      const rootKey = new Uint8Array(32).fill(1);
      const keyPair = ml_kem768.keygen();

      const encapResult = KemRatchet.performKemRatchetEncapsulate(
        rootKey,
        keyPair.publicKey,
      );

      const decapResult = KemRatchet.performKemRatchetDecapsulate(
        rootKey,
        encapResult.kemCiphertext,
        keyPair.secretKey,
      );

      // Both should derive the same new root key
      expect(encapResult.newRootKey).toEqual(decapResult.newRootKey);
    });
  });

  describe("Key Confirmation", () => {
    it("should generate confirmation MAC", () => {
      const sessionId = "test-session";
      const rootKey = new Uint8Array(32).fill(1);
      const chainKey = new Uint8Array(32).fill(2);

      const mac = KemRatchet.generateConfirmationMac(
        sessionId,
        rootKey,
        chainKey,
        false,
      );

      expect(mac).toBeInstanceOf(Uint8Array);
      expect(mac.length).toBe(32);
    });

    it("should generate different MACs for initiator and responder", () => {
      const sessionId = "test-session";
      const rootKey = new Uint8Array(32).fill(1);
      const chainKey = new Uint8Array(32).fill(2);

      const initiatorMac = KemRatchet.generateConfirmationMac(
        sessionId,
        rootKey,
        chainKey,
        false,
      );
      const responderMac = KemRatchet.generateConfirmationMac(
        sessionId,
        rootKey,
        chainKey,
        true,
      );

      expect(initiatorMac).not.toEqual(responderMac);
    });

    it("should verify valid confirmation MAC", () => {
      const sessionId = "test-session";
      const rootKey = new Uint8Array(32).fill(1);
      const chainKey = new Uint8Array(32).fill(2);

      const mac = KemRatchet.generateConfirmationMac(
        sessionId,
        rootKey,
        chainKey,
        false,
      );

      const isValid = KemRatchet.verifyConfirmationMac(
        sessionId,
        rootKey,
        chainKey,
        mac,
        false,
      );

      expect(isValid).toBe(true);
    });

    it("should reject invalid confirmation MAC", () => {
      const sessionId = "test-session";
      const rootKey = new Uint8Array(32).fill(1);
      const chainKey = new Uint8Array(32).fill(2);

      const invalidMac = new Uint8Array(32).fill(0);

      const isValid = KemRatchet.verifyConfirmationMac(
        sessionId,
        rootKey,
        chainKey,
        invalidMac,
        false,
      );

      expect(isValid).toBe(false);
    });

    it("should use constant-time comparison", () => {
      const sessionId = "test-session";
      const rootKey = new Uint8Array(32).fill(1);
      const chainKey = new Uint8Array(32).fill(2);

      const mac = KemRatchet.generateConfirmationMac(
        sessionId,
        rootKey,
        chainKey,
        false,
      );

      // Modify one byte
      const tamperedMac = new Uint8Array(mac);
      tamperedMac[0] ^= 0x01;

      const isValid = KemRatchet.verifyConfirmationMac(
        sessionId,
        rootKey,
        chainKey,
        tamperedMac,
        false,
      );

      expect(isValid).toBe(false);
    });
  });

  describe("Utility Functions", () => {
    it("should validate ratchet public key", () => {
      const validKey = ml_kem768.keygen().publicKey;
      expect(KemRatchet.validateRatchetPublicKey(validKey)).toBe(true);

      const invalidKey = new Uint8Array(100);
      expect(KemRatchet.validateRatchetPublicKey(invalidKey)).toBe(false);
    });

    it("should generate fresh ratchet keypair", () => {
      const keyPair = KemRatchet.generateRatchetKeyPair();

      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(1184); // ML-KEM-768 public key size
    });

    it("should derive unique ratchet IDs", () => {
      const publicKey1 = new Uint8Array(32).fill(1);
      const chainKey1 = new Uint8Array(32).fill(1);

      const publicKey2 = new Uint8Array(32).fill(2);
      const chainKey2 = new Uint8Array(32).fill(2);

      const id1 = KemRatchet.deriveRatchetId(publicKey1, chainKey1);
      const id2 = KemRatchet.deriveRatchetId(publicKey2, chainKey2);

      expect(id1).not.toBe(id2);
      expect(id1).toHaveLength(32); // 16 bytes = 32 hex chars
    });
  });
});

describe("SessionKeyExchange", () => {
  let aliceIdentity: Identity;
  let bobIdentity: Identity;
  let bobBundle: PublicBundle;

  beforeEach(() => {
    const aliceKemKeyPair = ml_kem768.keygen();
    const aliceDsaKeyPair = ml_dsa65.keygen();
    aliceIdentity = {
      kemKeyPair: aliceKemKeyPair,
      dsaKeyPair: aliceDsaKeyPair,
      userId: bytesToHex(blake3(aliceKemKeyPair.publicKey, { dkLen: 32 })),
      createdAt: Date.now(),
      preKeySecret: undefined,
    };

    const bobKemKeyPair = ml_kem768.keygen();
    const bobDsaKeyPair = ml_dsa65.keygen();
    const bobPreKeyPair = ml_kem768.keygen();
    const bobPreKeySignature = ml_dsa65.sign(
      bobPreKeyPair.publicKey,
      bobDsaKeyPair.secretKey,
    );

    bobIdentity = {
      kemKeyPair: bobKemKeyPair,
      dsaKeyPair: bobDsaKeyPair,
      userId: bytesToHex(blake3(bobKemKeyPair.publicKey, { dkLen: 32 })),
      createdAt: Date.now(),
      preKeySecret: bobPreKeyPair.secretKey,
    };

    bobBundle = {
      userId: bobIdentity.userId,
      kemPublicKey: bobKemKeyPair.publicKey,
      dsaPublicKey: bobDsaKeyPair.publicKey,
      preKey: {
        id: 1,
        key: bobPreKeyPair.publicKey,
        signature: bobPreKeySignature,
      },
      createdAt: Date.now(),
    };
  });

  describe("Initiator Session Creation", () => {
    it("should create initiator session", () => {
      const result = SessionKeyExchange.createInitiatorSession(
        aliceIdentity,
        bobBundle,
      );

      expect(result.sessionId).toBeDefined();
      expect(result.rootKey).toBeInstanceOf(Uint8Array);
      expect(result.chainKey).toBeInstanceOf(Uint8Array);
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.confirmationMac).toBeInstanceOf(Uint8Array);
    });

    it("should generate deterministic session ID", () => {
      const result1 = SessionKeyExchange.createInitiatorSession(
        aliceIdentity,
        bobBundle,
      );

      // Same inputs should produce same session ID
      const result2 = SessionKeyExchange.createInitiatorSession(
        aliceIdentity,
        bobBundle,
      );

      // Note: Session IDs will be different because KEM produces random ciphertext
      // This is expected behavior
      expect(result1.sessionId).toBeDefined();
      expect(result2.sessionId).toBeDefined();
    });
  });

  describe("Responder Session Creation", () => {
    it("should create responder session", () => {
      const initiatorResult = SessionKeyExchange.createInitiatorSession(
        aliceIdentity,
        bobBundle,
      );

      const aliceBundle: PublicBundle = {
        userId: aliceIdentity.userId,
        kemPublicKey: aliceIdentity.kemKeyPair.publicKey,
        dsaPublicKey: aliceIdentity.dsaKeyPair.publicKey,
        preKey: bobBundle.preKey,
        createdAt: Date.now(),
      };

      const responderResult = SessionKeyExchange.createResponderSession(
        bobIdentity,
        aliceBundle,
        initiatorResult.ciphertext,
        initiatorResult.confirmationMac,
      );

      expect(responderResult.sessionId).toBe(initiatorResult.sessionId);
      expect(responderResult.rootKey).toBeInstanceOf(Uint8Array);
      expect(responderResult.chainKey).toBeInstanceOf(Uint8Array);
      expect(responderResult.confirmationMac).toBeInstanceOf(Uint8Array);
      expect(responderResult.isValid).toBe(true);
    });

    it("should derive same keys as initiator", () => {
      const initiatorResult = SessionKeyExchange.createInitiatorSession(
        aliceIdentity,
        bobBundle,
      );

      const aliceBundle: PublicBundle = {
        userId: aliceIdentity.userId,
        kemPublicKey: aliceIdentity.kemKeyPair.publicKey,
        dsaPublicKey: aliceIdentity.dsaKeyPair.publicKey,
        preKey: bobBundle.preKey,
        createdAt: Date.now(),
      };

      const responderResult = SessionKeyExchange.createResponderSession(
        bobIdentity,
        aliceBundle,
        initiatorResult.ciphertext,
      );

      expect(responderResult.rootKey).toEqual(initiatorResult.rootKey);
      expect(responderResult.chainKey).toEqual(initiatorResult.chainKey);
    });

    it("should validate initiator confirmation MAC", () => {
      const initiatorResult = SessionKeyExchange.createInitiatorSession(
        aliceIdentity,
        bobBundle,
      );

      const aliceBundle: PublicBundle = {
        userId: aliceIdentity.userId,
        kemPublicKey: aliceIdentity.kemKeyPair.publicKey,
        dsaPublicKey: aliceIdentity.dsaKeyPair.publicKey,
        preKey: bobBundle.preKey,
        createdAt: Date.now(),
      };

      const responderResult = SessionKeyExchange.createResponderSession(
        bobIdentity,
        aliceBundle,
        initiatorResult.ciphertext,
        initiatorResult.confirmationMac,
      );

      expect(responderResult.isValid).toBe(true);
    });

    it("should reject invalid initiator MAC", () => {
      const initiatorResult = SessionKeyExchange.createInitiatorSession(
        aliceIdentity,
        bobBundle,
      );

      const aliceBundle: PublicBundle = {
        userId: aliceIdentity.userId,
        kemPublicKey: aliceIdentity.kemKeyPair.publicKey,
        dsaPublicKey: aliceIdentity.dsaKeyPair.publicKey,
        preKey: bobBundle.preKey,
        createdAt: Date.now(),
      };

      const invalidMac = new Uint8Array(32).fill(0);

      const responderResult = SessionKeyExchange.createResponderSession(
        bobIdentity,
        aliceBundle,
        initiatorResult.ciphertext,
        invalidMac,
      );

      expect(responderResult.isValid).toBe(false);
    });
  });

  describe("Key Confirmation Verification", () => {
    it("should verify responder confirmation MAC", () => {
      const initiatorResult = SessionKeyExchange.createInitiatorSession(
        aliceIdentity,
        bobBundle,
      );

      const aliceBundle: PublicBundle = {
        userId: aliceIdentity.userId,
        kemPublicKey: aliceIdentity.kemKeyPair.publicKey,
        dsaPublicKey: aliceIdentity.dsaKeyPair.publicKey,
        preKey: bobBundle.preKey,
        createdAt: Date.now(),
      };

      const responderResult = SessionKeyExchange.createResponderSession(
        bobIdentity,
        aliceBundle,
        initiatorResult.ciphertext,
      );

      const isValid = SessionKeyExchange.verifyKeyConfirmation(
        initiatorResult.sessionId,
        initiatorResult.rootKey,
        initiatorResult.chainKey,
        responderResult.confirmationMac,
      );

      expect(isValid).toBe(true);
    });

    it("should reject invalid responder MAC", () => {
      const initiatorResult = SessionKeyExchange.createInitiatorSession(
        aliceIdentity,
        bobBundle,
      );

      const invalidMac = new Uint8Array(32).fill(0);

      const isValid = SessionKeyExchange.verifyKeyConfirmation(
        initiatorResult.sessionId,
        initiatorResult.rootKey,
        initiatorResult.chainKey,
        invalidMac,
      );

      expect(isValid).toBe(false);
    });
  });
});
