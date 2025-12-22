import { describe, it, expect } from "vitest";
import {
  hash,
  deriveKey,
  getRandomBytes,
  encrypt,
  decrypt,
  generateNonce,
  generateKey,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  stringToBytes,
  bytesToString,
} from "../src/crypto";

describe("Crypto Utilities", () => {
  describe("Hashing (Blake3)", () => {
    it("should hash data consistently", () => {
      const input = "test-data";
      const h1 = hash(input);
      const h2 = hash(input);
      expect(bytesToHex(h1)).toBe(bytesToHex(h2));
      expect(h1.length).toBe(32);
    });

    it("should derive keys consistently", () => {
      const secret = "shared-secret";
      const context = "context";
      const k1 = deriveKey(secret, context);
      const k2 = deriveKey(secret, context);
      expect(bytesToHex(k1)).toBe(bytesToHex(k2));
      expect(k1.length).toBe(32);
    });

    it("should produce different keys for different contexts", () => {
      const secret = "shared-secret";
      const k1 = deriveKey(secret, "context1");
      const k2 = deriveKey(secret, "context2");
      expect(bytesToHex(k1)).not.toBe(bytesToHex(k2));
    });
  });

  describe("Encryption (ChaCha20-Poly1305)", () => {
    it("should encrypt and decrypt correctly", () => {
      const key = generateKey();
      const nonce = generateNonce();
      const plaintext = "Hello World";
      const plaintextBytes = stringToBytes(plaintext);

      const ciphertext = encrypt(key, nonce, plaintextBytes);
      const decrypted = decrypt(key, nonce, ciphertext);

      expect(bytesToString(decrypted)).toBe(plaintext);
    });

    it("should fail validation with wrong key", () => {
      const key = generateKey();
      const wrongKey = generateKey();
      const nonce = generateNonce();
      const plaintext = stringToBytes("sensitive");
      const ciphertext = encrypt(key, nonce, plaintext);

      expect(() => decrypt(wrongKey, nonce, ciphertext)).toThrow();
    });

    it("should fail validation with wrong nonce", () => {
      const key = generateKey();
      const nonce = generateNonce();
      const wrongNonce = generateNonce();
      const plaintext = stringToBytes("sensitive");
      const ciphertext = encrypt(key, nonce, plaintext);

      expect(() => decrypt(key, wrongNonce, ciphertext)).toThrow();
    });
  });

  describe("Encoding", () => {
    it("should roundtrip base64", () => {
      const original = getRandomBytes(32);
      const b64 = bytesToBase64(original);
      const decoded = base64ToBytes(b64);
      expect(bytesToHex(decoded)).toBe(bytesToHex(original));
    });

    it("should roundtrip hex", () => {
      const original = getRandomBytes(32);
      const hex = bytesToHex(original);
      const decoded = hexToBytes(hex);
      expect(bytesToHex(decoded)).toBe(hex);
      // deep equality check on bytes
      expect(decoded).toEqual(original);
    });
  });
});
