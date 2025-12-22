/**
 * Core Cryptographic Utilities
 *
 * Implements cryptographic primitives using @noble libraries:
 * - Blake3 hashing for fingerprints and key derivation
 * - ChaCha20-Poly1305 for authenticated encryption
 * - Utilities for encoding and random generation
 */

import { blake3 } from "@noble/hashes/blake3.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/hashes/utils.js";

/**
 * Hash data using Blake3
 * @param data - Input data as Uint8Array or string
 * @param outputLength - Optional output length in bytes (default: 32)
 * @returns Blake3 hash as Uint8Array
 */
export function hash(
  data: Uint8Array | string,
  outputLength: number = 32
): Uint8Array {
  const input = typeof data === "string" ? stringToBytes(data) : data;
  return blake3(input, { dkLen: outputLength });
}

/**
 * Derive a key from input data using Blake3
 * @param data - Input data
 * @param context - Context string for domain separation
 * @param outputLength - Output length in bytes (default: 32)
 */
export function deriveKey(
  data: Uint8Array | string,
  context: string,
  outputLength: number = 32
): Uint8Array {
  const input = typeof data === "string" ? stringToBytes(data) : data;
  const contextBytes = stringToBytes(context);

  // Concatenate context and input
  const combined = new Uint8Array(contextBytes.length + input.length);
  combined.set(contextBytes, 0);
  combined.set(input, contextBytes.length);

  return blake3(combined, { dkLen: outputLength });
}

/**
 * Generate cryptographically secure random bytes
 * @param length - Number of bytes to generate
 */
export function getRandomBytes(length: number): Uint8Array {
  return randomBytes(length);
}

/**
 * Encrypt data using ChaCha20-Poly1305
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce (must be unique for each message)
 * @param plaintext - Data to encrypt
 * @param associatedData - Optional authenticated data (not encrypted)
 * @returns Ciphertext with authentication tag appended
 */
export function encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error("Key must be 32 bytes");
  }
  if (nonce.length !== 12) {
    throw new Error("Nonce must be 12 bytes");
  }

  const cipher = chacha20poly1305(key, nonce, associatedData);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypt data using ChaCha20-Poly1305
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce
 * @param ciphertext - Encrypted data with authentication tag
 * @param associatedData - Optional authenticated data (must match encryption)
 * @returns Decrypted plaintext
 * @throws Error if authentication fails
 */
export function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData?: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error("Key must be 32 bytes");
  }
  if (nonce.length !== 12) {
    throw new Error("Nonce must be 12 bytes");
  }

  const cipher = chacha20poly1305(key, nonce, associatedData);
  return cipher.decrypt(ciphertext);
}

/**
 * Generate a unique 12-byte nonce
 * IMPORTANT: Never reuse a nonce with the same key
 */
export function generateNonce(): Uint8Array {
  return getRandomBytes(12);
}

/**
 * Generate a 32-byte encryption key
 */
export function generateKey(): Uint8Array {
  return getRandomBytes(32);
}

/**
 * Convert string to Uint8Array (UTF-8 encoding)
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Convert Uint8Array to string (UTF-8 decoding)
 */
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Convert Uint8Array to base64 string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  // Simple base64 encoding for React Native
  const binary = Array.from(bytes)
    .map((byte) => String.fromCharCode(byte))
    .join("");

  // Use btoa if available (web), otherwise implement basic base64
  if (typeof btoa !== "undefined") {
    return btoa(binary);
  }

  // Fallback base64 encoding
  const base64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  let i = 0;

  while (i < bytes.length) {
    const a = bytes[i++];
    const b = i < bytes.length ? bytes[i++] : 0;
    const c = i < bytes.length ? bytes[i++] : 0;

    const bitmap = (a << 16) | (b << 8) | c;

    result += base64Chars[(bitmap >> 18) & 63];
    result += base64Chars[(bitmap >> 12) & 63];
    result += i - 2 < bytes.length ? base64Chars[(bitmap >> 6) & 63] : "=";
    result += i - 1 < bytes.length ? base64Chars[bitmap & 63] : "=";
  }

  return result;
}

/**
 * Convert base64 string to Uint8Array
 */
export function base64ToBytes(base64: string): Uint8Array {
  // Use atob if available (web)
  if (typeof atob !== "undefined") {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Fallback base64 decoding
  const base64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const lookup = new Uint8Array(256);
  for (let i = 0; i < base64Chars.length; i++) {
    lookup[base64Chars.charCodeAt(i)] = i;
  }

  const len = base64.length;
  let bufferLength = base64.length * 0.75;
  if (base64[len - 1] === "=") {
    bufferLength--;
    if (base64[len - 2] === "=") {
      bufferLength--;
    }
  }

  const bytes = new Uint8Array(bufferLength);
  let p = 0;

  for (let i = 0; i < len; i += 4) {
    const encoded1 = lookup[base64.charCodeAt(i)];
    const encoded2 = lookup[base64.charCodeAt(i + 1)];
    const encoded3 = lookup[base64.charCodeAt(i + 2)];
    const encoded4 = lookup[base64.charCodeAt(i + 3)];

    bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
    if (p < bufferLength) bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
    if (p < bufferLength) bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
  }

  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even length");
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return bytes;
}

/**
 * Constant-time comparison of two Uint8Arrays
 * Prevents timing attacks
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

/**
 * Zero out a buffer to clear sensitive data from memory (Best Effort)
 * Note: In JS, garbage collection might move memory, so this is not a guarantee.
 */
export function zeroBuffer(buffer: Uint8Array): void {
  buffer.fill(0);
}
