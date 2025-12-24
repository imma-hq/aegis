// crypto.ts - Ensuring consistent KDF contexts
import { blake3 } from "@noble/hashes/blake3.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/hashes/utils.js";

/**
 * Hash data using Blake3
 */
export function hash(
  data: Uint8Array | string,
  outputLength: number = 32,
): Uint8Array {
  if (!data) {
    throw new Error("Input data cannot be empty");
  }

  if (outputLength <= 0 || outputLength > 64) {
    throw new Error("Output length must be between 1 and 64 bytes");
  }

  const input = typeof data === "string" ? stringToBytes(data) : data;
  return blake3(input, { dkLen: outputLength });
}

/**
 * Derive a key from input data using Blake3 with proper domain separation
 */
export function deriveKey(
  data: Uint8Array | string,
  context: string,
  outputLength: number = 32,
): Uint8Array {
  const input = typeof data === "string" ? stringToBytes(data) : data;
  const contextBytes = stringToBytes(context);

  // Use HKDF-style construction: hash(context || input)
  const combined = new Uint8Array(contextBytes.length + input.length + 1);
  combined.set(contextBytes, 0);
  combined.set(input, contextBytes.length);
  combined[combined.length - 1] = outputLength; // Add output length for domain separation

  return blake3(combined, { dkLen: outputLength });
}

/**
 * Generate cryptographically secure random bytes
 */
export function getRandomBytes(length: number): Uint8Array {
  return randomBytes(length);
}

/**
 * Encrypt data using ChaCha20-Poly1305
 */
export function encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
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
 */
export function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData?: Uint8Array,
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
 * Convert Uint8Array to base64 string (URL-safe)
 */
export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  const binary = Array.from(bytes)
    .map((byte) => String.fromCharCode(byte))
    .join("");

  if (typeof btoa !== "undefined") {
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  const base64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let result = "";
  let i = 0;

  while (i < bytes.length) {
    const byte1 = bytes[i++];
    const byte2 = i < bytes.length ? bytes[i++] : 0;
    const byte3 = i < bytes.length ? bytes[i++] : 0;

    const triplet = (byte1 << 16) | (byte2 << 8) | byte3;

    result += base64Chars[(triplet >> 18) & 0x3f];
    result += base64Chars[(triplet >> 12) & 0x3f];
    result += i - 2 < bytes.length ? base64Chars[(triplet >> 6) & 0x3f] : "";
    result += i - 1 < bytes.length ? base64Chars[triplet & 0x3f] : "";
  }

  return result;
}

/**
 * Convert base64 string to Uint8Array (handles URL-safe base64)
 */
export function base64ToBytes(base64: string): Uint8Array {
  // Normalize base64 string (handle URL-safe encoding)
  let normalized = base64.replace(/-/g, "+").replace(/_/g, "/");

  // Add padding if needed
  while (normalized.length % 4 !== 0) {
    normalized += "=";
  }

  // For Node.js and modern browsers
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(normalized, "base64"));
  }

  // For React Native and web
  if (typeof atob !== "undefined") {
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Fallback implementation
  const base64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const lookup = new Uint8Array(256);
  for (let i = 0; i < base64Chars.length; i++) {
    lookup[base64Chars.charCodeAt(i)] = i;
  }

  // Remove padding
  const str = normalized.replace(/=+$/, "");
  let bufferLength = str.length * 0.75;

  const bytes = new Uint8Array(bufferLength);
  let p = 0;

  for (let i = 0; i < str.length; i += 4) {
    const encoded1 = lookup[str.charCodeAt(i)];
    const encoded2 = lookup[str.charCodeAt(i + 1)];
    const encoded3 = i + 2 < str.length ? lookup[str.charCodeAt(i + 2)] : 0;
    const encoded4 = i + 3 < str.length ? lookup[str.charCodeAt(i + 3)] : 0;

    const triplet =
      (encoded1 << 18) | (encoded2 << 12) | (encoded3 << 6) | encoded4;

    if (p < bufferLength) bytes[p++] = (triplet >> 16) & 0xff;
    if (p < bufferLength) bytes[p++] = (triplet >> 8) & 0xff;
    if (p < bufferLength) bytes[p++] = triplet & 0xff;
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
 * Zero out a buffer to clear sensitive data from memory
 */
export function zeroBuffer(buffer: Uint8Array): void {
  buffer.fill(0);
}

/**
 * Secure scrypt KDF implementation
 */
export async function scrypt(
  password: string | Uint8Array,
  salt: Uint8Array,
  options: { N: number; r: number; p: number; dkLen: number },
): Promise<Uint8Array> {
  const passwordBytes =
    typeof password === "string" ? stringToBytes(password) : password;

  const { scrypt: nobleScrypt } = await import("@noble/hashes/scrypt.js");
  return nobleScrypt(passwordBytes, salt, options);
}
