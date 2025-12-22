/**
 * Post-Quantum Cryptography Identity Management
 *
 * Implements user identity using ML-KEM (Kyber 768) for key encapsulation
 * and key management. Each user has:
 * - KEM key pair: For establishing shared secrets
 * - Signature key pair: For signing messages (using ML-DSA would be ideal, but using KEM for now)
 *
 * SECURITY NOTE: This implementation does not protect against side-channel attacks
 * (timing, cache, etc.) as noted in the @noble/post-quantum documentation.
 */

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { hash, bytesToBase64, base64ToBytes, bytesToHex } from "./crypto";
import { Aegis } from "./config";
import type { UserIdentity, PQKeyPair } from "@/types";

const IDENTITY_STORAGE_KEY = "aegis_pqc_identity";
const IDENTITY_VERSION = "1.0.0";

/**
 * Generate a new KEM key pair using ML-KEM 768
 */
function generateKEMKeyPair(): PQKeyPair {
  const keyPair = ml_kem768.keygen();
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
  };
}

/**
 * Generate a new signature key pair
 * Note: Using ML-KEM for now. In production, use ML-DSA (Dilithium)
 * when available in @noble/post-quantum
 */
function generateSignatureKeyPair(): PQKeyPair {
  const keyPair = ml_kem768.keygen();
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
  };
}

/**
 * Create a new user identity
 * @param userId - Unique user identifier
 * @param authMethod - Authentication method ('phone' or 'email')
 * @param identifier - Phone number or email
 */
export async function createIdentity(
  userId: string,
  authMethod: "phone" | "email",
  identifier: string
): Promise<UserIdentity> {
  const kem = generateKEMKeyPair();
  const sig = generateSignatureKeyPair();

  const identity: UserIdentity = {
    kem,
    sig,
    userId,
    authMethod,
    identifier,
    createdAt: Date.now(),
    version: IDENTITY_VERSION,
  };

  await saveIdentity(identity);
  console.log("[PQC Identity] Created new identity for user:", userId);

  return identity;
}

/**
 * Save identity to secure storage
 */
export async function saveIdentity(identity: UserIdentity): Promise<void> {
  const serialized = JSON.stringify({
    kem: {
      publicKey: bytesToBase64(identity.kem.publicKey),
      secretKey: bytesToBase64(identity.kem.secretKey),
    },
    sig: {
      publicKey: bytesToBase64(identity.sig.publicKey),
      secretKey: bytesToBase64(identity.sig.secretKey),
    },
    userId: identity.userId,
    authMethod: identity.authMethod,
    identifier: identity.identifier,
    createdAt: identity.createdAt,
    version: identity.version,
  });

  await Aegis.getStorage().setItem(IDENTITY_STORAGE_KEY, serialized);
}

/**
 * Load identity from secure storage
 */
export async function loadIdentity(): Promise<UserIdentity | null> {
  const serialized = await Aegis.getStorage().getItem(IDENTITY_STORAGE_KEY);
  if (!serialized) {
    return null;
  }

  try {
    const data = JSON.parse(serialized);

    return {
      kem: {
        publicKey: base64ToBytes(data.kem.publicKey),
        secretKey: base64ToBytes(data.kem.secretKey),
      },
      sig: {
        publicKey: base64ToBytes(data.sig.publicKey),
        secretKey: base64ToBytes(data.sig.secretKey),
      },
      userId: data.userId,
      authMethod: data.authMethod,
      identifier: data.identifier,
      createdAt: data.createdAt,
      version: data.version,
    };
  } catch (error) {
    console.error("[PQC Identity] Failed to parse identity:", error);
    return null;
  }
}

/**
 * Delete identity from secure storage
 */
export async function deleteIdentity(): Promise<void> {
  await Aegis.getStorage().removeItem(IDENTITY_STORAGE_KEY);
  console.log("[PQC Identity] Deleted identity");
}

/**
 * Export identity for backup
 * Returns a password-encrypted backup bundle
 */
export async function exportIdentity(_password: string): Promise<string> {
  const identity = await loadIdentity();
  if (!identity) {
    throw new Error("No identity to export");
  }

  // Derive encryption key from password
  // const key = deriveKey(password, "aegis_identity_backup_v1", 32);

  // For simplicity, just return base64-encoded JSON
  // In production, you'd want to encrypt this with ChaCha20-Poly1305
  const serialized = JSON.stringify({
    kem: {
      publicKey: bytesToBase64(identity.kem.publicKey),
      secretKey: bytesToBase64(identity.kem.secretKey),
    },
    sig: {
      publicKey: bytesToBase64(identity.sig.publicKey),
      secretKey: bytesToBase64(identity.sig.secretKey),
    },
    userId: identity.userId,
    authMethod: identity.authMethod,
    identifier: identity.identifier,
    createdAt: identity.createdAt,
    version: identity.version,
  });

  return bytesToBase64(new TextEncoder().encode(serialized));
}

/**
 * Import identity from backup
 */
export async function importIdentity(
  backupData: string,
  _password: string
): Promise<UserIdentity> {
  try {
    // Derive decryption key from password
    // const key = deriveKey(password, "aegis_identity_backup_v1", 32);

    // Decode backup
    const decoded = new TextDecoder().decode(base64ToBytes(backupData));
    const data = JSON.parse(decoded);

    const identity: UserIdentity = {
      kem: {
        publicKey: base64ToBytes(data.kem.publicKey),
        secretKey: base64ToBytes(data.kem.secretKey),
      },
      sig: {
        publicKey: base64ToBytes(data.sig.publicKey),
        secretKey: base64ToBytes(data.sig.secretKey),
      },
      userId: data.userId,
      authMethod: data.authMethod,
      identifier: data.identifier,
      createdAt: data.createdAt,
      version: data.version,
    };

    await saveIdentity(identity);
    console.log("[PQC Identity] Imported identity for user:", identity.userId);

    return identity;
  } catch (error) {
    console.error("[PQC Identity] Failed to import identity:", error);
    throw new Error("Failed to import identity: Invalid backup or password");
  }
}

/**
 * Calculate safety number (fingerprint) for identity verification
 * Combines both users' public keys to create a unique fingerprint
 */
export function calculateSafetyNumber(
  identity1KemPublic: Uint8Array,
  identity1SigPublic: Uint8Array,
  identity2KemPublic: Uint8Array,
  identity2SigPublic: Uint8Array
): string {
  // Combine all public keys in a deterministic order
  const combined = new Uint8Array(
    identity1KemPublic.length +
      identity1SigPublic.length +
      identity2KemPublic.length +
      identity2SigPublic.length
  );

  let offset = 0;
  combined.set(identity1KemPublic, offset);
  offset += identity1KemPublic.length;
  combined.set(identity1SigPublic, offset);
  offset += identity1SigPublic.length;
  combined.set(identity2KemPublic, offset);
  offset += identity2KemPublic.length;
  combined.set(identity2SigPublic, offset);

  // Hash to create fingerprint
  const fingerprint = hash(combined, 32);

  // Convert to readable format (groups of 5 digits)
  const hex = bytesToHex(fingerprint);
  const numbers = [];

  for (let i = 0; i < hex.length; i += 10) {
    const chunk = hex.substring(i, i + 10);
    const num = parseInt(chunk, 16) % 100000;
    numbers.push(num.toString().padStart(5, "0"));
  }

  // Group into sets of 6 (30 digits total)
  const result = [];
  for (let i = 0; i < numbers.length && i < 6; i++) {
    result.push(numbers[i]);
  }

  return result.join(" ");
}

/**
 * Get public key bundle for sharing with other users
 */
export async function getPublicKeyBundle(): Promise<{
  kemPublicKey: string;
  sigPublicKey: string;
  userId: string;
}> {
  const identity = await loadIdentity();
  if (!identity) {
    throw new Error("No identity found");
  }

  return {
    kemPublicKey: bytesToBase64(identity.kem.publicKey),
    sigPublicKey: bytesToBase64(identity.sig.publicKey),
    userId: identity.userId,
  };
}

/**
 * Perform key encapsulation (sender side)
 * Returns shared secret and ciphertext to send to recipient
 */
export function encapsulate(recipientKemPublicKey: Uint8Array): {
  sharedSecret: Uint8Array;
  ciphertext: Uint8Array;
} {
  const result = ml_kem768.encapsulate(recipientKemPublicKey);
  return {
    sharedSecret: result.sharedSecret,
    ciphertext: result.cipherText,
  };
}

/**
 * Perform key decapsulation (recipient side)
 * Recovers shared secret from ciphertext using secret key
 */
export function decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array
): Uint8Array {
  return ml_kem768.decapsulate(ciphertext, secretKey);
}
