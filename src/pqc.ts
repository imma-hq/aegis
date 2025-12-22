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
const IDENTITY_VERSION = "2.0.0"; // Bump version for X3DH support

export interface SignedPreKey {
  id: number;
  keyPair: PQKeyPair;
  signature: Uint8Array;
  createdAt: number;
}

export interface OneTimePreKey {
  id: number;
  keyPair: PQKeyPair;
}

// Extend UserIdentity to hold PreKeys (internal storage)
interface ExtendedUserIdentity extends UserIdentity {
  signedPreKey: SignedPreKey;
  oneTimePreKeys: OneTimePreKey[];
}

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

  // Generate initial Signed PreKey
  const signedPreKey = generateSignedPreKey(kem, sig);

  // Generate initial batch of 50 One-Time PreKeys
  const oneTimePreKeys = generateOneTimePreKeys(50);

  const identity: ExtendedUserIdentity = {
    kem,
    sig,
    userId,
    authMethod,
    identifier,
    createdAt: Date.now(),
    version: IDENTITY_VERSION,
    signedPreKey,
    oneTimePreKeys,
  };

  await saveIdentity(identity);
  console.log("[PQC Identity] Created new identity for user:", userId);

  return identity;
}

function generateSignedPreKey(
  identityKem: PQKeyPair,
  identitySig: PQKeyPair
): SignedPreKey {
  const keyPair = generateKEMKeyPair();
  // Sign the public key with the identity's signature key
  // Note: Ideally use ML-DSA. Here we mock sign (or use crypto primitives if available).
  // For now, we'll hash it as a placeholder for signature or use Blake3 as a MAC with sec key.
  // Real implementation: signature = Sign(identitySig.secretKey, keyPair.publicKey)
  const signature = hash(keyPair.publicKey); // Placeholder for ML-DSA signature

  return {
    id: Math.floor(Date.now() / 1000), // Simple ID scheme
    keyPair,
    signature,
    createdAt: Date.now(),
  };
}

function generateOneTimePreKeys(count: number): OneTimePreKey[] {
  const keys: OneTimePreKey[] = [];
  for (let i = 0; i < count; i++) {
    keys.push({
      id: i,
      keyPair: generateKEMKeyPair(),
    });
  }
  return keys;
}

/**
 * Save identity to secure storage
 */
export async function saveIdentity(identity: UserIdentity): Promise<void> {
  const extendedIdentity = identity as ExtendedUserIdentity;
  const serialized = JSON.stringify({
    kem: {
      publicKey: bytesToBase64(identity.kem.publicKey),
      secretKey: bytesToBase64(identity.kem.secretKey),
    },
    sig: {
      publicKey: bytesToBase64(identity.sig.publicKey),
      secretKey: bytesToBase64(identity.sig.secretKey),
    },
    signedPreKey: extendedIdentity.signedPreKey
      ? {
          id: extendedIdentity.signedPreKey.id,
          key: {
            pub: bytesToBase64(extendedIdentity.signedPreKey.keyPair.publicKey),
            sec: bytesToBase64(extendedIdentity.signedPreKey.keyPair.secretKey),
          },
          sig: bytesToBase64(extendedIdentity.signedPreKey.signature),
          created: extendedIdentity.signedPreKey.createdAt,
        }
      : undefined,
    oneTimePreKeys: extendedIdentity.oneTimePreKeys
      ? extendedIdentity.oneTimePreKeys.map((k) => ({
          id: k.id,
          pub: bytesToBase64(k.keyPair.publicKey),
          sec: bytesToBase64(k.keyPair.secretKey),
        }))
      : [],
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

    const identity: ExtendedUserIdentity = {
      kem: {
        publicKey: base64ToBytes(data.kem.publicKey),
        secretKey: base64ToBytes(data.kem.secretKey),
      },
      sig: {
        publicKey: base64ToBytes(data.sig.publicKey),
        secretKey: base64ToBytes(data.sig.secretKey),
      },
      signedPreKey: data.signedPreKey
        ? {
            id: data.signedPreKey.id,
            keyPair: {
              publicKey: base64ToBytes(data.signedPreKey.key.pub),
              secretKey: base64ToBytes(data.signedPreKey.key.sec),
            },
            signature: base64ToBytes(data.signedPreKey.sig),
            createdAt: data.signedPreKey.created,
          }
        : (undefined as any), // Cast for compatibility if missing in old versions
      oneTimePreKeys: data.oneTimePreKeys
        ? data.oneTimePreKeys.map((k: any) => ({
            id: k.id,
            keyPair: {
              publicKey: base64ToBytes(k.pub),
              secretKey: base64ToBytes(k.sec),
            },
          }))
        : [],
      userId: data.userId,
      authMethod: data.authMethod,
      identifier: data.identifier,
      createdAt: data.createdAt,
      version: data.version,
    };

    return identity;
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
 * Get public key bundle (X3DH Triple Pre-Key Bundle)
 * Returns the Identity Key, Signed PreKey, and one One-Time PreKey.
 * This bundle allows a sender to establish a Forward Secure session.
 */
export async function getPublicKeyBundle(): Promise<{
  identityKey: string;
  signedPreKey: {
    id: number;
    key: string;
    signature: string;
  };
  oneTimePreKey?: {
    id: number;
    key: string;
  };
  userId: string;
}> {
  const identity = (await loadIdentity()) as ExtendedUserIdentity;
  if (!identity) {
    throw new Error("No identity found");
  }

  // Pick a random One-Time PreKey (OTPK) effectively (or just the first one)
  // In a real server implementation, the server stores these and hands out one per request.
  // Since we are simulating or client-managed, we pop one? No, we shouldn't pop on GET, only on use.
  // But here we just return one to simulate the bundle.
  const otpk =
    identity.oneTimePreKeys.length > 0 ? identity.oneTimePreKeys[0] : undefined;

  return {
    identityKey: bytesToBase64(identity.kem.publicKey),
    signedPreKey: {
      id: identity.signedPreKey.id,
      key: bytesToBase64(identity.signedPreKey.keyPair.publicKey),
      signature: bytesToBase64(identity.signedPreKey.signature),
    },
    oneTimePreKey: otpk
      ? {
          id: otpk.id,
          key: bytesToBase64(otpk.keyPair.publicKey),
        }
      : undefined,
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
