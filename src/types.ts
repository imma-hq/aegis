/**
 * Public types for Aegis
 *
 * This file intentionally keeps only the types actively used by the codebase.
 * Unused / dead declarations (unused error classes and server-only payload types)
 * have been removed to reduce the public surface area and maintenance burden.
 */

/**
 * Simple representation for a KEM / keypair
 */
export interface PQKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * Authentication method used for an identity
 */
export type AuthMethod = "phone" | "email";

/**
 * Stored user identity.
 * - `kem` and `sig` contain the raw key material (stored as bytes).
 * - `version` is useful for migrations/keystore changes.
 */
export interface UserIdentity {
  kem: PQKeyPair;
  sig: PQKeyPair;
  userId: string;
  authMethod: AuthMethod;
  identifier: string;
  createdAt: number;
  version: string;
}

/**
 * Minimal storage adapter interface required by Aegis.
 *
 * Implementations should ensure stored values are protected appropriately
 * (e.g., using platform secure storage) since this will contain secret material.
 */
export interface StorageAdapter {
  setItem(key: string, value: string): Promise<void>;
  getItem(key: string): Promise<string | null>;
  removeItem(key: string): Promise<void>;
}
