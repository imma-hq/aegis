declare module "aegis" {
  /**
   * Public types for Aegis
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
   * Signed PreKey structure
   */
  export interface SignedPreKey {
    id: number;
    keyPair: PQKeyPair;
    signature: Uint8Array;
    createdAt: number;
  }

  /**
   * One-Time PreKey structure
   */
  export interface OneTimePreKey {
    id: number;
    keyPair: PQKeyPair;
  }

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
   * Extended user identity with pre-keys (for internal storage)
   */
  export interface ExtendedUserIdentity extends UserIdentity {
    signedPreKey: SignedPreKey;
    oneTimePreKeys: OneTimePreKey[];
  }

  /**
   * Minimal storage adapter interface required by Aegis.
   */
  export interface StorageAdapter {
    setItem(key: string, value: string): Promise<void>;
    getItem(key: string): Promise<string | null>;
    removeItem(key: string): Promise<void>;
  }

  /**
   * Session types for 1:1 messaging
   */
  export interface SessionInitData {
    sessionId: string;
    ciphertexts: {
      ik: string;
      spk: string;
      otpk?: string;
    };
    ratchetPubKey?: string;
    protocolVersion?: string;
  }

  export interface EncryptedMessage {
    sessionId: string;
    ciphertext: string;
    nonce: string;
    messageNumber: number;
    timestamp: number;
    ratchetPubKey?: string;
    pn?: number;
    protocolVersion?: string;
    pq?: {
      algorithm?: string;
      ciphertext?: string;
    };
  }

  /**
   * Group messaging types
   */
  export interface SenderKeyDistributionMessage {
    type: "distribution";
    senderId: string;
    groupId: string;
    chainKey: string;
    signatureKey: string;
    generation: number;
  }

  export interface SenderKeyMessage {
    type: "message";
    senderId: string;
    groupId: string;
    generation: number;
    cipherText: string;
    nonce: string;
  }
}
