/**
 * Public types for Aegis - Complete Type System
 */

/**
 * Core Cryptographic Types
 */
export interface PQKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export type AuthMethod = "phone" | "email";

/**
 * Pre-Key Types
 */
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

/**
 * User Identity Types
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

export interface ExtendedUserIdentity extends UserIdentity {
  signedPreKey: SignedPreKey;
  oneTimePreKeys: OneTimePreKey[];
}

/**
 * Storage Interface
 */
export interface StorageAdapter {
  setItem(key: string, value: string): Promise<void>;
  getItem(key: string): Promise<string | null>;
  removeItem(key: string): Promise<void>;
  clear?(): Promise<void>;
  keys?(): Promise<string[]>;
}

/**
 * 1:1 Session Types
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

export interface RecipientBundle {
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
  sigPublicKey?: string;
}

export interface SessionKeys {
  identitySecret: Uint8Array;
  signedPreKeySecret: Uint8Array;
  oneTimePreKeySecret?: Uint8Array;
}

/**
 * Group Messaging Types
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
  sequence: number;
  cipherText: string;
  nonce: string;
}

export interface SenderKeyState {
  chainKey: Uint8Array;
  signatureKey: Uint8Array;
  generation: number;
  sequence: number;
}

/**
 * Aegis Configuration Types
 */
export interface AegisConfig {
  storage: StorageAdapter;
  userId?: string;
  logLevel?: number;
  production?: boolean;
}

/**
 * Public Key Bundle Types
 */
export interface PublicKeyBundle {
  identityKey: string;
  sigPublicKey: string;
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
  otpkCount: number;
}

/**
 * Group Session Data Types
 */
export interface GroupParticipantData {
  currentChainKey: string;
  lastSequence?: number;
  seenSequences?: number[];
  addedAt: number;
}

export interface GroupSessionData {
  groupId: string;
  mySenderKey: {
    chainKey: string;
    signatureKey: string;
    generation: number;
    sequence: number;
  };
  participants: {
    [userId: string]: GroupParticipantData;
  };
  adminUserId: string;
  version: number;
  removedParticipants: string[];
  keyRotationLog: Array<{
    version: number;
    timestamp: number;
    initiator: string;
    reason: string;
  }>;
}

/**
 * Key Rotation Types
 */
export interface KeyRotationInfo {
  version: number;
  timestamp: number;
  initiator: string;
  reason: string;
}

/**
 * OTPK Status Types
 */
export interface OTPKStatus {
  count: number;
  minRequired: number;
  maxAllowed: number;
  isLow: boolean;
  needsReplenishment: boolean;
}

/**
 * Session Info Types
 */
export interface SessionInfo {
  createdAt: number;
  lastUsed: number;
  messagesSent: number;
  messagesReceived: number;
  skippedMessagesLimit: number;
}

/**
 * Group Info Types
 */
export interface GroupInfo {
  groupId: string;
  adminUserId: string;
  version: number;
  participantCount: number;
  removedParticipantCount: number;
  lastKeyRotation: number | null;
}

/**
 * Replenishment Result Types
 */
export interface ReplenishmentResult {
  added: number;
  total: number;
  wasLow: boolean;
}

/**
 * Consumed OTPK Result
 */
export interface ConsumedOTPKResult {
  id: number;
  keyPair: PQKeyPair;
  remaining: number;
}

/**
 * Backup Types
 */
export interface IdentityBackupV3 {
  v: "3";
  algorithm: "scrypt+chacha20poly1305";
  params: {
    N: number;
    r: number;
    p: number;
    dkLen: number;
  };
  salt: string;
  nonce: string;
  ciphertext: string;
}

export interface IdentityBackupV2 {
  v: "2";
  algorithm: "scrypt+chacha20poly1305";
  params: {
    N: number;
    r: number;
    p: number;
    dkLen: number;
  };
  salt: string;
  nonce: string;
  ciphertext: string;
}

export interface IdentityBackupV1 {
  v: "1";
  salt: string;
  nonce: string;
  ciphertext: string;
}

export type IdentityBackup =
  | IdentityBackupV3
  | IdentityBackupV2
  | IdentityBackupV1;

/**
 * Serialized Types for Storage
 */
export interface SerializedUserIdentity {
  kem: {
    publicKey: string;
    secretKey: string;
  };
  sig: {
    publicKey: string;
    secretKey: string;
  };
  signedPreKey: {
    id: number;
    key: {
      pub: string;
      sec: string;
    };
    sig: string;
    created: number;
  };
  oneTimePreKeys: Array<{
    id: number;
    pub: string;
    sec: string;
  }>;
  userId: string;
  authMethod: AuthMethod;
  identifier: string;
  createdAt: number;
  version: string;
}

export interface SerializedSessionState {
  sessionId: string;
  sendChainKey: string;
  receiveChainKey: string;
  sendMessageNumber: number;
  receiveMessageNumber: number;
  rootKey: string;
  dhPrivate: string;
  dhPublic: string;
  dhRemotePublic?: string;
  skippedMessageKeys?: {
    [ratchetPubKey: string]: { [messageNumber: number]: string };
  };
  skippedMessagesLimit: number;
  protocolVersion?: string;
  pendingRatchet?: { pub: string; pn: number };
  createdAt: number;
  lastUsed: number;
}

/**
 * KEM Result Types
 */
export interface KEMEncapsulationResult {
  sharedSecret: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * Validation Types
 */
export interface ValidationOptions {
  allowEmpty?: boolean;
  minLength?: number;
  maxLength?: number;
}

/**
 * Error Types
 */
export class AegisError extends Error {
  constructor(
    message: string,
    public code?: string,
    public details?: any,
  ) {
    super(message);
    this.name = "AegisError";
  }
}

export class ValidationError extends AegisError {
  constructor(
    message: string,
    public field?: string,
    details?: any,
  ) {
    super(message, "VALIDATION_ERROR", details);
    this.name = "ValidationError";
  }
}

export class CryptoError extends AegisError {
  constructor(
    message: string,
    public operation?: string,
    details?: any,
  ) {
    super(message, "CRYPTO_ERROR", details);
    this.name = "CryptoError";
  }
}

export class SessionError extends AegisError {
  constructor(
    message: string,
    public sessionId?: string,
    details?: any,
  ) {
    super(message, "SESSION_ERROR", details);
    this.name = "SessionError";
  }
}

export class GroupError extends AegisError {
  constructor(
    message: string,
    public groupId?: string,
    details?: any,
  ) {
    super(message, "GROUP_ERROR", details);
    this.name = "GroupError";
  }
}
