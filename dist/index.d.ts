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
interface PQKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}
/**
 * Authentication method used for an identity
 */
type AuthMethod = "phone" | "email";
/**
 * Stored user identity.
 * - `kem` and `sig` contain the raw key material (stored as bytes).
 * - `version` is useful for migrations/keystore changes.
 */
interface UserIdentity {
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
interface StorageAdapter {
    setItem(key: string, value: string): Promise<void>;
    getItem(key: string): Promise<string | null>;
    removeItem(key: string): Promise<void>;
}

/**
 * Post-Quantum Cryptography Identity Management
 *
 * Implements user identity using ML-KEM (Kyber 768) for key encapsulation
 * and key management. Each user has:
 * - KEM key pair: For establishing shared secrets
 * - Signature key pair: For signing messages
 */

interface SignedPreKey {
    id: number;
    keyPair: PQKeyPair;
    signature: Uint8Array;
    createdAt: number;
}
interface OneTimePreKey {
    id: number;
    keyPair: PQKeyPair;
}
/**
 * Create a new user identity
 * @param userId - Unique user identifier
 * @param authMethod - Authentication method ('phone' or 'email')
 * @param identifier - Phone number or email
 */
declare function createIdentity(userId: string, authMethod: "phone" | "email", identifier: string): Promise<UserIdentity>;
/**
 * Save identity to secure storage
 */
declare function saveIdentity(identity: UserIdentity): Promise<void>;
/**
 * Load identity from secure storage
 */
declare function loadIdentity(): Promise<UserIdentity | null>;
/**
 * Delete identity from secure storage
 */
declare function deleteIdentity(): Promise<void>;
/**
 * Export identity for backup
 * Returns a password-encrypted backup bundle
 */
declare function exportIdentity(password: string): Promise<string>;
/**
 * Import identity from backup
 */
declare function importIdentity(backupData: string, password: string): Promise<UserIdentity>;
/**
 * Calculate safety number (fingerprint) for identity verification
 * Combines both users' public keys to create a unique fingerprint
 */
declare function calculateSafetyNumber(identity1KemPublic: Uint8Array, identity1SigPublic: Uint8Array, identity2KemPublic: Uint8Array, identity2SigPublic: Uint8Array): string;
/**
 * Get public key bundle (X3DH Triple Pre-Key Bundle)
 * Returns the Identity Key, Signed PreKey, and one One-Time PreKey.
 * This bundle allows a sender to establish a Forward Secure session.
 */
declare function getPublicKeyBundle(): Promise<{
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
}>;
/**
 * Get and consume a public key bundle (consumes a One-Time PreKey)
 * This simulates server-side behavior where OTPKs are handed out once and
 * marked as used (removed from storage) so they cannot be reused.
 */
declare function getAndConsumePublicKeyBundle(): Promise<{
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
}>;
/**
 * Perform key encapsulation (sender side)
 * Returns shared secret and ciphertext to send to recipient
 */
declare function encapsulate(recipientKemPublicKey: Uint8Array): {
    sharedSecret: Uint8Array;
    ciphertext: Uint8Array;
};
/**
 * Verify the Signed PreKey's signature using the identity signature public key
 */
declare function verifySignedPreKey(spkPublicKey: Uint8Array, signature: Uint8Array, signerPublicKey: Uint8Array): Promise<boolean>;
/**
 * Perform key decapsulation (recipient side)
 * Recovers shared secret from ciphertext using secret key
 */
declare function decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;

/**
 * 1:1 Session Encryption
 *
 * Implements encrypted messaging between two users with:
 * - Post-quantum key exchange using ML-KEM 768
 * - ChaCha20-Poly1305 for message encryption
 * - Double ratchet for forward secrecy
 * - Session state persistence
 */
interface EncryptedMessage {
    sessionId: string;
    ciphertext: string;
    nonce: string;
    messageNumber: number;
    timestamp: number;
}
interface SessionInitData {
    sessionId: string;
    ciphertexts: {
        ik: string;
        spk: string;
        otpk?: string;
    };
}
/**
 * Initialize a new session as the initiator (X3DH-like)
 * @param recipientBundle - The recipient's public key bundle (IK, SPK, OTPK)
 */
declare function initializeSession(sessionId: string, recipientBundle: {
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
}): Promise<SessionInitData>;
/**
 * Accept a session as the recipient
 * @param sessionId - Session ID
 * @param ciphertexts - Ciphertexts from initiator (ik, spk, otpk)
 * @param keys - The user's keys (IK sec, SPK sec, OTPK sec)
 */
declare function acceptSession(sessionId: string, ciphertexts: {
    ik: string;
    spk: string;
    otpk?: string;
}, keys: {
    identitySecret: Uint8Array;
    signedPreKeySecret: Uint8Array;
    oneTimePreKeySecret?: Uint8Array;
}): Promise<void>;
/**
 * Encrypt a message for the session
 */
declare function encryptMessage(sessionId: string, plaintext: string): Promise<EncryptedMessage>;
/**
 * Decrypt a message from the session
 */
declare function decryptMessage(encryptedMsg: EncryptedMessage): Promise<string>;
/**
 * Delete a session
 */
declare function deleteSession(sessionId: string): Promise<void>;
/**
 * Get session info
 */
declare function getSessionInfo(sessionId: string): Promise<{
    createdAt: number;
    lastUsed: number;
    messagesSent: number;
} | null>;

interface AegisConfig {
    storage: StorageAdapter;
}
declare const Aegis: {
    /**
     * Initialize the Aegis library with the necessary adapters.
     * This must be called before using any other functionality.
     */
    init(configuration: AegisConfig): void;
    /**
     * Get the configured storage adapter.
     * Throws if the library has not been initialized.
     */
    getStorage(): StorageAdapter;
};

/**
 * Core Cryptographic Utilities
 */
/**
 * Hash data using Blake3
 * @param data - Input data as Uint8Array or string
 * @param outputLength - Optional output length in bytes (default: 32)
 * @returns Blake3 hash as Uint8Array
 */
declare function hash(data: Uint8Array | string, outputLength?: number): Uint8Array;
/**
 * Derive a key from input data using Blake3
 * @param data - Input data
 * @param context - Context string for domain separation
 * @param outputLength - Output length in bytes (default: 32)
 */
declare function deriveKey(data: Uint8Array | string, context: string, outputLength?: number): Uint8Array;
/**
 * Generate cryptographically secure random bytes
 * @param length - Number of bytes to generate
 */
declare function getRandomBytes(length: number): Uint8Array;
/**
 * Encrypt data using ChaCha20-Poly1305
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce (must be unique for each message)
 * @param plaintext - Data to encrypt
 * @param associatedData - Optional authenticated data (not encrypted)
 * @returns Ciphertext with authentication tag appended
 */
declare function encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, associatedData?: Uint8Array): Uint8Array;
/**
 * Decrypt data using ChaCha20-Poly1305
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce
 * @param ciphertext - Encrypted data with authentication tag
 * @param associatedData - Optional authenticated data (must match encryption)
 * @returns Decrypted plaintext
 * @throws Error if authentication fails
 */
declare function decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, associatedData?: Uint8Array): Uint8Array;
/**
 * Generate a unique 12-byte nonce
 * IMPORTANT: Never reuse a nonce with the same key
 */
declare function generateNonce(): Uint8Array;
/**
 * Generate a 32-byte encryption key
 */
declare function generateKey(): Uint8Array;
/**
 * Convert string to Uint8Array (UTF-8 encoding)
 */
declare function stringToBytes(str: string): Uint8Array;
/**
 * Convert Uint8Array to string (UTF-8 decoding)
 */
declare function bytesToString(bytes: Uint8Array): string;
/**
 * Convert Uint8Array to base64 string
 */
declare function bytesToBase64(bytes: Uint8Array): string;
/**
 * Convert base64 string to Uint8Array
 */
declare function base64ToBytes(base64: string): Uint8Array;
/**
 * Convert Uint8Array to hex string
 */
declare function bytesToHex(bytes: Uint8Array): string;
/**
 * Convert hex string to Uint8Array
 */
declare function hexToBytes(hex: string): Uint8Array;
/**
 * Constant-time comparison of two Uint8Arrays
 * Prevents timing attacks
 */
declare function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean;
/**
 * Zero out a buffer to clear sensitive data from memory (Best Effort)
 * Note: In JS, garbage collection might move memory, so this is not a guarantee.
 */
declare function zeroBuffer(buffer: Uint8Array): void;

/**
 * Payload sent to other group members to initialize them.
 * Encrypted via 1:1 sessions.
 */
interface SenderKeyDistributionMessage {
    type: "distribution";
    senderId: string;
    groupId: string;
    chainKey: string;
    signatureKey: string;
    generation: number;
}
/**
 * The actual group message payload.
 */
interface SenderKeyMessage {
    type: "message";
    senderId: string;
    groupId: string;
    generation: number;
    cipherText: string;
    nonce: string;
}

/**
 * Group Session Manager
 * Handles initializing groups, distributing sender keys, and messaging.
 */
declare class GroupSession {
    private groupId;
    private data;
    private constructor();
    /**
     * Load or Create a Group Session
     */
    static get(groupId: string): Promise<GroupSession>;
    /**
     * Create a Distribution Message to send to a new participant.
     * This MUST be sent via the secure 1:1 session (encryptMessage).
     */
    createDistributionMessage(senderId: string): SenderKeyDistributionMessage;
    /**
     * Process an incoming Distribution Message from another member.
     * Call this AFTER decrypting the 1:1 message containing this payload.
     */
    processDistributionMessage(payload: SenderKeyDistributionMessage): Promise<void>;
    /**
     * Encrypt a message for the group.
     * O(1) operation (just one encryption).
     */
    encrypt(plaintext: string, myUserId: string): Promise<SenderKeyMessage>;
    /**
     * Decrypt a message from the group.
     * O(1) operation.
     */
    decrypt(msg: SenderKeyMessage): Promise<string>;
    private save;
    static getLoaded(groupId: string): Promise<GroupSession>;
}
declare function getGroupSession(groupId: string): Promise<GroupSession>;

export { Aegis, type AuthMethod, GroupSession, type OneTimePreKey, type PQKeyPair, type SignedPreKey, type StorageAdapter, type UserIdentity, acceptSession, base64ToBytes, bytesToBase64, bytesToHex, bytesToString, calculateSafetyNumber, constantTimeEqual, createIdentity, decapsulate, decrypt, decryptMessage, deleteIdentity, deleteSession, deriveKey, encapsulate, encrypt, encryptMessage, exportIdentity, generateKey, generateNonce, getAndConsumePublicKeyBundle, getGroupSession, getPublicKeyBundle, getRandomBytes, getSessionInfo, hash, hexToBytes, importIdentity, initializeSession, loadIdentity, saveIdentity, stringToBytes, verifySignedPreKey, zeroBuffer };
