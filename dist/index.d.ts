interface PQKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}
type AuthMethod = "phone" | "email";
interface UserIdentity {
    kem: PQKeyPair;
    sig: PQKeyPair;
    userId: string;
    authMethod: AuthMethod;
    identifier: string;
    createdAt: number;
    version: string;
}
interface TheirIdentity {
    kem: {
        publicKey: Uint8Array;
    };
    sig: {
        publicKey: Uint8Array;
    };
}
interface ServerKeyBundle {
    kem_public_key: string;
    sig_public_key: string;
    signed_pre_key: string;
    signed_pre_key_signature: string;
    one_time_pre_keys: string[];
    device_id: string;
    device_fingerprint: string;
}
interface EncryptedMessagePayload {
    session_id: string;
    ciphertext: string;
    nonce: string;
    signature: string;
    sequence: number;
    additional_data?: string;
}
interface SessionInitiationRequest {
    their_user_id: string;
    their_device_id?: string;
    initiation_data: {
        session_id: string;
        ephemeral_public_key: string;
        ciphertext: string;
        signature: string;
        initiator_kem_public_key: string;
        initiator_sig_public_key: string;
    };
}
/**
 * Interface that must be implemented by the host application
 * to provide secure storage for keys and session data.
 */
interface StorageAdapter {
    /**
     * Store a value securely.
     * On mobile, this should use EncryptedStorage or Keychain/Keystore.
     * On web, this might use IndexedDB with encryption.
     */
    setItem(key: string, value: string): Promise<void>;
    /**
     * Retrieve a value from secure storage.
     */
    getItem(key: string): Promise<string | null>;
    /**
     * Delete a value from secure storage.
     */
    removeItem(key: string): Promise<void>;
}

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
declare function exportIdentity(_password: string): Promise<string>;
/**
 * Import identity from backup
 */
declare function importIdentity(backupData: string, _password: string): Promise<UserIdentity>;
/**
 * Calculate safety number (fingerprint) for identity verification
 * Combines both users' public keys to create a unique fingerprint
 */
declare function calculateSafetyNumber(identity1KemPublic: Uint8Array, identity1SigPublic: Uint8Array, identity2KemPublic: Uint8Array, identity2SigPublic: Uint8Array): string;
/**
 * Get public key bundle for sharing with other users
 */
declare function getPublicKeyBundle(): Promise<{
    kemPublicKey: string;
    sigPublicKey: string;
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
    kemCiphertext: string;
    initiatorKemPublic: string;
}
/**
 * Initialize a new session as the initiator
 * @param recipientKemPublicKey - Recipient's KEM public key
 * @param initiatorKemSecretKey - Initiator's KEM secret key
 */
declare function initializeSession(sessionId: string, recipientKemPublicKey: Uint8Array): Promise<SessionInitData>;
/**
 * Accept a session as the recipient
 * @param sessionId - Session ID from initiator
 * @param kemCiphertext - KEM ciphertext from initiator
 * @param recipientKemSecretKey - Recipient's KEM secret key
 */
declare function acceptSession(sessionId: string, kemCiphertext: string, recipientKemSecretKey: Uint8Array): Promise<void>;
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
 *
 * Implements cryptographic primitives using @noble libraries:
 * - Blake3 hashing for fingerprints and key derivation
 * - ChaCha20-Poly1305 for authenticated encryption
 * - Utilities for encoding and random generation
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
 * Interface for a group message bundle.
 * Maps User ID -> Encrypted Message for that user.
 */
interface GroupMessageBundle {
    groupId: string;
    messages: Record<string, any>;
}
/**
 * Send a message to a group of users.
 * Uses client-side fan-out: encrypts the message individually for each participant.
 *
 * @param groupId - The ID of the group
 * @param participantSessionIds - Map of userId -> sessionId for all participants
 * @param plaintext - The content to encrypt
 */
declare function sendGroupMessage(groupId: string, participantSessionIds: Record<string, string>, plaintext: string): Promise<GroupMessageBundle>;
/**
 * Decrypt a group message.
 * Since we use fan-out, this is just a wrapper around decrypting a 1:1 message.
 *
 * @param encryptedMsg - The encrypted message payload
 */
declare function decryptGroupMessage(encryptedMsg: any): Promise<string>;

export { Aegis, type AuthMethod, type EncryptedMessagePayload, type GroupMessageBundle, type PQKeyPair, type ServerKeyBundle, type SessionInitiationRequest, type StorageAdapter, type TheirIdentity, type UserIdentity, acceptSession, base64ToBytes, bytesToBase64, bytesToHex, bytesToString, calculateSafetyNumber, constantTimeEqual, createIdentity, decapsulate, decrypt, decryptGroupMessage, decryptMessage, deleteIdentity, deleteSession, deriveKey, encapsulate, encrypt, encryptMessage, exportIdentity, generateKey, generateNonce, getPublicKeyBundle, getRandomBytes, getSessionInfo, hash, hexToBytes, importIdentity, initializeSession, loadIdentity, saveIdentity, sendGroupMessage, stringToBytes };
