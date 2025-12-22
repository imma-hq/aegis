/**
 * Sender Keys for Scalable Group Messaging (Hash Ratchet)
 *
 * Implements the Sender Key protocol (similar to Signal's Sender Keys).
 *
 * CONCEPT:
 * - Each member generates a random 32-byte "Chain Key".
 * - From a Chain Key, we derive:
 *   1. A "Message Key" (to encrypt the actual content).
 *   2. The NEXT "Chain Key" (forward secrecy).
 *
 * - "Sender Key Distribution":
 *   - A user sends their current Chain Key + Public Signing Key to all members privately (1:1 sessions).
 *   - Members store this and can now decrypt ALL future messages from that user by ratcheting forward.
 *   - This is O(1) for sending messages (encrypt once).
 */

import {
  deriveKey,
  encrypt,
  decrypt,
  generateNonce,
  generateKey,
  bytesToBase64,
  base64ToBytes,
  stringToBytes,
  bytesToString,
} from "./crypto";

// Constants for KDF (Key Derivation Function)
const KDF_CHAIN_KEY_SEED = "aegis_sender_chain_step";
const KDF_MESSAGE_KEY_SEED = "aegis_sender_message_key";

export interface SenderKeyState {
  chainKey: Uint8Array;
  signatureKey: Uint8Array; // Public signing key (Identity or separate)
  generation: number; // For identifying key generations (rotations)
}

/**
 * Payload sent to other group members to initialize them.
 * Encrypted via 1:1 sessions.
 */
export interface SenderKeyDistributionMessage {
  type: "distribution";
  senderId: string;
  groupId: string;
  chainKey: string; // Base64
  signatureKey: string; // Base64
  generation: number;
}

/**
 * The actual group message payload.
 */
export interface SenderKeyMessage {
  type: "message";
  senderId: string;
  groupId: string;
  generation: number;
  cipherText: string;
  nonce: string;
}

/**
 * Generate a new Sender Key State
 */
export function generateSenderKey(): SenderKeyState {
  return {
    chainKey: generateKey(),
    signatureKey: new Uint8Array(0), // Placeholder, ideally actual Sig Pub Key
    generation: Math.floor(Date.now() / 1000), // Use timestamp as generation ID for simplicity
  };
}

/**
 * Derive the Message Key from the current Chain Key
 */
function deriveMessageKey(chainKey: Uint8Array): Uint8Array {
  // HMAC-SHA256 or Blake3(chainKey, 0x01)
  return deriveKey(chainKey, KDF_MESSAGE_KEY_SEED, 32);
}

/**
 * Advance the Chain Key (Ratchet Forward)
 */
function ratchetChainKey(chainKey: Uint8Array): Uint8Array {
  // HMAC-SHA256 or Blake3(chainKey, 0x02)
  return deriveKey(chainKey, KDF_CHAIN_KEY_SEED, 32);
}

/**
 * Encrypt a message using the current Sender Key State.
 * ! MUTATES STATE (advances ratchet) !
 */
export function encryptGroupMessage(
  state: SenderKeyState,
  groupId: string,
  senderId: string,
  plaintext: string
): SenderKeyMessage {
  // 1. Derive Message Key
  const messageKey = deriveMessageKey(state.chainKey);

  // 2. Encrypt
  const nonce = generateNonce();
  const plaintextBytes = stringToBytes(plaintext);
  const cipherText = encrypt(messageKey, nonce, plaintextBytes);

  const message: SenderKeyMessage = {
    type: "message",
    senderId,
    groupId,
    generation: state.generation,
    cipherText: bytesToBase64(cipherText),
    nonce: bytesToBase64(nonce),
  };

  // 3. Ratchet Forward (Delete old key from memory conceptually)
  state.chainKey = ratchetChainKey(state.chainKey);

  return message;
}

/**
 * Decrypt a message using a known Chain Key.
 *
 * NOTE: In a real implementation, you must handle "out-of-order" messages by:
 * 1. Trying to decrypt with current chain key.
 * 2. If valid, return plaintext and ratchet forward.
 * 3. If "future" key (N steps ahead), fast-forward N steps, store skipped keys, decrypt.
 *
 * For this simplified implementation, we assume mostly ordered delivery or stateless trial.
 * But wait, we cannot be stateless. We must update the receiver's state of the sender.
 */
export function decryptGroupMessage(
  currentChainKey: Uint8Array,
  message: SenderKeyMessage
): { plaintext: string; nextChainKey: Uint8Array } {
  // Try decrypting with current derived message key
  const messageKey = deriveMessageKey(currentChainKey);
  const nonce = base64ToBytes(message.nonce);
  const ciphertext = base64ToBytes(message.cipherText);

  const plaintextBytes = decrypt(messageKey, nonce, ciphertext);

  // If successful, calculate next chain key
  const nextChainKey = ratchetChainKey(currentChainKey);

  return {
    plaintext: bytesToString(plaintextBytes),
    nextChainKey,
  };
}
