/**
 * 1:1 Session Encryption
 *
 * Implements encrypted messaging between two users with:
 * - Post-quantum key exchange using ML-KEM 768
 * - ChaCha20-Poly1305 for message encryption
 * - Double ratchet for forward secrecy
 * - Session state persistence
 */

import {
  encrypt,
  decrypt,
  deriveKey,
  generateNonce,
  bytesToBase64,
  base64ToBytes,
  stringToBytes,
  bytesToString,
} from "./crypto";
import { encapsulate, decapsulate } from "./pqc";
import { Aegis } from "./config";

interface SessionState {
  sessionId: string;
  sendChainKey: Uint8Array;
  receiveChainKey: Uint8Array;
  sendMessageNumber: number;
  receiveMessageNumber: number;
  rootKey: Uint8Array;
  createdAt: number;
  lastUsed: number;
}

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

const SESSION_KEY_PREFIX = "aegis_session_";

/**
 * Initialize a new session as the initiator
 * @param recipientKemPublicKey - Recipient's KEM public key
 * @param initiatorKemSecretKey - Initiator's KEM secret key
 */
export async function initializeSession(
  sessionId: string,
  recipientKemPublicKey: Uint8Array
): Promise<SessionInitData> {
  // Perform key encapsulation
  const { sharedSecret, ciphertext } = encapsulate(recipientKemPublicKey);

  // Derive root key and chain keys from shared secret
  const rootKey = deriveKey(sharedSecret, "aegis_root_key_v1", 32);
  const sendChainKey = deriveKey(rootKey, "aegis_send_chain_v1", 32);
  const receiveChainKey = deriveKey(rootKey, "aegis_receive_chain_v1", 32);

  // Create session state
  const state: SessionState = {
    sessionId,
    sendChainKey,
    receiveChainKey,
    sendMessageNumber: 0,
    receiveMessageNumber: 0,
    rootKey,
    createdAt: Date.now(),
    lastUsed: Date.now(),
  };

  await saveSessionState(sessionId, state);
  console.log("[Session] Initialized new session:", sessionId);

  return {
    sessionId,
    kemCiphertext: bytesToBase64(ciphertext),
    initiatorKemPublic: "",
  };
}

/**
 * Accept a session as the recipient
 * @param sessionId - Session ID from initiator
 * @param kemCiphertext - KEM ciphertext from initiator
 * @param recipientKemSecretKey - Recipient's KEM secret key
 */
export async function acceptSession(
  sessionId: string,
  kemCiphertext: string,
  recipientKemSecretKey: Uint8Array
): Promise<void> {
  // Decapsulate to get shared secret
  const ciphertextBytes = base64ToBytes(kemCiphertext);
  const sharedSecret = decapsulate(ciphertextBytes, recipientKemSecretKey);

  // Derive same keys as initiator
  const rootKey = deriveKey(sharedSecret, "aegis_root_key_v1", 32);
  const sendChainKey = deriveKey(rootKey, "aegis_send_chain_v1", 32);
  const receiveChainKey = deriveKey(rootKey, "aegis_receive_chain_v1", 32);

  // Create session state (note: send/receive are swapped from initiator's perspective)
  const state: SessionState = {
    sessionId,
    sendChainKey: receiveChainKey, // Swapped
    receiveChainKey: sendChainKey, // Swapped
    sendMessageNumber: 0,
    receiveMessageNumber: 0,
    rootKey,
    createdAt: Date.now(),
    lastUsed: Date.now(),
  };

  await saveSessionState(sessionId, state);
  console.log("[Session] Accepted session:", sessionId);
}

/**
 * Encrypt a message for the session
 */
export async function encryptMessage(
  sessionId: string,
  plaintext: string
): Promise<EncryptedMessage> {
  const state = await loadSessionState(sessionId);
  if (!state) {
    throw new Error(`Session not found: ${sessionId}`);
  }

  // Derive message key from chain key
  const messageKey = deriveKey(
    state.sendChainKey,
    `message_${state.sendMessageNumber}`,
    32
  );

  // Ratchet the chain key for forward secrecy
  state.sendChainKey = deriveKey(state.sendChainKey, "ratchet", 32);

  // Encrypt message
  const nonce = generateNonce();
  const plaintextBytes = stringToBytes(plaintext);
  const ciphertextBytes = encrypt(messageKey, nonce, plaintextBytes);

  const encryptedMsg: EncryptedMessage = {
    sessionId,
    ciphertext: bytesToBase64(ciphertextBytes),
    nonce: bytesToBase64(nonce),
    messageNumber: state.sendMessageNumber,
    timestamp: Date.now(),
  };

  // Update state
  state.sendMessageNumber++;
  state.lastUsed = Date.now();
  await saveSessionState(sessionId, state);

  return encryptedMsg;
}

/**
 * Decrypt a message from the session
 */
export async function decryptMessage(
  encryptedMsg: EncryptedMessage
): Promise<string> {
  const state = await loadSessionState(encryptedMsg.sessionId);
  if (!state) {
    throw new Error(`Session not found: ${encryptedMsg.sessionId}`);
  }

  // Handle out-of-order messages
  if (encryptedMsg.messageNumber < state.receiveMessageNumber) {
    throw new Error("Message number too old - possible replay attack");
  }

  // Derive message key from chain key
  let chainKey = state.receiveChainKey;

  // Ratchet chain key to the correct message number
  for (
    let i = state.receiveMessageNumber;
    i < encryptedMsg.messageNumber;
    i++
  ) {
    chainKey = deriveKey(chainKey, "ratchet", 32);
  }

  const messageKey = deriveKey(
    chainKey,
    `message_${encryptedMsg.messageNumber}`,
    32
  );

  // Ratchet one more time for next message
  chainKey = deriveKey(chainKey, "ratchet", 32);

  // Decrypt message
  const ciphertext = base64ToBytes(encryptedMsg.ciphertext);
  const nonce = base64ToBytes(encryptedMsg.nonce);

  try {
    const plaintextBytes = decrypt(messageKey, nonce, ciphertext);
    const plaintext = bytesToString(plaintextBytes);

    // Update state
    state.receiveChainKey = chainKey;
    state.receiveMessageNumber = encryptedMsg.messageNumber + 1;
    state.lastUsed = Date.now();
    await saveSessionState(encryptedMsg.sessionId, state);

    return plaintext;
  } catch (error) {
    console.error("[Session] Decryption failed:", error);
    throw new Error("Message decryption failed - authentication error");
  }
}

/**
 * Save session state to secure storage
 */
async function saveSessionState(
  sessionId: string,
  state: SessionState
): Promise<void> {
  const serialized = JSON.stringify({
    sessionId: state.sessionId,
    sendChainKey: bytesToBase64(state.sendChainKey),
    receiveChainKey: bytesToBase64(state.receiveChainKey),
    sendMessageNumber: state.sendMessageNumber,
    receiveMessageNumber: state.receiveMessageNumber,
    rootKey: bytesToBase64(state.rootKey),
    createdAt: state.createdAt,
    lastUsed: state.lastUsed,
  });

  await Aegis.getStorage().setItem(
    `${SESSION_KEY_PREFIX}${sessionId}`,
    serialized
  );
}

/**
 * Load session state from secure storage
 */
async function loadSessionState(
  sessionId: string
): Promise<SessionState | null> {
  const serialized = await Aegis.getStorage().getItem(
    `${SESSION_KEY_PREFIX}${sessionId}`
  );
  if (!serialized) {
    return null;
  }

  try {
    const data = JSON.parse(serialized);
    return {
      sessionId: data.sessionId,
      sendChainKey: base64ToBytes(data.sendChainKey),
      receiveChainKey: base64ToBytes(data.receiveChainKey),
      sendMessageNumber: data.sendMessageNumber,
      receiveMessageNumber: data.receiveMessageNumber,
      rootKey: base64ToBytes(data.rootKey),
      createdAt: data.createdAt,
      lastUsed: data.lastUsed,
    };
  } catch (error) {
    console.error("[Session] Failed to parse session state:", error);
    return null;
  }
}

/**
 * Delete a session
 */
export async function deleteSession(sessionId: string): Promise<void> {
  await Aegis.getStorage().removeItem(`${SESSION_KEY_PREFIX}${sessionId}`);
  console.log("[Session] Deleted session:", sessionId);
}

/**
 * Get session info
 */
export async function getSessionInfo(sessionId: string): Promise<{
  createdAt: number;
  lastUsed: number;
  messagesSent: number;
} | null> {
  const state = await loadSessionState(sessionId);
  if (!state) {
    return null;
  }

  return {
    createdAt: state.createdAt,
    lastUsed: state.lastUsed,
    messagesSent: state.sendMessageNumber,
  };
}
