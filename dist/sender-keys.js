// sender-keys.ts
/**
 * Sender Keys for Scalable Group Messaging (Hash Ratchet)
 */
import { deriveKey, encrypt, decrypt, generateNonce, generateKey, bytesToBase64, base64ToBytes, stringToBytes, bytesToString, } from "./crypto";
import { CryptoError } from "./types";
const KDF_CHAIN_KEY_SEED = "aegis_sender_chain_step";
const KDF_MESSAGE_KEY_SEED = "aegis_sender_message_key";
/**
 * Generate a new Sender Key State
 */
export function generateSenderKey() {
    const chainKey = generateKey();
    if (chainKey.length !== 32) {
        throw new CryptoError("Generated chain key must be 32 bytes", "SENDER_KEY_GENERATION", { length: chainKey.length });
    }
    return {
        chainKey,
        signatureKey: new Uint8Array(64), // Ed25519 signature key placeholder
        generation: Math.floor(Date.now() / 1000),
        sequence: 0,
    };
}
/**
 * Derive the Message Key from the current Chain Key
 */
function deriveMessageKey(chainKey) {
    return deriveKey(chainKey, KDF_MESSAGE_KEY_SEED, 32);
}
/**
 * Advance the Chain Key (Ratchet Forward)
 */
function ratchetChainKey(chainKey) {
    return deriveKey(chainKey, KDF_CHAIN_KEY_SEED, 32);
}
/**
 * Encrypt a message using the current Sender Key State
 */
export function encryptGroupMessage(state, groupId, senderId, plaintext) {
    if (!state || !state.chainKey || state.chainKey.length === 0) {
        throw new CryptoError("Invalid sender key state", "ENCRYPT_INVALID_STATE");
    }
    if (!groupId || typeof groupId !== "string" || groupId.trim() === "") {
        throw new CryptoError("Group ID must be a non-empty string", "ENCRYPT_INVALID_GROUP_ID");
    }
    if (!senderId || typeof senderId !== "string" || senderId.trim() === "") {
        throw new CryptoError("Sender ID must be a non-empty string", "ENCRYPT_INVALID_SENDER_ID");
    }
    if (!plaintext || typeof plaintext !== "string") {
        throw new CryptoError("Plaintext must be a non-empty string", "ENCRYPT_INVALID_PLAINTEXT");
    }
    const messageKey = deriveMessageKey(state.chainKey);
    const nonce = generateNonce();
    const plaintextBytes = stringToBytes(plaintext);
    const cipherText = encrypt(messageKey, nonce, plaintextBytes);
    const message = {
        type: "message",
        senderId,
        groupId,
        generation: state.generation,
        sequence: state.sequence,
        cipherText: bytesToBase64(cipherText),
        nonce: bytesToBase64(nonce),
    };
    state.chainKey = ratchetChainKey(state.chainKey);
    state.sequence++;
    return message;
}
/**
 * Decrypt a message using a known Chain Key
 */
export function decryptGroupMessage(currentChainKey, message, expectedSequence) {
    if (!currentChainKey || currentChainKey.length === 0) {
        throw new CryptoError("Current chain key must be a non-empty Uint8Array", "DECRYPT_INVALID_CHAIN_KEY");
    }
    if (!message ||
        !message.senderId ||
        !message.groupId ||
        !message.cipherText ||
        !message.nonce) {
        throw new CryptoError("Invalid message format: missing required fields", "DECRYPT_INVALID_MESSAGE");
    }
    if (expectedSequence !== undefined && message.sequence < expectedSequence) {
        throw new CryptoError(`Message sequence too old: ${message.sequence} < ${expectedSequence}`, "DECRYPT_SEQUENCE_TOO_OLD", { sequence: message.sequence, expectedSequence });
    }
    const messageKey = deriveMessageKey(currentChainKey);
    const nonce = base64ToBytes(message.nonce);
    const ciphertext = base64ToBytes(message.cipherText);
    let plaintextBytes;
    try {
        plaintextBytes = decrypt(messageKey, nonce, ciphertext);
    }
    catch (error) {
        throw new CryptoError("Failed to decrypt message", "DECRYPT_FAILED", error);
    }
    const nextChainKey = ratchetChainKey(currentChainKey);
    return {
        plaintext: bytesToString(plaintextBytes),
        nextChainKey,
    };
}
