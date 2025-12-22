"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  Aegis: () => Aegis,
  acceptSession: () => acceptSession,
  base64ToBytes: () => base64ToBytes,
  bytesToBase64: () => bytesToBase64,
  bytesToHex: () => bytesToHex,
  bytesToString: () => bytesToString,
  calculateSafetyNumber: () => calculateSafetyNumber,
  constantTimeEqual: () => constantTimeEqual,
  createIdentity: () => createIdentity,
  decapsulate: () => decapsulate,
  decrypt: () => decrypt,
  decryptGroupMessage: () => decryptGroupMessage,
  decryptMessage: () => decryptMessage,
  deleteIdentity: () => deleteIdentity,
  deleteSession: () => deleteSession,
  deriveKey: () => deriveKey,
  encapsulate: () => encapsulate,
  encrypt: () => encrypt,
  encryptMessage: () => encryptMessage,
  exportIdentity: () => exportIdentity,
  generateKey: () => generateKey,
  generateNonce: () => generateNonce,
  getPublicKeyBundle: () => getPublicKeyBundle,
  getRandomBytes: () => getRandomBytes,
  getSessionInfo: () => getSessionInfo,
  hash: () => hash,
  hexToBytes: () => hexToBytes,
  importIdentity: () => importIdentity,
  initializeSession: () => initializeSession,
  loadIdentity: () => loadIdentity,
  saveIdentity: () => saveIdentity,
  sendGroupMessage: () => sendGroupMessage,
  stringToBytes: () => stringToBytes
});
module.exports = __toCommonJS(index_exports);

// src/pqc.ts
var import_ml_kem = require("@noble/post-quantum/ml-kem.js");

// src/crypto.ts
var import_blake3 = require("@noble/hashes/blake3.js");
var import_chacha = require("@noble/ciphers/chacha.js");
var import_utils = require("@noble/hashes/utils.js");
function hash(data, outputLength = 32) {
  const input = typeof data === "string" ? stringToBytes(data) : data;
  return (0, import_blake3.blake3)(input, { dkLen: outputLength });
}
function deriveKey(data, context, outputLength = 32) {
  const input = typeof data === "string" ? stringToBytes(data) : data;
  const contextBytes = stringToBytes(context);
  const combined = new Uint8Array(contextBytes.length + input.length);
  combined.set(contextBytes, 0);
  combined.set(input, contextBytes.length);
  return (0, import_blake3.blake3)(combined, { dkLen: outputLength });
}
function getRandomBytes(length) {
  return (0, import_utils.randomBytes)(length);
}
function encrypt(key, nonce, plaintext, associatedData) {
  if (key.length !== 32) {
    throw new Error("Key must be 32 bytes");
  }
  if (nonce.length !== 12) {
    throw new Error("Nonce must be 12 bytes");
  }
  const cipher = (0, import_chacha.chacha20poly1305)(key, nonce, associatedData);
  return cipher.encrypt(plaintext);
}
function decrypt(key, nonce, ciphertext, associatedData) {
  if (key.length !== 32) {
    throw new Error("Key must be 32 bytes");
  }
  if (nonce.length !== 12) {
    throw new Error("Nonce must be 12 bytes");
  }
  const cipher = (0, import_chacha.chacha20poly1305)(key, nonce, associatedData);
  return cipher.decrypt(ciphertext);
}
function generateNonce() {
  return getRandomBytes(12);
}
function generateKey() {
  return getRandomBytes(32);
}
function stringToBytes(str) {
  return new TextEncoder().encode(str);
}
function bytesToString(bytes) {
  return new TextDecoder().decode(bytes);
}
function bytesToBase64(bytes) {
  const binary = Array.from(bytes).map((byte) => String.fromCharCode(byte)).join("");
  if (typeof btoa !== "undefined") {
    return btoa(binary);
  }
  const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i++];
    const b = i < bytes.length ? bytes[i++] : 0;
    const c = i < bytes.length ? bytes[i++] : 0;
    const bitmap = a << 16 | b << 8 | c;
    result += base64Chars[bitmap >> 18 & 63];
    result += base64Chars[bitmap >> 12 & 63];
    result += i - 2 < bytes.length ? base64Chars[bitmap >> 6 & 63] : "=";
    result += i - 1 < bytes.length ? base64Chars[bitmap & 63] : "=";
  }
  return result;
}
function base64ToBytes(base64) {
  if (typeof atob !== "undefined") {
    const binary = atob(base64);
    const bytes2 = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes2[i] = binary.charCodeAt(i);
    }
    return bytes2;
  }
  const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const lookup = new Uint8Array(256);
  for (let i = 0; i < base64Chars.length; i++) {
    lookup[base64Chars.charCodeAt(i)] = i;
  }
  const len = base64.length;
  let bufferLength = base64.length * 0.75;
  if (base64[len - 1] === "=") {
    bufferLength--;
    if (base64[len - 2] === "=") {
      bufferLength--;
    }
  }
  const bytes = new Uint8Array(bufferLength);
  let p = 0;
  for (let i = 0; i < len; i += 4) {
    const encoded1 = lookup[base64.charCodeAt(i)];
    const encoded2 = lookup[base64.charCodeAt(i + 1)];
    const encoded3 = lookup[base64.charCodeAt(i + 2)];
    const encoded4 = lookup[base64.charCodeAt(i + 3)];
    bytes[p++] = encoded1 << 2 | encoded2 >> 4;
    if (p < bufferLength) bytes[p++] = (encoded2 & 15) << 4 | encoded3 >> 2;
    if (p < bufferLength) bytes[p++] = (encoded3 & 3) << 6 | encoded4 & 63;
  }
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

// src/config.ts
var config = null;
var Aegis = {
  /**
   * Initialize the Aegis library with the necessary adapters.
   * This must be called before using any other functionality.
   */
  init(configuration) {
    config = configuration;
  },
  /**
   * Get the configured storage adapter.
   * Throws if the library has not been initialized.
   */
  getStorage() {
    if (!config) {
      throw new Error(
        "Aegis library not initialized. Call Aegis.init() with a storage adapter."
      );
    }
    return config.storage;
  }
};

// src/pqc.ts
var IDENTITY_STORAGE_KEY = "aegis_pqc_identity";
var IDENTITY_VERSION = "1.0.0";
function generateKEMKeyPair() {
  const keyPair = import_ml_kem.ml_kem768.keygen();
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey
  };
}
function generateSignatureKeyPair() {
  const keyPair = import_ml_kem.ml_kem768.keygen();
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey
  };
}
async function createIdentity(userId, authMethod, identifier) {
  const kem = generateKEMKeyPair();
  const sig = generateSignatureKeyPair();
  const identity = {
    kem,
    sig,
    userId,
    authMethod,
    identifier,
    createdAt: Date.now(),
    version: IDENTITY_VERSION
  };
  await saveIdentity(identity);
  console.log("[PQC Identity] Created new identity for user:", userId);
  return identity;
}
async function saveIdentity(identity) {
  const serialized = JSON.stringify({
    kem: {
      publicKey: bytesToBase64(identity.kem.publicKey),
      secretKey: bytesToBase64(identity.kem.secretKey)
    },
    sig: {
      publicKey: bytesToBase64(identity.sig.publicKey),
      secretKey: bytesToBase64(identity.sig.secretKey)
    },
    userId: identity.userId,
    authMethod: identity.authMethod,
    identifier: identity.identifier,
    createdAt: identity.createdAt,
    version: identity.version
  });
  await Aegis.getStorage().setItem(IDENTITY_STORAGE_KEY, serialized);
}
async function loadIdentity() {
  const serialized = await Aegis.getStorage().getItem(IDENTITY_STORAGE_KEY);
  if (!serialized) {
    return null;
  }
  try {
    const data = JSON.parse(serialized);
    return {
      kem: {
        publicKey: base64ToBytes(data.kem.publicKey),
        secretKey: base64ToBytes(data.kem.secretKey)
      },
      sig: {
        publicKey: base64ToBytes(data.sig.publicKey),
        secretKey: base64ToBytes(data.sig.secretKey)
      },
      userId: data.userId,
      authMethod: data.authMethod,
      identifier: data.identifier,
      createdAt: data.createdAt,
      version: data.version
    };
  } catch (error) {
    console.error("[PQC Identity] Failed to parse identity:", error);
    return null;
  }
}
async function deleteIdentity() {
  await Aegis.getStorage().removeItem(IDENTITY_STORAGE_KEY);
  console.log("[PQC Identity] Deleted identity");
}
async function exportIdentity(_password) {
  const identity = await loadIdentity();
  if (!identity) {
    throw new Error("No identity to export");
  }
  const serialized = JSON.stringify({
    kem: {
      publicKey: bytesToBase64(identity.kem.publicKey),
      secretKey: bytesToBase64(identity.kem.secretKey)
    },
    sig: {
      publicKey: bytesToBase64(identity.sig.publicKey),
      secretKey: bytesToBase64(identity.sig.secretKey)
    },
    userId: identity.userId,
    authMethod: identity.authMethod,
    identifier: identity.identifier,
    createdAt: identity.createdAt,
    version: identity.version
  });
  return bytesToBase64(new TextEncoder().encode(serialized));
}
async function importIdentity(backupData, _password) {
  try {
    const decoded = new TextDecoder().decode(base64ToBytes(backupData));
    const data = JSON.parse(decoded);
    const identity = {
      kem: {
        publicKey: base64ToBytes(data.kem.publicKey),
        secretKey: base64ToBytes(data.kem.secretKey)
      },
      sig: {
        publicKey: base64ToBytes(data.sig.publicKey),
        secretKey: base64ToBytes(data.sig.secretKey)
      },
      userId: data.userId,
      authMethod: data.authMethod,
      identifier: data.identifier,
      createdAt: data.createdAt,
      version: data.version
    };
    await saveIdentity(identity);
    console.log("[PQC Identity] Imported identity for user:", identity.userId);
    return identity;
  } catch (error) {
    console.error("[PQC Identity] Failed to import identity:", error);
    throw new Error("Failed to import identity: Invalid backup or password");
  }
}
function calculateSafetyNumber(identity1KemPublic, identity1SigPublic, identity2KemPublic, identity2SigPublic) {
  const combined = new Uint8Array(
    identity1KemPublic.length + identity1SigPublic.length + identity2KemPublic.length + identity2SigPublic.length
  );
  let offset = 0;
  combined.set(identity1KemPublic, offset);
  offset += identity1KemPublic.length;
  combined.set(identity1SigPublic, offset);
  offset += identity1SigPublic.length;
  combined.set(identity2KemPublic, offset);
  offset += identity2KemPublic.length;
  combined.set(identity2SigPublic, offset);
  const fingerprint = hash(combined, 32);
  const hex = bytesToHex(fingerprint);
  const numbers = [];
  for (let i = 0; i < hex.length; i += 10) {
    const chunk = hex.substring(i, i + 10);
    const num = parseInt(chunk, 16) % 1e5;
    numbers.push(num.toString().padStart(5, "0"));
  }
  const result = [];
  for (let i = 0; i < numbers.length && i < 6; i++) {
    result.push(numbers[i]);
  }
  return result.join(" ");
}
async function getPublicKeyBundle() {
  const identity = await loadIdentity();
  if (!identity) {
    throw new Error("No identity found");
  }
  return {
    kemPublicKey: bytesToBase64(identity.kem.publicKey),
    sigPublicKey: bytesToBase64(identity.sig.publicKey),
    userId: identity.userId
  };
}
function encapsulate(recipientKemPublicKey) {
  const result = import_ml_kem.ml_kem768.encapsulate(recipientKemPublicKey);
  return {
    sharedSecret: result.sharedSecret,
    ciphertext: result.cipherText
  };
}
function decapsulate(ciphertext, secretKey) {
  return import_ml_kem.ml_kem768.decapsulate(ciphertext, secretKey);
}

// src/session.ts
var SESSION_KEY_PREFIX = "aegis_session_";
async function initializeSession(sessionId, recipientKemPublicKey) {
  const { sharedSecret, ciphertext } = encapsulate(recipientKemPublicKey);
  const rootKey = deriveKey(sharedSecret, "aegis_root_key_v1", 32);
  const sendChainKey = deriveKey(rootKey, "aegis_send_chain_v1", 32);
  const receiveChainKey = deriveKey(rootKey, "aegis_receive_chain_v1", 32);
  const state = {
    sessionId,
    sendChainKey,
    receiveChainKey,
    sendMessageNumber: 0,
    receiveMessageNumber: 0,
    rootKey,
    createdAt: Date.now(),
    lastUsed: Date.now()
  };
  await saveSessionState(sessionId, state);
  console.log("[Session] Initialized new session:", sessionId);
  return {
    sessionId,
    kemCiphertext: bytesToBase64(ciphertext),
    initiatorKemPublic: ""
  };
}
async function acceptSession(sessionId, kemCiphertext, recipientKemSecretKey) {
  const ciphertextBytes = base64ToBytes(kemCiphertext);
  const sharedSecret = decapsulate(ciphertextBytes, recipientKemSecretKey);
  const rootKey = deriveKey(sharedSecret, "aegis_root_key_v1", 32);
  const sendChainKey = deriveKey(rootKey, "aegis_send_chain_v1", 32);
  const receiveChainKey = deriveKey(rootKey, "aegis_receive_chain_v1", 32);
  const state = {
    sessionId,
    sendChainKey: receiveChainKey,
    // Swapped
    receiveChainKey: sendChainKey,
    // Swapped
    sendMessageNumber: 0,
    receiveMessageNumber: 0,
    rootKey,
    createdAt: Date.now(),
    lastUsed: Date.now()
  };
  await saveSessionState(sessionId, state);
  console.log("[Session] Accepted session:", sessionId);
}
async function encryptMessage(sessionId, plaintext) {
  const state = await loadSessionState(sessionId);
  if (!state) {
    throw new Error(`Session not found: ${sessionId}`);
  }
  const messageKey = deriveKey(
    state.sendChainKey,
    `message_${state.sendMessageNumber}`,
    32
  );
  state.sendChainKey = deriveKey(state.sendChainKey, "ratchet", 32);
  const nonce = generateNonce();
  const plaintextBytes = stringToBytes(plaintext);
  const ciphertextBytes = encrypt(messageKey, nonce, plaintextBytes);
  const encryptedMsg = {
    sessionId,
    ciphertext: bytesToBase64(ciphertextBytes),
    nonce: bytesToBase64(nonce),
    messageNumber: state.sendMessageNumber,
    timestamp: Date.now()
  };
  state.sendMessageNumber++;
  state.lastUsed = Date.now();
  await saveSessionState(sessionId, state);
  return encryptedMsg;
}
async function decryptMessage(encryptedMsg) {
  const state = await loadSessionState(encryptedMsg.sessionId);
  if (!state) {
    throw new Error(`Session not found: ${encryptedMsg.sessionId}`);
  }
  if (encryptedMsg.messageNumber < state.receiveMessageNumber) {
    throw new Error("Message number too old - possible replay attack");
  }
  let chainKey = state.receiveChainKey;
  for (let i = state.receiveMessageNumber; i < encryptedMsg.messageNumber; i++) {
    chainKey = deriveKey(chainKey, "ratchet", 32);
  }
  const messageKey = deriveKey(
    chainKey,
    `message_${encryptedMsg.messageNumber}`,
    32
  );
  chainKey = deriveKey(chainKey, "ratchet", 32);
  const ciphertext = base64ToBytes(encryptedMsg.ciphertext);
  const nonce = base64ToBytes(encryptedMsg.nonce);
  try {
    const plaintextBytes = decrypt(messageKey, nonce, ciphertext);
    const plaintext = bytesToString(plaintextBytes);
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
async function saveSessionState(sessionId, state) {
  const serialized = JSON.stringify({
    sessionId: state.sessionId,
    sendChainKey: bytesToBase64(state.sendChainKey),
    receiveChainKey: bytesToBase64(state.receiveChainKey),
    sendMessageNumber: state.sendMessageNumber,
    receiveMessageNumber: state.receiveMessageNumber,
    rootKey: bytesToBase64(state.rootKey),
    createdAt: state.createdAt,
    lastUsed: state.lastUsed
  });
  await Aegis.getStorage().setItem(
    `${SESSION_KEY_PREFIX}${sessionId}`,
    serialized
  );
}
async function loadSessionState(sessionId) {
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
      lastUsed: data.lastUsed
    };
  } catch (error) {
    console.error("[Session] Failed to parse session state:", error);
    return null;
  }
}
async function deleteSession(sessionId) {
  await Aegis.getStorage().removeItem(`${SESSION_KEY_PREFIX}${sessionId}`);
  console.log("[Session] Deleted session:", sessionId);
}
async function getSessionInfo(sessionId) {
  const state = await loadSessionState(sessionId);
  if (!state) {
    return null;
  }
  return {
    createdAt: state.createdAt,
    lastUsed: state.lastUsed,
    messagesSent: state.sendMessageNumber
  };
}

// src/group.ts
async function sendGroupMessage(groupId, participantSessionIds, plaintext) {
  const bundle = {
    groupId,
    messages: {}
  };
  const promises = Object.entries(participantSessionIds).map(
    async ([userId, sessionId]) => {
      try {
        const encrypted = await encryptMessage(sessionId, plaintext);
        bundle.messages[userId] = encrypted;
      } catch (error) {
        console.error(
          `Failed to encrypt for user ${userId} in session ${sessionId}:`,
          error
        );
      }
    }
  );
  await Promise.all(promises);
  return bundle;
}
async function decryptGroupMessage(encryptedMsg) {
  return decryptMessage(encryptedMsg);
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Aegis,
  acceptSession,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToString,
  calculateSafetyNumber,
  constantTimeEqual,
  createIdentity,
  decapsulate,
  decrypt,
  decryptGroupMessage,
  decryptMessage,
  deleteIdentity,
  deleteSession,
  deriveKey,
  encapsulate,
  encrypt,
  encryptMessage,
  exportIdentity,
  generateKey,
  generateNonce,
  getPublicKeyBundle,
  getRandomBytes,
  getSessionInfo,
  hash,
  hexToBytes,
  importIdentity,
  initializeSession,
  loadIdentity,
  saveIdentity,
  sendGroupMessage,
  stringToBytes
});
