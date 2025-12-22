var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);

// src/pqc.ts
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ed25519 } from "@noble/curves/ed25519.js";

// src/crypto.ts
import { blake3 } from "@noble/hashes/blake3.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/hashes/utils.js";
function hash(data, outputLength = 32) {
  if (!data) {
    throw new Error("Input data cannot be empty");
  }
  if (outputLength <= 0 || outputLength > 64) {
    throw new Error("Output length must be between 1 and 64 bytes");
  }
  const input = typeof data === "string" ? stringToBytes(data) : data;
  return blake3(input, { dkLen: outputLength });
}
function deriveKey(data, context, outputLength = 32) {
  const input = typeof data === "string" ? stringToBytes(data) : data;
  const contextBytes = stringToBytes(context);
  const combined = new Uint8Array(contextBytes.length + input.length);
  combined.set(contextBytes, 0);
  combined.set(input, contextBytes.length);
  return blake3(combined, { dkLen: outputLength });
}
function getRandomBytes(length) {
  return randomBytes(length);
}
function encrypt(key, nonce, plaintext, associatedData) {
  if (key.length !== 32) {
    throw new Error("Key must be 32 bytes");
  }
  if (nonce.length !== 12) {
    throw new Error("Nonce must be 12 bytes");
  }
  const cipher = chacha20poly1305(key, nonce, associatedData);
  return cipher.encrypt(plaintext);
}
function decrypt(key, nonce, ciphertext, associatedData) {
  if (key.length !== 32) {
    throw new Error("Key must be 32 bytes");
  }
  if (nonce.length !== 12) {
    throw new Error("Nonce must be 12 bytes");
  }
  const cipher = chacha20poly1305(key, nonce, associatedData);
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
function zeroBuffer(buffer) {
  buffer.fill(0);
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
var IDENTITY_VERSION = "2.0.0";
function generateKEMKeyPair() {
  const keyPair = ml_kem768.keygen();
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey
  };
}
async function generateSignatureKeyPair() {
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = await ed25519.getPublicKey(secretKey);
  return {
    publicKey,
    secretKey
  };
}
async function createIdentity(userId, authMethod, identifier) {
  if (!userId || typeof userId !== "string") {
    throw new Error("User ID must be a non-empty string");
  }
  if (!authMethod || authMethod !== "phone" && authMethod !== "email") {
    throw new Error("Auth method must be either 'phone' or 'email'");
  }
  if (!identifier || typeof identifier !== "string") {
    throw new Error("Identifier must be a non-empty string");
  }
  const kem = generateKEMKeyPair();
  const sig = await generateSignatureKeyPair();
  const signedPreKey = await generateSignedPreKey(sig.secretKey);
  const oneTimePreKeys = generateOneTimePreKeys(50);
  const identity = {
    kem,
    sig,
    userId,
    authMethod,
    identifier,
    createdAt: Date.now(),
    version: IDENTITY_VERSION,
    signedPreKey,
    oneTimePreKeys
  };
  await saveIdentity(identity);
  console.log("[PQC Identity] Created new identity for user:", userId);
  return identity;
}
async function generateSignedPreKey(signingSecretKey) {
  const keyPair = generateKEMKeyPair();
  let signature;
  if (signingSecretKey && signingSecretKey.length > 0) {
    signature = await ed25519.sign(keyPair.publicKey, signingSecretKey);
  } else {
    signature = hash(keyPair.publicKey);
  }
  return {
    id: Math.floor(Date.now() / 1e3),
    // Simple ID scheme
    keyPair,
    signature,
    createdAt: Date.now()
  };
}
function generateOneTimePreKeys(count) {
  const keys = [];
  for (let i = 0; i < count; i++) {
    keys.push({
      id: i,
      keyPair: generateKEMKeyPair()
    });
  }
  return keys;
}
async function saveIdentity(identity) {
  if (!identity) {
    throw new Error("Identity cannot be null or undefined");
  }
  if (!identity.userId || !identity.authMethod || !identity.identifier) {
    throw new Error("Identity is missing required fields");
  }
  const extendedIdentity = identity;
  const serialized = JSON.stringify({
    kem: {
      publicKey: bytesToBase64(identity.kem.publicKey),
      secretKey: bytesToBase64(identity.kem.secretKey)
    },
    sig: {
      publicKey: bytesToBase64(identity.sig.publicKey),
      secretKey: bytesToBase64(identity.sig.secretKey)
    },
    signedPreKey: extendedIdentity.signedPreKey ? {
      id: extendedIdentity.signedPreKey.id,
      key: {
        pub: bytesToBase64(extendedIdentity.signedPreKey.keyPair.publicKey),
        sec: bytesToBase64(extendedIdentity.signedPreKey.keyPair.secretKey)
      },
      sig: bytesToBase64(extendedIdentity.signedPreKey.signature),
      created: extendedIdentity.signedPreKey.createdAt
    } : void 0,
    oneTimePreKeys: extendedIdentity.oneTimePreKeys ? extendedIdentity.oneTimePreKeys.map((k) => ({
      id: k.id,
      pub: bytesToBase64(k.keyPair.publicKey),
      sec: bytesToBase64(k.keyPair.secretKey)
    })) : [],
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
    if (!data.userId || !data.authMethod || !data.identifier || !data.version) {
      throw new Error("Invalid identity data: missing required fields");
    }
    if (!data.kem || !data.kem.publicKey || !data.kem.secretKey) {
      throw new Error("Invalid identity data: missing KEM keys");
    }
    if (!data.sig || !data.sig.publicKey || !data.sig.secretKey) {
      throw new Error("Invalid identity data: missing signature keys");
    }
    const identity = {
      kem: {
        publicKey: base64ToBytes(data.kem.publicKey),
        secretKey: base64ToBytes(data.kem.secretKey)
      },
      sig: {
        publicKey: base64ToBytes(data.sig.publicKey),
        secretKey: base64ToBytes(data.sig.secretKey)
      },
      signedPreKey: data.signedPreKey ? {
        id: data.signedPreKey.id,
        keyPair: {
          publicKey: base64ToBytes(data.signedPreKey.key.pub),
          secretKey: base64ToBytes(data.signedPreKey.key.sec)
        },
        signature: base64ToBytes(data.signedPreKey.sig),
        createdAt: data.signedPreKey.created
      } : void 0,
      // Cast for compatibility if missing in old versions
      oneTimePreKeys: data.oneTimePreKeys ? data.oneTimePreKeys.map((k) => ({
        id: k.id,
        keyPair: {
          publicKey: base64ToBytes(k.pub),
          secretKey: base64ToBytes(k.sec)
        }
      })) : [],
      userId: data.userId,
      authMethod: data.authMethod,
      identifier: data.identifier,
      createdAt: data.createdAt,
      version: data.version
    };
    return identity;
  } catch (error) {
    console.error("[PQC Identity] Failed to parse identity:", error);
    return null;
  }
}
async function deleteIdentity() {
  await Aegis.getStorage().removeItem(IDENTITY_STORAGE_KEY);
  console.log("[PQC Identity] Deleted identity");
}
async function exportIdentity(password) {
  if (!password || typeof password !== "string") {
    throw new Error("Password must be a non-empty string");
  }
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
  const salt = generateNonce();
  const key = deriveKey(
    new Uint8Array([...new TextEncoder().encode(password), ...salt]),
    "aegis_identity_backup_v1",
    32
  );
  const nonce = generateNonce();
  const ciphertext = encrypt(key, nonce, new TextEncoder().encode(serialized));
  const backup = JSON.stringify({
    v: "1",
    salt: bytesToBase64(salt),
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(ciphertext)
  });
  return bytesToBase64(new TextEncoder().encode(backup));
}
async function importIdentity(backupData, password) {
  if (!backupData || typeof backupData !== "string") {
    throw new Error("Backup data must be a non-empty string");
  }
  if (!password || typeof password !== "string") {
    throw new Error("Password must be a non-empty string");
  }
  try {
    const decoded = new TextDecoder().decode(base64ToBytes(backupData));
    const data = JSON.parse(decoded);
    let parsed = data;
    if (data && data.v === "1" && data.salt && data.nonce && data.ciphertext) {
      const salt = base64ToBytes(data.salt);
      const nonce = base64ToBytes(data.nonce);
      const ciphertext = base64ToBytes(data.ciphertext);
      const key = deriveKey(
        new Uint8Array([...new TextEncoder().encode(password), ...salt]),
        "aegis_identity_backup_v1",
        32
      );
      const plaintextBytes = decrypt(key, nonce, ciphertext);
      const plaintext = new TextDecoder().decode(plaintextBytes);
      parsed = JSON.parse(plaintext);
    }
    if (!parsed.kem || !parsed.sig) {
      throw new Error("Invalid identity backup format");
    }
    const identity = {
      kem: {
        publicKey: base64ToBytes(parsed.kem.publicKey),
        secretKey: base64ToBytes(parsed.kem.secretKey)
      },
      sig: {
        publicKey: base64ToBytes(parsed.sig.publicKey),
        secretKey: base64ToBytes(parsed.sig.secretKey)
      },
      userId: parsed.userId,
      authMethod: parsed.authMethod,
      identifier: parsed.identifier,
      createdAt: parsed.createdAt,
      version: parsed.version
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
  if (!identity1KemPublic || identity1KemPublic.length === 0 || !identity1SigPublic || identity1SigPublic.length === 0 || !identity2KemPublic || identity2KemPublic.length === 0 || !identity2SigPublic || identity2SigPublic.length === 0) {
    throw new Error("All public keys must be non-empty Uint8Arrays");
  }
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
  const otpk = identity.oneTimePreKeys.length > 0 ? identity.oneTimePreKeys[0] : void 0;
  return {
    identityKey: bytesToBase64(identity.kem.publicKey),
    sigPublicKey: bytesToBase64(identity.sig.publicKey),
    signedPreKey: {
      id: identity.signedPreKey.id,
      key: bytesToBase64(identity.signedPreKey.keyPair.publicKey),
      signature: bytesToBase64(identity.signedPreKey.signature)
    },
    oneTimePreKey: otpk ? {
      id: otpk.id,
      key: bytesToBase64(otpk.keyPair.publicKey)
    } : void 0,
    userId: identity.userId
  };
}
async function getAndConsumePublicKeyBundle() {
  const identity = await loadIdentity();
  if (!identity) {
    throw new Error("No identity found");
  }
  const otpk = identity.oneTimePreKeys.length > 0 ? identity.oneTimePreKeys.shift() : void 0;
  await saveIdentity(identity);
  return {
    identityKey: bytesToBase64(identity.kem.publicKey),
    sigPublicKey: bytesToBase64(identity.sig.publicKey),
    signedPreKey: {
      id: identity.signedPreKey.id,
      key: bytesToBase64(identity.signedPreKey.keyPair.publicKey),
      signature: bytesToBase64(identity.signedPreKey.signature)
    },
    oneTimePreKey: otpk ? {
      id: otpk.id,
      key: bytesToBase64(otpk.keyPair.publicKey)
    } : void 0,
    userId: identity.userId
  };
}
function encapsulate(recipientKemPublicKey) {
  if (!recipientKemPublicKey || recipientKemPublicKey.length === 0) {
    throw new Error("Recipient public key must be a non-empty Uint8Array");
  }
  const result = ml_kem768.encapsulate(recipientKemPublicKey);
  return {
    sharedSecret: result.sharedSecret,
    ciphertext: result.cipherText
  };
}
async function verifySignedPreKey(spkPublicKey, signature, signerPublicKey) {
  try {
    return await ed25519.verify(signature, spkPublicKey, signerPublicKey);
  } catch {
    return false;
  }
}
function decapsulate(ciphertext, secretKey) {
  if (!ciphertext || ciphertext.length === 0) {
    throw new Error("Ciphertext must be a non-empty Uint8Array");
  }
  if (!secretKey || secretKey.length === 0) {
    throw new Error("Secret key must be a non-empty Uint8Array");
  }
  return ml_kem768.decapsulate(ciphertext, secretKey);
}

// src/session.ts
var SESSION_KEY_PREFIX = "aegis_session_";
var sessionLocks = /* @__PURE__ */ new Map();
async function withSessionLock(sessionId, fn) {
  const current = sessionLocks.get(sessionId) ?? Promise.resolve();
  const next = current.then(
    () => fn(),
    () => fn()
  );
  sessionLocks.set(
    sessionId,
    next.then(
      () => void 0,
      () => void 0
    )
  );
  try {
    const result = await next;
    return result;
  } finally {
    const tail = sessionLocks.get(sessionId);
    if (tail && tail === next.then(
      () => void 0,
      () => void 0
    )) {
      sessionLocks.delete(sessionId);
    }
  }
}
async function initializeSession(sessionId, recipientBundle) {
  if (!sessionId || typeof sessionId !== "string") {
    throw new Error("Invalid session ID");
  }
  if (!recipientBundle) {
    throw new Error("Recipient bundle is required");
  }
  if (!recipientBundle.identityKey || typeof recipientBundle.identityKey !== "string") {
    throw new Error("Invalid identity key");
  }
  if (!recipientBundle.signedPreKey || typeof recipientBundle.signedPreKey !== "object") {
    throw new Error("Invalid signed pre-key");
  }
  const sharedSecrets = [];
  const ciphertexts = {};
  const ikBytes = base64ToBytes(recipientBundle.identityKey);
  const encIk = encapsulate(ikBytes);
  sharedSecrets.push(encIk.sharedSecret);
  ciphertexts.ik = bytesToBase64(encIk.ciphertext);
  const spkBytes = base64ToBytes(recipientBundle.signedPreKey.key);
  const encSpk = encapsulate(spkBytes);
  sharedSecrets.push(encSpk.sharedSecret);
  ciphertexts.spk = bytesToBase64(encSpk.ciphertext);
  if (recipientBundle.oneTimePreKey) {
    const otpkBytes = base64ToBytes(recipientBundle.oneTimePreKey.key);
    const encOtpk = encapsulate(otpkBytes);
    sharedSecrets.push(encOtpk.sharedSecret);
    ciphertexts.otpk = bytesToBase64(encOtpk.ciphertext);
  }
  const combinedSecret = new Uint8Array(
    sharedSecrets.reduce((acc, curr) => acc + curr.length, 0)
  );
  let offset = 0;
  for (const secret of sharedSecrets) {
    combinedSecret.set(secret, offset);
    offset += secret.length;
  }
  const rootKey = deriveKey(combinedSecret, "aegis_x3dh_root_v2", 32);
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
  console.log("[Session] Initialized new X3DH session:", sessionId);
  return {
    sessionId,
    ciphertexts
  };
}
async function acceptSession(sessionId, ciphertexts, keys) {
  const sharedSecrets = [];
  sharedSecrets.push(
    decapsulate(base64ToBytes(ciphertexts.ik), keys.identitySecret)
  );
  sharedSecrets.push(
    decapsulate(base64ToBytes(ciphertexts.spk), keys.signedPreKeySecret)
  );
  if (ciphertexts.otpk && keys.oneTimePreKeySecret) {
    sharedSecrets.push(
      decapsulate(base64ToBytes(ciphertexts.otpk), keys.oneTimePreKeySecret)
    );
  } else if (ciphertexts.otpk && !keys.oneTimePreKeySecret) {
    throw new Error("Missing One-Time PreKey to decrypt session");
  }
  const combinedSecret = new Uint8Array(
    sharedSecrets.reduce((acc, curr) => acc + curr.length, 0)
  );
  let offset = 0;
  for (const secret of sharedSecrets) {
    combinedSecret.set(secret, offset);
    offset += secret.length;
  }
  const rootKey = deriveKey(combinedSecret, "aegis_x3dh_root_v2", 32);
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
  console.log("[Session] Accepted X3DH session:", sessionId);
}
async function encryptMessage(sessionId, plaintext) {
  return withSessionLock(sessionId, async () => {
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
  });
}
async function decryptMessage(encryptedMsg) {
  return withSessionLock(encryptedMsg.sessionId, async () => {
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
  });
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

// src/sender-keys.ts
var KDF_CHAIN_KEY_SEED = "aegis_sender_chain_step";
var KDF_MESSAGE_KEY_SEED = "aegis_sender_message_key";
function generateSenderKey() {
  const chainKey = generateKey();
  if (chainKey.length !== 32) {
    throw new Error("Generated chain key must be 32 bytes");
  }
  return {
    chainKey,
    signatureKey: new Uint8Array(0),
    // Placeholder, ideally actual Sig Pub Key
    generation: Math.floor(Date.now() / 1e3)
    // Use timestamp as generation ID for simplicity
  };
}
function deriveMessageKey(chainKey) {
  return deriveKey(chainKey, KDF_MESSAGE_KEY_SEED, 32);
}
function ratchetChainKey(chainKey) {
  return deriveKey(chainKey, KDF_CHAIN_KEY_SEED, 32);
}
function encryptGroupMessage(state, groupId, senderId, plaintext) {
  if (!state || !state.chainKey || state.chainKey.length === 0) {
    throw new Error("Invalid sender key state");
  }
  if (!groupId || typeof groupId !== "string" || groupId.trim() === "") {
    throw new Error("Group ID must be a non-empty string");
  }
  if (!senderId || typeof senderId !== "string" || senderId.trim() === "") {
    throw new Error("Sender ID must be a non-empty string");
  }
  if (!plaintext || typeof plaintext !== "string") {
    throw new Error("Plaintext must be a non-empty string");
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
    cipherText: bytesToBase64(cipherText),
    nonce: bytesToBase64(nonce)
  };
  state.chainKey = ratchetChainKey(state.chainKey);
  return message;
}
function decryptGroupMessage(currentChainKey, message) {
  if (!currentChainKey || currentChainKey.length === 0) {
    throw new Error("Current chain key must be a non-empty Uint8Array");
  }
  if (!message || !message.senderId || !message.groupId || !message.cipherText || !message.nonce) {
    throw new Error("Invalid message format: missing required fields");
  }
  const messageKey = deriveMessageKey(currentChainKey);
  const nonce = base64ToBytes(message.nonce);
  const ciphertext = base64ToBytes(message.cipherText);
  const plaintextBytes = decrypt(messageKey, nonce, ciphertext);
  const nextChainKey = ratchetChainKey(currentChainKey);
  return {
    plaintext: bytesToString(plaintextBytes),
    nextChainKey
  };
}

// src/group.ts
function validateGroupId(groupId) {
  if (!groupId || typeof groupId !== "string" || groupId.trim() === "") {
    throw new Error("Group ID must be a non-empty string");
  }
}
function validateSenderKeyState(state) {
  if (!state || !state.chainKey || state.chainKey.length === 0) {
    throw new Error("Invalid sender key state");
  }
}
var GROUP_STORAGE_PREFIX = "aegis_group_";
var GroupSession = class _GroupSession {
  constructor(groupId, data) {
    __publicField(this, "groupId");
    __publicField(this, "data");
    validateGroupId(groupId);
    validateSenderKeyState(data.mySenderKey);
    this.groupId = groupId;
    this.data = data;
  }
  /**
   * Load or Create a Group Session
   */
  static async get(groupId) {
    return _GroupSession.getLoaded(groupId);
  }
  /**
   * Create a Distribution Message to send to a new participant.
   * This MUST be sent via the secure 1:1 session (encryptMessage).
   */
  createDistributionMessage(senderId) {
    if (!senderId || typeof senderId !== "string" || senderId.trim() === "") {
      throw new Error("Sender ID must be a non-empty string");
    }
    return {
      type: "distribution",
      senderId,
      groupId: this.data.groupId,
      chainKey: bytesToBase64(this.data.mySenderKey.chainKey),
      signatureKey: bytesToBase64(this.data.mySenderKey.signatureKey),
      generation: this.data.mySenderKey.generation
    };
  }
  /**
   * Process an incoming Distribution Message from another member.
   * Call this AFTER decrypting the 1:1 message containing this payload.
   */
  async processDistributionMessage(payload) {
    if (payload.groupId !== this.groupId) return;
    this.data.participants[payload.senderId] = {
      currentChainKey: payload.chainKey
    };
    await this.save();
    console.log(`[Group] Updated sender key for ${payload.senderId}`);
  }
  /**
   * Encrypt a message for the group.
   * O(1) operation (just one encryption).
   */
  async encrypt(plaintext, myUserId) {
    if (!plaintext || typeof plaintext !== "string") {
      throw new Error("Plaintext must be a non-empty string");
    }
    if (!myUserId || typeof myUserId !== "string" || myUserId.trim() === "") {
      throw new Error("User ID must be a non-empty string");
    }
    const msg = encryptGroupMessage(
      this.data.mySenderKey,
      this.groupId,
      myUserId,
      plaintext
    );
    await this.save();
    return msg;
  }
  /**
   * Decrypt a message from the group.
   * O(1) operation.
   */
  async decrypt(msg) {
    if (!msg || !msg.senderId || !msg.groupId || !msg.cipherText || !msg.nonce) {
      throw new Error("Invalid message format");
    }
    const participant = this.data.participants[msg.senderId];
    if (!participant) {
      throw new Error(
        `No sender key found for ${msg.senderId}. Did you receive a distribution message?`
      );
    }
    const currentChainKey = base64ToBytes(participant.currentChainKey);
    const { plaintext, nextChainKey } = decryptGroupMessage(
      currentChainKey,
      msg
    );
    participant.currentChainKey = bytesToBase64(nextChainKey);
    await this.save();
    return plaintext;
  }
  async save() {
    const storageFormat = {
      groupId: this.data.groupId,
      mySenderKey: {
        chainKey: bytesToBase64(this.data.mySenderKey.chainKey),
        signatureKey: bytesToBase64(this.data.mySenderKey.signatureKey),
        generation: this.data.mySenderKey.generation
      },
      participants: this.data.participants
    };
    await Aegis.getStorage().setItem(
      `${GROUP_STORAGE_PREFIX}${this.groupId}`,
      JSON.stringify(storageFormat)
    );
  }
  // Override static get to handle deserialization
  static async getLoaded(groupId) {
    const key = `${GROUP_STORAGE_PREFIX}${groupId}`;
    const stored = await Aegis.getStorage().getItem(key);
    if (!stored) {
      const newData = {
        groupId,
        mySenderKey: generateSenderKey(),
        participants: {}
      };
      const storageFormat = {
        groupId: newData.groupId,
        mySenderKey: {
          chainKey: bytesToBase64(newData.mySenderKey.chainKey),
          signatureKey: bytesToBase64(newData.mySenderKey.signatureKey),
          generation: newData.mySenderKey.generation
        },
        participants: newData.participants
      };
      await Aegis.getStorage().setItem(key, JSON.stringify(storageFormat));
      return new _GroupSession(groupId, newData);
    }
    const raw = JSON.parse(stored);
    const data = {
      groupId: raw.groupId,
      mySenderKey: {
        chainKey: base64ToBytes(raw.mySenderKey.chainKey),
        signatureKey: base64ToBytes(raw.mySenderKey.signatureKey),
        generation: raw.mySenderKey.generation
      },
      participants: raw.participants
    };
    return new _GroupSession(groupId, data);
  }
};
async function getGroupSession(groupId) {
  return GroupSession.getLoaded(groupId);
}
export {
  Aegis,
  GroupSession,
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
  getAndConsumePublicKeyBundle,
  getGroupSession,
  getPublicKeyBundle,
  getRandomBytes,
  getSessionInfo,
  hash,
  hexToBytes,
  importIdentity,
  initializeSession,
  loadIdentity,
  saveIdentity,
  stringToBytes,
  verifySignedPreKey,
  zeroBuffer
};
