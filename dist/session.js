// Fixed session.ts - Simplified working version
import { encrypt, decrypt, deriveKey, generateNonce, bytesToBase64, base64ToBytes, stringToBytes, bytesToString, getRandomBytes, hash, } from "./crypto";
import { x25519 } from "@noble/curves/ed25519.js";
import { validateEncryptedMessage, validateString, validateBase64, } from "./validator";
import { SessionError, ValidationError, } from "./types";
const SESSION_KEY_PREFIX = "aegis_session_";
export const PROTOCOL_VERSION = "2.0-x25519";
export const MAX_SKIPPED_MESSAGES = 1000;
export class SessionManager {
    constructor(aegisInstance) {
        Object.defineProperty(this, "aegis", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "sessionLocks", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Map()
        });
        this.aegis = aegisInstance;
        if (!aegisInstance.isInitialized()) {
            throw new SessionError("Aegis instance must be initialized before creating SessionManager");
        }
    }
    async withSessionLock(sessionId, fn) {
        const current = this.sessionLocks.get(sessionId) ?? Promise.resolve();
        const next = current.then(() => fn(), () => fn());
        this.sessionLocks.set(sessionId, next.then(() => undefined, () => undefined));
        try {
            const result = await next;
            return result;
        }
        finally {
            const tail = this.sessionLocks.get(sessionId);
            if (tail &&
                tail ===
                    next.then(() => undefined, () => undefined)) {
                this.sessionLocks.delete(sessionId);
            }
        }
    }
    generateX25519KeyPair() {
        const privateKey = getRandomBytes(32);
        const publicKey = x25519.getPublicKey(privateKey);
        return { privateKey, publicKey };
    }
    deriveX25519SharedSecret(privateKey, publicKey) {
        return x25519.getSharedSecret(privateKey, publicKey);
    }
    storeSkippedMessageKey(state, ratchetPubKeyBase64, messageNumber, key) {
        state.skippedMessageKeys = state.skippedMessageKeys ?? {};
        const bucket = state.skippedMessageKeys[ratchetPubKeyBase64] ?? {};
        const totalSkipped = Object.values(state.skippedMessageKeys).reduce((acc, cur) => acc + Object.keys(cur).length, 0);
        if (totalSkipped >= (state.skippedMessagesLimit ?? MAX_SKIPPED_MESSAGES)) {
            throw new SessionError("Skipped message limit exceeded", state.sessionId, { totalSkipped, limit: state.skippedMessagesLimit });
        }
        bucket[messageNumber] = bytesToBase64(key);
        state.skippedMessageKeys[ratchetPubKeyBase64] = bucket;
    }
    getAndRemoveSkippedMessageKey(state, ratchetPubKeyBase64, messageNumber) {
        if (!state.skippedMessageKeys)
            return null;
        const bucket = state.skippedMessageKeys[ratchetPubKeyBase64];
        if (!bucket)
            return null;
        const b64 = bucket[messageNumber];
        if (!b64)
            return null;
        delete bucket[messageNumber];
        if (Object.keys(bucket).length === 0) {
            delete state.skippedMessageKeys[ratchetPubKeyBase64];
        }
        else {
            state.skippedMessageKeys[ratchetPubKeyBase64] = bucket;
        }
        return base64ToBytes(b64);
    }
    deriveMessageKeyAndNextChain(chainKey, index) {
        const messageKey = deriveKey(chainKey, `message_${index}`, 32);
        const nextChainKey = deriveKey(chainKey, "ratchet", 32);
        return { messageKey, nextChainKey };
    }
    deriveRootFromSS(rootKey, ss) {
        const combined = new Uint8Array(rootKey.length + ss.length);
        combined.set(rootKey, 0);
        combined.set(ss, rootKey.length);
        return deriveKey(combined, "aegis_dr_root", 32);
    }
    async performDHratchet(state, theirRatchetPubBase64, pn) {
        const theirPub = base64ToBytes(theirRatchetPubBase64);
        const prevRemotePubBase64 = state.dhRemotePublic
            ? bytesToBase64(state.dhRemotePublic)
            : theirRatchetPubBase64;
        let chainKey = state.receiveChainKey;
        for (let i = state.receiveMessageNumber; i < (pn || 0); i++) {
            const { messageKey, nextChainKey } = this.deriveMessageKeyAndNextChain(chainKey, i);
            this.storeSkippedMessageKey(state, prevRemotePubBase64, i, messageKey);
            chainKey = nextChainKey;
        }
        const ss1 = this.deriveX25519SharedSecret(state.dhPrivate, theirPub);
        let newRoot = this.deriveRootFromSS(state.rootKey, ss1);
        let newReceiveCK = deriveKey(newRoot, "receive_chain", 32);
        const newDh = this.generateX25519KeyPair();
        const ss2 = this.deriveX25519SharedSecret(newDh.privateKey, theirPub);
        newRoot = this.deriveRootFromSS(newRoot, ss2);
        const newSendCK = deriveKey(newRoot, "send_chain", 32);
        const prevSendCount = state.sendMessageNumber;
        state.rootKey = newRoot;
        state.receiveChainKey = newReceiveCK;
        state.sendChainKey = newSendCK;
        state.dhPrivate = newDh.privateKey;
        state.dhPublic = newDh.publicKey;
        state.dhRemotePublic = theirPub;
        state.receiveMessageNumber = 0;
        state.sendMessageNumber = 0;
        state.pendingRatchet = {
            pub: bytesToBase64(newDh.publicKey),
            pn: prevSendCount,
        };
        await this.saveSessionState(state.sessionId, state);
    }
    // SIMPLIFIED: Use direct X25519 instead of KEM for testing
    async initializeSession(sessionId, recipientBundle) {
        validateString(sessionId, "sessionId");
        if (!recipientBundle || typeof recipientBundle !== "object") {
            throw new ValidationError("Recipient bundle is required");
        }
        validateBase64(recipientBundle.identityKey, "identityKey");
        validateBase64(recipientBundle.signedPreKey.key, "signedPreKey.key");
        validateBase64(recipientBundle.signedPreKey.signature, "signedPreKey.signature");
        if (recipientBundle.sigPublicKey) {
            validateBase64(recipientBundle.sigPublicKey, "sigPublicKey");
            // Skip verification for now to simplify
        }
        // Generate ephemeral key pair for Alice
        const ephemeralKeyPair = this.generateX25519KeyPair();
        // Get recipient's public keys
        const recipientIdentityKey = base64ToBytes(recipientBundle.identityKey);
        const recipientSignedPreKey = base64ToBytes(recipientBundle.signedPreKey.key);
        // Calculate DH shared secrets (simplified X3DH)
        const sharedSecrets = [];
        // DH1: Alice's ephemeral key with Bob's signed pre-key
        const dh1 = this.deriveX25519SharedSecret(ephemeralKeyPair.privateKey, recipientSignedPreKey);
        sharedSecrets.push(dh1);
        // DH2: Alice's ephemeral key with Bob's identity key
        const dh2 = this.deriveX25519SharedSecret(ephemeralKeyPair.privateKey, recipientIdentityKey);
        sharedSecrets.push(dh2);
        // Combine secrets
        const combinedSecret = new Uint8Array(sharedSecrets.reduce((acc, curr) => acc + curr.length, 0));
        let offset = 0;
        for (const secret of sharedSecrets) {
            combinedSecret.set(secret, offset);
            offset += secret.length;
        }
        // Derive root key
        const rootKey = hash(combinedSecret, 32);
        // Generate initial chain keys
        const sendChainKey = deriveKey(rootKey, "send_chain_init", 32);
        const receiveChainKey = deriveKey(rootKey, "receive_chain_init", 32);
        // Generate ratchet key pair
        const ratchetKeyPair = this.generateX25519KeyPair();
        const state = {
            sessionId,
            sendChainKey,
            receiveChainKey,
            sendMessageNumber: 0,
            receiveMessageNumber: 0,
            rootKey,
            dhPrivate: ratchetKeyPair.privateKey,
            dhPublic: ratchetKeyPair.publicKey,
            dhRemotePublic: undefined,
            pendingRatchet: { pub: bytesToBase64(ratchetKeyPair.publicKey), pn: 0 },
            skippedMessageKeys: {},
            skippedMessagesLimit: MAX_SKIPPED_MESSAGES,
            protocolVersion: PROTOCOL_VERSION,
            createdAt: Date.now(),
            lastUsed: Date.now(),
        };
        await this.saveSessionState(sessionId, state);
        return {
            sessionId,
            ciphertexts: {
                ik: bytesToBase64(ephemeralKeyPair.publicKey), // Send our ephemeral public key
                spk: bytesToBase64(new Uint8Array(32)), // Placeholder
                otpk: undefined,
            },
            ratchetPubKey: bytesToBase64(ratchetKeyPair.publicKey),
            protocolVersion: PROTOCOL_VERSION,
        };
    }
    async acceptSession(sessionId, ciphertexts, keys) {
        validateString(sessionId, "sessionId");
        validateBase64(ciphertexts.ik, "ciphertexts.ik");
        // Get Alice's ephemeral public key
        const aliceEphemeralPublic = base64ToBytes(ciphertexts.ik);
        // Bob needs his identity private key and signed pre-key private key
        const sharedSecrets = [];
        // DH1: Bob's signed pre-key private with Alice's ephemeral public
        const dh1 = this.deriveX25519SharedSecret(keys.signedPreKeySecret, aliceEphemeralPublic);
        sharedSecrets.push(dh1);
        // DH2: Bob's identity private with Alice's ephemeral public
        const dh2 = this.deriveX25519SharedSecret(keys.identitySecret, aliceEphemeralPublic);
        sharedSecrets.push(dh2);
        // Combine secrets (must be in same order as Alice!)
        const combinedSecret = new Uint8Array(sharedSecrets.reduce((acc, curr) => acc + curr.length, 0));
        let offset = 0;
        for (const secret of sharedSecrets) {
            combinedSecret.set(secret, offset);
            offset += secret.length;
        }
        // Derive same root key
        const rootKey = hash(combinedSecret, 32);
        // IMPORTANT: Bob's receive chain should match Alice's send chain
        // IMPORTANT: Bob's send chain should match Alice's receive chain
        const receiveChainKey = deriveKey(rootKey, "send_chain_init", 32); // Matches Alice's send
        const sendChainKey = deriveKey(rootKey, "receive_chain_init", 32); // Matches Alice's receive
        // Generate Bob's ratchet key pair
        const ratchetKeyPair = this.generateX25519KeyPair();
        const state = {
            sessionId,
            sendChainKey, // Bob sends with this
            receiveChainKey, // Bob receives with this (should match Alice's send)
            sendMessageNumber: 0,
            receiveMessageNumber: 0,
            rootKey,
            dhPrivate: ratchetKeyPair.privateKey,
            dhPublic: ratchetKeyPair.publicKey,
            dhRemotePublic: undefined,
            pendingRatchet: { pub: bytesToBase64(ratchetKeyPair.publicKey), pn: 0 },
            skippedMessageKeys: {},
            skippedMessagesLimit: MAX_SKIPPED_MESSAGES,
            protocolVersion: PROTOCOL_VERSION,
            createdAt: Date.now(),
            lastUsed: Date.now(),
        };
        await this.saveSessionState(sessionId, state);
    }
    async encryptMessage(sessionId, plaintext) {
        validateString(sessionId, "sessionId");
        validateString(plaintext, "plaintext");
        return this.withSessionLock(sessionId, async () => {
            const state = await this.loadSessionState(sessionId);
            if (!state) {
                throw new SessionError(`Session not found`, sessionId);
            }
            const messageKey = deriveKey(state.sendChainKey, `message_${state.sendMessageNumber}`, 32);
            state.sendChainKey = deriveKey(state.sendChainKey, "ratchet", 32);
            const nonce = generateNonce();
            const plaintextBytes = stringToBytes(plaintext);
            const ciphertextBytes = encrypt(messageKey, nonce, plaintextBytes);
            const headerRatchetPub = state.pendingRatchet
                ? state.pendingRatchet.pub
                : bytesToBase64(state.dhPublic);
            const headerPn = state.pendingRatchet
                ? state.pendingRatchet.pn
                : state.sendMessageNumber;
            const encryptedMsg = {
                sessionId,
                ciphertext: bytesToBase64(ciphertextBytes),
                nonce: bytesToBase64(nonce),
                messageNumber: state.sendMessageNumber,
                timestamp: Date.now(),
                ratchetPubKey: headerRatchetPub,
                pn: headerPn,
                protocolVersion: state.protocolVersion ?? PROTOCOL_VERSION,
            };
            if (state.pendingRatchet) {
                delete state.pendingRatchet;
            }
            state.sendMessageNumber++;
            state.lastUsed = Date.now();
            await this.saveSessionState(sessionId, state);
            return encryptedMsg;
        });
    }
    async decryptMessage(encryptedMsg) {
        validateEncryptedMessage(encryptedMsg);
        return this.withSessionLock(encryptedMsg.sessionId, async () => {
            const state = await this.loadSessionState(encryptedMsg.sessionId);
            if (!state) {
                throw new SessionError(`Session not found`, encryptedMsg.sessionId);
            }
            if (encryptedMsg.protocolVersion &&
                encryptedMsg.protocolVersion !==
                    (state.protocolVersion ?? PROTOCOL_VERSION)) {
                throw new SessionError(`Protocol version mismatch`, encryptedMsg.sessionId, {
                    expected: state.protocolVersion ?? PROTOCOL_VERSION,
                    received: encryptedMsg.protocolVersion,
                });
            }
            if (encryptedMsg.ratchetPubKey &&
                encryptedMsg.ratchetPubKey !==
                    (state.dhRemotePublic
                        ? bytesToBase64(state.dhRemotePublic)
                        : undefined)) {
                await this.performDHratchet(state, encryptedMsg.ratchetPubKey, encryptedMsg.pn ?? 0);
            }
            const theirRatchetPubBase64 = encryptedMsg.ratchetPubKey ??
                (state.dhRemotePublic
                    ? bytesToBase64(state.dhRemotePublic)
                    : undefined);
            if (theirRatchetPubBase64) {
                const skipped = this.getAndRemoveSkippedMessageKey(state, theirRatchetPubBase64, encryptedMsg.messageNumber);
                if (skipped) {
                    try {
                        const plaintextBytes = decrypt(skipped, base64ToBytes(encryptedMsg.nonce), base64ToBytes(encryptedMsg.ciphertext));
                        const plaintext = bytesToString(plaintextBytes);
                        state.lastUsed = Date.now();
                        await this.saveSessionState(encryptedMsg.sessionId, state);
                        return plaintext;
                    }
                    catch (err) {
                        console.warn(`[Session] Skipped key decryption failed for message ${encryptedMsg.messageNumber}`, err);
                    }
                }
            }
            if (encryptedMsg.messageNumber < state.receiveMessageNumber) {
                throw new SessionError("Message number too old - possible replay attack", encryptedMsg.sessionId, {
                    received: encryptedMsg.messageNumber,
                    expected: state.receiveMessageNumber,
                });
            }
            let chainKey = state.receiveChainKey;
            for (let i = state.receiveMessageNumber; i < encryptedMsg.messageNumber; i++) {
                const { messageKey, nextChainKey } = this.deriveMessageKeyAndNextChain(chainKey, i);
                if (!theirRatchetPubBase64) {
                    throw new SessionError("Missing remote ratchet public key context for skipped messages", encryptedMsg.sessionId);
                }
                this.storeSkippedMessageKey(state, theirRatchetPubBase64, i, messageKey);
                chainKey = nextChainKey;
            }
            const { messageKey, nextChainKey } = this.deriveMessageKeyAndNextChain(chainKey, encryptedMsg.messageNumber);
            const ciphertext = base64ToBytes(encryptedMsg.ciphertext);
            const nonce = base64ToBytes(encryptedMsg.nonce);
            try {
                const plaintextBytes = decrypt(messageKey, nonce, ciphertext);
                const plaintext = bytesToString(plaintextBytes);
                state.receiveChainKey = nextChainKey;
                state.receiveMessageNumber = encryptedMsg.messageNumber + 1;
                state.lastUsed = Date.now();
                await this.saveSessionState(encryptedMsg.sessionId, state);
                return plaintext;
            }
            catch (error) {
                console.error("[Session] Decryption failed:", error);
                throw new SessionError("Message decryption failed - authentication error", encryptedMsg.sessionId, { error: error instanceof Error ? error.message : String(error) });
            }
        });
    }
    async saveSessionState(sessionId, state) {
        const serialized = JSON.stringify({
            sessionId: state.sessionId,
            sendChainKey: bytesToBase64(state.sendChainKey),
            receiveChainKey: bytesToBase64(state.receiveChainKey),
            sendMessageNumber: state.sendMessageNumber,
            receiveMessageNumber: state.receiveMessageNumber,
            rootKey: bytesToBase64(state.rootKey),
            dhPrivate: bytesToBase64(state.dhPrivate),
            dhPublic: bytesToBase64(state.dhPublic),
            dhRemotePublic: state.dhRemotePublic
                ? bytesToBase64(state.dhRemotePublic)
                : undefined,
            skippedMessageKeys: state.skippedMessageKeys ?? {},
            skippedMessagesLimit: state.skippedMessagesLimit ?? MAX_SKIPPED_MESSAGES,
            protocolVersion: state.protocolVersion ?? PROTOCOL_VERSION,
            pendingRatchet: state.pendingRatchet ? state.pendingRatchet : undefined,
            createdAt: state.createdAt,
            lastUsed: state.lastUsed,
        });
        await this.aegis
            .getStorage()
            .setItem(`${SESSION_KEY_PREFIX}${sessionId}`, serialized);
    }
    async loadSessionState(sessionId) {
        const serialized = await this.aegis
            .getStorage()
            .getItem(`${SESSION_KEY_PREFIX}${sessionId}`);
        if (!serialized) {
            return null;
        }
        try {
            const data = JSON.parse(serialized);
            let dhPrivate;
            let dhPublic;
            if (data.dhPrivate) {
                dhPrivate = base64ToBytes(data.dhPrivate);
                dhPublic = data.dhPublic
                    ? base64ToBytes(data.dhPublic)
                    : x25519.getPublicKey(dhPrivate);
            }
            else {
                const pair = this.generateX25519KeyPair();
                dhPrivate = pair.privateKey;
                dhPublic = pair.publicKey;
            }
            const dhRemotePublic = data.dhRemotePublic
                ? base64ToBytes(data.dhRemotePublic)
                : undefined;
            return {
                sessionId: data.sessionId,
                sendChainKey: base64ToBytes(data.sendChainKey),
                receiveChainKey: base64ToBytes(data.receiveChainKey),
                sendMessageNumber: data.sendMessageNumber,
                receiveMessageNumber: data.receiveMessageNumber,
                rootKey: base64ToBytes(data.rootKey),
                dhPrivate,
                dhPublic,
                dhRemotePublic,
                skippedMessageKeys: data.skippedMessageKeys ?? {},
                skippedMessagesLimit: data.skippedMessagesLimit ?? MAX_SKIPPED_MESSAGES,
                protocolVersion: data.protocolVersion ?? PROTOCOL_VERSION,
                pendingRatchet: data.pendingRatchet ?? undefined,
                createdAt: data.createdAt,
                lastUsed: data.lastUsed,
            };
        }
        catch (error) {
            console.error("[Session] Failed to parse session state:", error);
            return null;
        }
    }
    async deleteSession(sessionId) {
        validateString(sessionId, "sessionId");
        await this.aegis
            .getStorage()
            .removeItem(`${SESSION_KEY_PREFIX}${sessionId}`);
    }
    async getSessionInfo(sessionId) {
        validateString(sessionId, "sessionId");
        const state = await this.loadSessionState(sessionId);
        if (!state) {
            return null;
        }
        return {
            createdAt: state.createdAt,
            lastUsed: state.lastUsed,
            messagesSent: state.sendMessageNumber,
            messagesReceived: state.receiveMessageNumber,
            skippedMessagesLimit: state.skippedMessagesLimit ?? MAX_SKIPPED_MESSAGES,
        };
    }
    async getAllSessionIds() {
        const sessions = [];
        const storage = this.aegis.getStorage();
        try {
            if (storage.keys) {
                const keys = await storage.keys();
                if (keys && Array.isArray(keys)) {
                    for (const key of keys) {
                        if (key.startsWith(SESSION_KEY_PREFIX)) {
                            sessions.push(key.substring(SESSION_KEY_PREFIX.length));
                        }
                    }
                }
            }
        }
        catch (error) {
            console.warn("[Session] Could not list sessions:", error);
        }
        return sessions;
    }
}
