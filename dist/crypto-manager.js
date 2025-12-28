import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/post-quantum/utils.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Logger } from "./logger.js";
import { ERRORS, MAX_MESSAGE_AGE } from "./constants.js";
import { serializeHeader } from "./utils.js";
import { KemRatchet } from "./ratchet.js";
export class CryptoManager {
    constructor(storage) {
        Object.defineProperty(this, "storage", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.storage = storage;
    }
    async encryptMessage(sessionId, plaintext, identity, shouldRatchet, performSendingRatchet, updateSessionState) {
        try {
            Logger.log("Encrypt", "Encrypting message");
            const session = await this.storage.getSession(sessionId);
            if (!session)
                throw new Error(ERRORS.SESSION_NOT_FOUND);
            if (!session.confirmed && session.state !== "CREATED") {
                throw new Error(ERRORS.SESSION_NOT_CONFIRMED);
            }
            const plaintextBytes = typeof plaintext === "string" ? utf8ToBytes(plaintext) : plaintext;
            // Check if we should perform a sending KEM ratchet
            const shouldRatchetResult = shouldRatchet(session);
            let kemCiphertext;
            let updatedSession = session;
            if (shouldRatchetResult) {
                Logger.log("Ratchet", "Performing sending KEM ratchet before encryption");
                if (!session.peerRatchetPublicKey) {
                    throw new Error("No peer ratchet public key available for ratchet");
                }
                const ratchetResult = performSendingRatchet(session);
                updatedSession = ratchetResult.session;
                kemCiphertext = ratchetResult.kemCiphertext;
                Logger.log("Ratchet", "Sent KEM ratchet", {
                    ratchetCount: updatedSession.ratchetCount,
                    newKeyHash: bytesToHex(updatedSession.currentRatchetKeyPair.publicKey).substring(0, 16) + "...",
                });
            }
            else if (session.state === "RATCHET_PENDING" &&
                session.pendingRatchetCiphertext) {
                // If we previously triggered a ratchet manually, use the pending ciphertext
                kemCiphertext = session.pendingRatchetCiphertext;
                Logger.log("Ratchet", "Using pending ratchet ciphertext", {
                    ratchetCount: session.ratchetCount,
                });
            }
            if (!updatedSession.sendingChain) {
                throw new Error("No sending chain available");
            }
            // Symmetric ratchet for this message
            const { messageKey, newChain } = KemRatchet.symmetricRatchet(updatedSession.sendingChain);
            // Encrypt
            const nonce = randomBytes(24);
            const cipher = xchacha20poly1305(messageKey, nonce);
            const ciphertext = cipher.encrypt(plaintextBytes);
            const fullciphertext = concatBytes(nonce, ciphertext);
            // Create header with timestamp for replay protection
            const header = {
                messageId: bytesToHex(blake3(fullciphertext, { dkLen: 32 })),
                ratchetPublicKey: updatedSession.currentRatchetKeyPair.publicKey,
                messageNumber: updatedSession.sendingChain.messageNumber,
                previousChainLength: updatedSession.previousSendingChainLength,
                kemCiphertext: kemCiphertext,
                isRatchetMessage: shouldRatchetResult || (kemCiphertext ? true : false), // Mark as ratchet message if we have a ciphertext
                timestamp: Date.now(), // Timestamp for replay protection
            };
            // Include confirmation MAC if this is the first message from initiator
            let confirmationMac;
            if (updatedSession.state === "CREATED" && updatedSession.isInitiator) {
                confirmationMac = updatedSession.confirmationMac;
                Logger.log("Session", "Including key confirmation MAC in first message");
            }
            // Sign
            const headerBytes = serializeHeader(header);
            const messageToSign = concatBytes(headerBytes, fullciphertext);
            const signature = ml_dsa65.sign(messageToSign, identity.dsaKeyPair.secretKey);
            // Update session
            updatedSession.sendingChain = newChain;
            updatedSession.lastUsed = Date.now();
            if (updatedSession.state === "CREATED" && updatedSession.isInitiator) {
                updatedSession.state = "KEY_CONFIRMED";
            }
            // Update session state after ratchet message is sent
            if (updatedSession.state === "RATCHET_PENDING" && kemCiphertext) {
                updatedSession.state = "ACTIVE";
            }
            await updateSessionState(sessionId, updatedSession);
            Logger.log("Encrypt", "Message encrypted", {
                messageNumber: header.messageNumber,
                ratchetCount: updatedSession.ratchetCount,
                usedRatchetKey: shouldRatchetResult,
                state: updatedSession.state,
            });
            return {
                ciphertext: fullciphertext,
                header,
                signature,
                confirmationMac,
            };
        }
        catch (error) {
            Logger.error("Encrypt", "Failed to encrypt message", error);
            throw error;
        }
    }
    async decryptMessage(sessionId, encrypted, needsReceivingRatchet, performReceivingRatchet, getSkippedKeyId, storeReceivedMessageId, cleanupSkippedKeys, updateSessionState) {
        try {
            Logger.log("Decrypt", "Decrypting message");
            const session = await this.storage.getSession(sessionId);
            if (!session)
                throw new Error(ERRORS.SESSION_NOT_FOUND);
            // 1. Verify signature first
            const headerBytes = serializeHeader(encrypted.header);
            const messageToVerify = concatBytes(headerBytes, encrypted.ciphertext);
            const isValid = ml_dsa65.verify(encrypted.signature, messageToVerify, session.peerDsaPublicKey);
            if (!isValid) {
                throw new Error(ERRORS.INVALID_MESSAGE_SIGNATURE);
            }
            // 2. Check for duplicate message (Simple replay protection)
            if (session.receivedMessageIds.has(encrypted.header.messageId)) {
                Logger.warn("Replay", "Duplicate message detected", {
                    messageId: encrypted.header.messageId.substring(0, 16) + "...",
                });
                throw new Error(ERRORS.DUPLICATE_MESSAGE);
            }
            // 3. Check message freshness (Simple timestamp check)
            const now = Date.now();
            const messageAge = now - encrypted.header.timestamp;
            if (messageAge > MAX_MESSAGE_AGE) {
                Logger.warn("Replay", "Message too old", {
                    age: `${Math.round(messageAge / 1000)}s`,
                    maxAge: `${MAX_MESSAGE_AGE / 1000}s`,
                });
                throw new Error(ERRORS.MESSAGE_TOO_OLD_TIMESTAMP);
            }
            // Update last processed timestamp
            session.lastProcessedTimestamp = now;
            // Handle key confirmation if this is the first message from initiator
            if (encrypted.confirmationMac &&
                !session.isInitiator &&
                session.state === "CREATED") {
                Logger.log("Session", "Processing key confirmation from initiator");
                const isValidConfirmation = KemRatchet.verifyConfirmationMac(sessionId, session.rootKey, session.sendingChain.chainKey, encrypted.confirmationMac, false);
                if (isValidConfirmation) {
                    session.confirmed = true;
                    session.state = "KEY_CONFIRMED";
                    Logger.log("Session", "Key confirmation received and verified");
                }
                else {
                    session.state = "ERROR";
                    await updateSessionState(sessionId, session);
                    throw new Error(ERRORS.KEY_CONFIRMATION_FAILED);
                }
            }
            // Check if we need to perform receiving KEM ratchet
            const needsRatchet = needsReceivingRatchet(session, encrypted.header);
            if (needsRatchet && encrypted.header.kemCiphertext) {
                Logger.log("Ratchet", "Performing receiving KEM ratchet");
                if (!session.currentRatchetKeyPair?.secretKey) {
                    throw new Error("No current ratchet secret key available");
                }
                const updatedSession = performReceivingRatchet(session, encrypted.header.kemCiphertext);
                // Update session
                session.rootKey = updatedSession.rootKey;
                session.currentRatchetKeyPair = updatedSession.currentRatchetKeyPair;
                session.peerRatchetPublicKey = encrypted.header.ratchetPublicKey;
                session.previousSendingChainLength =
                    session.sendingChain?.messageNumber ?? 0;
                session.pendingRatchetCiphertext = undefined;
                // Reset chains with new keys
                session.sendingChain = updatedSession.sendingChain;
                session.receivingChain = updatedSession.receivingChain;
                session.ratchetCount++;
                session.state = "ACTIVE";
                Logger.log("Ratchet", "Received KEM ratchet", {
                    ratchetCount: session.ratchetCount,
                    peerKeyHash: bytesToHex(encrypted.header.ratchetPublicKey).substring(0, 16) +
                        "...",
                });
            }
            else if (needsRatchet && !encrypted.header.kemCiphertext) {
                throw new Error(ERRORS.RATCHET_CIPHERTEXT_MISSING);
            }
            // Store the peer's ratchet public key if this is first time we see it
            if (!session.peerRatchetPublicKey && encrypted.header.ratchetPublicKey) {
                session.peerRatchetPublicKey = encrypted.header.ratchetPublicKey;
                Logger.log("Session", "Stored peer ratchet public key", {
                    keyHash: bytesToHex(encrypted.header.ratchetPublicKey).substring(0, 16) +
                        "...",
                });
            }
            // Try skipped keys first (for out-of-order messages)
            const skippedKeyId = getSkippedKeyId(encrypted.header.ratchetPublicKey, encrypted.header.messageNumber);
            const skippedKey = session.skippedMessageKeys.get(skippedKeyId);
            if (skippedKey) {
                Logger.log("Decrypt", "Using skipped message key", {
                    messageNumber: encrypted.header.messageNumber,
                });
                const plaintext = this.decryptWithKey(encrypted.ciphertext, skippedKey.messageKey);
                // Store message ID after successful decryption
                storeReceivedMessageId(session, encrypted.header.messageId);
                session.skippedMessageKeys.delete(skippedKeyId);
                session.lastUsed = Date.now();
                await updateSessionState(sessionId, session);
                return { plaintext };
            }
            // Handle out-of-order messages by skipping ahead
            if (session.receivingChain &&
                encrypted.header.messageNumber > session.receivingChain.messageNumber) {
                const skipCount = encrypted.header.messageNumber - session.receivingChain.messageNumber;
                // Simple replay protection: reject messages too far in the future
                if (skipCount > session.maxSkippedMessages) {
                    throw new Error(`Cannot skip ${skipCount} messages, max is ${session.maxSkippedMessages}`);
                }
                Logger.log("Decrypt", "Skipping message keys", {
                    from: session.receivingChain.messageNumber,
                    to: encrypted.header.messageNumber,
                    count: skipCount,
                });
                const { skippedKeys, newChain } = KemRatchet.skipMessageKeys(session.receivingChain, encrypted.header.messageNumber, session.maxSkippedMessages);
                // Store skipped keys for potential future out-of-order messages
                for (const [msgNum, msgKey] of skippedKeys) {
                    const keyId = getSkippedKeyId(encrypted.header.ratchetPublicKey, msgNum);
                    session.skippedMessageKeys.set(keyId, {
                        messageKey: msgKey,
                        timestamp: Date.now(),
                    });
                }
                session.receivingChain = newChain;
            }
            // Decrypt current message
            if (!session.receivingChain) {
                // First message received - initialize receiving chain
                if (!session.sendingChain) {
                    throw new Error("No chain available for decryption");
                }
                session.receivingChain = {
                    chainKey: session.sendingChain.chainKey,
                    messageNumber: 0,
                };
            }
            const { messageKey, newChain } = KemRatchet.symmetricRatchet(session.receivingChain);
            const plaintext = this.decryptWithKey(encrypted.ciphertext, messageKey);
            // Update session state
            session.receivingChain = newChain;
            session.highestReceivedMessageNumber = Math.max(session.highestReceivedMessageNumber, encrypted.header.messageNumber);
            session.lastUsed = Date.now();
            // Store message ID after successful decryption
            storeReceivedMessageId(session, encrypted.header.messageId);
            // Cleanup old skipped keys
            cleanupSkippedKeys(session);
            // Check if we need to send confirmation response
            const needsConfirmation = !session.isInitiator &&
                encrypted.confirmationMac &&
                session.state === "KEY_CONFIRMED" &&
                !session.confirmed;
            if (needsConfirmation) {
                session.confirmed = true;
                Logger.log("Session", "Ready to send key confirmation response");
            }
            await updateSessionState(sessionId, session);
            Logger.log("Decrypt", "Message decrypted successfully", {
                messageNumber: encrypted.header.messageNumber,
                ratchetCount: session.ratchetCount,
                state: session.state,
            });
            return {
                plaintext,
                needsConfirmation: needsConfirmation,
            };
        }
        catch (error) {
            Logger.error("Decrypt", "Failed to decrypt message", error);
            throw error;
        }
    }
    decryptWithKey(ciphertext, messageKey) {
        const nonce = ciphertext.slice(0, 24);
        const encryptedData = ciphertext.slice(24);
        const cipher = xchacha20poly1305(messageKey, nonce);
        return cipher.decrypt(encryptedData);
    }
}
