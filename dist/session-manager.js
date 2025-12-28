import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { Logger } from "./logger.js";
import { ERRORS } from "./constants.js";
import { SessionKeyExchange } from "./session.js";
import { validatePublicBundle } from "./utils.js";
export class SessionManager {
    constructor(storage) {
        Object.defineProperty(this, "storage", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.storage = storage;
    }
    async createSession(identity, peerBundle) {
        try {
            Logger.log("Session", "Creating new session as initiator");
            validatePublicBundle(peerBundle);
            const isValid = ml_dsa65.verify(peerBundle.preKey.signature, peerBundle.preKey.key, peerBundle.dsaPublicKey);
            if (!isValid) {
                throw new Error(ERRORS.INVALID_PREKEY_SIGNATURE);
            }
            const { sessionId, rootKey, chainKey, ciphertext, confirmationMac } = SessionKeyExchange.createInitiatorSession(identity, peerBundle);
            const ratchetKeyPair = ml_kem768.keygen();
            const session = {
                sessionId,
                peerUserId: peerBundle.userId,
                peerDsaPublicKey: peerBundle.dsaPublicKey,
                rootKey,
                currentRatchetKeyPair: ratchetKeyPair,
                peerRatchetPublicKey: null,
                sendingChain: {
                    chainKey,
                    messageNumber: 0,
                },
                receivingChain: null,
                previousSendingChainLength: 0,
                skippedMessageKeys: new Map(),
                highestReceivedMessageNumber: -1,
                maxSkippedMessages: 100,
                createdAt: Date.now(),
                lastUsed: Date.now(),
                isInitiator: true,
                ratchetCount: 0,
                state: "CREATED",
                confirmed: false,
                confirmationMac,
                // Simple replay protection
                receivedMessageIds: new Set(),
                replayWindowSize: 100,
                lastProcessedTimestamp: Date.now(),
            };
            await this.storage.saveSession(sessionId, session);
            Logger.log("Session", "Session created successfully as initiator", {
                sessionId: sessionId.substring(0, 16) + "...",
            });
            return { sessionId, ciphertext, confirmationMac };
        }
        catch (error) {
            Logger.error("Session", "Failed to create session", error);
            throw error;
        }
    }
    async createResponderSession(identity, peerBundle, ciphertext, initiatorConfirmationMac) {
        try {
            Logger.log("Session", "Creating session as responder");
            validatePublicBundle(peerBundle);
            const isValidSignature = ml_dsa65.verify(peerBundle.preKey.signature, peerBundle.preKey.key, peerBundle.dsaPublicKey);
            if (!isValidSignature) {
                throw new Error(ERRORS.INVALID_PREKEY_SIGNATURE);
            }
            const { sessionId, rootKey, chainKey, confirmationMac, isValid } = SessionKeyExchange.createResponderSession(identity, peerBundle, ciphertext, initiatorConfirmationMac);
            if (!isValid && initiatorConfirmationMac) {
                throw new Error(ERRORS.KEY_CONFIRMATION_FAILED);
            }
            const ratchetKeyPair = ml_kem768.keygen();
            const session = {
                sessionId,
                peerUserId: peerBundle.userId,
                peerDsaPublicKey: peerBundle.dsaPublicKey,
                rootKey,
                currentRatchetKeyPair: ratchetKeyPair,
                peerRatchetPublicKey: null,
                sendingChain: {
                    chainKey,
                    messageNumber: 0,
                },
                receivingChain: null,
                previousSendingChainLength: 0,
                skippedMessageKeys: new Map(),
                highestReceivedMessageNumber: -1,
                maxSkippedMessages: 100,
                createdAt: Date.now(),
                lastUsed: Date.now(),
                isInitiator: false,
                ratchetCount: 0,
                state: "CREATED",
                confirmed: isValid && initiatorConfirmationMac !== undefined,
                confirmationMac,
                // Simple replay protection
                receivedMessageIds: new Set(),
                replayWindowSize: 100,
                lastProcessedTimestamp: Date.now(),
            };
            await this.storage.saveSession(sessionId, session);
            Logger.log("Session", "Session created as responder", {
                sessionId: sessionId.substring(0, 16) + "...",
                keyConfirmed: session.confirmed,
            });
            return { sessionId, confirmationMac, isValid };
        }
        catch (error) {
            Logger.error("Session", "Failed to create responder session", error);
            throw error;
        }
    }
    async confirmSession(sessionId, responderConfirmationMac) {
        try {
            Logger.log("Session", "Confirming session keys");
            const session = await this.storage.getSession(sessionId);
            if (!session)
                throw new Error(ERRORS.SESSION_NOT_FOUND);
            if (!session.sendingChain) {
                throw new Error("No sending chain available");
            }
            const isValid = SessionKeyExchange.verifyKeyConfirmation(sessionId, session.rootKey, session.sendingChain.chainKey, responderConfirmationMac);
            if (isValid) {
                session.confirmed = true;
                session.state = "KEY_CONFIRMED";
                await this.storage.saveSession(sessionId, session);
                Logger.log("Session", "Session keys confirmed successfully");
            }
            else {
                session.state = "ERROR";
                await this.storage.saveSession(sessionId, session);
                Logger.warn("Session", "Key confirmation failed");
            }
            return isValid;
        }
        catch (error) {
            Logger.error("Session", "Failed to confirm session", error);
            throw error;
        }
    }
    async getSessions() {
        const sessionIds = await this.storage.listSessions();
        const sessions = [];
        for (const sessionId of sessionIds) {
            const session = await this.storage.getSession(sessionId);
            if (session) {
                sessions.push(session);
            }
        }
        return sessions;
    }
    async cleanupOldSessions(maxAge) {
        const sessions = await this.getSessions();
        const cutoff = Date.now() - (maxAge || 30 * 24 * 60 * 60 * 1000); // Default 30 days
        for (const session of sessions) {
            if (session.lastUsed < cutoff) {
                await this.storage.deleteSession(session.sessionId);
                Logger.log("Cleanup", "Removed old session", {
                    sessionId: session.sessionId.substring(0, 16) + "...",
                    age: Math.round((Date.now() - session.lastUsed) / (1000 * 60 * 60 * 24)) + " days",
                });
            }
        }
    }
}
