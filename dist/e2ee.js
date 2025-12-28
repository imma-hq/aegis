import { Logger } from "./logger.js";
import { IdentityManager } from "./identity-manager.js";
import { SessionManager } from "./session-manager.js";
import { CryptoManager } from "./crypto-manager.js";
import { RatchetManager } from "./ratchet-manager.js";
import { ReplayProtection } from "./replay-protection.js";
import { GroupManager } from "./group-manager.js";
export class E2EE {
    constructor(storage) {
        Object.defineProperty(this, "identityManager", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "sessionManager", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "cryptoManager", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "ratchetManager", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "replayProtection", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "groupManager", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "storage", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.storage = storage;
        this.identityManager = new IdentityManager(storage);
        this.sessionManager = new SessionManager(storage);
        this.cryptoManager = new CryptoManager(storage);
        this.ratchetManager = new RatchetManager();
        this.replayProtection = new ReplayProtection();
        this.groupManager = new GroupManager(storage);
        Logger.log("E2EE", "Initialized with storage adapter");
    }
    // Identity Management
    async createIdentity() {
        return this.identityManager.createIdentity();
    }
    async getIdentity() {
        return this.identityManager.getIdentity();
    }
    async getPublicBundle() {
        return this.identityManager.getPublicBundle();
    }
    async rotateIdentity() {
        return this.identityManager.rotateIdentity();
    }
    // Session Management
    async createSession(peerBundle) {
        const identity = await this.identityManager.getIdentity();
        return this.sessionManager.createSession(identity, peerBundle);
    }
    async createResponderSession(peerBundle, ciphertext, initiatorConfirmationMac) {
        const identity = await this.identityManager.getIdentity();
        return this.sessionManager.createResponderSession(identity, peerBundle, ciphertext, initiatorConfirmationMac);
    }
    async confirmSession(sessionId, responderConfirmationMac) {
        return this.sessionManager.confirmSession(sessionId, responderConfirmationMac);
    }
    async getSessions() {
        return this.sessionManager.getSessions();
    }
    async cleanupOldSessions(maxAge) {
        return this.sessionManager.cleanupOldSessions(maxAge);
    }
    // Message Encryption/Decryption
    async encryptMessage(sessionId, plaintext) {
        // Check if session exists first to throw SESSION_NOT_FOUND before IDENTITY_NOT_FOUND
        const session = await this.storage.getSession(sessionId);
        if (!session)
            throw new Error("Session not found");
        const identity = await this.identityManager.getIdentity();
        const shouldRatchet = (session) => {
            return this.ratchetManager.shouldPerformSendingRatchet(session);
        };
        const performSendingRatchet = (session) => {
            return this.ratchetManager.performSendingRatchet(session);
        };
        const updateSessionState = async (sessionId, session) => {
            await this.storage.saveSession(sessionId, session);
        };
        return this.cryptoManager.encryptMessage(sessionId, plaintext, identity, shouldRatchet, performSendingRatchet, updateSessionState);
    }
    async decryptMessage(sessionId, encrypted) {
        // Check if session exists first to throw SESSION_NOT_FOUND before other errors
        const session = await this.storage.getSession(sessionId);
        if (!session)
            throw new Error("Session not found");
        const needsReceivingRatchet = (session, header) => {
            return this.ratchetManager.needsReceivingRatchet(session, header);
        };
        const performReceivingRatchet = (session, kemCiphertext) => {
            return this.ratchetManager.performReceivingRatchet(session, kemCiphertext);
        };
        const getSkippedKeyId = (ratchetPublicKey, messageNumber) => {
            return this.replayProtection.getSkippedKeyId(ratchetPublicKey, messageNumber);
        };
        const storeReceivedMessageId = (session, messageId) => {
            this.replayProtection.storeReceivedMessageId(session, messageId);
        };
        const cleanupSkippedKeys = (session) => {
            this.replayProtection.cleanupSkippedKeys(session);
        };
        const updateSessionState = async (sessionId, session) => {
            await this.storage.saveSession(sessionId, session);
        };
        return this.cryptoManager.decryptMessage(sessionId, encrypted, needsReceivingRatchet, performReceivingRatchet, getSkippedKeyId, storeReceivedMessageId, cleanupSkippedKeys, updateSessionState);
    }
    // Ratchet Management
    async triggerRatchet(sessionId) {
        const session = await this.storage.getSession(sessionId);
        if (!session)
            throw new Error("Session not found");
        const updatedSession = await this.ratchetManager.triggerRatchet(sessionId, session);
        await this.storage.saveSession(sessionId, updatedSession);
    }
    // Replay Protection
    async getReplayProtectionStatus(sessionId) {
        const session = await this.storage.getSession(sessionId);
        if (!session)
            throw new Error("Session not found");
        return this.replayProtection.getReplayProtectionStatus(sessionId, session);
    }
    // Get confirmation MAC for responder to send back to initiator
    async getConfirmationMac(sessionId) {
        const session = await this.storage.getSession(sessionId);
        if (!session || !session.confirmationMac) {
            return null;
        }
        return session.confirmationMac;
    }
    // Group Management
    async createGroup(name, members) {
        const identity = await this.identityManager.getIdentity();
        if (!identity)
            throw new Error("Identity not found");
        await this.groupManager.initialize(identity);
        return this.groupManager.createGroup(name, members);
    }
    async addGroupMember(groupId, userId, session) {
        const identity = await this.identityManager.getIdentity();
        if (!identity)
            throw new Error("Identity not found");
        await this.groupManager.initialize(identity);
        return this.groupManager.addMember(groupId, userId, session);
    }
    async removeGroupMember(groupId, userId) {
        const identity = await this.identityManager.getIdentity();
        if (!identity)
            throw new Error("Identity not found");
        await this.groupManager.initialize(identity);
        return this.groupManager.removeMember(groupId, userId);
    }
    async updateGroupKey(groupId) {
        const identity = await this.identityManager.getIdentity();
        if (!identity)
            throw new Error("Identity not found");
        await this.groupManager.initialize(identity);
        return this.groupManager.updateGroupKey(groupId);
    }
    async encryptGroupMessage(groupId, message) {
        const identity = await this.identityManager.getIdentity();
        if (!identity)
            throw new Error("Identity not found");
        await this.groupManager.initialize(identity);
        return this.groupManager.encryptMessage(groupId, message);
    }
    async decryptGroupMessage(groupId, encrypted) {
        const identity = await this.identityManager.getIdentity();
        if (!identity)
            throw new Error("Identity not found");
        await this.groupManager.initialize(identity);
        return this.groupManager.decryptMessage(groupId, encrypted);
    }
    async getGroup(groupId) {
        return this.groupManager.getGroup(groupId);
    }
    async getGroups() {
        return this.groupManager.getGroups();
    }
}
