import { Logger } from "./logger";
import { IdentityManager } from "./identity-manager";
import { SessionManager } from "./session-manager";
import { CryptoManager } from "./crypto-manager";
import { RatchetManager } from "./ratchet-manager";
import { ReplayProtection } from "./replay-protection";
import { GroupManager } from "./group-manager";
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
    async encryptMessage(sessionId, plaintext) {
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
        const applyPendingRatchet = (session) => {
            return this.ratchetManager.applyPendingRatchet(session);
        };
        const getDecryptionChainForRatchetMessage = (session) => {
            return this.ratchetManager.getDecryptionChainForRatchetMessage(session);
        };
        const updateSessionState = async (sessionId, session) => {
            await this.storage.saveSession(sessionId, session);
        };
        return this.cryptoManager.decryptMessage(sessionId, encrypted, needsReceivingRatchet, performReceivingRatchet, getSkippedKeyId, storeReceivedMessageId, cleanupSkippedKeys, applyPendingRatchet, getDecryptionChainForRatchetMessage, updateSessionState);
    }
    async triggerRatchet(sessionId) {
        const session = await this.storage.getSession(sessionId);
        if (!session)
            throw new Error("Session not found");
        const updatedSession = await this.ratchetManager.triggerRatchet(sessionId, session);
        await this.storage.saveSession(sessionId, updatedSession);
    }
    async getReplayProtectionStatus(sessionId) {
        const session = await this.storage.getSession(sessionId);
        if (!session)
            throw new Error("Session not found");
        return this.replayProtection.getReplayProtectionStatus(sessionId, session);
    }
    async getConfirmationMac(sessionId) {
        const session = await this.storage.getSession(sessionId);
        if (!session || !session.confirmationMac) {
            return null;
        }
        return session.confirmationMac;
    }
    getStorage() {
        return this.storage;
    }
    async createGroup(name, members, memberKemPublicKeys, memberDsaPublicKeys) {
        const identity = await this.identityManager.getIdentity();
        if (!identity)
            throw new Error("Identity not found");
        await this.groupManager.initialize(identity);
        return this.groupManager.createGroup(name, members, memberKemPublicKeys, memberDsaPublicKeys);
    }
    async addGroupMember(groupId, userId, session, userPublicKey) {
        const identity = await this.identityManager.getIdentity();
        if (!identity)
            throw new Error("Identity not found");
        await this.groupManager.initialize(identity);
        return this.groupManager.addMember(groupId, userId, session, userPublicKey);
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
