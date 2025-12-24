// group.ts
import { generateSenderKey, encryptGroupMessage as encryptHashRatchet, decryptGroupMessage as decryptHashRatchet, } from "./sender-keys";
import { GroupError, } from "./types";
import { bytesToBase64, base64ToBytes } from "./crypto";
import { validateSenderKeyDistributionMessage, validateSenderKeyMessage, validateString, } from "./validator";
const GROUP_STORAGE_PREFIX = "aegis_group_";
const MAX_SEEN_SEQUENCES = 100;
export class GroupSessionManager {
    constructor(aegisInstance) {
        Object.defineProperty(this, "aegis", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.aegis = aegisInstance;
        if (!aegisInstance.isInitialized()) {
            throw new GroupError("Aegis instance must be initialized before creating GroupSessionManager");
        }
    }
    async createGroup(groupId, adminUserId, initialMembers = []) {
        validateString(groupId, "groupId");
        validateString(adminUserId, "adminUserId");
        const senderKey = generateSenderKey();
        const participants = {};
        for (const member of initialMembers) {
            if (member !== adminUserId) {
                participants[member] = {
                    currentChainKey: "",
                    lastSequence: -1,
                    seenSequences: [],
                    addedAt: Date.now(),
                };
            }
        }
        const data = {
            groupId,
            mySenderKey: {
                chainKey: bytesToBase64(senderKey.chainKey),
                signatureKey: bytesToBase64(senderKey.signatureKey),
                generation: senderKey.generation,
                sequence: senderKey.sequence,
            },
            participants,
            adminUserId,
            version: 1,
            removedParticipants: [],
            keyRotationLog: [
                {
                    version: 1,
                    timestamp: Date.now(),
                    initiator: adminUserId,
                    reason: "group_creation",
                },
            ],
        };
        const session = new GroupSession(this.aegis, data);
        await session.save();
        return session;
    }
    async loadGroup(groupId) {
        validateString(groupId, "groupId");
        const key = `${GROUP_STORAGE_PREFIX}${groupId}`;
        const stored = await this.aegis.getStorage().getItem(key);
        if (!stored) {
            return null;
        }
        try {
            const data = JSON.parse(stored);
            if (!data.groupId || !data.adminUserId || !data.mySenderKey) {
                throw new GroupError("Invalid group session data", groupId);
            }
            return new GroupSession(this.aegis, data);
        }
        catch (error) {
            console.error(`[Group] Failed to parse group session data for ${groupId}:`, error);
            return null;
        }
    }
    async deleteGroup(groupId) {
        validateString(groupId, "groupId");
        await this.aegis
            .getStorage()
            .removeItem(`${GROUP_STORAGE_PREFIX}${groupId}`);
    }
    async listUserGroups() {
        const groups = [];
        const storage = this.aegis.getStorage();
        try {
            if (storage.keys) {
                const keys = await storage.keys();
                if (keys && Array.isArray(keys)) {
                    for (const key of keys) {
                        if (key.startsWith(GROUP_STORAGE_PREFIX)) {
                            groups.push(key.substring(GROUP_STORAGE_PREFIX.length));
                        }
                    }
                }
            }
        }
        catch (error) {
            console.warn("[Group] Could not list groups:", error);
        }
        return groups;
    }
}
export class GroupSession {
    constructor(aegisInstance, data) {
        Object.defineProperty(this, "aegis", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "data", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.aegis = aegisInstance;
        this.data = data;
    }
    getGroupId() {
        return this.data.groupId;
    }
    getAdminUserId() {
        return this.data.adminUserId;
    }
    getVersion() {
        return this.data.version;
    }
    getParticipants() {
        return Object.keys(this.data.participants);
    }
    getRemovedParticipants() {
        return [...this.data.removedParticipants];
    }
    isParticipant(userId) {
        return this.data.participants[userId] !== undefined;
    }
    isAdmin(userId) {
        return userId === this.data.adminUserId;
    }
    wasRemoved(userId) {
        return this.data.removedParticipants.includes(userId);
    }
    createDistributionMessage(senderId) {
        validateString(senderId, "senderId");
        if (!this.isParticipant(senderId) && !this.isAdmin(senderId)) {
            throw new GroupError(`User ${senderId} is not a participant in this group`, this.data.groupId);
        }
        return {
            type: "distribution",
            senderId,
            groupId: this.data.groupId,
            chainKey: this.data.mySenderKey.chainKey,
            signatureKey: this.data.mySenderKey.signatureKey,
            generation: this.data.mySenderKey.generation,
        };
    }
    async processDistributionMessage(payload) {
        validateSenderKeyDistributionMessage(payload);
        if (payload.groupId !== this.data.groupId) {
            throw new GroupError(`Distribution message group ID mismatch: ${payload.groupId} != ${this.data.groupId}`, this.data.groupId);
        }
        if (this.wasRemoved(payload.senderId)) {
            throw new GroupError(`Sender ${payload.senderId} was removed from the group`, this.data.groupId);
        }
        if (!this.data.participants[payload.senderId]) {
            this.data.participants[payload.senderId] = {
                currentChainKey: "",
                lastSequence: -1,
                seenSequences: [],
                addedAt: Date.now(),
            };
        }
        this.data.participants[payload.senderId].currentChainKey = payload.chainKey;
        this.data.participants[payload.senderId].lastSequence = -1;
        this.data.participants[payload.senderId].seenSequences = [];
        await this.save();
    }
    async encrypt(plaintext, senderId) {
        validateString(plaintext, "plaintext");
        validateString(senderId, "senderId");
        if (!this.isParticipant(senderId) && !this.isAdmin(senderId)) {
            throw new GroupError(`User ${senderId} is not a participant in this group`, this.data.groupId);
        }
        const chainKeyBytes = base64ToBytes(this.data.mySenderKey.chainKey);
        const signatureKeyBytes = base64ToBytes(this.data.mySenderKey.signatureKey);
        const senderKeyState = {
            chainKey: chainKeyBytes,
            signatureKey: signatureKeyBytes,
            generation: this.data.mySenderKey.generation,
            sequence: this.data.mySenderKey.sequence,
        };
        const msg = encryptHashRatchet(senderKeyState, this.data.groupId, senderId, plaintext);
        this.data.mySenderKey.chainKey = bytesToBase64(senderKeyState.chainKey);
        this.data.mySenderKey.sequence = senderKeyState.sequence;
        await this.save();
        return msg;
    }
    async decrypt(msg) {
        validateSenderKeyMessage(msg);
        if (msg.groupId !== this.data.groupId) {
            throw new GroupError(`Message group ID mismatch: ${msg.groupId} != ${this.data.groupId}`, this.data.groupId);
        }
        if (this.wasRemoved(msg.senderId)) {
            throw new GroupError(`Sender ${msg.senderId} was removed from the group`, this.data.groupId);
        }
        const participant = this.data.participants[msg.senderId];
        if (!participant) {
            throw new GroupError(`No sender key found for ${msg.senderId}. Did you receive a distribution message?`, this.data.groupId);
        }
        if (participant.lastSequence !== undefined &&
            msg.sequence <= participant.lastSequence) {
            if (participant.seenSequences &&
                participant.seenSequences.includes(msg.sequence)) {
                throw new GroupError(`Possible replay attack: duplicate sequence ${msg.sequence} from ${msg.senderId}`, this.data.groupId);
            }
            if (participant.lastSequence - msg.sequence > 50) {
                throw new GroupError(`Message sequence too far in the past: ${msg.sequence}, last seen: ${participant.lastSequence}`, this.data.groupId);
            }
        }
        const currentChainKey = base64ToBytes(participant.currentChainKey);
        const { plaintext, nextChainKey } = decryptHashRatchet(currentChainKey, msg, participant.lastSequence);
        participant.currentChainKey = bytesToBase64(nextChainKey);
        if (participant.lastSequence === undefined ||
            msg.sequence > participant.lastSequence) {
            participant.lastSequence = msg.sequence;
        }
        participant.seenSequences = participant.seenSequences || [];
        participant.seenSequences.push(msg.sequence);
        if (participant.seenSequences.length > MAX_SEEN_SEQUENCES) {
            participant.seenSequences =
                participant.seenSequences.slice(-MAX_SEEN_SEQUENCES);
        }
        await this.save();
        return plaintext;
    }
    async addParticipant(userId, initiatorUserId) {
        validateString(userId, "userId");
        validateString(initiatorUserId, "initiatorUserId");
        if (!this.isAdmin(initiatorUserId)) {
            throw new GroupError("Only group admin can add participants", this.data.groupId);
        }
        if (this.isParticipant(userId)) {
            throw new GroupError(`Participant ${userId} is already in the group`, this.data.groupId);
        }
        this.data.removedParticipants = this.data.removedParticipants.filter((id) => id !== userId);
        this.data.participants[userId] = {
            currentChainKey: "",
            lastSequence: -1,
            seenSequences: [],
            addedAt: Date.now(),
        };
        await this.save();
        return this.createDistributionMessage(initiatorUserId);
    }
    async removeParticipant(userId, initiatorUserId, reason = "removed_by_admin") {
        validateString(userId, "userId");
        validateString(initiatorUserId, "initiatorUserId");
        if (!this.isAdmin(initiatorUserId)) {
            throw new GroupError("Only group admin can remove participants", this.data.groupId);
        }
        if (userId === initiatorUserId) {
            throw new GroupError("Cannot remove yourself from group", this.data.groupId);
        }
        if (!this.isParticipant(userId)) {
            throw new GroupError(`Participant ${userId} not found in group`, this.data.groupId);
        }
        if (!this.data.removedParticipants.includes(userId)) {
            this.data.removedParticipants.push(userId);
        }
        delete this.data.participants[userId];
        const distributionMessages = await this.rotateKeys(initiatorUserId, `participant_removal:${userId}:${reason}`);
        await this.save();
        return distributionMessages;
    }
    async rotateKeys(initiatorUserId, reason = "manual_rotation") {
        validateString(initiatorUserId, "initiatorUserId");
        if (!this.isAdmin(initiatorUserId)) {
            throw new GroupError("Only group admin can rotate keys", this.data.groupId);
        }
        const newSenderKey = generateSenderKey();
        this.data.mySenderKey = {
            chainKey: bytesToBase64(newSenderKey.chainKey),
            signatureKey: bytesToBase64(newSenderKey.signatureKey),
            generation: newSenderKey.generation,
            sequence: newSenderKey.sequence,
        };
        this.data.version += 1;
        this.data.keyRotationLog.push({
            version: this.data.version,
            timestamp: Date.now(),
            initiator: initiatorUserId,
            reason,
        });
        const distributionMessages = [];
        for (const [participantId, participantData] of Object.entries(this.data.participants)) {
            if (this.data.removedParticipants.includes(participantId)) {
                continue;
            }
            const distributionMsg = {
                type: "distribution",
                senderId: this.aegis.getUserId() || "unknown",
                groupId: this.data.groupId,
                chainKey: this.data.mySenderKey.chainKey,
                signatureKey: this.data.mySenderKey.signatureKey,
                generation: this.data.mySenderKey.generation,
            };
            distributionMessages.push(distributionMsg);
            participantData.currentChainKey = this.data.mySenderKey.chainKey;
            participantData.lastSequence = -1;
            participantData.seenSequences = [];
        }
        await this.save();
        return distributionMessages;
    }
    getKeyRotationLog() {
        return [...this.data.keyRotationLog];
    }
    getGroupInfo() {
        const lastRotation = this.data.keyRotationLog.length > 0
            ? this.data.keyRotationLog[this.data.keyRotationLog.length - 1]
                .timestamp
            : null;
        return {
            groupId: this.data.groupId,
            adminUserId: this.data.adminUserId,
            version: this.data.version,
            participantCount: Object.keys(this.data.participants).length,
            removedParticipantCount: this.data.removedParticipants.length,
            lastKeyRotation: lastRotation,
        };
    }
    async save() {
        await this.aegis
            .getStorage()
            .setItem(`${GROUP_STORAGE_PREFIX}${this.data.groupId}`, JSON.stringify(this.data));
    }
    async delete() {
        await this.aegis
            .getStorage()
            .removeItem(`${GROUP_STORAGE_PREFIX}${this.data.groupId}`);
    }
}
