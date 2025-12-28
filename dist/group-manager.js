import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/post-quantum/utils.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Logger } from "./logger.js";
import { MAX_MESSAGE_AGE } from "./constants.js";
export class GroupManager {
    constructor(storage) {
        Object.defineProperty(this, "storage", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "identity", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        this.storage = storage;
    }
    async initialize(identity) {
        this.identity = identity;
    }
    async createGroup(name, members) {
        if (!this.identity) {
            throw new Error("GroupManager not initialized with identity");
        }
        if (members.length < 2) {
            throw new Error("Group must have at least 2 members");
        }
        // Generate a random shared key for the group
        const sharedKey = randomBytes(32);
        // Create group ID based on name and members
        const groupId = "GROUP_" +
            bytesToHex(blake3(concatBytes(utf8ToBytes(name), ...members.map((m) => utf8ToBytes(String(m)))), { dkLen: 32 }));
        // Check if group already exists in storage
        const existingGroup = await this.storage.getSession(groupId);
        if (existingGroup) {
            throw new Error("Group already exists");
        }
        // Create member keys - encrypt the shared key for each member
        const memberKeys = new Map();
        const memberPublicKeys = new Map();
        // For now, we'll store the shared key directly for each member
        // In a real implementation, we'd encrypt it with each member's public key
        for (const memberId of members) {
            // In a real implementation, we'd encrypt the shared key with the member's public key
            // For now, we'll just store it (this is not secure but serves as a placeholder for the architecture)
            memberKeys.set(memberId, sharedKey);
            // In a real implementation, we'd need to fetch the member's public key
            // For now, we'll use our own public key as a placeholder
            memberPublicKeys.set(memberId, this.identity.dsaKeyPair.publicKey);
        }
        const group = {
            groupId,
            name,
            members,
            sharedKey,
            createdAt: Date.now(),
            lastUpdated: Date.now(),
            owner: this.identity.userId,
            memberKeys,
            memberPublicKeys,
        };
        // Store the group in the storage with a special format
        // We'll store it as a session with additional group-specific data
        await this.storage.saveSession(groupId, {
            sessionId: groupId,
            peerUserId: "GROUP", // Special marker for group sessions
            peerDsaPublicKey: this.identity.dsaKeyPair.publicKey,
            rootKey: group.sharedKey,
            currentRatchetKeyPair: null,
            peerRatchetPublicKey: null,
            sendingChain: null,
            receivingChain: null,
            previousSendingChainLength: 0,
            skippedMessageKeys: new Map(),
            highestReceivedMessageNumber: -1,
            maxSkippedMessages: 100,
            createdAt: group.createdAt,
            lastUsed: Date.now(),
            isInitiator: true,
            ratchetCount: 0,
            state: "ACTIVE",
            confirmed: true,
            // Store group-specific data in additional fields
            groupData: {
                name: group.name,
                members: group.members,
                owner: group.owner,
                memberKeys: Array.from(group.memberKeys.entries()),
                memberPublicKeys: Array.from(group.memberPublicKeys.entries()),
            },
            receivedMessageIds: new Set(),
            replayWindowSize: 100,
            lastProcessedTimestamp: Date.now(),
        });
        Logger.log("GroupManager", "Group created successfully", {
            groupId: groupId.substring(0, 16) + "...",
            name,
            membersCount: members.length,
        });
        return group;
    }
    async addMember(groupId, userId, _session) {
        if (!this.identity) {
            throw new Error("GroupManager not initialized with identity");
        }
        const group = await this.getGroup(groupId);
        if (!group) {
            throw new Error("Group not found");
        }
        // Only owner can add members
        if (group.owner !== this.identity.userId) {
            throw new Error("Only group owner can add members");
        }
        // Check if user is already a member
        if (group.members.includes(userId)) {
            throw new Error("User is already a member of this group");
        }
        // Add user to members list
        group.members.push(userId);
        group.lastUpdated = Date.now();
        // Update member keys for the new member
        // In a real implementation, we'd securely distribute the shared key to the new member
        group.memberKeys.set(userId, group.sharedKey);
        // Update member public keys - in a real implementation we'd get the user's actual public key
        // For now, we'll use our own public key as a placeholder
        group.memberPublicKeys.set(userId, this.identity.dsaKeyPair.publicKey);
        // Save updated group to storage
        await this.storage.saveSession(groupId, {
            sessionId: groupId,
            peerUserId: "GROUP", // Special marker for group sessions
            peerDsaPublicKey: this.identity.dsaKeyPair.publicKey,
            rootKey: group.sharedKey,
            currentRatchetKeyPair: null,
            peerRatchetPublicKey: null,
            sendingChain: null,
            receivingChain: null,
            previousSendingChainLength: 0,
            skippedMessageKeys: new Map(),
            highestReceivedMessageNumber: -1,
            maxSkippedMessages: 100,
            createdAt: group.createdAt,
            lastUsed: Date.now(),
            isInitiator: true,
            ratchetCount: 0,
            state: "ACTIVE",
            confirmed: true,
            // Store group-specific data in additional fields
            groupData: {
                name: group.name,
                members: group.members,
                owner: group.owner,
                memberKeys: Array.from(group.memberKeys.entries()),
                memberPublicKeys: Array.from(group.memberPublicKeys.entries()),
            },
            receivedMessageIds: new Set(),
            replayWindowSize: 100,
            lastProcessedTimestamp: Date.now(),
        });
        Logger.log("GroupManager", "Member added to group", {
            groupId: groupId.substring(0, 16) + "...",
            userId,
            membersCount: group.members.length,
        });
    }
    async removeMember(groupId, userId) {
        if (!this.identity) {
            throw new Error("GroupManager not initialized with identity");
        }
        const group = await this.getGroup(groupId);
        if (!group) {
            throw new Error("Group not found");
        }
        // Only owner can remove members
        if (group.owner !== this.identity.userId) {
            throw new Error("Only group owner can remove members");
        }
        // Check if user is a member
        const memberIndex = group.members.indexOf(userId);
        if (memberIndex === -1) {
            throw new Error("User is not a member of this group");
        }
        // Remove user from members list
        group.members.splice(memberIndex, 1);
        group.lastUpdated = Date.now();
        // Remove member key
        group.memberKeys.delete(userId);
        // Remove member public key
        group.memberPublicKeys.delete(userId);
        // Save updated group to storage
        await this.storage.saveSession(groupId, {
            sessionId: groupId,
            peerUserId: "GROUP", // Special marker for group sessions
            peerDsaPublicKey: this.identity.dsaKeyPair.publicKey,
            rootKey: group.sharedKey,
            currentRatchetKeyPair: null,
            peerRatchetPublicKey: null,
            sendingChain: null,
            receivingChain: null,
            previousSendingChainLength: 0,
            skippedMessageKeys: new Map(),
            highestReceivedMessageNumber: -1,
            maxSkippedMessages: 100,
            createdAt: group.createdAt,
            lastUsed: Date.now(),
            isInitiator: true,
            ratchetCount: 0,
            state: "ACTIVE",
            confirmed: true,
            // Store group-specific data in additional fields
            groupData: {
                name: group.name,
                members: group.members,
                owner: group.owner,
                memberKeys: Array.from(group.memberKeys.entries()),
                memberPublicKeys: Array.from(group.memberPublicKeys.entries()),
            },
            receivedMessageIds: new Set(),
            replayWindowSize: 100,
            lastProcessedTimestamp: Date.now(),
        });
        Logger.log("GroupManager", "Member removed from group", {
            groupId: groupId.substring(0, 16) + "...",
            userId,
            membersCount: group.members.length,
        });
    }
    async updateGroupKey(groupId) {
        if (!this.identity) {
            throw new Error("GroupManager not initialized with identity");
        }
        const group = await this.getGroup(groupId);
        if (!group) {
            throw new Error("Group not found");
        }
        // Only owner can update group key
        if (group.owner !== this.identity.userId) {
            throw new Error("Only group owner can update group key");
        }
        // Generate new shared key
        const newSharedKey = randomBytes(32);
        // Update member keys for all members
        for (const memberId of group.members) {
            // In a real implementation, we'd encrypt the new key with each member's public key
            group.memberKeys.set(memberId, newSharedKey);
        }
        // Note: We don't update public keys when updating the group key
        // Update the group shared key
        group.sharedKey = newSharedKey;
        group.lastUpdated = Date.now();
        // Save updated group to storage
        await this.storage.saveSession(groupId, {
            sessionId: groupId,
            peerUserId: "GROUP", // Special marker for group sessions
            peerDsaPublicKey: this.identity.dsaKeyPair.publicKey,
            rootKey: group.sharedKey,
            currentRatchetKeyPair: null,
            peerRatchetPublicKey: null,
            sendingChain: null,
            receivingChain: null,
            previousSendingChainLength: 0,
            skippedMessageKeys: new Map(),
            highestReceivedMessageNumber: -1,
            maxSkippedMessages: 100,
            createdAt: group.createdAt,
            lastUsed: Date.now(),
            isInitiator: true,
            ratchetCount: 0,
            state: "ACTIVE",
            confirmed: true,
            // Store group-specific data in additional fields
            groupData: {
                name: group.name,
                members: group.members,
                owner: group.owner,
                memberKeys: Array.from(group.memberKeys.entries()),
                memberPublicKeys: Array.from(group.memberPublicKeys.entries()),
            },
            receivedMessageIds: new Set(),
            replayWindowSize: 100,
            lastProcessedTimestamp: Date.now(),
        });
        Logger.log("GroupManager", "Group key updated", {
            groupId: groupId.substring(0, 16) + "...",
        });
    }
    async encryptMessage(groupId, message) {
        if (!this.identity) {
            throw new Error("GroupManager not initialized with identity");
        }
        const group = await this.getGroup(groupId);
        if (!group) {
            throw new Error("Group not found");
        }
        // Check if user is a member of the group
        if (!group.members.includes(this.identity.userId)) {
            throw new Error("User is not a member of this group");
        }
        const messageBytes = typeof message === "string" ? utf8ToBytes(message) : message;
        // Encrypt the message with the shared key
        const nonce = randomBytes(24);
        const cipher = xchacha20poly1305(group.sharedKey, nonce);
        const ciphertext = cipher.encrypt(messageBytes);
        const fullCiphertext = concatBytes(nonce, ciphertext);
        // Create message header
        const header = {
            messageId: bytesToHex(blake3(fullCiphertext, { dkLen: 32 })),
            timestamp: Date.now(),
            senderId: this.identity.userId,
            messageNumber: Date.now(), // Use timestamp as a simple sequence number for now
        };
        // Sign the message
        const headerBytes = this.serializeGroupHeader(header);
        const messageToSign = concatBytes(headerBytes, fullCiphertext);
        const signature = ml_dsa65.sign(messageToSign, this.identity.dsaKeyPair.secretKey);
        Logger.log("GroupManager", "Group message encrypted", {
            groupId: groupId.substring(0, 16) + "...",
            messageId: header.messageId.substring(0, 16) + "...",
            senderId: this.identity.userId,
        });
        return {
            groupId,
            message: fullCiphertext,
            header,
            signature,
        };
    }
    async decryptMessage(groupId, encrypted) {
        if (!this.identity) {
            throw new Error("GroupManager not initialized with identity");
        }
        const group = await this.getGroup(groupId);
        if (!group) {
            throw new Error("Group not found");
        }
        // Check if user is a member of the group
        if (!group.members.includes(this.identity.userId)) {
            throw new Error("User is not a member of this group");
        }
        // Get the sender's public key from the group
        const senderPublicKey = await this.getSenderPublicKey(groupId, encrypted.header.senderId);
        if (!senderPublicKey) {
            throw new Error("Could not retrieve sender's public key");
        }
        // Verify signature
        const headerBytes = this.serializeGroupHeader(encrypted.header);
        const messageToVerify = concatBytes(headerBytes, encrypted.message);
        const isValid = ml_dsa65.verify(encrypted.signature, messageToVerify, senderPublicKey);
        if (!isValid) {
            throw new Error("Invalid message signature");
        }
        // Check message freshness
        const now = Date.now();
        const messageAge = now - encrypted.header.timestamp;
        if (messageAge > MAX_MESSAGE_AGE) {
            throw new Error(`Message too old: ${Math.round(messageAge / 1000)}s`);
        }
        // Decrypt the message
        const nonce = encrypted.message.slice(0, 24);
        const encryptedData = encrypted.message.slice(24);
        const cipher = xchacha20poly1305(group.sharedKey, nonce);
        const plaintext = cipher.decrypt(encryptedData);
        Logger.log("GroupManager", "Group message decrypted", {
            groupId: groupId.substring(0, 16) + "...",
            messageId: encrypted.header.messageId.substring(0, 16) + "...",
            senderId: encrypted.header.senderId,
        });
        return plaintext;
    }
    async getGroup(groupId) {
        const session = await this.storage.getSession(groupId);
        if (!session || session.peerUserId !== "GROUP") {
            return null;
        }
        // Reconstruct the group from the stored session data
        const groupData = session.groupData;
        if (!groupData) {
            return null;
        }
        // Convert the stored arrays back to Maps
        const memberKeys = new Map(groupData.memberKeys);
        const memberPublicKeys = new Map(groupData.memberPublicKeys);
        return {
            groupId: session.sessionId,
            name: groupData.name,
            members: groupData.members,
            sharedKey: session.rootKey,
            createdAt: session.createdAt,
            lastUpdated: session.lastUsed,
            owner: groupData.owner,
            memberKeys,
            memberPublicKeys,
        };
    }
    async getGroups() {
        const sessionIds = await this.storage.listSessions();
        const groups = [];
        for (const sessionId of sessionIds) {
            if (sessionId.startsWith("GROUP_")) {
                // Only retrieve group sessions
                const group = await this.getGroup(sessionId);
                if (group) {
                    groups.push(group);
                }
            }
        }
        return groups;
    }
    async getSenderPublicKey(groupId, senderId) {
        const group = await this.getGroup(groupId);
        if (!group) {
            return null;
        }
        return group.memberPublicKeys.get(senderId) || null;
    }
    serializeGroupHeader(header) {
        // Simple serialization - in a real implementation, we'd use a more robust format
        const timestampBytes = new Uint8Array(8);
        new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(header.timestamp), true);
        const messageNumberBytes = new Uint8Array(8);
        new DataView(messageNumberBytes.buffer).setBigUint64(0, BigInt(header.messageNumber), true);
        const senderIdBytes = utf8ToBytes(header.senderId);
        return concatBytes(utf8ToBytes(header.messageId), timestampBytes, senderIdBytes, messageNumberBytes);
    }
}
