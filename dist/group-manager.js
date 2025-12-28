import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/post-quantum/utils.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Logger } from "./logger";
import { MAX_MESSAGE_AGE } from "./constants";
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
        Object.defineProperty(this, "sentMessageNumbers", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        }); // groupId -> senderId -> messageNumber
        this.storage = storage;
        this.sentMessageNumbers = new Map();
    }
    async initialize(identity) {
        this.identity = identity;
    }
    async createGroup(name, members, memberKemPublicKeys, memberDsaPublicKeys) {
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
        const memberPublicKeysMap = new Map();
        const memberDsaPublicKeysMap = new Map();
        // Use the provided member public keys
        for (const memberId of members) {
            const kemPublicKey = memberKemPublicKeys.get(memberId);
            if (!kemPublicKey) {
                throw new Error(`KEM public key not provided for member: ${memberId}`);
            }
            memberPublicKeysMap.set(memberId, kemPublicKey);
            const dsaPublicKey = memberDsaPublicKeys.get(memberId);
            if (!dsaPublicKey) {
                throw new Error(`DSA public key not provided for member: ${memberId}`);
            }
            memberDsaPublicKeysMap.set(memberId, dsaPublicKey);
            // Encrypt the shared key with the member's KEM public key using ML-KEM
            const encryptedSharedKey = await this.encryptKeyWithPublicKey(sharedKey, kemPublicKey);
            memberKeys.set(memberId, encryptedSharedKey);
        }
        const group = {
            groupId,
            name,
            members,
            sharedKey, // This is the actual shared key for the group owner
            createdAt: Date.now(),
            lastUpdated: Date.now(),
            owner: this.identity.userId,
            memberKeys, // These are encrypted with each member's KEM public key
            memberPublicKeys: memberPublicKeysMap,
            memberDsaPublicKeys: memberDsaPublicKeysMap, // DSA public keys for signature verification
            receivedMessageNumbers: new Map(), // Initialize received message numbers tracking
        };
        // Store the group in the storage with a special format
        // We'll store it as a session with additional group-specific data
        await this.storage.saveSession(groupId, {
            sessionId: groupId,
            peerUserId: "GROUP", // Special marker for group sessions
            peerDsaPublicKey: this.identity.dsaKeyPair.publicKey,
            rootKey: group.sharedKey, // The actual shared key for the group owner
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
                memberKeys: Array.from(group.memberKeys.entries()), // Encrypted keys
                memberPublicKeys: Array.from(group.memberPublicKeys.entries()),
                memberDsaPublicKeys: Array.from(group.memberDsaPublicKeys.entries()),
                receivedMessageNumbers: Array.from(group.receivedMessageNumbers.entries()),
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
    async addMember(groupId, userId, _session, // Unused parameter, using underscore prefix
    userPublicKey) {
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
        // Encrypt the shared key with the new member's public key
        const encryptedSharedKey = await this.encryptKeyWithPublicKey(group.sharedKey, userPublicKey);
        group.memberKeys.set(userId, encryptedSharedKey);
        // Update member public keys with the provided public key
        group.memberPublicKeys.set(userId, userPublicKey);
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
                memberDsaPublicKeys: Array.from(group.memberDsaPublicKeys.entries()),
                receivedMessageNumbers: Array.from(group.receivedMessageNumbers.entries()),
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
                memberDsaPublicKeys: Array.from(group.memberDsaPublicKeys.entries()),
                receivedMessageNumbers: Array.from(group.receivedMessageNumbers.entries()),
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
        // Update member keys for all members - encrypt the new key with each member's public key
        for (const memberId of group.members) {
            const memberPublicKey = group.memberPublicKeys.get(memberId);
            if (!memberPublicKey) {
                throw new Error(`Public key not found for member: ${memberId}`);
            }
            // Encrypt the new shared key with the member's public key
            const encryptedNewSharedKey = await this.encryptKeyWithPublicKey(newSharedKey, memberPublicKey);
            group.memberKeys.set(memberId, encryptedNewSharedKey);
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
                memberDsaPublicKeys: Array.from(group.memberDsaPublicKeys.entries()),
                receivedMessageNumbers: Array.from(group.receivedMessageNumbers.entries()),
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
        // Get the group's actual shared key for encryption
        // For the group owner, they have the key directly
        // For other members, they would need to decrypt their encrypted key
        let encryptionKey;
        if (group.owner === this.identity.userId) {
            // Group owner has the key directly
            encryptionKey = group.sharedKey;
        }
        else {
            // Other members need to decrypt their copy of the key
            const encryptedSharedKey = group.memberKeys.get(this.identity.userId);
            if (!encryptedSharedKey) {
                throw new Error("No encrypted shared key found for user");
            }
            if (!this.identity.kemKeyPair.secretKey) {
                throw new Error("User's secret key not available");
            }
            encryptionKey = await this.decryptKeyWithSecretKey(encryptedSharedKey, this.identity.kemKeyPair.secretKey);
        }
        // Encrypt the message with the shared key
        const nonce = randomBytes(24);
        const cipher = xchacha20poly1305(encryptionKey, nonce);
        const ciphertext = cipher.encrypt(messageBytes);
        const fullCiphertext = concatBytes(nonce, ciphertext);
        // Create message header with a simple incrementing number per sender (in memory, not stored)
        // For a real implementation, you'd want a more robust approach to message numbering
        if (!this.sentMessageNumbers) {
            this.sentMessageNumbers = new Map(); // groupId -> senderId -> messageNumber
        }
        if (!this.sentMessageNumbers.has(groupId)) {
            this.sentMessageNumbers.set(groupId, new Map());
        }
        const groupSentNumbers = this.sentMessageNumbers.get(groupId);
        const currentMessageNumber = (groupSentNumbers.get(this.identity.userId) || 0) + 1;
        groupSentNumbers.set(this.identity.userId, currentMessageNumber);
        // Create message header
        const header = {
            messageId: bytesToHex(blake3(fullCiphertext, { dkLen: 32 })),
            timestamp: Date.now(),
            senderId: this.identity.userId,
            messageNumber: currentMessageNumber,
        };
        // Note: We don't update the stored group state here because sent message numbers
        // are tracked separately per participant
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
        // Get the encrypted shared key for this user and decrypt it
        const encryptedSharedKey = group.memberKeys.get(this.identity.userId);
        if (!encryptedSharedKey) {
            throw new Error("No encrypted shared key found for user");
        }
        // We need the user's KEM secret key to decrypt the shared group key
        // For this demo, we'll assume we have access to the user's identity secret key
        // In a real implementation, this would be securely stored and accessed
        if (!this.identity.kemKeyPair.secretKey) {
            throw new Error("User's secret key not available");
        }
        const sharedKey = await this.decryptKeyWithSecretKey(encryptedSharedKey, this.identity.kemKeyPair.secretKey);
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
        // Check message ordering/replay protection
        const lastMessageNumber = group.receivedMessageNumbers.get(encrypted.header.senderId) || 0;
        if (encrypted.header.messageNumber <= lastMessageNumber) {
            throw new Error(`Message number too low: ${encrypted.header.messageNumber} <= ${lastMessageNumber}`);
        }
        // Update the received message number for this sender
        group.receivedMessageNumbers.set(encrypted.header.senderId, encrypted.header.messageNumber);
        // Update the group in storage with the new received message number
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
                memberDsaPublicKeys: Array.from(group.memberDsaPublicKeys.entries()),
                receivedMessageNumbers: Array.from(group.receivedMessageNumbers.entries()),
            },
            receivedMessageIds: new Set(),
            replayWindowSize: 100,
            lastProcessedTimestamp: Date.now(),
        });
        // Decrypt the message
        const nonce = encrypted.message.slice(0, 24);
        const encryptedData = encrypted.message.slice(24);
        const cipher = xchacha20poly1305(sharedKey, nonce);
        const plaintext = cipher.decrypt(encryptedData);
        Logger.log("GroupManager", "Group message decrypted", {
            groupId: groupId.substring(0, 16) + "...",
            messageId: encrypted.header.messageId.substring(0, 16) + "...",
            senderId: encrypted.header.senderId,
            messageNumber: encrypted.header.messageNumber,
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
        // Initialize received message numbers
        const receivedMessageNumbers = new Map();
        if (groupData.receivedMessageNumbers) {
            for (const [senderId, number] of groupData.receivedMessageNumbers) {
                receivedMessageNumbers.set(senderId, number);
            }
        }
        // Initialize DSA public keys
        const memberDsaPublicKeys = new Map(groupData.memberDsaPublicKeys || []);
        return {
            groupId: session.sessionId,
            name: groupData.name,
            members: groupData.members,
            sharedKey: session.rootKey, // This is the actual shared key for the group owner
            createdAt: session.createdAt,
            lastUpdated: session.lastUsed,
            owner: groupData.owner,
            memberKeys, // These are the encrypted keys for each member
            memberPublicKeys,
            memberDsaPublicKeys,
            receivedMessageNumbers, // This is now always initialized
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
        return group.memberDsaPublicKeys.get(senderId) || null;
    }
    // Encrypt a key with a public key using ML-KEM
    async encryptKeyWithPublicKey(key, publicKey) {
        const { ml_kem768 } = await import("@noble/post-quantum/ml-kem.js");
        const { blake3 } = await import("@noble/hashes/blake3.js");
        const { xchacha20poly1305 } = await import("@noble/ciphers/chacha.js");
        const { randomBytes, concatBytes } = await import("@noble/hashes/utils.js");
        // Use ML-KEM to generate a shared secret with the recipient's public key
        const result = ml_kem768.encapsulate(publicKey);
        const sharedSecret = result.sharedSecret;
        const ciphertext = result.cipherText;
        // Use the shared secret to derive a symmetric key for encrypting the actual key
        const encryptionKey = blake3(sharedSecret, { dkLen: 32 });
        // Generate a random nonce for encryption
        const nonce = randomBytes(24);
        // Encrypt the key using ChaCha20-Poly1305 with the derived key
        const cipher = xchacha20poly1305(encryptionKey, nonce);
        const encryptedKey = cipher.encrypt(key);
        // Return ciphertext (for decapsulation) + nonce + encrypted key
        return concatBytes(ciphertext, nonce, encryptedKey);
    }
    // Decrypt an encrypted key with a secret key using ML-KEM
    async decryptKeyWithSecretKey(encryptedKey, secretKey) {
        const { ml_kem768 } = await import("@noble/post-quantum/ml-kem.js");
        const { blake3 } = await import("@noble/hashes/blake3.js");
        const { xchacha20poly1305 } = await import("@noble/ciphers/chacha.js");
        // Extract components: first ML-KEM ciphertext (1088 bytes for ML-KEM 768)
        // Then 24-byte nonce, then the rest is the encrypted key
        const kemCiphertextLength = 1088; // Length of ML-KEM 768 ciphertext
        const nonceLength = 24;
        if (encryptedKey.length < kemCiphertextLength + nonceLength) {
            throw new Error("Invalid encrypted key format");
        }
        const kemCiphertext = encryptedKey.slice(0, kemCiphertextLength);
        const nonce = encryptedKey.slice(kemCiphertextLength, kemCiphertextLength + nonceLength);
        const encryptedData = encryptedKey.slice(kemCiphertextLength + nonceLength);
        // Use ML-KEM to decapsulate and get the shared secret
        const sharedSecret = ml_kem768.decapsulate(kemCiphertext, secretKey);
        // Use the shared secret to derive the symmetric key
        const encryptionKey = blake3(sharedSecret, { dkLen: 32 });
        // Decrypt the key using ChaCha20-Poly1305 with the derived key
        const cipher = xchacha20poly1305(encryptionKey, nonce);
        return cipher.decrypt(encryptedData);
    }
    serializeGroupHeader(header) {
        // More robust serialization format
        const timestampBytes = new Uint8Array(8);
        new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(header.timestamp), true);
        const messageNumberBytes = new Uint8Array(8);
        new DataView(messageNumberBytes.buffer).setBigUint64(0, BigInt(header.messageNumber), true);
        const senderIdBytes = utf8ToBytes(header.senderId);
        const messageIdBytes = utf8ToBytes(header.messageId);
        // Format: [messageId length][messageId][timestamp][senderId length][senderId][messageNumber]
        const messageIdLength = new Uint8Array(4);
        new DataView(messageIdLength.buffer).setUint32(0, messageIdBytes.length, true);
        const senderIdLength = new Uint8Array(4);
        new DataView(senderIdLength.buffer).setUint32(0, senderIdBytes.length, true);
        return concatBytes(messageIdLength, messageIdBytes, timestampBytes, senderIdLength, senderIdBytes, messageNumberBytes);
    }
}
