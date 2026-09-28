import { describe, it, expect, beforeEach } from "vitest";
import { Aegis, MemoryStorage } from "../src/index";
import type { Group, Session } from "../src/types";

// Builds the session record a member needs in order to read/write group
// messages. `rootKey` is whatever that member already holds locally, so it can
// deliberately differ from the real shared key to exercise key unwrapping.
function makeGroupSessionRecord(
  group: Group,
  ownerDsaPublicKey: Uint8Array,
  rootKey: Uint8Array,
): Session {
  return {
    sessionId: group.groupId,
    peerUserId: "GROUP",
    peerDsaPublicKey: ownerDsaPublicKey,
    rootKey,
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
    groupData: {
      name: group.name,
      members: group.members,
      owner: group.owner,
      memberKeys: Array.from(group.memberKeys.entries()),
      memberPublicKeys: Array.from(group.memberPublicKeys.entries()),
      memberDsaPublicKeys: Array.from(group.memberDsaPublicKeys.entries()),
      receivedMessageNumbers: Array.from(
        group.receivedMessageNumbers.entries(),
      ),
    },
    receivedMessageIds: new Set<string>(),
    replayWindowSize: 100,
    lastProcessedTimestamp: Date.now(),
  };
}

describe("Group", () => {
  let alice: Aegis;
  let bob: Aegis;
  let charlie: Aegis;

  beforeEach(() => {
    alice = new Aegis(new MemoryStorage());
    bob = new Aegis(new MemoryStorage());
    charlie = new Aegis(new MemoryStorage());
  });

  describe("Group Creation", () => {
    it("should create a group with multiple members", async () => {
      // Create identities
      const aliceIdentityResult = await alice.createIdentity();
      const aliceIdentity = aliceIdentityResult.identity;
      const bobIdentityResult = await bob.createIdentity();
      const bobIdentity = bobIdentityResult.identity;
      const charlieIdentityResult = await charlie.createIdentity();
      const charlieIdentity = charlieIdentityResult.identity;

      // Create maps for KEM and DSA public keys
      const memberKemPublicKeys = new Map<string, Uint8Array>();
      memberKemPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        charlieIdentity.userId,
        charlieIdentity.kemKeyPair.publicKey,
      );

      const memberDsaPublicKeys = new Map<string, Uint8Array>();
      memberDsaPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        charlieIdentity.userId,
        charlieIdentity.dsaKeyPair.publicKey,
      );

      // Create group
      const group = await alice.createGroup(
        "Test Group",
        [aliceIdentity.userId, bobIdentity.userId, charlieIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      expect(group).toBeDefined();
      expect(group.name).toBe("Test Group");
      expect(group.members).toContain(aliceIdentity.userId);
      expect(group.members).toContain(bobIdentity.userId);
      expect(group.members).toContain(charlieIdentity.userId);
      expect(group.owner).toBe(aliceIdentity.userId);
      expect(group.sharedKey).toBeInstanceOf(Uint8Array);
      expect(group.memberKeys.size).toBe(3); // All members should have encrypted keys
      expect(group.memberPublicKeys.size).toBe(3); // All members should have public keys
      expect(group.memberDsaPublicKeys.size).toBe(3); // All members should have DSA public keys
    });

    it("should fail to create group with less than 2 members", async () => {
      const aliceIdentityResult = await alice.createIdentity();
      const aliceIdentity = aliceIdentityResult.identity;
      const bobIdentityResult = await bob.createIdentity();
      const _bobIdentity = bobIdentityResult.identity;

      const memberKemPublicKeys = new Map<string, Uint8Array>();
      memberKemPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.kemKeyPair.publicKey,
      );

      const memberDsaPublicKeys = new Map<string, Uint8Array>();
      memberDsaPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.dsaKeyPair.publicKey,
      );

      await expect(
        alice.createGroup(
          "Small Group",
          [aliceIdentity.userId],
          memberKemPublicKeys,
          memberDsaPublicKeys,
        ),
      ).rejects.toThrow("Group must have at least 2 members");
    });

    it("should properly encrypt group keys with member public keys", async () => {
      const aliceIdentityResult = await alice.createIdentity();
      const aliceIdentity = aliceIdentityResult.identity;
      const bobIdentityResult = await bob.createIdentity();
      const bobIdentity = bobIdentityResult.identity;

      const memberKemPublicKeys = new Map<string, Uint8Array>();
      memberKemPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.kemKeyPair.publicKey,
      );

      const memberDsaPublicKeys = new Map<string, Uint8Array>();
      memberDsaPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.dsaKeyPair.publicKey,
      );

      const group = await alice.createGroup(
        "Test Group",
        [aliceIdentity.userId, bobIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      // Check that member keys are encrypted (not equal to the shared key)
      const aliceEncryptedKey = group.memberKeys.get(aliceIdentity.userId);
      const bobEncryptedKey = group.memberKeys.get(bobIdentity.userId);

      expect(aliceEncryptedKey).toBeDefined();
      expect(bobEncryptedKey).toBeDefined();
      expect(aliceEncryptedKey).not.toEqual(group.sharedKey);
      expect(bobEncryptedKey).not.toEqual(group.sharedKey);
    });
  });

  describe("Group Message Encryption/Decryption", () => {
    let group: Group;
    let aliceIdentity: any;
    let bobIdentity: any;
    let charlieIdentity: any;

    beforeEach(async () => {
      // Create identities
      const aliceIdentityResult = await alice.createIdentity();
      aliceIdentity = aliceIdentityResult.identity;
      const bobIdentityResult = await bob.createIdentity();
      bobIdentity = bobIdentityResult.identity;
      const charlieIdentityResult = await charlie.createIdentity();
      charlieIdentity = charlieIdentityResult.identity;

      // Create maps for KEM and DSA public keys
      const memberKemPublicKeys = new Map<string, Uint8Array>();
      memberKemPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        charlieIdentity.userId,
        charlieIdentity.kemKeyPair.publicKey,
      );

      const memberDsaPublicKeys = new Map<string, Uint8Array>();
      memberDsaPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        charlieIdentity.userId,
        charlieIdentity.dsaKeyPair.publicKey,
      );

      // Create group
      group = await alice.createGroup(
        "Test Group",
        [aliceIdentity.userId, bobIdentity.userId, charlieIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      // Sync group data to all participants (similar to how it's done in the demo)
      const allParticipants = [alice, bob, charlie];
      const aliceGroupSession = await alice.getGroup(group.groupId);
      if (aliceGroupSession) {
        for (const participant of allParticipants) {
          // Save the group session data to each participant's storage
          await participant.getStorage().saveSession(group.groupId, {
            sessionId: group.groupId,
            peerUserId: "GROUP", // Special marker for group sessions
            peerDsaPublicKey: aliceIdentity.dsaKeyPair.publicKey,
            rootKey: aliceGroupSession.sharedKey,
            currentRatchetKeyPair: null,
            peerRatchetPublicKey: null,
            sendingChain: null,
            receivingChain: null,
            previousSendingChainLength: 0,
            skippedMessageKeys: new Map(),
            highestReceivedMessageNumber: -1,
            maxSkippedMessages: 100,
            createdAt: aliceGroupSession.createdAt,
            lastUsed: Date.now(),
            isInitiator: true,
            ratchetCount: 0,
            state: "ACTIVE",
            confirmed: true,
            groupData: {
              name: aliceGroupSession.name,
              members: aliceGroupSession.members,
              owner: aliceGroupSession.owner,
              memberKeys: Array.from(aliceGroupSession.memberKeys.entries()),
              memberPublicKeys: Array.from(
                aliceGroupSession.memberPublicKeys.entries(),
              ),
              memberDsaPublicKeys: Array.from(
                aliceGroupSession.memberDsaPublicKeys.entries(),
              ),
              receivedMessageNumbers: Array.from(
                aliceGroupSession.receivedMessageNumbers.entries(),
              ),
            },
            receivedMessageIds: new Set<string>(),
            replayWindowSize: 100,
            lastProcessedTimestamp: Date.now(),
          });
        }
      }
    });

    it("should encrypt and decrypt a message successfully", async () => {
      const originalMessage = "Hello, group!";
      const encrypted = await alice.encryptGroupMessage(
        group.groupId,
        originalMessage,
      );
      const decrypted = await bob.decryptGroupMessage(group.groupId, encrypted);

      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(originalMessage);
    });

    it("should handle Uint8Array messages", async () => {
      const originalMessage = new TextEncoder().encode("Uint8Array message");
      const encrypted = await alice.encryptGroupMessage(
        group.groupId,
        originalMessage,
      );
      const decrypted = await bob.decryptGroupMessage(group.groupId, encrypted);

      expect(decrypted).toEqual(originalMessage);
    });

    it("should verify message signatures correctly", async () => {
      const originalMessage = "Message with signature";
      const encrypted = await alice.encryptGroupMessage(
        group.groupId,
        originalMessage,
      );

      // Verify that Bob can decrypt (signature verification passes)
      const decrypted = await bob.decryptGroupMessage(group.groupId, encrypted);
      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(originalMessage);
    });

    it("should reject messages with invalid signatures", async () => {
      const originalMessage = "Original message";
      const encrypted = await alice.encryptGroupMessage(
        group.groupId,
        originalMessage,
      );

      // Modify the signature to make it invalid
      const invalidEncrypted = {
        ...encrypted,
        signature: new Uint8Array(64).fill(1), // Invalid signature
      };

      await expect(
        bob.decryptGroupMessage(group.groupId, invalidEncrypted),
      ).rejects.toThrow("Invalid message signature");
    });

    it("should maintain message ordering with sequence numbers", async () => {
      const message1 = await alice.encryptGroupMessage(
        group.groupId,
        "First message",
      );
      const message2 = await alice.encryptGroupMessage(
        group.groupId,
        "Second message",
      );

      expect(message1.header.messageNumber).toBe(1);
      expect(message2.header.messageNumber).toBe(2);

      const decrypted1 = await bob.decryptGroupMessage(group.groupId, message1);
      const decrypted2 = await bob.decryptGroupMessage(group.groupId, message2);

      expect(new TextDecoder().decode(decrypted1)).toBe("First message");
      expect(new TextDecoder().decode(decrypted2)).toBe("Second message");
    });

    it("should prevent replay attacks for group messages", async () => {
      const message = await alice.encryptGroupMessage(
        group.groupId,
        "Test message",
      );

      // First decryption should succeed
      const decrypted1 = await bob.decryptGroupMessage(group.groupId, message);
      const text1 = new TextDecoder().decode(decrypted1);
      expect(text1).toBe("Test message");

      // Second decryption of the same message should fail due to message ordering protection
      await expect(
        bob.decryptGroupMessage(group.groupId, message),
      ).rejects.toThrow("Message number too low");
    });
  });

  describe("Group Management", () => {
    let group: Group;
    let aliceIdentity: any;
    let bobIdentity: any;
    let charlieIdentity: any;

    beforeEach(async () => {
      // Create identities
      const aliceIdentityResult = await alice.createIdentity();
      aliceIdentity = aliceIdentityResult.identity;
      const bobIdentityResult = await bob.createIdentity();
      bobIdentity = bobIdentityResult.identity;
      const charlieIdentityResult = await charlie.createIdentity();
      charlieIdentity = charlieIdentityResult.identity;

      // Create maps for KEM and DSA public keys
      const memberKemPublicKeys = new Map<string, Uint8Array>();
      memberKemPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        charlieIdentity.userId,
        charlieIdentity.kemKeyPair.publicKey,
      );

      const memberDsaPublicKeys = new Map<string, Uint8Array>();
      memberDsaPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        charlieIdentity.userId,
        charlieIdentity.dsaKeyPair.publicKey,
      );

      // Create group
      group = await alice.createGroup(
        "Test Group",
        [aliceIdentity.userId, bobIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      // Sync group data to all participants (similar to how it's done in the demo)
      const allParticipants = [alice, bob]; // Only Alice and Bob in this group
      const aliceGroupSession = await alice.getGroup(group.groupId);
      if (aliceGroupSession) {
        for (const participant of allParticipants) {
          // Save the group session data to each participant's storage
          await participant.getStorage().saveSession(group.groupId, {
            sessionId: group.groupId,
            peerUserId: "GROUP", // Special marker for group sessions
            peerDsaPublicKey: aliceIdentity.dsaKeyPair.publicKey,
            rootKey: aliceGroupSession.sharedKey,
            currentRatchetKeyPair: null,
            peerRatchetPublicKey: null,
            sendingChain: null,
            receivingChain: null,
            previousSendingChainLength: 0,
            skippedMessageKeys: new Map(),
            highestReceivedMessageNumber: -1,
            maxSkippedMessages: 100,
            createdAt: aliceGroupSession.createdAt,
            lastUsed: Date.now(),
            isInitiator: true,
            ratchetCount: 0,
            state: "ACTIVE",
            confirmed: true,
            groupData: {
              name: aliceGroupSession.name,
              members: aliceGroupSession.members,
              owner: aliceGroupSession.owner,
              memberKeys: Array.from(aliceGroupSession.memberKeys.entries()),
              memberPublicKeys: Array.from(
                aliceGroupSession.memberPublicKeys.entries(),
              ),
              memberDsaPublicKeys: Array.from(
                aliceGroupSession.memberDsaPublicKeys.entries(),
              ),
              receivedMessageNumbers: Array.from(
                aliceGroupSession.receivedMessageNumbers.entries(),
              ),
            },
            receivedMessageIds: new Set<string>(),
            replayWindowSize: 100,
            lastProcessedTimestamp: Date.now(),
          });
        }
      }
    });

    it("should retrieve group information", async () => {
      const retrievedGroup = await alice.getGroup(group.groupId);
      expect(retrievedGroup).toBeDefined();
      expect(retrievedGroup?.name).toBe("Test Group");
      expect(retrievedGroup?.groupId).toBe(group.groupId);
      expect(retrievedGroup?.members).toContain(aliceIdentity.userId);
      expect(retrievedGroup?.members).toContain(bobIdentity.userId);
      expect(retrievedGroup?.owner).toBe(aliceIdentity.userId);
    });

    it("should retrieve all groups", async () => {
      const allGroups = await alice.getGroups();
      expect(allGroups).toBeDefined();
      expect(allGroups.length).toBe(1);
      expect(allGroups[0].name).toBe("Test Group");
    });

    it("should update group key", async () => {
      const originalSharedKey = group.sharedKey;

      await alice.updateGroupKey(group.groupId);

      const updatedGroup = await alice.getGroup(group.groupId);
      expect(updatedGroup).toBeDefined();
      expect(updatedGroup?.sharedKey).not.toEqual(originalSharedKey);
    });

    it("should only allow owner to update group key", async () => {
      await expect(bob.updateGroupKey(group.groupId)).rejects.toThrow(
        "Only group owner can update group key",
      );
    });
  });

  describe("Group Member Management", () => {
    let group: Group;
    let aliceIdentity: any;
    let bobIdentity: any;
    let charlieIdentity: any;

    beforeEach(async () => {
      // Create identities
      const aliceIdentityResult = await alice.createIdentity();
      aliceIdentity = aliceIdentityResult.identity;
      const bobIdentityResult = await bob.createIdentity();
      bobIdentity = bobIdentityResult.identity;
      const charlieIdentityResult = await charlie.createIdentity();
      charlieIdentity = charlieIdentityResult.identity;

      // Create maps for KEM and DSA public keys
      const memberKemPublicKeys = new Map<string, Uint8Array>();
      memberKemPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.kemKeyPair.publicKey,
      );

      const memberDsaPublicKeys = new Map<string, Uint8Array>();
      memberDsaPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.dsaKeyPair.publicKey,
      );

      // Create group with Alice and Bob
      group = await alice.createGroup(
        "Test Group",
        [aliceIdentity.userId, bobIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      // Sync group data to all participants
      const allParticipants = [alice, bob];
      const aliceGroupSession = await alice.getGroup(group.groupId);
      if (aliceGroupSession) {
        for (const participant of allParticipants) {
          await participant.getStorage().saveSession(group.groupId, {
            sessionId: group.groupId,
            peerUserId: "GROUP",
            peerDsaPublicKey: aliceIdentity.dsaKeyPair.publicKey,
            rootKey: aliceGroupSession.sharedKey,
            currentRatchetKeyPair: null,
            peerRatchetPublicKey: null,
            sendingChain: null,
            receivingChain: null,
            previousSendingChainLength: 0,
            skippedMessageKeys: new Map(),
            highestReceivedMessageNumber: -1,
            maxSkippedMessages: 100,
            createdAt: aliceGroupSession.createdAt,
            lastUsed: Date.now(),
            isInitiator: true,
            ratchetCount: 0,
            state: "ACTIVE",
            confirmed: true,
            groupData: {
              name: aliceGroupSession.name,
              members: aliceGroupSession.members,
              owner: aliceGroupSession.owner,
              memberKeys: Array.from(aliceGroupSession.memberKeys.entries()),
              memberPublicKeys: Array.from(
                aliceGroupSession.memberPublicKeys.entries(),
              ),
              memberDsaPublicKeys: Array.from(
                aliceGroupSession.memberDsaPublicKeys.entries(),
              ),
              receivedMessageNumbers: Array.from(
                aliceGroupSession.receivedMessageNumbers.entries(),
              ),
            },
            receivedMessageIds: new Set<string>(),
            replayWindowSize: 100,
            lastProcessedTimestamp: Date.now(),
          });
        }
      }
    });

    it("should add a new member to the group", async () => {
      // Add Charlie to the group
      await alice.addGroupMember(
        group.groupId,
        charlieIdentity.userId,
        {} as any, // session parameter (unused)
        charlieIdentity.kemKeyPair.publicKey, // Charlie's public key
      );

      const updatedGroup = await alice.getGroup(group.groupId);
      expect(updatedGroup).toBeDefined();
      expect(updatedGroup?.members).toContain(charlieIdentity.userId);
      expect(updatedGroup?.members.length).toBe(3);
    });

    it("should only allow owner to add members", async () => {
      await expect(
        bob.addGroupMember(
          group.groupId,
          charlieIdentity.userId,
          {} as any,
          charlieIdentity.kemKeyPair.publicKey,
        ),
      ).rejects.toThrow("Only group owner can add members");
    });

    it("should prevent adding duplicate members", async () => {
      await expect(
        alice.addGroupMember(
          group.groupId,
          bobIdentity.userId,
          {} as any,
          bobIdentity.kemKeyPair.publicKey,
        ),
      ).rejects.toThrow("User is already a member of this group");
    });

    it("should encrypt new group key for added member", async () => {
      // Add Charlie to the group
      await alice.addGroupMember(
        group.groupId,
        charlieIdentity.userId,
        {} as any,
        charlieIdentity.kemKeyPair.publicKey,
      );

      const updatedGroup = await alice.getGroup(group.groupId);
      expect(updatedGroup).toBeDefined();

      // Check that Charlie's key is encrypted and stored
      const charlieEncryptedKey = updatedGroup?.memberKeys.get(
        charlieIdentity.userId,
      );
      expect(charlieEncryptedKey).toBeDefined();
      expect(charlieEncryptedKey).not.toEqual(updatedGroup?.sharedKey);
    });
  });

  describe("Cross-member Communication", () => {
    let group: Group;
    let aliceIdentity: any;
    let bobIdentity: any;
    let charlieIdentity: any;

    beforeEach(async () => {
      // Create identities
      const aliceIdentityResult = await alice.createIdentity();
      aliceIdentity = aliceIdentityResult.identity;
      const bobIdentityResult = await bob.createIdentity();
      bobIdentity = bobIdentityResult.identity;
      const charlieIdentityResult = await charlie.createIdentity();
      charlieIdentity = charlieIdentityResult.identity;

      // Create maps for KEM and DSA public keys
      const memberKemPublicKeys = new Map<string, Uint8Array>();
      memberKemPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.kemKeyPair.publicKey,
      );
      memberKemPublicKeys.set(
        charlieIdentity.userId,
        charlieIdentity.kemKeyPair.publicKey,
      );

      const memberDsaPublicKeys = new Map<string, Uint8Array>();
      memberDsaPublicKeys.set(
        aliceIdentity.userId,
        aliceIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        bobIdentity.userId,
        bobIdentity.dsaKeyPair.publicKey,
      );
      memberDsaPublicKeys.set(
        charlieIdentity.userId,
        charlieIdentity.dsaKeyPair.publicKey,
      );

      // Create group
      group = await alice.createGroup(
        "Test Group",
        [aliceIdentity.userId, bobIdentity.userId, charlieIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      // Sync group data to all participants (similar to how it's done in the demo)
      const allParticipants = [alice, bob, charlie];
      const aliceGroupSession = await alice.getGroup(group.groupId);
      if (aliceGroupSession) {
        for (const participant of allParticipants) {
          // Save the group session data to each participant's storage
          await participant.getStorage().saveSession(group.groupId, {
            sessionId: group.groupId,
            peerUserId: "GROUP", // Special marker for group sessions
            peerDsaPublicKey: aliceIdentity.dsaKeyPair.publicKey,
            rootKey: aliceGroupSession.sharedKey,
            currentRatchetKeyPair: null,
            peerRatchetPublicKey: null,
            sendingChain: null,
            receivingChain: null,
            previousSendingChainLength: 0,
            skippedMessageKeys: new Map(),
            highestReceivedMessageNumber: -1,
            maxSkippedMessages: 100,
            createdAt: aliceGroupSession.createdAt,
            lastUsed: Date.now(),
            isInitiator: true,
            ratchetCount: 0,
            state: "ACTIVE",
            confirmed: true,
            groupData: {
              name: aliceGroupSession.name,
              members: aliceGroupSession.members,
              owner: aliceGroupSession.owner,
              memberKeys: Array.from(aliceGroupSession.memberKeys.entries()),
              memberPublicKeys: Array.from(
                aliceGroupSession.memberPublicKeys.entries(),
              ),
              memberDsaPublicKeys: Array.from(
                aliceGroupSession.memberDsaPublicKeys.entries(),
              ),
              receivedMessageNumbers: Array.from(
                aliceGroupSession.receivedMessageNumbers.entries(),
              ),
            },
            receivedMessageIds: new Set<string>(),
            replayWindowSize: 100,
            lastProcessedTimestamp: Date.now(),
          });
        }
      }
    });

    it("should allow all members to encrypt and decrypt messages", async () => {
      // Alice sends a message
      const messageFromAlice = "Hello from Alice";
      const encryptedByAlice = await alice.encryptGroupMessage(
        group.groupId,
        messageFromAlice,
      );

      // Bob should be able to decrypt Alice's message
      const decryptedByBob = await bob.decryptGroupMessage(
        group.groupId,
        encryptedByAlice,
      );
      expect(new TextDecoder().decode(decryptedByBob)).toBe(messageFromAlice);

      // Charlie should also be able to decrypt Alice's message
      const decryptedByCharlie = await charlie.decryptGroupMessage(
        group.groupId,
        encryptedByAlice,
      );
      expect(new TextDecoder().decode(decryptedByCharlie)).toBe(
        messageFromAlice,
      );

      // Bob sends a message
      const messageFromBob = "Hello from Bob";
      const encryptedByBob = await bob.encryptGroupMessage(
        group.groupId,
        messageFromBob,
      );

      // Alice and Charlie should be able to decrypt Bob's message
      const decryptedByAlice2 = await alice.decryptGroupMessage(
        group.groupId,
        encryptedByBob,
      );
      expect(new TextDecoder().decode(decryptedByAlice2)).toBe(messageFromBob);

      const decryptedByCharlie2 = await charlie.decryptGroupMessage(
        group.groupId,
        encryptedByBob,
      );
      expect(new TextDecoder().decode(decryptedByCharlie2)).toBe(
        messageFromBob,
      );
    });

    it("should not allow non-members to decrypt messages", async () => {
      const outsider = new Aegis(new MemoryStorage());
      await outsider.createIdentity();

      const message = "Secret group message";
      const encrypted = await alice.encryptGroupMessage(group.groupId, message);

      // Without any group state the outsider cannot even find the group
      await expect(
        outsider.decryptGroupMessage(group.groupId, encrypted),
      ).rejects.toThrow("Group not found");

      // Even when handed the full group record, membership is still enforced
      await outsider
        .getStorage()
        .saveSession(
          group.groupId,
          makeGroupSessionRecord(
            group,
            aliceIdentity.dsaKeyPair.publicKey,
            group.sharedKey,
          ),
        );

      await expect(
        outsider.decryptGroupMessage(group.groupId, encrypted),
      ).rejects.toThrow("User is not a member of this group");
    });
  });

  describe("Group Key Distribution", () => {
    it("should let non-owner members read and send via the wrapped group key", async () => {
      const aliceIdentity = (await alice.createIdentity()).identity;
      const bobIdentity = (await bob.createIdentity()).identity;
      const charlieIdentity = (await charlie.createIdentity()).identity;

      const memberKemPublicKeys = new Map<string, Uint8Array>([
        [aliceIdentity.userId, aliceIdentity.kemKeyPair.publicKey],
        [bobIdentity.userId, bobIdentity.kemKeyPair.publicKey],
        [charlieIdentity.userId, charlieIdentity.kemKeyPair.publicKey],
      ]);
      const memberDsaPublicKeys = new Map<string, Uint8Array>([
        [aliceIdentity.userId, aliceIdentity.dsaKeyPair.publicKey],
        [bobIdentity.userId, bobIdentity.dsaKeyPair.publicKey],
        [charlieIdentity.userId, charlieIdentity.dsaKeyPair.publicKey],
      ]);

      const group = await alice.createGroup(
        "Distributed Key Group",
        [aliceIdentity.userId, bobIdentity.userId, charlieIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      // Members only receive their wrapped key + public keys, never the
      // plaintext shared key, so seed their storage with a placeholder rootKey.
      const placeholderKey = new Uint8Array(32).fill(7);
      expect(placeholderKey).not.toEqual(group.sharedKey);

      await bob
        .getStorage()
        .saveSession(
          group.groupId,
          makeGroupSessionRecord(
            group,
            aliceIdentity.dsaKeyPair.publicKey,
            placeholderKey,
          ),
        );
      await charlie
        .getStorage()
        .saveSession(
          group.groupId,
          makeGroupSessionRecord(
            group,
            aliceIdentity.dsaKeyPair.publicKey,
            placeholderKey,
          ),
        );

      // Owner -> members
      const fromAlice = await alice.encryptGroupMessage(
        group.groupId,
        "hello from owner",
      );
      expect(
        new TextDecoder().decode(
          await bob.decryptGroupMessage(group.groupId, fromAlice),
        ),
      ).toBe("hello from owner");
      expect(
        new TextDecoder().decode(
          await charlie.decryptGroupMessage(group.groupId, fromAlice),
        ),
      ).toBe("hello from owner");

      // Member -> owner: only succeeds if the KEM-unwrapped key equals the
      // owner's shared key.
      const fromBob = await bob.encryptGroupMessage(
        group.groupId,
        "hello from member",
      );
      expect(
        new TextDecoder().decode(
          await alice.decryptGroupMessage(group.groupId, fromBob),
        ),
      ).toBe("hello from member");
    });

    it("should wrap a unique ciphertext of the shared key per member", async () => {
      const aliceIdentity = (await alice.createIdentity()).identity;
      const bobIdentity = (await bob.createIdentity()).identity;

      const memberKemPublicKeys = new Map<string, Uint8Array>([
        [aliceIdentity.userId, aliceIdentity.kemKeyPair.publicKey],
        [bobIdentity.userId, bobIdentity.kemKeyPair.publicKey],
      ]);
      const memberDsaPublicKeys = new Map<string, Uint8Array>([
        [aliceIdentity.userId, aliceIdentity.dsaKeyPair.publicKey],
        [bobIdentity.userId, bobIdentity.dsaKeyPair.publicKey],
      ]);

      const group = await alice.createGroup(
        "Unique Wrap Group",
        [aliceIdentity.userId, bobIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      const aliceWrapped = group.memberKeys.get(aliceIdentity.userId);
      const bobWrapped = group.memberKeys.get(bobIdentity.userId);

      expect(aliceWrapped).toBeDefined();
      expect(bobWrapped).toBeDefined();
      expect(aliceWrapped).not.toEqual(group.sharedKey);
      expect(bobWrapped).not.toEqual(group.sharedKey);
      expect(aliceWrapped).not.toEqual(bobWrapped);
    });
  });

  describe("Group Membership Changes", () => {
    async function setupThreeMemberGroup() {
      const aliceIdentity = (await alice.createIdentity()).identity;
      const bobIdentity = (await bob.createIdentity()).identity;
      const charlieIdentity = (await charlie.createIdentity()).identity;

      const memberKemPublicKeys = new Map<string, Uint8Array>([
        [aliceIdentity.userId, aliceIdentity.kemKeyPair.publicKey],
        [bobIdentity.userId, bobIdentity.kemKeyPair.publicKey],
        [charlieIdentity.userId, charlieIdentity.kemKeyPair.publicKey],
      ]);
      const memberDsaPublicKeys = new Map<string, Uint8Array>([
        [aliceIdentity.userId, aliceIdentity.dsaKeyPair.publicKey],
        [bobIdentity.userId, bobIdentity.dsaKeyPair.publicKey],
        [charlieIdentity.userId, charlieIdentity.dsaKeyPair.publicKey],
      ]);

      const group = await alice.createGroup(
        "Membership Group",
        [aliceIdentity.userId, bobIdentity.userId, charlieIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      return { group, aliceIdentity, bobIdentity, charlieIdentity };
    }

    it("should rotate the group key and lock out a removed member", async () => {
      const { group, aliceIdentity, charlieIdentity } =
        await setupThreeMemberGroup();
      const originalSharedKey = group.sharedKey;

      await alice.removeGroupMember(group.groupId, charlieIdentity.userId);

      const updated = await alice.getGroup(group.groupId);
      expect(updated).toBeDefined();
      expect(updated?.members).not.toContain(charlieIdentity.userId);
      expect(updated?.members).toHaveLength(2);
      expect(updated?.memberKeys.has(charlieIdentity.userId)).toBe(false);
      expect(updated?.memberDsaPublicKeys.has(charlieIdentity.userId)).toBe(
        false,
      );
      expect(updated?.sharedKey).not.toEqual(originalSharedKey);

      // Remaining member gets the rotated record and keeps working
      await bob
        .getStorage()
        .saveSession(
          group.groupId,
          makeGroupSessionRecord(
            updated!,
            aliceIdentity.dsaKeyPair.publicKey,
            updated!.sharedKey,
          ),
        );
      // The removed member retains the OLD record and OLD key
      await charlie
        .getStorage()
        .saveSession(
          group.groupId,
          makeGroupSessionRecord(
            group,
            aliceIdentity.dsaKeyPair.publicKey,
            group.sharedKey,
          ),
        );

      const message = await alice.encryptGroupMessage(
        group.groupId,
        "after removal",
      );
      expect(
        new TextDecoder().decode(
          await bob.decryptGroupMessage(group.groupId, message),
        ),
      ).toBe("after removal");

      // Charlie still holds the old key but cannot read post-removal messages
      await expect(
        charlie.decryptGroupMessage(group.groupId, message),
      ).rejects.toThrow();
    });

    it("should only allow the owner to remove members", async () => {
      const { group, aliceIdentity, charlieIdentity } =
        await setupThreeMemberGroup();

      await bob
        .getStorage()
        .saveSession(
          group.groupId,
          makeGroupSessionRecord(
            group,
            aliceIdentity.dsaKeyPair.publicKey,
            group.sharedKey,
          ),
        );

      await expect(
        bob.removeGroupMember(group.groupId, charlieIdentity.userId),
      ).rejects.toThrow("Only group owner can remove members");
    });

    it("should reject removing a non-member", async () => {
      const { group } = await setupThreeMemberGroup();
      const outsider = (await new Aegis(new MemoryStorage()).createIdentity())
        .identity;

      await expect(
        alice.removeGroupMember(group.groupId, outsider.userId),
      ).rejects.toThrow("User is not a member of this group");
    });

    it("should not let a late joiner read pre-join history", async () => {
      const aliceIdentity = (await alice.createIdentity()).identity;
      const bobIdentity = (await bob.createIdentity()).identity;
      const charlieIdentity = (await charlie.createIdentity()).identity;

      const memberKemPublicKeys = new Map<string, Uint8Array>([
        [aliceIdentity.userId, aliceIdentity.kemKeyPair.publicKey],
        [bobIdentity.userId, bobIdentity.kemKeyPair.publicKey],
      ]);
      const memberDsaPublicKeys = new Map<string, Uint8Array>([
        [aliceIdentity.userId, aliceIdentity.dsaKeyPair.publicKey],
        [bobIdentity.userId, bobIdentity.dsaKeyPair.publicKey],
      ]);

      const group = await alice.createGroup(
        "Late Join Group",
        [aliceIdentity.userId, bobIdentity.userId],
        memberKemPublicKeys,
        memberDsaPublicKeys,
      );

      const historyMessage = await alice.encryptGroupMessage(
        group.groupId,
        "before charlie joined",
      );

      // Charlie joins afterwards, which rotates the group key
      await alice.addGroupMember(
        group.groupId,
        charlieIdentity.userId,
        {} as any,
        charlieIdentity.kemKeyPair.publicKey,
      );

      const joined = await alice.getGroup(group.groupId);
      expect(joined).toBeDefined();
      await charlie
        .getStorage()
        .saveSession(
          group.groupId,
          makeGroupSessionRecord(
            joined!,
            aliceIdentity.dsaKeyPair.publicKey,
            joined!.sharedKey,
          ),
        );

      // Charlie cannot read messages sent before the join...
      await expect(
        charlie.decryptGroupMessage(group.groupId, historyMessage),
      ).rejects.toThrow();

      // ...but can read messages sent after joining
      const afterJoin = await alice.encryptGroupMessage(
        group.groupId,
        "after charlie joined",
      );
      expect(
        new TextDecoder().decode(
          await charlie.decryptGroupMessage(group.groupId, afterJoin),
        ),
      ).toBe("after charlie joined");
    });
  });
});
