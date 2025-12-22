import {
  generateSenderKey,
  encryptGroupMessage as encryptHashRatchet,
  decryptGroupMessage as decryptHashRatchet,
  SenderKeyState,
  SenderKeyDistributionMessage,
  SenderKeyMessage,
} from "./sender-keys";
import { encryptMessage, decryptMessage } from "./session";
import { bytesToBase64, base64ToBytes } from "./crypto";
import { Aegis } from "./config";

interface GroupSessionData {
  groupId: string;
  mySenderKey: SenderKeyState;
  participants: {
    [userId: string]: {
      currentChainKey: string; // Base64
    };
  };
}

const GROUP_STORAGE_PREFIX = "aegis_group_";

/**
 * Group Session Manager
 * Handles initializing groups, distributing sender keys, and messaging.
 */
export class GroupSession {
  private groupId: string;
  private data: GroupSessionData;

  private constructor(groupId: string, data: GroupSessionData) {
    this.groupId = groupId;
    this.data = data;
  }

  /**
   * Load or Create a Group Session
   */
  static async get(groupId: string): Promise<GroupSession> {
    return GroupSession.getLoaded(groupId);
  }

  /**
   * Create a Distribution Message to send to a new participant.
   * This MUST be sent via the secure 1:1 session (encryptMessage).
   */
  createDistributionMessage(senderId: string): SenderKeyDistributionMessage {
    return {
      type: "distribution",
      senderId,
      groupId: this.data.groupId,
      chainKey: bytesToBase64(this.data.mySenderKey.chainKey),
      signatureKey: bytesToBase64(this.data.mySenderKey.signatureKey),
      generation: this.data.mySenderKey.generation,
    };
  }

  /**
   * Process an incoming Distribution Message from another member.
   * Call this AFTER decrypting the 1:1 message containing this payload.
   */
  async processDistributionMessage(
    payload: SenderKeyDistributionMessage
  ): Promise<void> {
    if (payload.groupId !== this.groupId) return;

    // Store their Chain Key
    this.data.participants[payload.senderId] = {
      currentChainKey: payload.chainKey,
    };

    await this.save();
    console.log(`[Group] Updated sender key for ${payload.senderId}`);
  }

  /**
   * Encrypt a message for the group.
   * O(1) operation (just one encryption).
   */
  async encrypt(
    plaintext: string,
    myUserId: string
  ): Promise<SenderKeyMessage> {
    const msg = encryptHashRatchet(
      this.data.mySenderKey,
      this.groupId,
      myUserId,
      plaintext
    );
    // console.log(`DEBUG_ALICE_KEY: ${bytesToBase64(this.data.mySenderKey.chainKey)}`);
    await this.save(); // Save ratcheted state
    return msg;
  }

  /**
   * Decrypt a message from the group.
   * O(1) operation.
   */
  async decrypt(msg: SenderKeyMessage): Promise<string> {
    const participant = this.data.participants[msg.senderId];
    if (!participant) {
      throw new Error(
        `No sender key found for ${msg.senderId}. Did you receive a distribution message?`
      );
    }

    const currentChainKey = base64ToBytes(participant.currentChainKey);
    // Trial decrypt (and ratchet)
    const { plaintext, nextChainKey } = decryptHashRatchet(
      currentChainKey,
      msg
    );

    // Update state
    participant.currentChainKey = bytesToBase64(nextChainKey);
    await this.save();

    return plaintext;
  }

  private async save(): Promise<void> {
    // Manually serialize Uint8Arrays in `mySenderKey`
    const toSave = {
      ...this.data,
      mySenderKey: {
        ...this.data.mySenderKey,
        chainKey: Array.from(this.data.mySenderKey.chainKey), // Serialize as array for storage
        signatureKey: Array.from(this.data.mySenderKey.signatureKey),
      },
    };

    // NOTE: In a real app complexity, we need a better proper serializer for Uint8Array <-> JSON
    // because `JSON.stringify` on Uint8Array turns it into object {"0": 1, ...} or array.
    // Let's implement a quick fix here or assume the StorageAdapter handles objects.
    // For safety, let's stick to Base64 in storage for keys.
    const storageFormat = {
      groupId: this.data.groupId,
      mySenderKey: {
        chainKey: bytesToBase64(this.data.mySenderKey.chainKey),
        signatureKey: bytesToBase64(this.data.mySenderKey.signatureKey),
        generation: this.data.mySenderKey.generation,
      },
      participants: this.data.participants,
    };

    await Aegis.getStorage().setItem(
      `${GROUP_STORAGE_PREFIX}${this.groupId}`,
      JSON.stringify(storageFormat)
    );
  }

  // Override static get to handle deserialization
  static async getLoaded(groupId: string): Promise<GroupSession> {
    const key = `${GROUP_STORAGE_PREFIX}${groupId}`;
    const stored = await Aegis.getStorage().getItem(key);

    if (!stored) {
      // Create new
      const newData: GroupSessionData = {
        groupId,
        mySenderKey: generateSenderKey(),
        participants: {},
      };

      // Persist using our custom format (Base64 for keys)
      const storageFormat = {
        groupId: newData.groupId,
        mySenderKey: {
          chainKey: bytesToBase64(newData.mySenderKey.chainKey),
          signatureKey: bytesToBase64(newData.mySenderKey.signatureKey),
          generation: newData.mySenderKey.generation,
        },
        participants: newData.participants,
      };

      await Aegis.getStorage().setItem(key, JSON.stringify(storageFormat));
      return new GroupSession(groupId, newData);
    }

    const raw = JSON.parse(stored);
    const data: GroupSessionData = {
      groupId: raw.groupId,
      mySenderKey: {
        chainKey: base64ToBytes(raw.mySenderKey.chainKey),
        signatureKey: base64ToBytes(raw.mySenderKey.signatureKey),
        generation: raw.mySenderKey.generation,
      },
      participants: raw.participants,
    };
    return new GroupSession(groupId, data);
  }
}

// Helper specific for the example/usage flow
export async function getGroupSession(groupId: string): Promise<GroupSession> {
  return GroupSession.getLoaded(groupId);
}
