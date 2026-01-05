declare module "@immahq/aegis" {
  export interface MemoryStorage extends StorageAdapter {}
  export interface Identity {
    kemKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
    dsaKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
    userId: string;
    createdAt: number;
    preKeySecret?: Uint8Array;
  }

  export interface PublicBundle {
    userId: string;
    kemPublicKey: Uint8Array;
    dsaPublicKey: Uint8Array;
    preKey: {
      id: number;
      key: Uint8Array;
      signature: Uint8Array;
    };
    createdAt: number;
  }

  export interface RatchetChain {
    chainKey: Uint8Array;
    messageNumber: number;
  }

  export interface SkippedMessageKey {
    messageKey: Uint8Array;
    timestamp: number;
  }

  export interface PendingRatchetState {
    newRootKey: Uint8Array;
    newRatchetKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
    sendingChain: RatchetChain;
    receivingChain: RatchetChain;
    kemCiphertext: Uint8Array;
    previousReceivingChain: RatchetChain | null;
    previousSendingChain: RatchetChain | null;
  }

  export interface Session {
    sessionId: string;
    peerUserId: string;
    peerDsaPublicKey: Uint8Array;
    rootKey: Uint8Array;
    currentRatchetKeyPair: {
      publicKey: Uint8Array;
      secretKey: Uint8Array;
    } | null;
    peerRatchetPublicKey: Uint8Array | null;

    pendingRatchetState?: PendingRatchetState;

    sendingChain: RatchetChain | null;
    receivingChain: RatchetChain | null;
    previousSendingChainLength: number;
    skippedMessageKeys: Map<string, SkippedMessageKey>;
    highestReceivedMessageNumber: number;
    maxSkippedMessages: number;
    createdAt: number;
    lastUsed: number;
    isInitiator: boolean;
    ratchetCount: number;
    state: "CREATED" | "KEY_CONFIRMED" | "ACTIVE" | "RATCHET_PENDING" | "ERROR";
    confirmed: boolean;
    confirmationMac?: Uint8Array;

    receivedMessageIds: Set<string>;
    replayWindowSize: number;
    lastProcessedTimestamp: number;

    groupData?: {
      name: string;
      members: string[];
      owner: string;
      memberKeys: [string, Uint8Array][];
      memberPublicKeys: [string, Uint8Array][]; // KEM public keys for key encryption
      memberDsaPublicKeys?: [string, Uint8Array][]; // DSA public keys for signature verification
      receivedMessageNumbers?: [string, number][];
    };
  }

  export interface MessageHeader {
    messageId: string;
    ratchetPublicKey: Uint8Array;
    messageNumber: number;
    previousChainLength: number;
    kemCiphertext?: Uint8Array;
    isRatchetMessage?: boolean;
    timestamp: number;
  }

  export interface EncryptedMessage {
    ciphertext: Uint8Array;
    header: MessageHeader;
    signature: Uint8Array;
    confirmationMac?: Uint8Array;
  }

  export interface PreKey {
    id: number;
    keyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
    signature: Uint8Array;
    used: boolean;
    createdAt: number;
  }

  export interface StorageAdapter {
    saveIdentity(identity: Identity): Promise<void>;
    getIdentity(): Promise<Identity | null>;
    deleteIdentity(): Promise<void>;
    saveSession(sessionId: string, session: Session): Promise<void>;
    getSession(sessionId: string): Promise<Session | null>;
    deleteSession(sessionId: string): Promise<void>;
    listSessions(): Promise<string[]>;
    deleteAllSessions(): Promise<void>;
  }

  export interface KeyConfirmationData {
    sessionId: string;
    mac: Uint8Array;
    timestamp: number;
  }

  export interface Group {
    groupId: string;
    name: string;
    members: string[];
    sharedKey: Uint8Array;
    createdAt: number;
    lastUpdated: number;
    owner: string;
    memberKeys: Map<string, Uint8Array>;
    memberPublicKeys: Map<string, Uint8Array>; // KEM public keys for key encryption
    memberDsaPublicKeys: Map<string, Uint8Array>; // DSA public keys for signature verification
    receivedMessageNumbers: Map<string, number>;
  }

  export interface GroupMessage {
    groupId: string;
    message: Uint8Array;
    header: GroupMessageHeader;
    signature: Uint8Array;
  }

  export interface GroupMessageHeader {
    messageId: string;
    timestamp: number;
    senderId: string;
    messageNumber: number;
  }

  export interface GroupSession {
    sessionId: string;
    groupId: string;
    userId: string;
    sharedKey: Uint8Array;
    lastUsed: number;
    permissions: GroupPermissions;
  }

  export interface GroupPermissions {
    canSend: boolean;
    canReceive: boolean;
    canManageMembers: boolean;
    canUpdateGroup: boolean;
  }

  export interface GroupManager {
    createGroup(
      name: string,
      members: string[],
      memberKemPublicKeys: Map<string, Uint8Array>,
      memberDsaPublicKeys: Map<string, Uint8Array>,
    ): Promise<Group>;
    addMember(
      groupId: string,
      userId: string,
      session: Session,
      userPublicKey: Uint8Array,
    ): Promise<void>;
    removeMember(groupId: string, userId: string): Promise<void>;
    updateGroupKey(groupId: string): Promise<void>;
    encryptMessage(
      groupId: string,
      message: string | Uint8Array,
    ): Promise<GroupMessage>;
    decryptMessage(
      groupId: string,
      encrypted: GroupMessage,
    ): Promise<Uint8Array>;
    getGroup(groupId: string): Promise<Group | null>;
    getGroups(): Promise<Group[]>;
  }
}
