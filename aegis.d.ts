declare module "@immahq/aegis" {
  export class Aegis {
    constructor(storage: StorageAdapter);
    createIdentity(userId?: string): Promise<AegisIdentity>;
    getIdentity(): Promise<Identity>;
    rotateIdentity(userId?: string): Promise<AegisIdentity>;
    getPublicBundle(): Promise<PublicBundle>;
    createSession(publicBundle: PublicBundle): Promise<{
      sessionId: string;
      ciphertext: Uint8Array;
      confirmationMac: Uint8Array;
    }>;
    createResponderSession(
      publicBundle: PublicBundle,
      ciphertext: Uint8Array,
      initiatorConfirmationMac?: Uint8Array,
    ): Promise<{
      sessionId: string;
      confirmationMac: Uint8Array;
      isValid: boolean;
    }>;
    confirmSession(
      sessionId: string,
      responderConfirmationMac: Uint8Array,
    ): Promise<boolean>;
    getSessions(): Promise<Session[]>;
    cleanupOldSessions(maxAge?: number): Promise<void>;
    encryptMessage(
      sessionId: string,
      plaintext: string | Uint8Array,
    ): Promise<EncryptedMessage>;
    decryptMessage(
      sessionId: string,
      encrypted: EncryptedMessage,
    ): Promise<{
      plaintext: Uint8Array;
      needsConfirmation?: boolean;
    }>;
    triggerRatchet(sessionId: string): Promise<void>;
    getReplayProtectionStatus(sessionId: string): Promise<{
      storedMessageIds: number;
      lastProcessedTimestamp: number;
      replayWindowSize: number;
    }>;
    getConfirmationMac(sessionId: string): Promise<Uint8Array | null>;
    getStorage(): StorageAdapter;
    createGroup(
      name: string,
      members: string[],
      memberKemPublicKeys: Map<string, Uint8Array>,
      memberDsaPublicKeys: Map<string, Uint8Array>,
    ): Promise<Group>;
    addGroupMember(
      groupId: string,
      userId: string,
      session: Session,
      userPublicKey: Uint8Array,
    ): Promise<void>;
    removeGroupMember(groupId: string, userId: string): Promise<void>;
    updateGroupKey(groupId: string): Promise<void>;
    encryptGroupMessage(
      groupId: string,
      message: string | Uint8Array,
    ): Promise<GroupMessage>;
    decryptGroupMessage(
      groupId: string,
      encrypted: GroupMessage,
    ): Promise<Uint8Array>;
    getGroup(groupId: string): Promise<Group | null>;
    getGroups(): Promise<Group[]>;
  }

  export class MemoryStorage implements StorageAdapter {
    saveIdentity(identity: Identity): Promise<void>;
    getIdentity(): Promise<Identity | null>;
    deleteIdentity(): Promise<void>;
    saveSession(sessionId: string, session: Session): Promise<void>;
    getSession(sessionId: string): Promise<Session | null>;
    deleteSession(sessionId: string): Promise<void>;
    listSessions(): Promise<string[]>;
    deleteAllSessions(): Promise<void>;
  }

  export class Logger {
    static log(
      component: string,
      message: string,
      data?: Record<string, any>,
    ): void;
    static error(component: string, message: string, error?: any): void;
    static warn(
      component: string,
      message: string,
      data?: Record<string, any>,
    ): void;
  }

  export class KemRatchet {}

  export class SessionKeyExchange {
    static createInitiatorSession(
      identity: Identity,
      peerBundle: PublicBundle,
    ): {
      sessionId: string;
      rootKey: Uint8Array;
      sendingChainKey: Uint8Array;
      receivingChainKey: Uint8Array;
      ciphertext: Uint8Array;
      confirmationMac: Uint8Array;
    };
    static createResponderSession(
      identity: Identity,
      peerBundle: PublicBundle,
      ciphertext: Uint8Array,
      initiatorConfirmationMac?: Uint8Array,
    ): {
      sessionId: string;
      rootKey: Uint8Array;
      sendingChainKey: Uint8Array;
      receivingChainKey: Uint8Array;
      confirmationMac: Uint8Array;
      isValid: boolean;
    };
    static verifyKeyConfirmation(
      sessionId: string,
      rootKey: Uint8Array,
      receivingChainKey: Uint8Array,
      confirmationMac: Uint8Array,
    ): boolean;
  }

  export class IdentityManager {
    constructor(storage: StorageAdapter);
    createIdentity(userId?: string): Promise<AegisIdentity>;
    getIdentity(): Promise<Identity>;
    getPublicBundle(): Promise<PublicBundle>;
    rotateIdentity(userId?: string): Promise<AegisIdentity>;
  }

  export class SessionManager {
    constructor(storage: StorageAdapter);
    createSession(
      identity: Identity,
      peerBundle: PublicBundle,
    ): Promise<{
      sessionId: string;
      ciphertext: Uint8Array;
      confirmationMac: Uint8Array;
    }>;
    createResponderSession(
      identity: Identity,
      peerBundle: PublicBundle,
      ciphertext: Uint8Array,
      initiatorConfirmationMac?: Uint8Array,
    ): Promise<{
      sessionId: string;
      confirmationMac: Uint8Array;
      isValid: boolean;
    }>;
    confirmSession(
      sessionId: string,
      responderConfirmationMac: Uint8Array,
    ): Promise<boolean>;
    getSessions(): Promise<Session[]>;
    cleanupOldSessions(maxAge?: number): Promise<void>;
  }

  export class CryptoManager {
    constructor(storage: StorageAdapter);
  }

  export class RatchetManager {
    shouldPerformSendingRatchet(session: Session): boolean;
    performSendingRatchet(session: Session): Session;
    needsReceivingRatchet(session: Session, header: any): boolean;
    performReceivingRatchet(
      session: Session,
      kemCiphertext: Uint8Array,
    ): Session;
    applyPendingRatchet(session: Session): Session;
    getDecryptionChainForRatchetMessage(session: Session): RatchetChain | null;
    triggerRatchet(sessionId: string, session: Session): Promise<Session>;
  }

  export class ReplayProtection {
    getSkippedKeyId(
      ratchetPublicKey: Uint8Array,
      messageNumber: number,
    ): string;
    storeReceivedMessageId(session: Session, messageId: string): void;
    cleanupSkippedKeys(session: Session): void;
    getReplayProtectionStatus(
      sessionId: string,
      session: Session,
    ): Promise<{
      storedMessageIds: number;
      lastProcessedTimestamp: number;
      replayWindowSize: number;
    }>;
  }

  export class GroupManager {
    constructor(storage: StorageAdapter);
    initialize(identity: Identity): Promise<void>;
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

  export interface AegisIdentity {
    identity: Identity;
    publicBundle: PublicBundle;
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
}
