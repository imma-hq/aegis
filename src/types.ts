// src/types.ts
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
  pendingRatchetCiphertext?: Uint8Array;
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

  // Simple replay protection
  receivedMessageIds: Set<string>; // Store last N message IDs
  replayWindowSize: number; // Allow messages N numbers behind
  lastProcessedTimestamp: number; // Last valid message timestamp
}

export interface MessageHeader {
  messageId: string;
  ratchetPublicKey: Uint8Array;
  messageNumber: number;
  previousChainLength: number;
  kemCiphertext?: Uint8Array;
  isRatchetMessage?: boolean;
  timestamp: number; // Simple timestamp for freshness
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
