export interface GroupMember {
  userId: string;
  publicBundle: {
    kemPublicKey: Uint8Array;
    dsaPublicKey: Uint8Array;
  };
  joinedAt: number;
  role: "admin" | "member";
}

export interface GroupKeyPackage {
  groupId: string;
  epoch: number; // Increments on membership changes
  groupKey: Uint8Array; // Symmetric group key
  createdAt: number;
  createdBy: string;
}

export interface GroupState {
  groupId: string;
  name: string;
  creator: string;
  members: Map<string, GroupMember>;
  currentEpoch: number;
  keyHistory: Map<number, GroupKeyPackage>; // epoch -> key
  createdAt: number;
  lastModified: number;
  pendingProposals: GroupProposal[];
}

export interface GroupProposal {
  proposalId: string;
  type: "add" | "remove" | "update_key";
  proposer: string;
  timestamp: number;
  data: {
    userId?: string;
    publicBundle?: any;
    reason?: string;
  };
}

export interface EncryptedGroupMessage {
  groupId: string;
  epoch: number; // Which group key was used
  senderId: string;
  messageId: string;
  timestamp: number;
  ciphertext: Uint8Array; // Encrypted with group key
  signature: Uint8Array; // Signed by sender
  nonce: Uint8Array;
}

export interface WelcomeMessage {
  groupId: string;
  groupName: string;
  currentEpoch: number;
  groupKey: Uint8Array;
  members: GroupMember[];
  encryptedFor: string; // userId this welcome is for
  createdAt: number;
}

export interface GroupUpdate {
  groupId: string;
  updateType: "member_add" | "member_remove" | "key_rotation" | "admin_change";
  epoch: number;
  timestamp: number;
  data: any;
  signature: Uint8Array;
}

export interface SenderKeyState {
  userId: string;
  chainKey: Uint8Array;
  messageNumber: number;
  generationNumber: number; // Increments on key rotation
}

export interface GroupStorageAdapter {
  // Group management
  saveGroup(groupId: string, group: GroupState): Promise<void>;
  getGroup(groupId: string): Promise<GroupState | null>;
  deleteGroup(groupId: string): Promise<void>;
  listGroups(): Promise<string[]>;

  // Member management
  addMember(groupId: string, member: GroupMember): Promise<void>;
  removeMember(groupId: string, userId: string): Promise<void>;

  // Key management
  saveGroupKey(
    groupId: string,
    epoch: number,
    keyPackage: GroupKeyPackage,
  ): Promise<void>;
  getGroupKey(groupId: string, epoch: number): Promise<GroupKeyPackage | null>;

  // Sender keys (for sender key ratchet optimization)
  saveSenderKey(
    groupId: string,
    userId: string,
    state: SenderKeyState,
  ): Promise<void>;
  getSenderKey(groupId: string, userId: string): Promise<SenderKeyState | null>;
}
