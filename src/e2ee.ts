import type {
  Group,
  GroupMessage,
  PublicBundle,
  Session,
  EncryptedMessage,
  StorageAdapter,
} from "./types";
import { Logger } from "./logger";
import { IdentityManager } from "./identity-manager";
import { SessionManager } from "./session-manager";
import { CryptoManager } from "./crypto-manager";
import { RatchetManager } from "./ratchet-manager";
import { ReplayProtection } from "./replay-protection";
import { GroupManager } from "./group-manager";

export class E2EE {
  private identityManager: IdentityManager;
  private sessionManager: SessionManager;
  private cryptoManager: CryptoManager;
  private ratchetManager: RatchetManager;
  private replayProtection: ReplayProtection;
  private groupManager: GroupManager;
  private storage: StorageAdapter;

  constructor(storage: StorageAdapter) {
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

  async createSession(peerBundle: PublicBundle) {
    const identity = await this.identityManager.getIdentity();
    return this.sessionManager.createSession(identity, peerBundle);
  }

  async createResponderSession(
    peerBundle: PublicBundle,
    ciphertext: Uint8Array,
    initiatorConfirmationMac?: Uint8Array,
  ) {
    const identity = await this.identityManager.getIdentity();
    return this.sessionManager.createResponderSession(
      identity,
      peerBundle,
      ciphertext,
      initiatorConfirmationMac,
    );
  }

  async confirmSession(
    sessionId: string,
    responderConfirmationMac: Uint8Array,
  ) {
    return this.sessionManager.confirmSession(
      sessionId,
      responderConfirmationMac,
    );
  }

  async getSessions() {
    return this.sessionManager.getSessions();
  }

  async cleanupOldSessions(maxAge?: number) {
    return this.sessionManager.cleanupOldSessions(maxAge);
  }

  async encryptMessage(sessionId: string, plaintext: string | Uint8Array) {
    const session = await this.storage.getSession(sessionId);
    if (!session) throw new Error("Session not found");

    const identity = await this.identityManager.getIdentity();

    const shouldRatchet = (session: Session) => {
      return this.ratchetManager.shouldPerformSendingRatchet(session);
    };

    const performSendingRatchet = (session: Session) => {
      return this.ratchetManager.performSendingRatchet(session);
    };

    const updateSessionState = async (sessionId: string, session: Session) => {
      await this.storage.saveSession(sessionId, session);
    };

    return this.cryptoManager.encryptMessage(
      sessionId,
      plaintext,
      identity,
      shouldRatchet,
      performSendingRatchet,
      updateSessionState,
    );
  }

  async decryptMessage(sessionId: string, encrypted: EncryptedMessage) {
    const session = await this.storage.getSession(sessionId);
    if (!session) throw new Error("Session not found");

    const needsReceivingRatchet = (session: Session, header: any) => {
      return this.ratchetManager.needsReceivingRatchet(session, header);
    };

    const performReceivingRatchet = (
      session: Session,
      kemCiphertext: Uint8Array,
    ) => {
      return this.ratchetManager.performReceivingRatchet(
        session,
        kemCiphertext,
      );
    };

    const getSkippedKeyId = (
      ratchetPublicKey: Uint8Array,
      messageNumber: number,
    ) => {
      return this.replayProtection.getSkippedKeyId(
        ratchetPublicKey,
        messageNumber,
      );
    };

    const storeReceivedMessageId = (session: Session, messageId: string) => {
      this.replayProtection.storeReceivedMessageId(session, messageId);
    };

    const cleanupSkippedKeys = (session: Session) => {
      this.replayProtection.cleanupSkippedKeys(session);
    };

    const applyPendingRatchet = (session: Session) => {
      return this.ratchetManager.applyPendingRatchet(session);
    };

    const getDecryptionChainForRatchetMessage = (session: Session) => {
      return this.ratchetManager.getDecryptionChainForRatchetMessage(session);
    };

    const updateSessionState = async (sessionId: string, session: Session) => {
      await this.storage.saveSession(sessionId, session);
    };

    return this.cryptoManager.decryptMessage(
      sessionId,
      encrypted,
      needsReceivingRatchet,
      performReceivingRatchet,
      getSkippedKeyId,
      storeReceivedMessageId,
      cleanupSkippedKeys,
      applyPendingRatchet,
      getDecryptionChainForRatchetMessage,
      updateSessionState,
    );
  }

  async triggerRatchet(sessionId: string) {
    const session = await this.storage.getSession(sessionId);
    if (!session) throw new Error("Session not found");

    const updatedSession = await this.ratchetManager.triggerRatchet(
      sessionId,
      session,
    );
    await this.storage.saveSession(sessionId, updatedSession);
  }

  async getReplayProtectionStatus(sessionId: string) {
    const session = await this.storage.getSession(sessionId);
    if (!session) throw new Error("Session not found");

    return this.replayProtection.getReplayProtectionStatus(sessionId, session);
  }

  async getConfirmationMac(sessionId: string): Promise<Uint8Array | null> {
    const session = await this.storage.getSession(sessionId);
    if (!session || !session.confirmationMac) {
      return null;
    }
    return session.confirmationMac;
  }

  getStorage(): StorageAdapter {
    return this.storage;
  }

  async createGroup(
    name: string,
    members: string[],
    memberKemPublicKeys: Map<string, Uint8Array>,
    memberDsaPublicKeys: Map<string, Uint8Array>,
  ): Promise<Group> {
    const identity = await this.identityManager.getIdentity();
    if (!identity) throw new Error("Identity not found");

    await this.groupManager.initialize(identity);
    return this.groupManager.createGroup(
      name,
      members,
      memberKemPublicKeys,
      memberDsaPublicKeys,
    );
  }

  async addGroupMember(
    groupId: string,
    userId: string,
    session: Session,
    userPublicKey: Uint8Array,
  ): Promise<void> {
    const identity = await this.identityManager.getIdentity();
    if (!identity) throw new Error("Identity not found");

    await this.groupManager.initialize(identity);
    return this.groupManager.addMember(groupId, userId, session, userPublicKey);
  }

  async removeGroupMember(groupId: string, userId: string): Promise<void> {
    const identity = await this.identityManager.getIdentity();
    if (!identity) throw new Error("Identity not found");

    await this.groupManager.initialize(identity);
    return this.groupManager.removeMember(groupId, userId);
  }

  async updateGroupKey(groupId: string): Promise<void> {
    const identity = await this.identityManager.getIdentity();
    if (!identity) throw new Error("Identity not found");

    await this.groupManager.initialize(identity);
    return this.groupManager.updateGroupKey(groupId);
  }

  async encryptGroupMessage(
    groupId: string,
    message: string | Uint8Array,
  ): Promise<GroupMessage> {
    const identity = await this.identityManager.getIdentity();
    if (!identity) throw new Error("Identity not found");

    await this.groupManager.initialize(identity);
    return this.groupManager.encryptMessage(groupId, message);
  }

  async decryptGroupMessage(
    groupId: string,
    encrypted: GroupMessage,
  ): Promise<Uint8Array> {
    const identity = await this.identityManager.getIdentity();
    if (!identity) throw new Error("Identity not found");

    await this.groupManager.initialize(identity);
    return this.groupManager.decryptMessage(groupId, encrypted);
  }

  async getGroup(groupId: string): Promise<Group | null> {
    return this.groupManager.getGroup(groupId);
  }

  async getGroups(): Promise<Group[]> {
    return this.groupManager.getGroups();
  }
}
