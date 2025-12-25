import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { randomBytes } from "@noble/post-quantum/utils.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import type {
  Identity,
  PublicBundle,
  Session,
  EncryptedMessage,
  StorageAdapter,
  MessageHeader,
} from "./types.js";
import { Logger } from "./logger.js";
import {
  ERRORS,
  RATCHET_AFTER_MESSAGES,
  MAX_SKIPPED_MESSAGES,
  REPLAY_WINDOW_SIZE,
  MAX_MESSAGE_AGE,
  MAX_STORED_MESSAGE_IDS,
} from "./constants.js";
import { validatePublicBundle, serializeHeader } from "./utils.js";
import { PreKeyManager } from "./prekey-manager.js";
import { SessionKeyExchange } from "./session.js";
import { KemRatchet } from "./ratchet.js";

export class E2EE {
  private storage: StorageAdapter;
  private preKeyManager: PreKeyManager;

  constructor(storage: StorageAdapter) {
    this.storage = storage;
    this.preKeyManager = new PreKeyManager();
    Logger.log("E2EE", "Initialized with storage adapter");
  }

  async createIdentity(): Promise<{
    identity: Identity;
    publicBundle: PublicBundle;
  }> {
    try {
      Logger.log("Identity", "Creating new identity");

      const kemKeyPair = ml_kem768.keygen();
      const dsaKeyPair = ml_dsa65.keygen();

      const userId = bytesToHex(
        blake3(concatBytes(kemKeyPair.publicKey, dsaKeyPair.publicKey), {
          dkLen: 32,
        }),
      );

      const preKeyPair = ml_kem768.keygen();
      const preKeySignature = ml_dsa65.sign(
        preKeyPair.publicKey,
        dsaKeyPair.secretKey,
      );

      const preKey = {
        id: 1,
        keyPair: preKeyPair,
        signature: preKeySignature,
        used: false,
        createdAt: Date.now(),
      };

      await this.preKeyManager.savePreKey(preKey);

      const identity: Identity = {
        kemKeyPair,
        dsaKeyPair,
        userId,
        createdAt: Date.now(),
        preKeySecret: preKeyPair.secretKey,
      };

      const publicBundle: PublicBundle = {
        userId,
        kemPublicKey: kemKeyPair.publicKey,
        dsaPublicKey: dsaKeyPair.publicKey,
        preKey: {
          id: preKey.id,
          key: preKeyPair.publicKey,
          signature: preKeySignature,
        },
        createdAt: Date.now(),
      };

      await this.storage.saveIdentity(identity);

      Logger.log("Identity", "Identity created successfully", {
        userId: userId.substring(0, 16) + "...",
      });

      return { identity, publicBundle };
    } catch (error) {
      Logger.error("Identity", "Failed to create identity", error);
      throw error;
    }
  }

  async createSession(peerBundle: PublicBundle): Promise<{
    sessionId: string;
    ciphertext: Uint8Array;
    confirmationMac: Uint8Array;
  }> {
    try {
      Logger.log("Session", "Creating new session as initiator");

      const identity = await this.getIdentity();
      validatePublicBundle(peerBundle);

      const isValid = ml_dsa65.verify(
        peerBundle.preKey.signature,
        peerBundle.preKey.key,
        peerBundle.dsaPublicKey,
      );

      if (!isValid) {
        throw new Error(ERRORS.INVALID_PREKEY_SIGNATURE);
      }

      const { sessionId, rootKey, chainKey, ciphertext, confirmationMac } =
        SessionKeyExchange.createInitiatorSession(identity, peerBundle);

      const ratchetKeyPair = ml_kem768.keygen();

      const session: Session = {
        sessionId,
        peerUserId: peerBundle.userId,
        peerDsaPublicKey: peerBundle.dsaPublicKey,
        rootKey,
        currentRatchetKeyPair: ratchetKeyPair,
        peerRatchetPublicKey: null,
        sendingChain: {
          chainKey,
          messageNumber: 0,
        },
        receivingChain: null,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map(),
        highestReceivedMessageNumber: -1,
        maxSkippedMessages: MAX_SKIPPED_MESSAGES,
        createdAt: Date.now(),
        lastUsed: Date.now(),
        isInitiator: true,
        ratchetCount: 0,
        state: "CREATED",
        confirmed: false,
        confirmationMac,

        // Simple replay protection
        receivedMessageIds: new Set<string>(),
        replayWindowSize: REPLAY_WINDOW_SIZE,
        lastProcessedTimestamp: Date.now(),
      };

      await this.storage.saveSession(sessionId, session);

      Logger.log("Session", "Session created successfully as initiator", {
        sessionId: sessionId.substring(0, 16) + "...",
      });

      return { sessionId, ciphertext, confirmationMac };
    } catch (error) {
      Logger.error("Session", "Failed to create session", error);
      throw error;
    }
  }

  async createResponderSession(
    peerBundle: PublicBundle,
    ciphertext: Uint8Array,
    initiatorConfirmationMac?: Uint8Array,
  ): Promise<{
    sessionId: string;
    confirmationMac: Uint8Array;
    isValid: boolean;
  }> {
    try {
      Logger.log("Session", "Creating session as responder");

      const identity = await this.getIdentity();
      validatePublicBundle(peerBundle);

      const isValidSignature = ml_dsa65.verify(
        peerBundle.preKey.signature,
        peerBundle.preKey.key,
        peerBundle.dsaPublicKey,
      );

      if (!isValidSignature) {
        throw new Error(ERRORS.INVALID_PREKEY_SIGNATURE);
      }

      const { sessionId, rootKey, chainKey, confirmationMac, isValid } =
        SessionKeyExchange.createResponderSession(
          identity,
          peerBundle,
          ciphertext,
          initiatorConfirmationMac,
        );

      if (!isValid && initiatorConfirmationMac) {
        throw new Error(ERRORS.KEY_CONFIRMATION_FAILED);
      }

      const ratchetKeyPair = ml_kem768.keygen();

      const session: Session = {
        sessionId,
        peerUserId: peerBundle.userId,
        peerDsaPublicKey: peerBundle.dsaPublicKey,
        rootKey,
        currentRatchetKeyPair: ratchetKeyPair,
        peerRatchetPublicKey: null,
        sendingChain: {
          chainKey,
          messageNumber: 0,
        },
        receivingChain: null,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map(),
        highestReceivedMessageNumber: -1,
        maxSkippedMessages: MAX_SKIPPED_MESSAGES,
        createdAt: Date.now(),
        lastUsed: Date.now(),
        isInitiator: false,
        ratchetCount: 0,
        state: "CREATED",
        confirmed: isValid && initiatorConfirmationMac !== undefined,
        confirmationMac,

        // Simple replay protection
        receivedMessageIds: new Set<string>(),
        replayWindowSize: REPLAY_WINDOW_SIZE,
        lastProcessedTimestamp: Date.now(),
      };

      await this.storage.saveSession(sessionId, session);

      Logger.log("Session", "Session created as responder", {
        sessionId: sessionId.substring(0, 16) + "...",
        keyConfirmed: session.confirmed,
      });

      return { sessionId, confirmationMac, isValid };
    } catch (error) {
      Logger.error("Session", "Failed to create responder session", error);
      throw error;
    }
  }

  async confirmSession(
    sessionId: string,
    responderConfirmationMac: Uint8Array,
  ): Promise<boolean> {
    try {
      Logger.log("Session", "Confirming session keys");

      const session = await this.storage.getSession(sessionId);
      if (!session) throw new Error(ERRORS.SESSION_NOT_FOUND);

      if (!session.sendingChain) {
        throw new Error("No sending chain available");
      }

      const isValid = SessionKeyExchange.verifyKeyConfirmation(
        sessionId,
        session.rootKey,
        session.sendingChain.chainKey,
        responderConfirmationMac,
      );

      if (isValid) {
        session.confirmed = true;
        session.state = "KEY_CONFIRMED";
        await this.storage.saveSession(sessionId, session);

        Logger.log("Session", "Session keys confirmed successfully");
      } else {
        session.state = "ERROR";
        await this.storage.saveSession(sessionId, session);
        Logger.warn("Session", "Key confirmation failed");
      }

      return isValid;
    } catch (error) {
      Logger.error("Session", "Failed to confirm session", error);
      throw error;
    }
  }

  async encryptMessage(
    sessionId: string,
    plaintext: string | Uint8Array,
  ): Promise<EncryptedMessage> {
    try {
      Logger.log("Encrypt", "Encrypting message");

      const session = await this.storage.getSession(sessionId);
      if (!session) throw new Error(ERRORS.SESSION_NOT_FOUND);

      if (!session.confirmed && session.state !== "CREATED") {
        throw new Error(ERRORS.SESSION_NOT_CONFIRMED);
      }

      const identity = await this.getIdentity();
      const plaintextBytes =
        typeof plaintext === "string" ? utf8ToBytes(plaintext) : plaintext;

      // Check if we should perform a sending KEM ratchet
      const shouldRatchet = this.shouldPerformSendingRatchet(session);

      let kemCiphertext: Uint8Array | undefined;

      if (shouldRatchet) {
        Logger.log(
          "Ratchet",
          "Performing sending KEM ratchet before encryption",
        );

        if (!session.peerRatchetPublicKey) {
          throw new Error("No peer ratchet public key available for ratchet");
        }

        const result = KemRatchet.performKemRatchetEncapsulate(
          session.rootKey,
          session.peerRatchetPublicKey,
        );

        // Update session state
        session.rootKey = result.newRootKey;
        session.currentRatchetKeyPair = result.newRatchetKeyPair;
        session.previousSendingChainLength =
          session.sendingChain?.messageNumber ?? 0;
        session.sendingChain = result.sendingChain;
        session.pendingRatchetCiphertext = result.kemCiphertext;
        kemCiphertext = result.kemCiphertext;

        // If we're the initiator and this is our first ratchet, set receiving chain too
        if (!session.receivingChain && session.isInitiator) {
          session.receivingChain = result.receivingChain;
        }

        session.ratchetCount++;
        session.state = "RATCHET_PENDING";

        Logger.log("Ratchet", "Sent KEM ratchet", {
          ratchetCount: session.ratchetCount,
          newKeyHash:
            bytesToHex(result.newRatchetKeyPair.publicKey).substring(0, 16) +
            "...",
        });
      }

      if (!session.sendingChain) {
        throw new Error("No sending chain available");
      }

      // Symmetric ratchet for this message
      const { messageKey, newChain } = KemRatchet.symmetricRatchet(
        session.sendingChain,
      );

      // Encrypt
      const nonce = randomBytes(24);
      const cipher = xchacha20poly1305(messageKey, nonce);
      const ciphertext = cipher.encrypt(plaintextBytes);
      const fullciphertext = concatBytes(nonce, ciphertext);

      // Create header with timestamp for replay protection
      const header: MessageHeader = {
        messageId: bytesToHex(blake3(fullciphertext, { dkLen: 32 })),
        ratchetPublicKey: session.currentRatchetKeyPair!.publicKey,
        messageNumber: session.sendingChain.messageNumber,
        previousChainLength: session.previousSendingChainLength,
        kemCiphertext: kemCiphertext,
        isRatchetMessage: shouldRatchet,
        timestamp: Date.now(), // Timestamp for replay protection
      };

      // Include confirmation MAC if this is the first message from initiator
      let confirmationMac: Uint8Array | undefined;
      if (session.state === "CREATED" && session.isInitiator) {
        confirmationMac = session.confirmationMac;
        Logger.log(
          "Session",
          "Including key confirmation MAC in first message",
        );
      }

      // Sign
      const headerBytes = serializeHeader(header);
      const messageToSign = concatBytes(headerBytes, fullciphertext);
      const signature = ml_dsa65.sign(
        messageToSign,
        identity.dsaKeyPair.secretKey,
      );

      // Update session
      session.sendingChain = newChain;
      session.lastUsed = Date.now();

      if (session.state === "CREATED" && session.isInitiator) {
        session.state = "KEY_CONFIRMED";
      } else if (session.state === "RATCHET_PENDING") {
        session.state = "ACTIVE";
      }

      await this.storage.saveSession(sessionId, session);

      Logger.log("Encrypt", "Message encrypted", {
        messageNumber: header.messageNumber,
        ratchetCount: session.ratchetCount,
        usedRatchetKey: shouldRatchet,
        state: session.state,
      });

      return {
        ciphertext: fullciphertext,
        header,
        signature,
        confirmationMac,
      };
    } catch (error) {
      Logger.error("Encrypt", "Failed to encrypt message", error);
      throw error;
    }
  }

  async decryptMessage(
    sessionId: string,
    encrypted: EncryptedMessage,
  ): Promise<{ plaintext: Uint8Array; needsConfirmation?: boolean }> {
    try {
      Logger.log("Decrypt", "Decrypting message");

      const session = await this.storage.getSession(sessionId);
      if (!session) throw new Error(ERRORS.SESSION_NOT_FOUND);

      // 1. Verify signature first
      const headerBytes = serializeHeader(encrypted.header);
      const messageToVerify = concatBytes(headerBytes, encrypted.ciphertext);
      const isValid = ml_dsa65.verify(
        encrypted.signature,
        messageToVerify,
        session.peerDsaPublicKey,
      );

      if (!isValid) {
        throw new Error(ERRORS.INVALID_MESSAGE_SIGNATURE);
      }

      // 2. Check for duplicate message (Simple replay protection)
      if (session.receivedMessageIds.has(encrypted.header.messageId)) {
        Logger.warn("Replay", "Duplicate message detected", {
          messageId: encrypted.header.messageId.substring(0, 16) + "...",
        });
        throw new Error(ERRORS.DUPLICATE_MESSAGE);
      }

      // 3. Check message freshness (Simple timestamp check)
      const now = Date.now();
      const messageAge = now - encrypted.header.timestamp;
      if (messageAge > MAX_MESSAGE_AGE) {
        Logger.warn("Replay", "Message too old", {
          age: `${Math.round(messageAge / 1000)}s`,
          maxAge: `${MAX_MESSAGE_AGE / 1000}s`,
        });
        throw new Error(ERRORS.MESSAGE_TOO_OLD_TIMESTAMP);
      }

      // Update last processed timestamp
      session.lastProcessedTimestamp = now;

      // Handle key confirmation if this is the first message from initiator
      if (
        encrypted.confirmationMac &&
        !session.isInitiator &&
        session.state === "CREATED"
      ) {
        Logger.log("Session", "Processing key confirmation from initiator");

        const isValidConfirmation = KemRatchet.verifyConfirmationMac(
          sessionId,
          session.rootKey,
          session.sendingChain!.chainKey,
          encrypted.confirmationMac,
          false,
        );

        if (isValidConfirmation) {
          session.confirmed = true;
          session.state = "KEY_CONFIRMED";
          Logger.log("Session", "Key confirmation received and verified");
        } else {
          session.state = "ERROR";
          await this.storage.saveSession(sessionId, session);
          throw new Error(ERRORS.KEY_CONFIRMATION_FAILED);
        }
      }

      // Check if we need to perform receiving KEM ratchet
      const needsRatchet = this.needsReceivingRatchet(
        session,
        encrypted.header,
      );

      if (needsRatchet && encrypted.header.kemCiphertext) {
        Logger.log("Ratchet", "Performing receiving KEM ratchet");

        if (!session.currentRatchetKeyPair?.secretKey) {
          throw new Error("No current ratchet secret key available");
        }

        const result = KemRatchet.performKemRatchetDecapsulate(
          session.rootKey,
          encrypted.header.kemCiphertext,
          session.currentRatchetKeyPair.secretKey,
        );

        // Update session
        session.rootKey = result.newRootKey;
        session.currentRatchetKeyPair = result.newRatchetKeyPair;
        session.peerRatchetPublicKey = encrypted.header.ratchetPublicKey;
        session.previousSendingChainLength =
          session.sendingChain?.messageNumber ?? 0;
        session.pendingRatchetCiphertext = undefined;

        // Reset chains with new keys
        session.sendingChain = result.sendingChain;
        session.receivingChain = result.receivingChain;

        session.ratchetCount++;
        session.state = "ACTIVE";

        Logger.log("Ratchet", "Received KEM ratchet", {
          ratchetCount: session.ratchetCount,
          peerKeyHash:
            bytesToHex(encrypted.header.ratchetPublicKey).substring(0, 16) +
            "...",
        });
      } else if (needsRatchet && !encrypted.header.kemCiphertext) {
        throw new Error(ERRORS.RATCHET_CIPHERTEXT_MISSING);
      }

      // Store the peer's ratchet public key if this is first time we see it
      if (!session.peerRatchetPublicKey && encrypted.header.ratchetPublicKey) {
        session.peerRatchetPublicKey = encrypted.header.ratchetPublicKey;
        Logger.log("Session", "Stored peer ratchet public key", {
          keyHash:
            bytesToHex(encrypted.header.ratchetPublicKey).substring(0, 16) +
            "...",
        });
      }

      // Try skipped keys first (for out-of-order messages)
      const skippedKeyId = this.getSkippedKeyId(
        encrypted.header.ratchetPublicKey,
        encrypted.header.messageNumber,
      );

      const skippedKey = session.skippedMessageKeys.get(skippedKeyId);
      if (skippedKey) {
        Logger.log("Decrypt", "Using skipped message key", {
          messageNumber: encrypted.header.messageNumber,
        });

        const plaintext = this.decryptWithKey(
          encrypted.ciphertext,
          skippedKey.messageKey,
        );

        // Store message ID after successful decryption
        this.storeReceivedMessageId(session, encrypted.header.messageId);

        session.skippedMessageKeys.delete(skippedKeyId);
        session.lastUsed = Date.now();
        await this.storage.saveSession(sessionId, session);
        return { plaintext };
      }

      // Handle out-of-order messages by skipping ahead
      if (
        session.receivingChain &&
        encrypted.header.messageNumber > session.receivingChain.messageNumber
      ) {
        const skipCount =
          encrypted.header.messageNumber - session.receivingChain.messageNumber;

        // Simple replay protection: reject messages too far in the future
        if (skipCount > session.maxSkippedMessages) {
          throw new Error(
            `Cannot skip ${skipCount} messages, max is ${session.maxSkippedMessages}`,
          );
        }

        Logger.log("Decrypt", "Skipping message keys", {
          from: session.receivingChain.messageNumber,
          to: encrypted.header.messageNumber,
          count: skipCount,
        });

        const { skippedKeys, newChain } = KemRatchet.skipMessageKeys(
          session.receivingChain,
          encrypted.header.messageNumber,
          session.maxSkippedMessages,
        );

        // Store skipped keys for potential future out-of-order messages
        for (const [msgNum, msgKey] of skippedKeys) {
          const keyId = this.getSkippedKeyId(
            encrypted.header.ratchetPublicKey,
            msgNum,
          );
          session.skippedMessageKeys.set(keyId, {
            messageKey: msgKey,
            timestamp: Date.now(),
          });
        }

        session.receivingChain = newChain;
      }

      // Decrypt current message
      if (!session.receivingChain) {
        // First message received - initialize receiving chain
        if (!session.sendingChain) {
          throw new Error("No chain available for decryption");
        }
        session.receivingChain = {
          chainKey: session.sendingChain.chainKey,
          messageNumber: 0,
        };
      }

      const { messageKey, newChain } = KemRatchet.symmetricRatchet(
        session.receivingChain,
      );

      const plaintext = this.decryptWithKey(encrypted.ciphertext, messageKey);

      // Update session state
      session.receivingChain = newChain;
      session.highestReceivedMessageNumber = Math.max(
        session.highestReceivedMessageNumber,
        encrypted.header.messageNumber,
      );
      session.lastUsed = Date.now();

      // Store message ID after successful decryption
      this.storeReceivedMessageId(session, encrypted.header.messageId);

      // Cleanup old skipped keys
      this.cleanupSkippedKeys(session);

      // Check if we need to send confirmation response
      const needsConfirmation =
        !session.isInitiator &&
        encrypted.confirmationMac &&
        session.state === "KEY_CONFIRMED" &&
        !session.confirmed;

      if (needsConfirmation) {
        session.confirmed = true;
        Logger.log("Session", "Ready to send key confirmation response");
      }

      await this.storage.saveSession(sessionId, session);

      Logger.log("Decrypt", "Message decrypted successfully", {
        messageNumber: encrypted.header.messageNumber,
        ratchetCount: session.ratchetCount,
        state: session.state,
      });

      return {
        plaintext,
        needsConfirmation: needsConfirmation,
      };
    } catch (error) {
      Logger.error("Decrypt", "Failed to decrypt message", error);
      throw error;
    }
  }

  private shouldPerformSendingRatchet(session: Session): boolean {
    const messageCount = session.sendingChain?.messageNumber || 0;
    const isFirstMessageAsInitiator = session.isInitiator && messageCount === 0;

    return (
      session.peerRatchetPublicKey !== null &&
      !isFirstMessageAsInitiator &&
      messageCount >= RATCHET_AFTER_MESSAGES
    );
  }

  private needsReceivingRatchet(
    session: Session,
    header: MessageHeader,
  ): boolean | null {
    return (
      header.isRatchetMessage === true ||
      session.pendingRatchetCiphertext !== undefined ||
      (session.peerRatchetPublicKey &&
        bytesToHex(header.ratchetPublicKey) !==
          bytesToHex(session.peerRatchetPublicKey))
    );
  }

  private decryptWithKey(
    ciphertext: Uint8Array,
    messageKey: Uint8Array,
  ): Uint8Array {
    const nonce = ciphertext.slice(0, 24);
    const encryptedData = ciphertext.slice(24);
    const cipher = xchacha20poly1305(messageKey, nonce);
    return cipher.decrypt(encryptedData);
  }

  private getSkippedKeyId(
    ratchetPublicKey: Uint8Array,
    messageNumber: number,
  ): string {
    return `${bytesToHex(ratchetPublicKey)}:${messageNumber}`;
  }

  private cleanupSkippedKeys(session: Session): void {
    const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
    const now = Date.now();

    for (const [keyId, key] of session.skippedMessageKeys.entries()) {
      if (now - key.timestamp > maxAge) {
        session.skippedMessageKeys.delete(keyId);
      }
    }
  }

  // Simple replay protection: Store received message IDs
  private storeReceivedMessageId(session: Session, messageId: string): void {
    session.receivedMessageIds.add(messageId);

    // Keep the set size manageable
    if (session.receivedMessageIds.size > MAX_STORED_MESSAGE_IDS) {
      // Remove oldest entries (Set doesn't have order, so we recreate)
      const ids = Array.from(session.receivedMessageIds);
      session.receivedMessageIds = new Set(ids.slice(-MAX_STORED_MESSAGE_IDS));
    }
  }

  private async getIdentity(): Promise<Identity> {
    const identity = await this.storage.getIdentity();
    if (!identity) throw new Error(ERRORS.IDENTITY_NOT_FOUND);
    return identity;
  }

  async getPublicBundle(): Promise<PublicBundle> {
    const identity = await this.getIdentity();
    const preKey = await this.preKeyManager.getUnusedPreKey();

    if (!preKey) {
      const newPreKey = await this.preKeyManager.generatePreKey(identity);
      return {
        userId: identity.userId,
        kemPublicKey: identity.kemKeyPair.publicKey,
        dsaPublicKey: identity.dsaKeyPair.publicKey,
        preKey: {
          id: newPreKey.id,
          key: newPreKey.keyPair.publicKey,
          signature: newPreKey.signature,
        },
        createdAt: identity.createdAt,
      };
    }

    return {
      userId: identity.userId,
      kemPublicKey: identity.kemKeyPair.publicKey,
      dsaPublicKey: identity.dsaKeyPair.publicKey,
      preKey: {
        id: preKey.id,
        key: preKey.keyPair.publicKey,
        signature: preKey.signature,
      },
      createdAt: identity.createdAt,
    };
  }

  async getSessions(): Promise<Session[]> {
    const sessionIds = await this.storage.listSessions();
    const sessions: Session[] = [];

    for (const sessionId of sessionIds) {
      const session = await this.storage.getSession(sessionId);
      if (session) {
        sessions.push(session);
      }
    }

    return sessions;
  }

  async rotateIdentity(): Promise<{
    identity: Identity;
    publicBundle: PublicBundle;
  }> {
    const result = await this.createIdentity();
    await this.storage.deleteAllSessions();
    this.preKeyManager.clear();
    return result;
  }

  // Get confirmation MAC for responder to send back to initiator
  async getConfirmationMac(sessionId: string): Promise<Uint8Array | null> {
    const session = await this.storage.getSession(sessionId);
    if (!session || !session.confirmationMac) {
      return null;
    }
    return session.confirmationMac;
  }

  // Cleanup old sessions
  async cleanupOldSessions(maxAge?: number): Promise<void> {
    const sessions = await this.getSessions();
    const cutoff = Date.now() - (maxAge || 30 * 24 * 60 * 60 * 1000); // Default 30 days

    for (const session of sessions) {
      if (session.lastUsed < cutoff) {
        await this.storage.deleteSession(session.sessionId);
        Logger.log("Cleanup", "Removed old session", {
          sessionId: session.sessionId.substring(0, 16) + "...",
          age:
            Math.round(
              (Date.now() - session.lastUsed) / (1000 * 60 * 60 * 24),
            ) + " days",
        });
      }
    }
  }

  // Helper method to manually trigger a ratchet (for testing)
  async triggerRatchet(sessionId: string): Promise<void> {
    const session = await this.storage.getSession(sessionId);
    if (!session) throw new Error(ERRORS.SESSION_NOT_FOUND);

    if (!session.peerRatchetPublicKey) {
      throw new Error("No peer ratchet public key available");
    }

    const result = KemRatchet.performKemRatchetEncapsulate(
      session.rootKey,
      session.peerRatchetPublicKey,
    );

    session.rootKey = result.newRootKey;
    session.currentRatchetKeyPair = result.newRatchetKeyPair;
    session.previousSendingChainLength =
      session.sendingChain?.messageNumber ?? 0;
    session.sendingChain = result.sendingChain;
    session.pendingRatchetCiphertext = result.kemCiphertext;
    session.ratchetCount++;
    session.state = "RATCHET_PENDING";

    await this.storage.saveSession(sessionId, session);

    Logger.log("Ratchet", "Manually triggered ratchet", {
      sessionId: sessionId.substring(0, 16) + "...",
      newRatchetCount: session.ratchetCount,
    });
  }

  // Simple method to check replay protection status
  async getReplayProtectionStatus(sessionId: string): Promise<{
    storedMessageIds: number;
    lastProcessedTimestamp: number;
    replayWindowSize: number;
  }> {
    const session = await this.storage.getSession(sessionId);
    if (!session) throw new Error(ERRORS.SESSION_NOT_FOUND);

    return {
      storedMessageIds: session.receivedMessageIds.size,
      lastProcessedTimestamp: session.lastProcessedTimestamp,
      replayWindowSize: session.replayWindowSize,
    };
  }
}
