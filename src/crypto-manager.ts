import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/post-quantum/utils.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type {
  Identity,
  Session,
  EncryptedMessage,
  StorageAdapter,
  MessageHeader,
  RatchetChain,
} from "./types";
import { Logger } from "./logger";
import { ERRORS, MAX_MESSAGE_AGE } from "./constants";
import { serializeHeader } from "./utils";
import { KemRatchet } from "./ratchet";

export class CryptoManager {
  private storage: StorageAdapter;

  constructor(storage: StorageAdapter) {
    this.storage = storage;
  }

  async encryptMessage(
    sessionId: string,
    plaintext: string | Uint8Array,
    identity: Identity,
    shouldRatchet: (session: Session) => boolean,
    performSendingRatchet: (session: Session) => {
      session: Session;
      kemCiphertext?: Uint8Array;
    },
    updateSessionState: (sessionId: string, session: Session) => Promise<void>,
  ): Promise<EncryptedMessage> {
    try {
      Logger.log("Encrypt", "Encrypting message");

      const session = await this.storage.getSession(sessionId);
      if (!session) throw new Error(ERRORS.SESSION_NOT_FOUND);

      if (!session.confirmed && session.state !== "CREATED") {
        throw new Error(ERRORS.SESSION_NOT_CONFIRMED);
      }

      const plaintextBytes =
        typeof plaintext === "string" ? utf8ToBytes(plaintext) : plaintext;

      const shouldRatchetResult = shouldRatchet(session);

      let kemCiphertext: Uint8Array | undefined;
      let updatedSession = session;

      if (shouldRatchetResult) {
        Logger.log(
          "Ratchet",
          "Performing sending KEM ratchet before encryption",
        );

        if (!session.peerRatchetPublicKey) {
          throw new Error("No peer ratchet public key available for ratchet");
        }

        const ratchetResult = performSendingRatchet(session);
        updatedSession = ratchetResult.session;
        kemCiphertext = ratchetResult.kemCiphertext;

        Logger.log("Ratchet", "Prepared sending KEM ratchet", {
          ratchetCount: updatedSession.ratchetCount,
        });
      } else if (session.pendingRatchetState) {
        kemCiphertext = session.pendingRatchetState.kemCiphertext;
        updatedSession = session;
        Logger.log("Ratchet", "Using pending ratchet ciphertext", {
          ratchetCount: session.ratchetCount,
        });
      }

      const chainToUse = kemCiphertext
        ? updatedSession.pendingRatchetState?.previousSendingChain ||
          session.sendingChain
        : updatedSession.sendingChain;

      if (!chainToUse) {
        throw new Error("No sending chain available");
      }

      const { messageKey, newChain } = KemRatchet.symmetricRatchet(chainToUse);

      const nonce = randomBytes(24);
      const cipher = xchacha20poly1305(messageKey, nonce);
      const ciphertext = cipher.encrypt(plaintextBytes);
      const fullciphertext = concatBytes(nonce, ciphertext);

      const ratchetPublicKey = updatedSession.currentRatchetKeyPair!.publicKey;

      const header: MessageHeader = {
        messageId: bytesToHex(blake3(fullciphertext, { dkLen: 32 })),
        ratchetPublicKey: ratchetPublicKey,
        messageNumber: chainToUse.messageNumber,
        previousChainLength: updatedSession.previousSendingChainLength,
        kemCiphertext: kemCiphertext,
        isRatchetMessage: kemCiphertext ? true : false,
        timestamp: Date.now(),
      };

      let confirmationMac: Uint8Array | undefined;
      if (updatedSession.state === "CREATED" && updatedSession.isInitiator) {
        confirmationMac = updatedSession.confirmationMac;
        Logger.log(
          "Session",
          "Including key confirmation MAC in first message",
        );
      }

      const headerBytes = serializeHeader(header);
      const messageToSign = concatBytes(headerBytes, fullciphertext);
      const signature = ml_dsa65.sign(
        messageToSign,
        identity.dsaKeyPair.secretKey,
      );

      let finalSessionState = updatedSession;

      if (kemCiphertext) {
        if (updatedSession.pendingRatchetState) {
          finalSessionState = {
            ...updatedSession,
            sendingChain: newChain,
            rootKey: updatedSession.pendingRatchetState.newRootKey,
            currentRatchetKeyPair:
              updatedSession.pendingRatchetState.newRatchetKeyPair,
            state: "ACTIVE",
          };
        }
      } else {
        finalSessionState.sendingChain = newChain;
      }

      finalSessionState.lastUsed = Date.now();

      if (
        finalSessionState.state === "CREATED" &&
        finalSessionState.isInitiator
      ) {
        finalSessionState.state = "KEY_CONFIRMED";
      }

      await updateSessionState(sessionId, finalSessionState);

      Logger.log("Encrypt", "Message encrypted", {
        messageNumber: header.messageNumber,
        ratchetCount: finalSessionState.ratchetCount,
        usedRatchetKey: shouldRatchetResult,
        state: finalSessionState.state,
        isRatchetMessage: !!kemCiphertext,
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
    needsReceivingRatchet: (session: Session, header: MessageHeader) => boolean,
    performReceivingRatchet: (
      session: Session,
      kemCiphertext: Uint8Array,
    ) => Session,
    getSkippedKeyId: (
      ratchetPublicKey: Uint8Array,
      messageNumber: number,
    ) => string,
    storeReceivedMessageId: (session: Session, messageId: string) => void,
    cleanupSkippedKeys: (session: Session) => void,
    applyPendingRatchet: (session: Session) => Session,
    getDecryptionChainForRatchetMessage: (
      session: Session,
    ) => RatchetChain | null,
    updateSessionState: (sessionId: string, session: Session) => Promise<void>,
  ): Promise<{ plaintext: Uint8Array; needsConfirmation?: boolean }> {
    try {
      Logger.log("Decrypt", "Decrypting message");

      const session = await this.storage.getSession(sessionId);
      if (!session) throw new Error(ERRORS.SESSION_NOT_FOUND);

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

      if (session.receivedMessageIds.has(encrypted.header.messageId)) {
        Logger.warn("Replay", "Duplicate message detected", {
          messageId: encrypted.header.messageId.substring(0, 16) + "...",
        });
        throw new Error(ERRORS.DUPLICATE_MESSAGE);
      }

      const now = Date.now();
      const messageAge = now - encrypted.header.timestamp;
      if (messageAge > MAX_MESSAGE_AGE) {
        Logger.warn("Replay", "Message too old", {
          age: `${Math.round(messageAge / 1000)}s`,
          maxAge: `${MAX_MESSAGE_AGE / 1000}s`,
        });
        throw new Error(ERRORS.MESSAGE_TOO_OLD_TIMESTAMP);
      }

      session.lastProcessedTimestamp = now;

      if (
        encrypted.confirmationMac &&
        !session.isInitiator &&
        session.state === "CREATED"
      ) {
        Logger.log("Session", "Processing key confirmation from initiator");

        const isValidConfirmation = KemRatchet.verifyConfirmationMac(
          sessionId,
          session.rootKey,
          session.receivingChain!.chainKey,
          encrypted.confirmationMac,
          false,
        );

        if (isValidConfirmation) {
          session.confirmed = true;
          session.state = "KEY_CONFIRMED";
          Logger.log("Session", "Key confirmation received and verified");
        } else {
          session.state = "ERROR";
          await updateSessionState(sessionId, session);
          throw new Error(ERRORS.KEY_CONFIRMATION_FAILED);
        }
      }

      const needsRatchet = needsReceivingRatchet(session, encrypted.header);

      let updatedSession = session;
      let isRatchetMessage = false;

      if (needsRatchet && encrypted.header.kemCiphertext) {
        Logger.log("Ratchet", "Performing receiving KEM ratchet");

        if (!session.currentRatchetKeyPair?.secretKey) {
          throw new Error("No current ratchet secret key available");
        }

        updatedSession = performReceivingRatchet(
          session,
          encrypted.header.kemCiphertext,
        );

        updatedSession.peerRatchetPublicKey = encrypted.header.ratchetPublicKey;
        updatedSession.previousSendingChainLength =
          session.sendingChain?.messageNumber ?? 0;

        isRatchetMessage = true;

        Logger.log("Ratchet", "Received KEM ratchet", {
          ratchetCount: updatedSession.ratchetCount,
          peerKeyHash:
            bytesToHex(encrypted.header.ratchetPublicKey).substring(0, 16) +
            "...",
        });
      } else if (needsRatchet && !encrypted.header.kemCiphertext) {
        throw new Error(ERRORS.RATCHET_CIPHERTEXT_MISSING);
      }

      if (
        !updatedSession.peerRatchetPublicKey &&
        encrypted.header.ratchetPublicKey
      ) {
        updatedSession.peerRatchetPublicKey = encrypted.header.ratchetPublicKey;
        Logger.log("Session", "Stored peer ratchet public key", {
          keyHash:
            bytesToHex(encrypted.header.ratchetPublicKey).substring(0, 16) +
            "...",
        });
      }

      const skippedKeyId = getSkippedKeyId(
        encrypted.header.ratchetPublicKey,
        encrypted.header.messageNumber,
      );

      const skippedKey = updatedSession.skippedMessageKeys.get(skippedKeyId);
      if (skippedKey) {
        Logger.log("Decrypt", "Using skipped message key", {
          messageNumber: encrypted.header.messageNumber,
        });

        const plaintext = this.decryptWithKey(
          encrypted.ciphertext,
          skippedKey.messageKey,
        );

        storeReceivedMessageId(updatedSession, encrypted.header.messageId);

        updatedSession.skippedMessageKeys.delete(skippedKeyId);
        updatedSession.lastUsed = Date.now();
        await updateSessionState(sessionId, updatedSession);
        return { plaintext };
      }

      let chainToUseForDecryption: RatchetChain | null;

      if (isRatchetMessage) {
        chainToUseForDecryption =
          getDecryptionChainForRatchetMessage(updatedSession);
      } else {
        // If we have a pending ratchet and this message doesn't seem to fit the current receiving chain,
        // it might be the first message acknowledging our ratchet.
        if (
          updatedSession.state === "RATCHET_PENDING" &&
          updatedSession.pendingRatchetState &&
          encrypted.header.messageNumber <
            updatedSession.receivingChain!.messageNumber
        ) {
          chainToUseForDecryption =
            updatedSession.pendingRatchetState.receivingChain;
          Logger.log(
            "Decrypt",
            "Message number is lower than current chain, trying pending ratchet chain",
          );
        } else {
          chainToUseForDecryption = updatedSession.receivingChain;
        }
      }

      if (
        chainToUseForDecryption &&
        encrypted.header.messageNumber > chainToUseForDecryption.messageNumber
      ) {
        const skipCount =
          encrypted.header.messageNumber -
          chainToUseForDecryption.messageNumber;

        if (skipCount > updatedSession.maxSkippedMessages) {
          throw new Error(
            `Cannot skip ${skipCount} messages, max is ${updatedSession.maxSkippedMessages}`,
          );
        }

        Logger.log("Decrypt", "Skipping message keys", {
          from: chainToUseForDecryption.messageNumber,
          to: encrypted.header.messageNumber,
          count: skipCount,
        });

        const { skippedKeys, newChain } = KemRatchet.skipMessageKeys(
          chainToUseForDecryption,
          encrypted.header.messageNumber,
          updatedSession.maxSkippedMessages,
        );

        for (const [msgNum, msgKey] of skippedKeys) {
          const keyId = getSkippedKeyId(
            encrypted.header.ratchetPublicKey,
            msgNum,
          );
          updatedSession.skippedMessageKeys.set(keyId, {
            messageKey: msgKey,
            timestamp: Date.now(),
          });
        }

        chainToUseForDecryption = newChain;
      }

      if (!chainToUseForDecryption) {
        throw new Error("No receiving chain available for decryption");
      }

      const { messageKey, newChain } = KemRatchet.symmetricRatchet(
        chainToUseForDecryption,
      );

      const plaintext = this.decryptWithKey(encrypted.ciphertext, messageKey);

      if (isRatchetMessage) {
        // Chains are already updated in updatedSession by performReceivingRatchet
      } else {
        updatedSession.receivingChain = newChain;
      }

      updatedSession.highestReceivedMessageNumber = Math.max(
        updatedSession.highestReceivedMessageNumber,
        encrypted.header.messageNumber,
      );
      updatedSession.lastUsed = Date.now();

      storeReceivedMessageId(updatedSession, encrypted.header.messageId);

      cleanupSkippedKeys(updatedSession);

      const needsConfirmation =
        !updatedSession.isInitiator &&
        encrypted.confirmationMac &&
        updatedSession.state === "KEY_CONFIRMED" &&
        !updatedSession.confirmed;

      if (needsConfirmation) {
        updatedSession.confirmed = true;
        Logger.log("Session", "Ready to send key confirmation response");
      }

      if (updatedSession.pendingRatchetState) {
        if (isRatchetMessage) {
          updatedSession = applyPendingRatchet(updatedSession);
        } else if (
          chainToUseForDecryption ===
          updatedSession.pendingRatchetState.receivingChain
        ) {
          updatedSession = applyPendingRatchet(updatedSession);
        }
      }

      // Ensure session state is properly updated atomically
      await updateSessionState(sessionId, updatedSession);

      Logger.log("Decrypt", "Message decrypted successfully", {
        messageNumber: encrypted.header.messageNumber,
        ratchetCount: updatedSession.ratchetCount,
        state: updatedSession.state,
        isRatchetMessage,
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

  private decryptWithKey(
    ciphertext: Uint8Array,
    messageKey: Uint8Array,
  ): Uint8Array {
    const nonce = ciphertext.slice(0, 24);
    const encryptedData = ciphertext.slice(24);
    const cipher = xchacha20poly1305(messageKey, nonce);
    return cipher.decrypt(encryptedData);
  }
}
