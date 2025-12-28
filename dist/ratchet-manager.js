import { bytesToHex } from "@noble/hashes/utils.js";
import { Logger } from "./logger.js";
import { RATCHET_AFTER_MESSAGES } from "./constants.js";
import { KemRatchet } from "./ratchet.js";
export class RatchetManager {
    shouldPerformSendingRatchet(session) {
        const messageCount = session.sendingChain?.messageNumber || 0;
        const isFirstMessageAsInitiator = session.isInitiator && messageCount === 0;
        return (session.peerRatchetPublicKey !== null &&
            !isFirstMessageAsInitiator &&
            messageCount >= RATCHET_AFTER_MESSAGES);
    }
    needsReceivingRatchet(session, header) {
        return (header.isRatchetMessage === true ||
            session.pendingRatchetCiphertext !== undefined ||
            (session.peerRatchetPublicKey !== null &&
                bytesToHex(header.ratchetPublicKey) !==
                    bytesToHex(session.peerRatchetPublicKey)));
    }
    performSendingRatchet(session) {
        if (!session.peerRatchetPublicKey) {
            throw new Error("No peer ratchet public key available for ratchet");
        }
        const result = KemRatchet.performKemRatchetEncapsulate(session.rootKey, session.peerRatchetPublicKey);
        const newSession = { ...session };
        newSession.rootKey = result.newRootKey;
        newSession.currentRatchetKeyPair = result.newRatchetKeyPair;
        newSession.previousSendingChainLength =
            session.sendingChain?.messageNumber ?? 0;
        newSession.sendingChain = result.sendingChain;
        newSession.pendingRatchetCiphertext = result.kemCiphertext;
        // If we're the initiator and this is our first ratchet, set receiving chain too
        if (!newSession.receivingChain && newSession.isInitiator) {
            newSession.receivingChain = result.receivingChain;
        }
        newSession.ratchetCount++;
        newSession.state = "RATCHET_PENDING";
        return {
            session: newSession,
            kemCiphertext: result.kemCiphertext,
        };
    }
    performReceivingRatchet(session, kemCiphertext) {
        if (!session.currentRatchetKeyPair?.secretKey) {
            throw new Error("No current ratchet secret key available");
        }
        const result = KemRatchet.performKemRatchetDecapsulate(session.rootKey, kemCiphertext, session.currentRatchetKeyPair.secretKey);
        // Create updated session with new ratchet state
        const updatedSession = { ...session };
        updatedSession.rootKey = result.newRootKey;
        updatedSession.currentRatchetKeyPair = result.newRatchetKeyPair;
        updatedSession.sendingChain = result.sendingChain;
        updatedSession.receivingChain = result.receivingChain;
        updatedSession.ratchetCount++;
        updatedSession.state = "ACTIVE";
        return updatedSession;
    }
    async triggerRatchet(sessionId, session) {
        if (!session.peerRatchetPublicKey) {
            throw new Error("No peer ratchet public key available");
        }
        const result = KemRatchet.performKemRatchetEncapsulate(session.rootKey, session.peerRatchetPublicKey);
        const newSession = { ...session };
        newSession.rootKey = result.newRootKey;
        newSession.currentRatchetKeyPair = result.newRatchetKeyPair;
        newSession.previousSendingChainLength =
            session.sendingChain?.messageNumber ?? 0;
        newSession.sendingChain = result.sendingChain;
        // If we're the initiator and this is our first ratchet, set receiving chain too
        if (!newSession.receivingChain && newSession.isInitiator) {
            newSession.receivingChain = result.receivingChain;
        }
        newSession.pendingRatchetCiphertext = result.kemCiphertext;
        newSession.ratchetCount++;
        newSession.state = "RATCHET_PENDING";
        Logger.log("Ratchet", "Manually triggered ratchet", {
            sessionId: sessionId.substring(0, 16) + "...",
            newRatchetCount: newSession.ratchetCount,
        });
        return newSession;
    }
}
