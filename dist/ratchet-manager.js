import { bytesToHex } from "@noble/hashes/utils.js";
import { Logger } from "./logger";
import { RATCHET_AFTER_MESSAGES, RATCHET_INTERVAL } from "./constants";
import { KemRatchet } from "./ratchet";
export class RatchetManager {
    shouldPerformSendingRatchet(session) {
        const messageCount = session.sendingChain?.messageNumber || 0;
        const isFirstMessageAsInitiator = session.isInitiator && messageCount === 0;
        // Without the peer's ratchet public key we cannot run a KEM ratchet yet.
        if (session.peerRatchetPublicKey === null || isFirstMessageAsInitiator) {
            return false;
        }
        // Don't start a new ratchet while one is still awaiting acknowledgement.
        if (session.pendingRatchetState) {
            return false;
        }
        // Policy 1: bound the number of messages sent under a single chain.
        if (messageCount >= RATCHET_AFTER_MESSAGES) {
            return true;
        }
        // Policy 2: bound the age of the chain so low-traffic sessions still rotate
        // keys without the app having to call triggerRatchet() manually.
        const lastRatchetAt = session.lastRatchetAt ?? session.createdAt;
        return Date.now() - lastRatchetAt >= RATCHET_INTERVAL;
    }
    needsReceivingRatchet(session, header) {
        return (header.isRatchetMessage === true ||
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
        const pendingRatchetState = {
            newRootKey: result.newRootKey,
            newRatchetKeyPair: result.newRatchetKeyPair,
            sendingChain: result.sendingChain,
            receivingChain: result.receivingChain,
            kemCiphertext: result.kemCiphertext,
            previousReceivingChain: session.receivingChain,
            previousSendingChain: session.sendingChain,
        };
        newSession.pendingRatchetState = pendingRatchetState;
        newSession.previousSendingChainLength =
            session.sendingChain?.messageNumber ?? 0;
        newSession.ratchetCount++;
        newSession.lastRatchetAt = Date.now();
        newSession.state = "RATCHET_PENDING";
        Logger.log("Ratchet", "Prepared sending KEM ratchet", {
            ratchetCount: newSession.ratchetCount,
            messageNumber: session.sendingChain?.messageNumber || 0,
        });
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
        const previousReceivingChain = session.receivingChain;
        const updatedSession = { ...session };
        updatedSession.rootKey = result.newRootKey;
        updatedSession.currentRatchetKeyPair = result.newRatchetKeyPair;
        updatedSession.sendingChain = result.sendingChain;
        updatedSession.receivingChain = result.receivingChain;
        updatedSession.ratchetCount++;
        updatedSession.lastRatchetAt = Date.now();
        updatedSession.state = "ACTIVE";
        updatedSession.pendingRatchetState = {
            newRootKey: result.newRootKey,
            newRatchetKeyPair: result.newRatchetKeyPair,
            sendingChain: result.sendingChain,
            receivingChain: result.receivingChain,
            kemCiphertext,
            previousReceivingChain,
            previousSendingChain: session.sendingChain,
        };
        Logger.log("Ratchet", "Performed receiving KEM ratchet", {
            ratchetCount: updatedSession.ratchetCount,
            hasOldChain: previousReceivingChain !== null,
        });
        return updatedSession;
    }
    applyPendingRatchet(session) {
        if (!session.pendingRatchetState) {
            return session;
        }
        const { pendingRatchetState } = session;
        const updatedSession = { ...session };
        updatedSession.rootKey = pendingRatchetState.newRootKey;
        updatedSession.currentRatchetKeyPair =
            pendingRatchetState.newRatchetKeyPair;
        updatedSession.sendingChain = pendingRatchetState.sendingChain;
        updatedSession.receivingChain = pendingRatchetState.receivingChain;
        updatedSession.pendingRatchetState = undefined;
        updatedSession.state = "ACTIVE";
        Logger.log("Ratchet", "Applied pending ratchet state", {
            ratchetCount: updatedSession.ratchetCount,
        });
        return updatedSession;
    }
    async triggerRatchet(sessionId, session) {
        if (!session.peerRatchetPublicKey) {
            throw new Error("No peer ratchet public key available");
        }
        const result = KemRatchet.performKemRatchetEncapsulate(session.rootKey, session.peerRatchetPublicKey);
        const newSession = {
            ...session,
            rootKey: result.newRootKey,
            currentRatchetKeyPair: result.newRatchetKeyPair,
            sendingChain: result.sendingChain,
            receivingChain: result.receivingChain,
            previousSendingChainLength: session.sendingChain?.messageNumber ?? 0,
            ratchetCount: session.ratchetCount + 1,
            lastRatchetAt: Date.now(),
            state: "ACTIVE",
            pendingRatchetState: {
                newRootKey: result.newRootKey,
                newRatchetKeyPair: result.newRatchetKeyPair,
                sendingChain: result.sendingChain,
                receivingChain: result.receivingChain,
                kemCiphertext: result.kemCiphertext,
                previousReceivingChain: session.receivingChain,
                previousSendingChain: session.sendingChain,
            },
        };
        Logger.log("Ratchet", "Manually triggered ratchet", {
            sessionId: `${sessionId.substring(0, 16)}...`,
            newRatchetCount: newSession.ratchetCount,
        });
        return newSession;
    }
    getDecryptionChainForRatchetMessage(session) {
        if (!session.pendingRatchetState?.previousReceivingChain) {
            return session.receivingChain;
        }
        return session.pendingRatchetState.previousReceivingChain;
    }
}
