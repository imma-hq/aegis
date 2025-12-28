import { MAX_STORED_MESSAGE_IDS } from "./constants.js";
export class ReplayProtection {
    getSkippedKeyId(ratchetPublicKey, messageNumber) {
        return `${this.bytesToHex(ratchetPublicKey)}:${messageNumber}`;
    }
    bytesToHex(bytes) {
        return Array.from(bytes)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    }
    cleanupSkippedKeys(session) {
        const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
        const now = Date.now();
        for (const [keyId, key] of session.skippedMessageKeys.entries()) {
            if (now - key.timestamp > maxAge) {
                session.skippedMessageKeys.delete(keyId);
            }
        }
    }
    // Simple replay protection: Store received message IDs
    storeReceivedMessageId(session, messageId) {
        session.receivedMessageIds.add(messageId);
        // Keep the set size manageable
        if (session.receivedMessageIds.size > MAX_STORED_MESSAGE_IDS) {
            // Remove oldest entries (Set doesn't have order, so we recreate)
            const ids = Array.from(session.receivedMessageIds);
            session.receivedMessageIds = new Set(ids.slice(-MAX_STORED_MESSAGE_IDS));
        }
    }
    async getReplayProtectionStatus(_sessionId, session) {
        return {
            storedMessageIds: session.receivedMessageIds.size,
            lastProcessedTimestamp: session.lastProcessedTimestamp,
            replayWindowSize: session.replayWindowSize,
        };
    }
}
