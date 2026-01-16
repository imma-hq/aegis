import { MAX_STORED_MESSAGE_IDS } from "./constants";
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
        // Also limit the total number of skipped keys to prevent memory leaks
        const maxSkippedKeys = 1000;
        if (session.skippedMessageKeys.size > maxSkippedKeys) {
            // Remove oldest entries if we exceed the limit
            const entries = Array.from(session.skippedMessageKeys.entries()).sort((a, b) => a[1].timestamp - b[1].timestamp);
            const toRemove = entries.slice(0, entries.length - maxSkippedKeys);
            for (const [keyId] of toRemove) {
                session.skippedMessageKeys.delete(keyId);
            }
        }
    }
    // Simple replay protection: Store received message IDs
    storeReceivedMessageId(session, messageId) {
        session.receivedMessageIds.add(messageId);
        // Keep the set size manageable
        if (session.receivedMessageIds.size > MAX_STORED_MESSAGE_IDS) {
            // Remove oldest entries by converting to array and removing first elements
            const ids = Array.from(session.receivedMessageIds);
            const idsToRemove = ids.slice(0, session.receivedMessageIds.size - MAX_STORED_MESSAGE_IDS);
            for (const id of idsToRemove) {
                session.receivedMessageIds.delete(id);
            }
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
