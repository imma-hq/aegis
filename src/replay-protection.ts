import type { Session } from "./types";
import { MAX_STORED_MESSAGE_IDS } from "./constants";

export class ReplayProtection {
  getSkippedKeyId(ratchetPublicKey: Uint8Array, messageNumber: number): string {
    return `${this.bytesToHex(ratchetPublicKey)}:${messageNumber}`;
  }

  private bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  cleanupSkippedKeys(session: Session): void {
    const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
    const now = Date.now();

    for (const [keyId, key] of session.skippedMessageKeys.entries()) {
      if (now - key.timestamp > maxAge) {
        session.skippedMessageKeys.delete(keyId);
      }
    }
  }

  // Simple replay protection: Store received message IDs
  storeReceivedMessageId(session: Session, messageId: string): void {
    session.receivedMessageIds.add(messageId);

    // Keep the set size manageable
    if (session.receivedMessageIds.size > MAX_STORED_MESSAGE_IDS) {
      // Remove oldest entries (Set doesn't have order, so we recreate)
      const ids = Array.from(session.receivedMessageIds);
      session.receivedMessageIds = new Set(ids.slice(-MAX_STORED_MESSAGE_IDS));
    }
  }

  async getReplayProtectionStatus(
    _sessionId: string,
    session: Session,
  ): Promise<{
    storedMessageIds: number;
    lastProcessedTimestamp: number;
    replayWindowSize: number;
  }> {
    return {
      storedMessageIds: session.receivedMessageIds.size,
      lastProcessedTimestamp: session.lastProcessedTimestamp,
      replayWindowSize: session.replayWindowSize,
    };
  }
}
