import { encryptMessage, decryptMessage } from "./session";

/**
 * Interface for a group message bundle.
 * Maps User ID -> Encrypted Message for that user.
 */
export interface GroupMessageBundle {
  groupId: string;
  messages: Record<string, any>; // Using any here as the structure matches EncryptedMessage from session
}

/**
 * Send a message to a group of users.
 * Uses client-side fan-out: encrypts the message individually for each participant.
 *
 * @param groupId - The ID of the group
 * @param participantSessionIds - Map of userId -> sessionId for all participants
 * @param plaintext - The content to encrypt
 */
export async function sendGroupMessage(
  groupId: string,
  participantSessionIds: Record<string, string>,
  plaintext: string
): Promise<GroupMessageBundle> {
  const bundle: GroupMessageBundle = {
    groupId,
    messages: {},
  };

  const promises = Object.entries(participantSessionIds).map(
    async ([userId, sessionId]) => {
      try {
        const encrypted = await encryptMessage(sessionId, plaintext);
        bundle.messages[userId] = encrypted;
      } catch (error) {
        console.error(
          `Failed to encrypt for user ${userId} in session ${sessionId}:`,
          error
        );
        // We continue intentionally to allow partial success,
        // or you implement logic to fail the whole batch.
      }
    }
  );

  await Promise.all(promises);
  return bundle;
}

/**
 * Decrypt a group message.
 * Since we use fan-out, this is just a wrapper around decrypting a 1:1 message.
 *
 * @param encryptedMsg - The encrypted message payload
 */
export async function decryptGroupMessage(
  encryptedMsg: any // EncryptedMessage from session
): Promise<string> {
  return decryptMessage(encryptedMsg);
}
