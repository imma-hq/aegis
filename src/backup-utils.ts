import { scrypt } from "@noble/hashes/scrypt.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { Logger } from "./logger";
import type { BackupData, EncryptedBackup, BackupOptions } from "./types";

export class BackupUtils {
  private static readonly SALT_LENGTH = 32;
  private static readonly IV_LENGTH = 24; // For XChaCha20-Poly1305
  private static readonly SCRYPT_N = 32768; // Conservative values for mobile
  private static readonly SCRYPT_r = 8;
  private static readonly SCRYPT_p = 1;
  private static readonly SCRYPT_KEYLEN = 32; // 256 bits

  /**
   * Encrypt backup data with a password
   */
  static async encryptBackup(
    backupData: BackupData,
    password: string,
  ): Promise<EncryptedBackup> {
    try {
      Logger.log("BackupUtils", "Starting backup encryption");

      // Convert password to bytes
      const passwordBytes = utf8ToBytes(password);

      // Generate random salt and IV
      const salt = randomBytes(this.SALT_LENGTH);
      const iv = randomBytes(this.IV_LENGTH);

      // Derive encryption key using scrypt
      const key = await scrypt(passwordBytes, salt, {
        N: this.SCRYPT_N,
        r: this.SCRYPT_r,
        p: this.SCRYPT_p,
        dkLen: this.SCRYPT_KEYLEN,
        onProgress: () => {}, // No progress callback needed
      });

      // Serialize backup data to JSON string then to bytes
      const jsonString = JSON.stringify(backupData);
      const dataBytes = utf8ToBytes(jsonString);

      // Encrypt using XChaCha20-Poly1305 for authenticated encryption
      const cipher = xchacha20poly1305(key, iv);
      const encryptedData = cipher.encrypt(dataBytes);
      // Extract the authentication tag from the cipher
      const authTag = cipher.tag;

      Logger.log("BackupUtils", "Backup encrypted successfully");

      return {
        encryptedData,
        salt,
        iv,
        authTag,
        version: "1.0.0",
      };
    } catch (error) {
      Logger.error("BackupUtils", "Failed to encrypt backup", error);
      throw error;
    }
  }

  /**
   * Decrypt backup data with a password
   */
  static async decryptBackup(
    encryptedBackup: EncryptedBackup,
    password: string,
  ): Promise<BackupData> {
    try {
      Logger.log("BackupUtils", "Starting backup decryption");

      // Convert password to bytes
      const passwordBytes = utf8ToBytes(password);

      // Derive the same encryption key using scrypt
      const key = await scrypt(passwordBytes, encryptedBackup.salt, {
        N: this.SCRYPT_N,
        r: this.SCRYPT_r,
        p: this.SCRYPT_p,
        dkLen: this.SCRYPT_KEYLEN,
        onProgress: () => {},
      });

      // Decrypt using XChaCha20-Poly1305
      const cipher = xchacha20poly1305(
        key,
        encryptedBackup.iv,
        encryptedBackup.authTag,
      );
      const decryptedBytes = cipher.decrypt(encryptedBackup.encryptedData);

      // Convert bytes back to JSON string
      const jsonString = new TextDecoder().decode(decryptedBytes);

      // Parse the backup data
      const backupData: BackupData = JSON.parse(jsonString);

      Logger.log("BackupUtils", "Backup decrypted successfully");

      return backupData;
    } catch (error) {
      Logger.error("BackupUtils", "Failed to decrypt backup", error);
      throw new Error("Invalid password or corrupted backup data");
    }
  }

  /**
   * Create backup data object from current state
   */
  static async createBackupData(
    identity: any, // Identity | null
    sessions: any[], // Session[]
    groups: any[], // Group[]
  ): Promise<BackupData> {
    // Convert sessions array to record/object
    const sessionsRecord: Record<string, any> = {};
    for (const session of sessions) {
      sessionsRecord[session.sessionId] = session;
    }

    return {
      identity: identity,
      sessions: sessionsRecord,
      groups: groups,
      createdAt: Date.now(),
      version: "1.0.0",
    };
  }

  /**
   * Validate backup data integrity
   */
  static validateBackupData(backupData: BackupData): boolean {
    try {
      // Basic validation checks
      if (!backupData.version) {
        Logger.warn("BackupUtils", "Backup data missing version");
        return false;
      }

      if (backupData.createdAt > Date.now()) {
        Logger.warn("BackupUtils", "Backup data has future timestamp");
        return false;
      }

      // Validate identity if present
      if (backupData.identity) {
        if (
          !backupData.identity.kemKeyPair ||
          !backupData.identity.dsaKeyPair
        ) {
          Logger.warn("BackupUtils", "Backup identity missing key pairs");
          return false;
        }
      }

      // Validate sessions
      if (backupData.sessions) {
        for (const [sessionId, session] of Object.entries(
          backupData.sessions,
        )) {
          if (!session.sessionId || session.sessionId !== sessionId) {
            Logger.warn(
              "BackupUtils",
              `Invalid session ID for session ${sessionId}`,
            );
            return false;
          }
        }
      }

      // Validate groups
      if (backupData.groups) {
        for (const group of backupData.groups) {
          if (!group.groupId || !group.name) {
            Logger.warn("BackupUtils", `Invalid group data: ${group.groupId}`);
            return false;
          }
        }
      }

      return true;
    } catch (error) {
      Logger.error("BackupUtils", "Error validating backup data", error);
      return false;
    }
  }
}
