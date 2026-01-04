import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import type { Identity, PublicBundle, StorageAdapter } from "./types";
import { Logger } from "./logger";
import { PreKeyManager } from "./prekey-manager";
import { ERRORS } from "./constants";

export class IdentityManager {
  private storage: StorageAdapter;
  private preKeyManager: PreKeyManager;

  constructor(storage: StorageAdapter) {
    this.storage = storage;
    this.preKeyManager = new PreKeyManager();
  }

  async createIdentity(userId?: string): Promise<{
    identity: Identity;
    publicBundle: PublicBundle;
  }> {
    try {
      Logger.log("Identity", "Creating new identity");

      const kemKeyPair = ml_kem768.keygen();
      const dsaKeyPair = ml_dsa65.keygen();

      // If userId is provided, use it; otherwise generate one from public keys
      const generatedUserId = bytesToHex(
        blake3(concatBytes(kemKeyPair.publicKey, dsaKeyPair.publicKey), {
          dkLen: 32,
        }),
      );

      const finalUserId = userId || generatedUserId;

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
        userId: finalUserId,
        createdAt: Date.now(),
        preKeySecret: preKeyPair.secretKey,
      };

      const publicBundle: PublicBundle = {
        userId: finalUserId,
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
        userId: finalUserId.substring(0, 16) + "...",
      });

      return { identity, publicBundle };
    } catch (error) {
      Logger.error("Identity", "Failed to create identity", error);
      throw error;
    }
  }

  async getIdentity(): Promise<Identity> {
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

  async rotateIdentity(userId?: string): Promise<{
    identity: Identity;
    publicBundle: PublicBundle;
  }> {
    // If userId is provided, use it; otherwise maintain the current userId
    const currentIdentity = await this.storage.getIdentity();
    const finalUserId =
      userId || (currentIdentity ? currentIdentity.userId : undefined);

    const result = await this.createIdentity(finalUserId);
    await this.preKeyManager.clear();
    return result;
  }
}
