import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import type { Identity, PreKey } from "./types";

export class PreKeyManager {
  private preKeys = new Map<number, PreKey>();
  private nextPreKeyId = 1;

  async generatePreKey(identity: Identity): Promise<PreKey> {
    const preKeyPair = ml_kem768.keygen();
    const preKeySignature = ml_dsa65.sign(
      preKeyPair.publicKey,
      identity.dsaKeyPair.secretKey,
    );

    const preKey: PreKey = {
      id: this.nextPreKeyId++,
      keyPair: preKeyPair,
      signature: preKeySignature,
      used: false,
      createdAt: Date.now(),
    };

    this.preKeys.set(preKey.id, preKey);
    return preKey;
  }

  async savePreKey(preKey: PreKey): Promise<void> {
    this.preKeys.set(preKey.id, preKey);
  }

  getPreKey(id: number): PreKey | null {
    return this.preKeys.get(id) || null;
  }

  getUnusedPreKey(): PreKey | null {
    for (const preKey of this.preKeys.values()) {
      if (!preKey.used) {
        return preKey;
      }
    }
    return null;
  }

  markPreKeyAsUsed(id: number): void {
    const preKey = this.preKeys.get(id);
    if (preKey) {
      preKey.used = true;
    }
  }

  removeOldPreKeys(maxAge: number = 7 * 24 * 60 * 60 * 1000): void {
    const now = Date.now();
    for (const [id, preKey] of this.preKeys.entries()) {
      if (now - preKey.createdAt > maxAge) {
        this.preKeys.delete(id);
      }
    }
  }

  clear(): void {
    this.preKeys.clear();
    this.nextPreKeyId = 1;
  }
}
