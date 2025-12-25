// src/prekey-manager.ts
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
export class PreKeyManager {
    constructor() {
        Object.defineProperty(this, "preKeys", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Map()
        });
        Object.defineProperty(this, "nextPreKeyId", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 1
        });
    }
    async generatePreKey(identity) {
        const preKeyPair = ml_kem768.keygen();
        const preKeySignature = ml_dsa65.sign(preKeyPair.publicKey, identity.dsaKeyPair.secretKey);
        const preKey = {
            id: this.nextPreKeyId++,
            keyPair: preKeyPair,
            signature: preKeySignature,
            used: false,
            createdAt: Date.now(),
        };
        this.preKeys.set(preKey.id, preKey);
        return preKey;
    }
    async savePreKey(preKey) {
        this.preKeys.set(preKey.id, preKey);
    }
    getPreKey(id) {
        return this.preKeys.get(id) || null;
    }
    getUnusedPreKey() {
        for (const preKey of this.preKeys.values()) {
            if (!preKey.used) {
                return preKey;
            }
        }
        return null;
    }
    markPreKeyAsUsed(id) {
        const preKey = this.preKeys.get(id);
        if (preKey) {
            preKey.used = true;
        }
    }
    removeOldPreKeys(maxAge = 7 * 24 * 60 * 60 * 1000) {
        const now = Date.now();
        for (const [id, preKey] of this.preKeys.entries()) {
            if (now - preKey.createdAt > maxAge) {
                this.preKeys.delete(id);
            }
        }
    }
    clear() {
        this.preKeys.clear();
        this.nextPreKeyId = 1;
    }
}
