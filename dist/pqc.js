// pqc.ts
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hash, bytesToBase64, base64ToBytes, bytesToHex, encrypt, decrypt, generateNonce, getRandomBytes, scrypt, } from "./crypto";
import { validateUserIdentity, validateString } from "./validator";
import { CryptoError, ValidationError, } from "./types";
const IDENTITY_STORAGE_KEY = "aegis_pqc_identity";
const IDENTITY_VERSION = "3.0.0";
const MIN_OTPKS = 20;
const OTPK_BATCH_SIZE = 100;
const MAX_OTPKS = 1000;
export class PQCIdentityManager {
    constructor(aegisInstance) {
        Object.defineProperty(this, "aegis", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.aegis = aegisInstance;
        if (!aegisInstance.isInitialized()) {
            throw new CryptoError("Aegis instance must be initialized before creating PQCIdentityManager");
        }
    }
    generateKEMKeyPair() {
        try {
            const keyPair = ml_kem768.keygen();
            return {
                publicKey: keyPair.publicKey,
                secretKey: keyPair.secretKey,
            };
        }
        catch (error) {
            throw new CryptoError("Failed to generate KEM key pair", "KEM_KEYGEN", error);
        }
    }
    async generateSignatureKeyPair() {
        try {
            const secretKey = ed25519.utils.randomSecretKey();
            const publicKey = await ed25519.getPublicKey(secretKey);
            return {
                publicKey,
                secretKey,
            };
        }
        catch (error) {
            throw new CryptoError("Failed to generate signature key pair", "SIG_KEYGEN", error);
        }
    }
    generateOneTimePreKeys(count) {
        if (count <= 0 || count > MAX_OTPKS) {
            throw new ValidationError(`One-time pre-key count must be between 1 and ${MAX_OTPKS}`, "otpkCount", { count, min: 1, max: MAX_OTPKS });
        }
        const keys = [];
        const baseId = Date.now();
        for (let i = 0; i < count; i++) {
            try {
                keys.push({
                    id: baseId + i,
                    keyPair: this.generateKEMKeyPair(),
                });
            }
            catch (error) {
                throw new CryptoError(`Failed to generate OTPK at index ${i}`, "OTPK_GENERATION", error);
            }
        }
        return keys;
    }
    async replenishOneTimePreKeys() {
        const identity = (await this.loadIdentity());
        if (!identity) {
            throw new CryptoError("No identity found to replenish OTPKs");
        }
        const currentCount = identity.oneTimePreKeys.length;
        let added = 0;
        const wasLow = currentCount < MIN_OTPKS;
        if (currentCount >= MIN_OTPKS && currentCount < MAX_OTPKS / 2) {
            console.log(`[PQC] OTPK count sufficient: ${currentCount}/${MIN_OTPKS}`);
            return { added: 0, total: currentCount, wasLow };
        }
        const needed = Math.min(OTPK_BATCH_SIZE, MAX_OTPKS - currentCount);
        if (needed > 0) {
            console.log(`[PQC] Replenishing OTPKs: ${currentCount} -> ${currentCount + needed}`);
            const newOTPKs = this.generateOneTimePreKeys(needed);
            identity.oneTimePreKeys.push(...newOTPKs);
            added = needed;
            await this.saveIdentity(identity);
            console.log(`[PQC] Successfully added ${added} OTPKs. Total: ${identity.oneTimePreKeys.length}`);
        }
        return {
            added,
            total: identity.oneTimePreKeys.length,
            wasLow,
        };
    }
    async checkAndReplenishOTPKs() {
        const identity = (await this.loadIdentity());
        if (!identity)
            return false;
        const currentCount = identity.oneTimePreKeys.length;
        if (currentCount < MIN_OTPKS) {
            console.log(`[PQC] OTPKs low (${currentCount}/${MIN_OTPKS}), replenishing...`);
            await this.replenishOneTimePreKeys();
            return true;
        }
        return false;
    }
    async getOTPKStatus() {
        const identity = (await this.loadIdentity());
        if (!identity) {
            throw new CryptoError("No identity found");
        }
        const count = identity.oneTimePreKeys.length;
        const isLow = count < MIN_OTPKS;
        const needsReplenishment = count < MIN_OTPKS * 2;
        return {
            count,
            minRequired: MIN_OTPKS,
            maxAllowed: MAX_OTPKS,
            isLow,
            needsReplenishment,
        };
    }
    async createIdentity(userId, authMethod, identifier) {
        validateString(userId, "userId");
        if (!authMethod || (authMethod !== "phone" && authMethod !== "email")) {
            throw new ValidationError("Auth method must be either 'phone' or 'email'", "authMethod");
        }
        validateString(identifier, "identifier");
        const kem = this.generateKEMKeyPair();
        const sig = await this.generateSignatureKeyPair();
        const signedPreKey = await this.generateSignedPreKey(sig.secretKey);
        const oneTimePreKeys = this.generateOneTimePreKeys(OTPK_BATCH_SIZE);
        const identity = {
            kem,
            sig,
            userId,
            authMethod,
            identifier,
            createdAt: Date.now(),
            version: IDENTITY_VERSION,
            signedPreKey,
            oneTimePreKeys,
        };
        await this.saveIdentity(identity);
        return identity;
    }
    async generateSignedPreKey(signingSecretKey) {
        try {
            const keyPair = this.generateKEMKeyPair();
            const signature = await ed25519.sign(keyPair.publicKey, signingSecretKey);
            return {
                id: Math.floor(Date.now() / 1000),
                keyPair,
                signature,
                createdAt: Date.now(),
            };
        }
        catch (error) {
            throw new CryptoError("Failed to generate signed pre-key", "SPK_GENERATION", error);
        }
    }
    async saveIdentity(identity) {
        if (!identity) {
            throw new ValidationError("Identity cannot be null or undefined");
        }
        try {
            validateUserIdentity(identity);
        }
        catch (error) {
            if (error instanceof ValidationError) {
                throw error;
            }
            throw new CryptoError("Failed to validate identity", "IDENTITY_VALIDATION", error);
        }
        const extendedIdentity = identity;
        const serialized = JSON.stringify({
            kem: {
                publicKey: bytesToBase64(identity.kem.publicKey),
                secretKey: bytesToBase64(identity.kem.secretKey),
            },
            sig: {
                publicKey: bytesToBase64(identity.sig.publicKey),
                secretKey: bytesToBase64(identity.sig.secretKey),
            },
            signedPreKey: {
                id: extendedIdentity.signedPreKey.id,
                key: {
                    pub: bytesToBase64(extendedIdentity.signedPreKey.keyPair.publicKey),
                    sec: bytesToBase64(extendedIdentity.signedPreKey.keyPair.secretKey),
                },
                sig: bytesToBase64(extendedIdentity.signedPreKey.signature),
                created: extendedIdentity.signedPreKey.createdAt,
            },
            oneTimePreKeys: extendedIdentity.oneTimePreKeys.map((k) => ({
                id: k.id,
                pub: bytesToBase64(k.keyPair.publicKey),
                sec: bytesToBase64(k.keyPair.secretKey),
            })),
            userId: identity.userId,
            authMethod: identity.authMethod,
            identifier: identity.identifier,
            createdAt: identity.createdAt,
            version: identity.version,
        });
        await this.aegis.getStorage().setItem(IDENTITY_STORAGE_KEY, serialized);
    }
    async loadIdentity() {
        const serialized = await this.aegis
            .getStorage()
            .getItem(IDENTITY_STORAGE_KEY);
        if (!serialized) {
            return null;
        }
        try {
            const data = JSON.parse(serialized);
            if (!data.userId ||
                !data.authMethod ||
                !data.identifier ||
                !data.version) {
                throw new ValidationError("Invalid identity data: missing required fields");
            }
            if (!data.kem || !data.kem.publicKey || !data.kem.secretKey) {
                throw new ValidationError("Invalid identity data: missing KEM keys");
            }
            if (!data.sig || !data.sig.publicKey || !data.sig.secretKey) {
                throw new ValidationError("Invalid identity data: missing signature keys");
            }
            const identity = {
                kem: {
                    publicKey: base64ToBytes(data.kem.publicKey),
                    secretKey: base64ToBytes(data.kem.secretKey),
                },
                sig: {
                    publicKey: base64ToBytes(data.sig.publicKey),
                    secretKey: base64ToBytes(data.sig.secretKey),
                },
                signedPreKey: {
                    id: data.signedPreKey.id,
                    keyPair: {
                        publicKey: base64ToBytes(data.signedPreKey.key.pub),
                        secretKey: base64ToBytes(data.signedPreKey.key.sec),
                    },
                    signature: base64ToBytes(data.signedPreKey.sig),
                    createdAt: data.signedPreKey.created,
                },
                oneTimePreKeys: data.oneTimePreKeys.map((k) => ({
                    id: k.id,
                    keyPair: {
                        publicKey: base64ToBytes(k.pub),
                        secretKey: base64ToBytes(k.sec),
                    },
                })),
                userId: data.userId,
                authMethod: data.authMethod,
                identifier: data.identifier,
                createdAt: data.createdAt,
                version: data.version,
            };
            return identity;
        }
        catch (error) {
            console.error("[PQC Identity] Failed to parse identity:", error);
            return null;
        }
    }
    async deleteIdentity() {
        await this.aegis.getStorage().removeItem(IDENTITY_STORAGE_KEY);
    }
    async rotateSignedPreKey() {
        const identity = (await this.loadIdentity());
        if (!identity) {
            throw new CryptoError("No identity found");
        }
        const newSignedPreKey = await this.generateSignedPreKey(identity.sig.secretKey);
        identity.signedPreKey = newSignedPreKey;
        await this.saveIdentity(identity);
        return {
            newId: newSignedPreKey.id,
            publicKey: bytesToBase64(newSignedPreKey.keyPair.publicKey),
        };
    }
    async getAndConsumeOneTimePreKey() {
        const identity = (await this.loadIdentity());
        if (!identity) {
            throw new CryptoError("No identity found");
        }
        if (identity.oneTimePreKeys.length === 0) {
            await this.replenishOneTimePreKeys();
            if (identity.oneTimePreKeys.length === 0) {
                throw new CryptoError("Failed to generate OTPKs");
            }
        }
        const otpk = identity.oneTimePreKeys.shift();
        const remaining = identity.oneTimePreKeys.length;
        await this.saveIdentity(identity);
        if (remaining < MIN_OTPKS) {
            setTimeout(() => this.replenishOneTimePreKeys(), 1000);
        }
        return {
            id: otpk.id,
            keyPair: otpk.keyPair,
            remaining,
        };
    }
    async getPublicKeyBundle() {
        const identity = (await this.loadIdentity());
        if (!identity) {
            throw new CryptoError("No identity found");
        }
        const otpk = identity.oneTimePreKeys.length > 0
            ? identity.oneTimePreKeys[0]
            : undefined;
        return {
            identityKey: bytesToBase64(identity.kem.publicKey),
            sigPublicKey: bytesToBase64(identity.sig.publicKey),
            signedPreKey: {
                id: identity.signedPreKey.id,
                key: bytesToBase64(identity.signedPreKey.keyPair.publicKey),
                signature: bytesToBase64(identity.signedPreKey.signature),
            },
            oneTimePreKey: otpk
                ? {
                    id: otpk.id,
                    key: bytesToBase64(otpk.keyPair.publicKey),
                }
                : undefined,
            userId: identity.userId,
            otpkCount: identity.oneTimePreKeys.length,
        };
    }
    async exportIdentity(password) {
        if (!password ||
            typeof password !== "string" ||
            password.trim().length === 0) {
            throw new ValidationError("Password must be a non-empty string", "password");
        }
        const identity = await this.loadIdentity();
        if (!identity) {
            throw new CryptoError("No identity to export");
        }
        const serialized = JSON.stringify({
            kem: {
                publicKey: bytesToBase64(identity.kem.publicKey),
                secretKey: bytesToBase64(identity.kem.secretKey),
            },
            sig: {
                publicKey: bytesToBase64(identity.sig.publicKey),
                secretKey: bytesToBase64(identity.sig.secretKey),
            },
            userId: identity.userId,
            authMethod: identity.authMethod,
            identifier: identity.identifier,
            createdAt: identity.createdAt,
            version: identity.version,
        });
        const salt = getRandomBytes(32);
        const key = await this.deriveBackupKey(password, salt);
        const nonce = generateNonce();
        const ciphertext = encrypt(key, nonce, new TextEncoder().encode(serialized));
        const backup = {
            v: "3",
            algorithm: "scrypt+chacha20poly1305",
            params: {
                N: 131072,
                r: 8,
                p: 1,
                dkLen: 32,
            },
            salt: bytesToBase64(salt),
            nonce: bytesToBase64(nonce),
            ciphertext: bytesToBase64(ciphertext),
        };
        return bytesToBase64(new TextEncoder().encode(JSON.stringify(backup)));
    }
    async importIdentity(backupData, password) {
        if (!backupData ||
            typeof backupData !== "string" ||
            backupData.trim().length === 0) {
            throw new ValidationError("Backup data must be a non-empty string", "backupData");
        }
        if (!password ||
            typeof password !== "string" ||
            password.trim().length === 0) {
            throw new ValidationError("Password must be a non-empty string", "password");
        }
        try {
            const decoded = new TextDecoder().decode(base64ToBytes(backupData));
            const data = JSON.parse(decoded);
            if (data.v !== "3") {
                throw new ValidationError(`Unsupported backup version: ${data.v}. Expected v3`, "backupVersion", { received: data.v, expected: "3" });
            }
            const backup = data;
            const salt = base64ToBytes(backup.salt);
            const nonce = base64ToBytes(backup.nonce);
            const ciphertext = base64ToBytes(backup.ciphertext);
            const key = await this.deriveBackupKey(password, salt);
            const plaintextBytes = decrypt(key, nonce, ciphertext);
            const plaintext = new TextDecoder().decode(plaintextBytes);
            const parsed = JSON.parse(plaintext);
            if (!parsed.kem || !parsed.sig) {
                throw new ValidationError("Invalid identity backup format", "backupFormat");
            }
            const identity = {
                kem: {
                    publicKey: base64ToBytes(parsed.kem.publicKey),
                    secretKey: base64ToBytes(parsed.kem.secretKey),
                },
                sig: {
                    publicKey: base64ToBytes(parsed.sig.publicKey),
                    secretKey: base64ToBytes(parsed.sig.secretKey),
                },
                signedPreKey: await this.generateSignedPreKey(base64ToBytes(parsed.sig.secretKey)),
                oneTimePreKeys: this.generateOneTimePreKeys(OTPK_BATCH_SIZE),
                userId: parsed.userId,
                authMethod: parsed.authMethod,
                identifier: parsed.identifier,
                createdAt: parsed.createdAt || Date.now(),
                version: parsed.version || IDENTITY_VERSION,
            };
            await this.saveIdentity(identity);
            return identity;
        }
        catch (error) {
            console.error("[PQC Identity] Failed to import identity:", error);
            if (error instanceof Error &&
                (error.message.includes("authentication") ||
                    error.message.includes("decryption failed"))) {
                throw new CryptoError("Failed to import identity: Invalid password or corrupted backup", "BACKUP_DECRYPTION", error);
            }
            throw new CryptoError(`Failed to import identity: ${error instanceof Error ? error.message : "Unknown error"}`, "BACKUP_IMPORT", error);
        }
    }
    async deriveBackupKey(password, salt) {
        try {
            return await scrypt(password, salt, {
                N: 131072,
                r: 8,
                p: 1,
                dkLen: 32,
            });
        }
        catch (error) {
            throw new CryptoError("Failed to derive backup key", "KDF_DERIVATION", error);
        }
    }
    calculateSafetyNumber(identity1KemPublic, identity1SigPublic, identity2KemPublic, identity2SigPublic) {
        if (!identity1KemPublic ||
            identity1KemPublic.length === 0 ||
            !identity1SigPublic ||
            identity1SigPublic.length === 0 ||
            !identity2KemPublic ||
            identity2KemPublic.length === 0 ||
            !identity2SigPublic ||
            identity2SigPublic.length === 0) {
            throw new ValidationError("All public keys must be non-empty Uint8Arrays");
        }
        const combined = new Uint8Array(identity1KemPublic.length +
            identity1SigPublic.length +
            identity2KemPublic.length +
            identity2SigPublic.length);
        let offset = 0;
        combined.set(identity1KemPublic, offset);
        offset += identity1KemPublic.length;
        combined.set(identity1SigPublic, offset);
        offset += identity1SigPublic.length;
        combined.set(identity2KemPublic, offset);
        offset += identity2KemPublic.length;
        combined.set(identity2SigPublic, offset);
        const fingerprint = hash(combined, 32);
        const hex = bytesToHex(fingerprint);
        const numbers = [];
        for (let i = 0; i < hex.length; i += 10) {
            const chunk = hex.substring(i, i + 10);
            const num = parseInt(chunk, 16) % 100000;
            numbers.push(num.toString().padStart(5, "0"));
        }
        const result = [];
        for (let i = 0; i < numbers.length && i < 6; i++) {
            result.push(numbers[i]);
        }
        return result.join(" ");
    }
}
export function encapsulate(recipientKemPublicKey) {
    if (!recipientKemPublicKey || recipientKemPublicKey.length === 0) {
        throw new ValidationError("Recipient public key must be a non-empty Uint8Array", "recipientKemPublicKey");
    }
    try {
        const result = ml_kem768.encapsulate(recipientKemPublicKey);
        return {
            sharedSecret: result.sharedSecret,
            ciphertext: result.cipherText,
        };
    }
    catch (error) {
        throw new CryptoError("Failed to encapsulate key", "KEM_ENCAPSULATION", error);
    }
}
export async function verifySignedPreKey(spkPublicKey, signature, signerPublicKey) {
    try {
        return await ed25519.verify(signature, spkPublicKey, signerPublicKey);
    }
    catch (error) {
        console.error("[PQC] Signature verification failed:", error);
        return false;
    }
}
export function decapsulate(ciphertext, secretKey) {
    if (!ciphertext || ciphertext.length === 0) {
        throw new ValidationError("Ciphertext must be a non-empty Uint8Array", "ciphertext");
    }
    if (!secretKey || secretKey.length === 0) {
        throw new ValidationError("Secret key must be a non-empty Uint8Array", "secretKey");
    }
    try {
        return ml_kem768.decapsulate(ciphertext, secretKey);
    }
    catch (error) {
        throw new CryptoError("Failed to decapsulate key", "KEM_DECAPSULATION", error);
    }
}
