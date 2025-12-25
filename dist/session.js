import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { KemRatchet } from "./ratchet.js";
export class SessionKeyExchange {
    // Helper: Sort two Uint8Arrays lexicographically and return in consistent order
    static getSortedKeys(key1, key2) {
        const str1 = bytesToHex(key1);
        const str2 = bytesToHex(key2);
        return str1 < str2 ? [key1, key2] : [key2, key1];
    }
    // Helper: Create deterministic session ID
    static createSessionId(key1, key2, ciphertext) {
        const [sortedKey1, sortedKey2] = this.getSortedKeys(key1, key2);
        return bytesToHex(blake3(concatBytes(sortedKey1, sortedKey2, ciphertext), { dkLen: 32 }));
    }
    // For initiator (Alice): creates session with Bob's bundle
    static createInitiatorSession(localIdentity, peerBundle) {
        // Validate inputs
        if (!(localIdentity.kemKeyPair.publicKey instanceof Uint8Array)) {
            throw new Error("localIdentity.kemKeyPair.publicKey is not Uint8Array");
        }
        if (!(peerBundle.preKey.key instanceof Uint8Array)) {
            throw new Error("peerBundle.preKey.key is not Uint8Array");
        }
        if (!(peerBundle.kemPublicKey instanceof Uint8Array)) {
            throw new Error("peerBundle.kemPublicKey is not Uint8Array");
        }
        // Perform KEM with peer's prekey
        const prekeyResult = ml_kem768.encapsulate(peerBundle.preKey.key);
        if (!prekeyResult || typeof prekeyResult !== "object") {
            throw new Error("ml_kem768.encapsulate returned invalid result");
        }
        const prekeySecret = prekeyResult.sharedSecret;
        const ciphertext = prekeyResult.cipherText;
        if (!(prekeySecret instanceof Uint8Array)) {
            throw new Error(`prekeySecret is not Uint8Array, got ${typeof prekeySecret}`);
        }
        if (!(ciphertext instanceof Uint8Array)) {
            throw new Error(`ciphertext is not Uint8Array, got ${typeof ciphertext}`);
        }
        // Create session ID (both parties will compute same)
        const sessionId = this.createSessionId(localIdentity.kemKeyPair.publicKey, peerBundle.kemPublicKey, ciphertext);
        // Derive keys - BOTH PARTIES MUST USE EXACT SAME INPUTS
        const [sortedKey1, sortedKey2] = this.getSortedKeys(localIdentity.kemKeyPair.publicKey, peerBundle.kemPublicKey);
        const combined = concatBytes(prekeySecret, ciphertext, sortedKey1, sortedKey2);
        const rootKey = blake3(combined, { dkLen: 32 });
        const chainKey = blake3(concatBytes(rootKey, new Uint8Array([0])), {
            dkLen: 32,
        });
        // Generate confirmation MAC
        const confirmationMac = KemRatchet.generateConfirmationMac(sessionId, rootKey, chainKey, false);
        return { sessionId, rootKey, chainKey, ciphertext, confirmationMac };
    }
    // For responder (Bob): creates session when receiving first message
    static createResponderSession(localIdentity, peerBundle, ciphertext, initiatorConfirmationMac) {
        // Validate inputs
        if (!(ciphertext instanceof Uint8Array)) {
            throw new Error("ciphertext is not Uint8Array");
        }
        if (!localIdentity.preKeySecret ||
            !(localIdentity.preKeySecret instanceof Uint8Array)) {
            throw new Error("No valid prekey secret available");
        }
        if (!(localIdentity.kemKeyPair.publicKey instanceof Uint8Array)) {
            throw new Error("localIdentity.kemKeyPair.publicKey is not Uint8Array");
        }
        if (!(peerBundle.kemPublicKey instanceof Uint8Array)) {
            throw new Error("peerBundle.kemPublicKey is not Uint8Array");
        }
        // Decapsulate prekey ciphertext
        const prekeySecret = ml_kem768.decapsulate(ciphertext, localIdentity.preKeySecret);
        if (!(prekeySecret instanceof Uint8Array)) {
            throw new Error(`ml_kem768.decapsulate returned non-Uint8Array: ${typeof prekeySecret}`);
        }
        // Create session ID (MUST MATCH INITIATOR)
        const sessionId = this.createSessionId(localIdentity.kemKeyPair.publicKey, peerBundle.kemPublicKey, ciphertext);
        // Derive keys - MUST USE EXACT SAME INPUTS AS INITIATOR
        const [sortedKey1, sortedKey2] = this.getSortedKeys(localIdentity.kemKeyPair.publicKey, peerBundle.kemPublicKey);
        const combined = concatBytes(prekeySecret, ciphertext, sortedKey1, sortedKey2);
        const rootKey = blake3(combined, { dkLen: 32 });
        const chainKey = blake3(concatBytes(rootKey, new Uint8Array([0])), {
            dkLen: 32,
        });
        // Generate response confirmation MAC
        const confirmationMac = KemRatchet.generateConfirmationMac(sessionId, rootKey, chainKey, true);
        // Verify initiator's MAC if provided
        let isValid = true;
        if (initiatorConfirmationMac) {
            isValid = KemRatchet.verifyConfirmationMac(sessionId, rootKey, chainKey, initiatorConfirmationMac, false);
        }
        return { sessionId, rootKey, chainKey, confirmationMac, isValid };
    }
    // Verify key confirmation (for initiator to verify responder's MAC)
    static verifyKeyConfirmation(sessionId, rootKey, chainKey, responseMac) {
        return KemRatchet.verifyConfirmationMac(sessionId, rootKey, chainKey, responseMac, true);
    }
}
