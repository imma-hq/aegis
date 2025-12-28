import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { ML_KEM768_PUBLIC_KEY_LENGTH } from "./constants";

export interface RatchetChain {
  chainKey: Uint8Array;
  messageNumber: number;
}

export interface KemRatchetResult {
  newRootKey: Uint8Array;
  newRatchetKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
  sendingChain: RatchetChain;
  receivingChain: RatchetChain;
  kemCiphertext: Uint8Array;
}

export interface SkippedMessageKey {
  messageKey: Uint8Array;
  timestamp: number;
}

export class KemRatchet {
  // Constants for key derivation contexts
  private static readonly CONTEXT_ROOT_KEY = new Uint8Array([0x01]);
  private static readonly CONTEXT_CHAIN_KEY = new Uint8Array([0x02]);
  private static readonly CONTEXT_MESSAGE_KEY = new Uint8Array([0x03]);
  private static readonly CONTEXT_CONFIRMATION = new Uint8Array([0x05]);

  // Perform KEM ratchet as encapsulator (when we send a new ratchet key)
  static performKemRatchetEncapsulate(
    rootKey: Uint8Array,
    peerRatchetPublicKey: Uint8Array
  ): KemRatchetResult {
    if (!peerRatchetPublicKey) {
      throw new Error(
        "peerRatchetPublicKey is required for KEM ratchet encapsulation"
      );
    }

    // Validate peer's ratchet public key
    if (!this.validateRatchetPublicKey(peerRatchetPublicKey)) {
      throw new Error("Invalid peer ratchet public key");
    }

    // Generate new ratchet keypair for NEXT round
    const newRatchetKeyPair = ml_kem768.keygen();

    // Perform KEM encapsulation to peer's CURRENT ratchet public key
    const { sharedSecret, cipherText } =
      ml_kem768.encapsulate(peerRatchetPublicKey);

    // Derive new root key
    const newRootKey = this.deriveKey(
      rootKey,
      sharedSecret,
      this.CONTEXT_ROOT_KEY
    );

    // Derive sending and receiving chain keys
    const sendingChainKey = this.deriveKey(
      newRootKey,
      cipherText,
      this.CONTEXT_CHAIN_KEY
    );

    const receivingChainKey = this.deriveKey(
      newRootKey,
      sharedSecret,
      this.CONTEXT_CHAIN_KEY
    );

    return {
      newRootKey,
      newRatchetKeyPair,
      sendingChain: {
        chainKey: sendingChainKey,
        messageNumber: 0,
      },
      receivingChain: {
        chainKey: receivingChainKey,
        messageNumber: 0,
      },
      kemCiphertext: cipherText,
    };
  }

  // Perform KEM ratchet as decapsulator (when we receive a new ratchet key)
  static performKemRatchetDecapsulate(
    rootKey: Uint8Array,
    kemCiphertext: Uint8Array,
    currentRatchetSecretKey: Uint8Array
  ): KemRatchetResult {
    if (!kemCiphertext || kemCiphertext.length === 0) {
      throw new Error("KEM ciphertext is required for decapsulation");
    }

    // Decapsulate the KEM cipherText using our current secret key
    const sharedSecret = ml_kem768.decapsulate(
      kemCiphertext,
      currentRatchetSecretKey
    );

    // Generate new ratchet keypair for next round
    const newRatchetKeyPair = ml_kem768.keygen();

    // Derive new root key (must match encapsulator's derivation)
    const newRootKey = this.deriveKey(
      rootKey,
      sharedSecret,
      this.CONTEXT_ROOT_KEY
    );

    // Derive chain keys (roles are swapped compared to encapsulator)
    const sendingChainKey = this.deriveKey(
      newRootKey,
      sharedSecret,
      this.CONTEXT_CHAIN_KEY
    );

    const receivingChainKey = this.deriveKey(
      newRootKey,
      kemCiphertext,
      this.CONTEXT_CHAIN_KEY
    );

    return {
      newRootKey,
      newRatchetKeyPair,
      sendingChain: {
        chainKey: sendingChainKey,
        messageNumber: 0,
      },
      receivingChain: {
        chainKey: receivingChainKey,
        messageNumber: 0,
      },
      kemCiphertext: new Uint8Array(0),
    };
  }

  // Generate confirmation MAC for session keys
  static generateConfirmationMac(
    sessionId: string,
    rootKey: Uint8Array,
    chainKey: Uint8Array,
    isResponse: boolean = false
  ): Uint8Array {
    const context = isResponse
      ? new Uint8Array([0x06]) // Different context for response
      : this.CONTEXT_CONFIRMATION;

    const data = concatBytes(
      new TextEncoder().encode(sessionId),
      rootKey,
      chainKey,
      new Uint8Array([isResponse ? 1 : 0])
    );

    return this.deriveKey(rootKey, data, context);
  }

  // Verify confirmation MAC
  static verifyConfirmationMac(
    sessionId: string,
    rootKey: Uint8Array,
    chainKey: Uint8Array,
    receivedMac: Uint8Array,
    isResponse: boolean = false
  ): boolean {
    const expectedMac = this.generateConfirmationMac(
      sessionId,
      rootKey,
      chainKey,
      isResponse
    );

    // Constant-time comparison
    if (expectedMac.length !== receivedMac.length) return false;

    let result = 0;
    for (let i = 0; i < expectedMac.length; i++) {
      result |= expectedMac[i] ^ receivedMac[i];
    }

    return result === 0;
  }

  // Symmetric ratchet for deriving message keys within a chain
  static symmetricRatchet(chain: RatchetChain): {
    messageKey: Uint8Array;
    newChain: RatchetChain;
  } {
    // Derive message key from current chain key
    const messageKey = this.deriveKey(
      chain.chainKey,
      new Uint8Array([0x00]),
      this.CONTEXT_MESSAGE_KEY
    );

    // Derive new chain key
    const newChainKey = this.deriveKey(
      chain.chainKey,
      new Uint8Array([0x01]),
      this.CONTEXT_CHAIN_KEY
    );

    const newChain: RatchetChain = {
      chainKey: newChainKey,
      messageNumber: chain.messageNumber + 1,
    };

    return { messageKey, newChain };
  }

  // Skip message keys for out-of-order messages
  static skipMessageKeys(
    chain: RatchetChain,
    targetMessageNumber: number,
    maxSkip: number
  ): { skippedKeys: Map<number, Uint8Array>; newChain: RatchetChain } {
    const skippedKeys = new Map<number, Uint8Array>();

    if (targetMessageNumber <= chain.messageNumber) {
      throw new Error("Cannot skip to earlier message number");
    }

    const skipCount = targetMessageNumber - chain.messageNumber;
    if (skipCount > maxSkip) {
      throw new Error(`Skip count ${skipCount} exceeds maximum ${maxSkip}`);
    }

    let currentChain = { ...chain };

    // Generate keys for skipped messages
    for (let i = 0; i < skipCount; i++) {
      const { messageKey, newChain } = this.symmetricRatchet(currentChain);
      skippedKeys.set(currentChain.messageNumber, messageKey);
      currentChain = newChain;
    }

    return { skippedKeys, newChain: currentChain };
  }

  // Helper method for key derivation
  private static deriveKey(
    key: Uint8Array,
    data: Uint8Array,
    context: Uint8Array
  ): Uint8Array {
    return blake3(concatBytes(key, data, context), { dkLen: 32 });
  }

  // Generate a fresh ratchet keypair
  static generateRatchetKeyPair(): {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  } {
    return ml_kem768.keygen();
  }

  // Check if we should perform a KEM ratchet
  static shouldPerformRatchet(
    messageCount: number,
    lastRatchetTime: number,
    maxMessages: number = 100,
    maxTime: number = 7 * 24 * 60 * 60 * 1000 // 7 days
  ): boolean {
    const now = Date.now();
    return messageCount >= maxMessages || now - lastRatchetTime >= maxTime;
  }

  // Validate a ratchet public key
  static validateRatchetPublicKey(publicKey: Uint8Array): boolean {
    return (
      publicKey instanceof Uint8Array &&
      publicKey.length === ML_KEM768_PUBLIC_KEY_LENGTH
    );
  }

  // Derive a unique ratchet identifier
  static deriveRatchetId(publicKey: Uint8Array, chainKey: Uint8Array): string {
    const hash = blake3(concatBytes(publicKey, chainKey), { dkLen: 16 });
    return Array.from(hash)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
}
