import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export function deriveMessageKey(chainKey: Uint8Array): Uint8Array {
  return blake3(concatBytes(chainKey, utf8ToBytes("msg_key")), { dkLen: 32 });
}

export function deriveNewChainKey(chainKey: Uint8Array): Uint8Array {
  return blake3(concatBytes(chainKey, utf8ToBytes("chain_key")), { dkLen: 32 });
}

export function generateSessionId(
  localKemPublicKey: Uint8Array,
  peerKemPublicKey: Uint8Array,
  preKey: Uint8Array,
): string {
  return bytesToHex(
    blake3(concatBytes(localKemPublicKey, peerKemPublicKey, preKey), {
      dkLen: 32,
    }),
  );
}

export function validatePublicBundle(bundle: any): void {
  if (!bundle || !bundle.preKey || !bundle.preKey.key) {
    throw new Error("Invalid peer bundle");
  }

  if (!bundle.userId || typeof bundle.userId !== "string") {
    throw new Error("Invalid userId in bundle");
  }

  if (!bundle.kemPublicKey || !bundle.dsaPublicKey) {
    throw new Error("Missing public keys in bundle");
  }
}

export function serializeHeader(header: any): Uint8Array {
  return utf8ToBytes(JSON.stringify(header));
}
