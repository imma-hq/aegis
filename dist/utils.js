import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
export function deriveMessageKey(chainKey) {
    return blake3(concatBytes(chainKey, utf8ToBytes("msg_key")), { dkLen: 32 });
}
export function deriveNewChainKey(chainKey) {
    return blake3(concatBytes(chainKey, utf8ToBytes("chain_key")), { dkLen: 32 });
}
export function generateSessionId(localKemPublicKey, peerKemPublicKey, preKey) {
    return bytesToHex(blake3(concatBytes(localKemPublicKey, peerKemPublicKey, preKey), {
        dkLen: 32,
    }));
}
export function validatePublicBundle(bundle) {
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
export function serializeHeader(header) {
    if (header === null || header === undefined) {
        throw new Error("Header cannot be null or undefined");
    }
    return utf8ToBytes(JSON.stringify(header));
}
