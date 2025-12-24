// validator.ts
import { ValidationError, } from "./types";
// Basic type validators
export function validateUint8Array(value, name, options) {
    if (!(value instanceof Uint8Array)) {
        throw new ValidationError(`${name} must be a Uint8Array`, name);
    }
    if (!options?.allowEmpty && value.length === 0) {
        throw new ValidationError(`${name} must not be empty`, name);
    }
    if (options?.minLength !== undefined && value.length < options.minLength) {
        throw new ValidationError(`${name} must be at least ${options.minLength} bytes`, name, { length: value.length, minLength: options.minLength });
    }
    if (options?.maxLength !== undefined && value.length > options.maxLength) {
        throw new ValidationError(`${name} must be at most ${options.maxLength} bytes`, name, { length: value.length, maxLength: options.maxLength });
    }
    return value;
}
export function validateBase64(value, name, options) {
    if (typeof value !== "string") {
        throw new ValidationError(`${name} must be a string`, name);
    }
    if (!options?.allowEmpty && value.trim() === "") {
        throw new ValidationError(`${name} must not be empty`, name);
    }
    if (options?.minLength !== undefined && value.length < options.minLength) {
        throw new ValidationError(`${name} must be at least ${options.minLength} characters`, name, { length: value.length, minLength: options.minLength });
    }
    try {
        atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    }
    catch (e) {
        throw new ValidationError(`${name} must be valid base64`, name);
    }
    return value;
}
export function validateAuthMethod(value) {
    if (value !== "phone" && value !== "email") {
        throw new ValidationError('Auth method must be "phone" or "email"', "authMethod", { received: value });
    }
    return value;
}
export function validateString(value, name, options) {
    if (typeof value !== "string") {
        throw new ValidationError(`${name} must be a string`, name);
    }
    if (!options?.allowEmpty && value.trim() === "") {
        throw new ValidationError(`${name} must not be empty`, name);
    }
    if (options?.minLength !== undefined && value.length < options.minLength) {
        throw new ValidationError(`${name} must be at least ${options.minLength} characters`, name, { length: value.length, minLength: options.minLength });
    }
    if (options?.maxLength !== undefined && value.length > options.maxLength) {
        throw new ValidationError(`${name} must be at most ${options.maxLength} characters`, name, { length: value.length, maxLength: options.maxLength });
    }
    return value;
}
export function validateNumber(value, name, options) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new ValidationError(`${name} must be a finite number`, name);
    }
    if (options?.min !== undefined && value < options.min) {
        throw new ValidationError(`${name} must be at least ${options.min}`, name, {
            value,
            min: options.min,
        });
    }
    if (options?.max !== undefined && value > options.max) {
        throw new ValidationError(`${name} must be at most ${options.max}`, name, {
            value,
            max: options.max,
        });
    }
    return value;
}
export function validatePositiveNumber(value, name) {
    const num = validateNumber(value, name);
    if (num < 0) {
        throw new ValidationError(`${name} must be non-negative`, name);
    }
    return num;
}
// Complex type validators
export function validatePQKeyPair(data, name) {
    if (!data || typeof data !== "object") {
        throw new ValidationError(`${name} must be an object`, name);
    }
    return {
        publicKey: validateUint8Array(data.publicKey, `${name}.publicKey`, {
            minLength: 32,
        }),
        secretKey: validateUint8Array(data.secretKey, `${name}.secretKey`, {
            minLength: 32,
        }),
    };
}
export function validateUserIdentity(data) {
    if (!data || typeof data !== "object") {
        throw new ValidationError("Identity must be an object");
    }
    return {
        kem: validatePQKeyPair(data.kem, "kem"),
        sig: validatePQKeyPair(data.sig, "sig"),
        userId: validateString(data.userId, "userId", { minLength: 1 }),
        authMethod: validateAuthMethod(data.authMethod),
        identifier: validateString(data.identifier, "identifier", { minLength: 1 }),
        createdAt: validatePositiveNumber(data.createdAt, "createdAt"),
        version: validateString(data.version, "version", { minLength: 1 }),
    };
}
export function validateSessionInitData(data) {
    if (!data || typeof data !== "object") {
        throw new ValidationError("SessionInitData must be an object");
    }
    const result = {
        sessionId: validateString(data.sessionId, "sessionId"),
        ciphertexts: {
            ik: validateBase64(data.ciphertexts?.ik, "ciphertexts.ik"),
            spk: validateBase64(data.ciphertexts?.spk, "ciphertexts.spk"),
        },
    };
    if (data.ciphertexts?.otpk) {
        result.ciphertexts.otpk = validateBase64(data.ciphertexts.otpk, "ciphertexts.otpk");
    }
    if (data.ratchetPubKey) {
        result.ratchetPubKey = validateBase64(data.ratchetPubKey, "ratchetPubKey");
    }
    if (data.protocolVersion) {
        result.protocolVersion = validateString(data.protocolVersion, "protocolVersion");
    }
    return result;
}
export function validateEncryptedMessage(data) {
    if (!data || typeof data !== "object") {
        throw new ValidationError("EncryptedMessage must be an object");
    }
    const result = {
        sessionId: validateString(data.sessionId, "sessionId"),
        ciphertext: validateBase64(data.ciphertext, "ciphertext"),
        nonce: validateBase64(data.nonce, "nonce"),
        messageNumber: validatePositiveNumber(data.messageNumber, "messageNumber"),
        timestamp: validatePositiveNumber(data.timestamp, "timestamp"),
    };
    if (data.ratchetPubKey !== undefined) {
        result.ratchetPubKey = validateBase64(data.ratchetPubKey, "ratchetPubKey");
    }
    if (data.pn !== undefined) {
        result.pn = validatePositiveNumber(data.pn, "pn");
    }
    if (data.protocolVersion !== undefined) {
        result.protocolVersion = validateString(data.protocolVersion, "protocolVersion");
    }
    if (data.pq !== undefined) {
        result.pq = {
            algorithm: data.pq.algorithm
                ? validateString(data.pq.algorithm, "pq.algorithm")
                : undefined,
            ciphertext: data.pq.ciphertext
                ? validateBase64(data.pq.ciphertext, "pq.ciphertext")
                : undefined,
        };
    }
    return result;
}
export function validateSenderKeyDistributionMessage(data) {
    if (!data || typeof data !== "object") {
        throw new ValidationError("SenderKeyDistributionMessage must be an object");
    }
    if (data.type !== "distribution") {
        throw new ValidationError('type must be "distribution"', "type");
    }
    return {
        type: "distribution",
        senderId: validateString(data.senderId, "senderId"),
        groupId: validateString(data.groupId, "groupId"),
        chainKey: validateBase64(data.chainKey, "chainKey"),
        signatureKey: validateBase64(data.signatureKey, "signatureKey"),
        generation: validatePositiveNumber(data.generation, "generation"),
    };
}
export function validateSenderKeyMessage(data) {
    if (!data || typeof data !== "object") {
        throw new ValidationError("SenderKeyMessage must be an object");
    }
    if (data.type !== "message") {
        throw new ValidationError('type must be "message"', "type");
    }
    return {
        type: "message",
        senderId: validateString(data.senderId, "senderId"),
        groupId: validateString(data.groupId, "groupId"),
        generation: validatePositiveNumber(data.generation, "generation"),
        sequence: validatePositiveNumber(data.sequence, "sequence"),
        cipherText: validateBase64(data.cipherText, "cipherText"),
        nonce: validateBase64(data.nonce, "nonce"),
    };
}
// Runtime type guards
export function isUserIdentity(data) {
    try {
        validateUserIdentity(data);
        return true;
    }
    catch {
        return false;
    }
}
export function isExtendedUserIdentity(data) {
    try {
        validateUserIdentity(data);
        return data.signedPreKey !== undefined && data.oneTimePreKeys !== undefined;
    }
    catch {
        return false;
    }
}
export function isSessionInitData(data) {
    try {
        validateSessionInitData(data);
        return true;
    }
    catch {
        return false;
    }
}
export function isEncryptedMessage(data) {
    try {
        validateEncryptedMessage(data);
        return true;
    }
    catch {
        return false;
    }
}
export function isSenderKeyDistributionMessage(data) {
    try {
        validateSenderKeyDistributionMessage(data);
        return true;
    }
    catch {
        return false;
    }
}
export function isSenderKeyMessage(data) {
    try {
        validateSenderKeyMessage(data);
        return true;
    }
    catch {
        return false;
    }
}
