/**
 * Public types for Aegis - Complete Type System
 */
/**
 * Error Types
 */
export class AegisError extends Error {
    constructor(message, code, details) {
        super(message);
        Object.defineProperty(this, "code", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: code
        });
        Object.defineProperty(this, "details", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: details
        });
        this.name = "AegisError";
    }
}
export class ValidationError extends AegisError {
    constructor(message, field, details) {
        super(message, "VALIDATION_ERROR", details);
        Object.defineProperty(this, "field", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: field
        });
        this.name = "ValidationError";
    }
}
export class CryptoError extends AegisError {
    constructor(message, operation, details) {
        super(message, "CRYPTO_ERROR", details);
        Object.defineProperty(this, "operation", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: operation
        });
        this.name = "CryptoError";
    }
}
export class SessionError extends AegisError {
    constructor(message, sessionId, details) {
        super(message, "SESSION_ERROR", details);
        Object.defineProperty(this, "sessionId", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: sessionId
        });
        this.name = "SessionError";
    }
}
export class GroupError extends AegisError {
    constructor(message, groupId, details) {
        super(message, "GROUP_ERROR", details);
        Object.defineProperty(this, "groupId", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: groupId
        });
        this.name = "GroupError";
    }
}
