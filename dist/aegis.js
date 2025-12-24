// aegis.ts
import { AegisError } from "./types";
export class Aegis {
    constructor(config) {
        Object.defineProperty(this, "config", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        Object.defineProperty(this, "currentUserId", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        if (config) {
            this.init(config);
        }
    }
    init(configuration) {
        if (!configuration.storage) {
            throw new AegisError("Storage adapter is required", "INIT_ERROR");
        }
        this.config = configuration;
        this.currentUserId = configuration.userId || null;
    }
    getStorage() {
        if (!this.config) {
            throw new AegisError("Aegis instance not initialized", "NOT_INITIALIZED");
        }
        return this.config.storage;
    }
    getUserId() {
        return this.currentUserId;
    }
    getScopedKey(baseKey) {
        if (!this.config) {
            throw new AegisError("Aegis instance not initialized", "NOT_INITIALIZED");
        }
        return this.config.userId ? `${this.config.userId}_${baseKey}` : baseKey;
    }
    isInitialized() {
        return this.config !== null;
    }
    getConfig() {
        return this.config;
    }
}
