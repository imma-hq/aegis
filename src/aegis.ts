// aegis.ts
import { StorageAdapter, AegisConfig, AegisError } from "./types";

export class Aegis {
  private config: AegisConfig | null = null;
  private currentUserId: string | null = null;

  constructor(config?: AegisConfig) {
    if (config) {
      this.init(config);
    }
  }

  init(configuration: AegisConfig): void {
    if (!configuration.storage) {
      throw new AegisError("Storage adapter is required", "INIT_ERROR");
    }

    this.config = configuration;
    this.currentUserId = configuration.userId || null;
  }

  getStorage(): StorageAdapter {
    if (!this.config) {
      throw new AegisError("Aegis instance not initialized", "NOT_INITIALIZED");
    }
    return this.config.storage;
  }

  getUserId(): string | null {
    return this.currentUserId;
  }

  getScopedKey(baseKey: string): string {
    if (!this.config) {
      throw new AegisError("Aegis instance not initialized", "NOT_INITIALIZED");
    }
    return this.config.userId ? `${this.config.userId}_${baseKey}` : baseKey;
  }

  isInitialized(): boolean {
    return this.config !== null;
  }

  getConfig(): AegisConfig | null {
    return this.config;
  }
}
