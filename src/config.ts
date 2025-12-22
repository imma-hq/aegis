import { StorageAdapter } from "./types";

interface AegisConfig {
  storage: StorageAdapter;
}

let config: AegisConfig | null = null;

export const Aegis = {
  /**
   * Initialize the Aegis library with the necessary adapters.
   * This must be called before using any other functionality.
   */
  init(configuration: AegisConfig) {
    config = configuration;
  },

  /**
   * Get the configured storage adapter.
   * Throws if the library has not been initialized.
   */
  getStorage(): StorageAdapter {
    if (!config) {
      throw new Error(
        "Aegis library not initialized. Call Aegis.init() with a storage adapter.",
      );
    }
    return config.storage;
  },
};
