import { StorageAdapter } from "../src/types";

export class MockStorage implements StorageAdapter {
  private store = new Map<string, string>();

  async setItem(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async getItem(key: string): Promise<string | null> {
    return this.store.get(key) || null;
  }

  async removeItem(key: string): Promise<void> {
    this.store.delete(key);
  }

  clear() {
    this.store.clear();
  }
}
