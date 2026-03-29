import type { StorageAdapter } from "./adapter.js";

interface Entry {
  value: string;
  expires_at: number;
  timer: ReturnType<typeof setTimeout>;
}

export class MemoryAdapter implements StorageAdapter {
  private store = new Map<string, Entry>();

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() >= entry.expires_at) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async put(key: string, value: string, ttlSeconds: number): Promise<void> {
    const existing = this.store.get(key);
    if (existing) clearTimeout(existing.timer);

    const expires_at = Date.now() + ttlSeconds * 1000;
    const timer = setTimeout(() => this.store.delete(key), ttlSeconds * 1000);
    // Unref so the timer doesn't keep the process alive
    if (typeof timer === "object" && "unref" in timer) timer.unref();

    this.store.set(key, { value, expires_at, timer });
  }

  async delete(key: string): Promise<void> {
    const entry = this.store.get(key);
    if (entry) clearTimeout(entry.timer);
    this.store.delete(key);
  }
}
