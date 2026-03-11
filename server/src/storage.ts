/**
 * Encrypted state management module.
 * Provides a simple key-value store interface persisted to the DATA_DIR.
 * Encryption is handled at the volume level (LUKS) by Kubernetes.
 */

import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { join } from 'node:path';
import type { StorageState, StorageEntry } from './types.js';

const STATE_FILE = 'state.json';
const CURRENT_VERSION = 1;

export class Storage {
  private dataDir: string;
  private state: StorageState;
  private initialized: boolean = false;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.state = {
      version: CURRENT_VERSION,
      entries: {},
    };
  }

  /** Ensure data directory exists */
  private async ensureDir(): Promise<void> {
    try {
      await access(this.dataDir);
    } catch {
      await mkdir(this.dataDir, { recursive: true });
    }
  }

  /** Get the full path to the state file */
  private get statePath(): string {
    return join(this.dataDir, STATE_FILE);
  }

  /** Initialize storage, loading existing state if present */
  async init(): Promise<void> {
    if (this.initialized) return;

    await this.ensureDir();

    try {
      const data = await readFile(this.statePath, 'utf-8');
      const parsed = JSON.parse(data) as StorageState;
      
      // Version migration could happen here
      if (parsed.version !== CURRENT_VERSION) {
        console.log(`[storage] Migrating state from v${parsed.version} to v${CURRENT_VERSION}`);
        // For now, just update version - add migration logic as needed
        parsed.version = CURRENT_VERSION;
      }
      
      this.state = parsed;
      console.log(`[storage] Loaded ${Object.keys(this.state.entries).length} entries from ${this.statePath}`);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        console.log('[storage] No existing state, starting fresh');
      } else {
        console.error('[storage] Error loading state:', err);
        throw err;
      }
    }

    this.initialized = true;
  }

  /** Persist current state to disk */
  private async save(): Promise<void> {
    await this.ensureDir();
    const data = JSON.stringify(this.state, null, 2);
    await writeFile(this.statePath, data, 'utf-8');
  }

  /** Get a value by key */
  async get<T = unknown>(key: string): Promise<T | undefined> {
    if (!this.initialized) await this.init();
    
    const entry = this.state.entries[key];
    return entry ? (entry.value as T) : undefined;
  }

  /** Set a value by key */
  async set<T = unknown>(key: string, value: T): Promise<void> {
    if (!this.initialized) await this.init();

    this.state.entries[key] = {
      key,
      value,
      updatedAt: Date.now(),
    };

    await this.save();
  }

  /** Delete a key */
  async delete(key: string): Promise<boolean> {
    if (!this.initialized) await this.init();

    if (!(key in this.state.entries)) {
      return false;
    }

    delete this.state.entries[key];
    await this.save();
    return true;
  }

  /** Check if a key exists */
  async has(key: string): Promise<boolean> {
    if (!this.initialized) await this.init();
    return key in this.state.entries;
  }

  /** Get all keys */
  async keys(): Promise<string[]> {
    if (!this.initialized) await this.init();
    return Object.keys(this.state.entries);
  }

  /** Get all entries */
  async entries(): Promise<StorageEntry[]> {
    if (!this.initialized) await this.init();
    return Object.values(this.state.entries);
  }

  /** Clear all entries */
  async clear(): Promise<void> {
    if (!this.initialized) await this.init();
    this.state.entries = {};
    await this.save();
  }
}

/** Create a new storage instance */
export function createStorage(dataDir: string): Storage {
  return new Storage(dataDir);
}
