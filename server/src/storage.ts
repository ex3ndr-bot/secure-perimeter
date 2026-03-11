/**
 * Multi-tenant Encrypted Storage Module
 * 
 * Provides encrypted key-value storage with per-user key isolation:
 * 1. Pod master key is derived from attestation identity on first boot
 * 2. Per-user subkeys are derived using HKDF(master_key, user_id)
 * 3. Each user's data is encrypted with their unique derived key
 * 4. Keys are sealed to the TEE (or stored securely in dev mode)
 * 
 * CRITICAL: Never share encryption keys between users!
 */

import { readFile, writeFile, mkdir, access, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes, createHash, hkdfSync } from 'node:crypto';
import type { StorageState, StorageEntry } from './types.js';

const STATE_FILE = 'state.json';
const MASTER_KEY_FILE = 'master.key.sealed';
const CURRENT_VERSION = 2;
const ENCRYPTION_ALGO = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12;  // 96 bits for GCM
const AUTH_TAG_LENGTH = 16;

/**
 * Configuration for the encrypted storage
 */
export interface EncryptedStorageConfig {
  dataDir: string;
  /** Pod identity for key derivation (e.g., measurement hash) */
  podIdentity?: Uint8Array;
  /** Whether to use hardware key sealing (requires TEE) */
  useHardwareSealing?: boolean;
}

/**
 * Encrypted entry stored on disk
 */
interface EncryptedEntry {
  /** IV used for encryption */
  iv: string;  // hex
  /** Encrypted value */
  ciphertext: string;  // hex
  /** GCM auth tag */
  authTag: string;  // hex
  /** Timestamp */
  updatedAt: number;
}

/**
 * Encrypted storage state on disk
 */
interface EncryptedStorageState {
  version: number;
  /** Per-user encrypted entries: userId -> { key -> EncryptedEntry } */
  users: Record<string, Record<string, EncryptedEntry>>;
}

/**
 * Multi-tenant encrypted storage with per-user key isolation
 */
export class EncryptedStorage {
  private config: EncryptedStorageConfig;
  private masterKey: Buffer | null = null;
  private userKeys: Map<string, Buffer> = new Map();
  private state: EncryptedStorageState;
  private initialized: boolean = false;

  constructor(config: EncryptedStorageConfig) {
    this.config = config;
    this.state = {
      version: CURRENT_VERSION,
      users: {},
    };
  }

  /** Ensure data directory exists */
  private async ensureDir(): Promise<void> {
    try {
      await access(this.config.dataDir);
    } catch {
      await mkdir(this.config.dataDir, { recursive: true });
    }
  }

  /** Get the full path to the state file */
  private get statePath(): string {
    return join(this.config.dataDir, STATE_FILE);
  }

  /** Get the full path to the sealed master key file */
  private get masterKeyPath(): string {
    return join(this.config.dataDir, MASTER_KEY_FILE);
  }

  /**
   * Generate or load the pod master key.
   * In production, this would be:
   * 1. Derived from attestation identity + KBS
   * 2. Sealed to the TEE for persistence
   * 
   * In dev mode, we generate and store locally (NOT SECURE!)
   */
  private async loadOrCreateMasterKey(): Promise<Buffer> {
    if (this.masterKey) {
      return this.masterKey;
    }

    try {
      // Try to load existing sealed key
      const sealedKey = await readFile(this.masterKeyPath);
      
      if (this.config.useHardwareSealing) {
        // In production: unseal using TPM/TEE
        // For now, we just read directly (dev mode)
        console.log('[storage] Unsealing master key (dev mode - not actually sealed)');
      } else {
        console.log('[storage] Loaded master key from disk');
      }
      
      this.masterKey = sealedKey;
      return this.masterKey;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw err;
      }
    }

    // Generate new master key
    console.log('[storage] Generating new pod master key');
    
    let keyMaterial: Buffer;
    
    if (this.config.podIdentity) {
      // Derive from pod identity for reproducibility
      // In production, this would involve KBS and attestation
      keyMaterial = createHash('sha256')
        .update(this.config.podIdentity)
        .update(Buffer.from('secure-perimeter-master-key-v1'))
        .digest();
    } else {
      // Random key for dev mode
      keyMaterial = randomBytes(KEY_LENGTH);
    }

    this.masterKey = keyMaterial;

    // Seal and persist the key
    await this.ensureDir();
    
    if (this.config.useHardwareSealing) {
      // In production: seal using TPM/TEE
      // For now, just write directly (dev mode)
      console.log('[storage] Sealing master key (dev mode - not actually sealed)');
    }
    
    await writeFile(this.masterKeyPath, this.masterKey, { mode: 0o600 });
    console.log('[storage] Master key generated and sealed');
    
    return this.masterKey;
  }

  /**
   * Derive a per-user encryption key using HKDF.
   * Each user gets a unique key derived from:
   *   HKDF(master_key, user_id, "secure-perimeter-user-key-v1")
   */
  private async deriveUserKey(userId: string): Promise<Buffer> {
    // Check cache
    const cached = this.userKeys.get(userId);
    if (cached) {
      return cached;
    }

    const masterKey = await this.loadOrCreateMasterKey();
    
    // Use HKDF to derive user-specific key
    const userKey = Buffer.from(hkdfSync(
      'sha256',
      masterKey,
      Buffer.from(userId),  // salt = userId
      Buffer.from('secure-perimeter-user-key-v1'),  // info
      KEY_LENGTH
    ));

    this.userKeys.set(userId, userKey);
    return userKey;
  }

  /**
   * Encrypt a value for a specific user
   */
  private async encryptValue(userId: string, value: unknown): Promise<EncryptedEntry> {
    const key = await this.deriveUserKey(userId);
    const iv = randomBytes(IV_LENGTH);
    const plaintext = JSON.stringify(value);
    
    const cipher = createCipheriv(ENCRYPTION_ALGO, key, iv, {
      authTagLength: AUTH_TAG_LENGTH
    });
    
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, 'utf-8'),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('hex'),
      ciphertext: ciphertext.toString('hex'),
      authTag: authTag.toString('hex'),
      updatedAt: Date.now()
    };
  }

  /**
   * Decrypt a value for a specific user
   */
  private async decryptValue<T>(userId: string, entry: EncryptedEntry): Promise<T> {
    const key = await this.deriveUserKey(userId);
    const iv = Buffer.from(entry.iv, 'hex');
    const ciphertext = Buffer.from(entry.ciphertext, 'hex');
    const authTag = Buffer.from(entry.authTag, 'hex');
    
    const decipher = createDecipheriv(ENCRYPTION_ALGO, key, iv, {
      authTagLength: AUTH_TAG_LENGTH
    });
    decipher.setAuthTag(authTag);
    
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]).toString('utf-8');
    
    return JSON.parse(plaintext) as T;
  }

  /** Initialize storage, loading existing state if present */
  async init(): Promise<void> {
    if (this.initialized) return;

    await this.ensureDir();
    await this.loadOrCreateMasterKey();

    try {
      const data = await readFile(this.statePath, 'utf-8');
      const parsed = JSON.parse(data) as EncryptedStorageState;

      // Version migration
      if (parsed.version !== CURRENT_VERSION) {
        console.log(`[storage] Migrating state from v${parsed.version} to v${CURRENT_VERSION}`);
        parsed.version = CURRENT_VERSION;
      }

      this.state = parsed;
      
      const userCount = Object.keys(this.state.users).length;
      const entryCount = Object.values(this.state.users)
        .reduce((sum, entries) => sum + Object.keys(entries).length, 0);
      console.log(`[storage] Loaded ${entryCount} entries for ${userCount} users`);
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

  /**
   * Get a value by key for a specific user
   */
  async get<T = unknown>(userId: string, key: string): Promise<T | undefined> {
    if (!this.initialized) await this.init();

    const userEntries = this.state.users[userId];
    if (!userEntries) return undefined;

    const entry = userEntries[key];
    if (!entry) return undefined;

    try {
      return await this.decryptValue<T>(userId, entry);
    } catch (err) {
      console.error(`[storage] Failed to decrypt entry ${key} for user ${userId}:`, err);
      return undefined;
    }
  }

  /**
   * Set a value by key for a specific user
   */
  async set<T = unknown>(userId: string, key: string, value: T): Promise<void> {
    if (!this.initialized) await this.init();

    if (!this.state.users[userId]) {
      this.state.users[userId] = {};
    }

    this.state.users[userId][key] = await this.encryptValue(userId, value);
    await this.save();
  }

  /**
   * Delete a key for a specific user
   */
  async delete(userId: string, key: string): Promise<boolean> {
    if (!this.initialized) await this.init();

    const userEntries = this.state.users[userId];
    if (!userEntries || !(key in userEntries)) {
      return false;
    }

    delete userEntries[key];
    
    // Clean up empty user records
    if (Object.keys(userEntries).length === 0) {
      delete this.state.users[userId];
    }
    
    await this.save();
    return true;
  }

  /**
   * Check if a key exists for a specific user
   */
  async has(userId: string, key: string): Promise<boolean> {
    if (!this.initialized) await this.init();
    return !!(this.state.users[userId]?.[key]);
  }

  /**
   * Get all keys for a specific user
   */
  async keys(userId: string): Promise<string[]> {
    if (!this.initialized) await this.init();
    return Object.keys(this.state.users[userId] || {});
  }

  /**
   * Get all entries for a specific user (decrypted)
   */
  async entries(userId: string): Promise<StorageEntry[]> {
    if (!this.initialized) await this.init();

    const userEntries = this.state.users[userId];
    if (!userEntries) return [];

    const results: StorageEntry[] = [];
    for (const [key, encrypted] of Object.entries(userEntries)) {
      try {
        const value = await this.decryptValue(userId, encrypted);
        results.push({ key, value, updatedAt: encrypted.updatedAt });
      } catch {
        // Skip entries that fail to decrypt
        console.warn(`[storage] Skipping entry ${key} - decryption failed`);
      }
    }
    return results;
  }

  /**
   * Clear all entries for a specific user
   */
  async clearUser(userId: string): Promise<void> {
    if (!this.initialized) await this.init();
    delete this.state.users[userId];
    this.userKeys.delete(userId);
    await this.save();
  }

  /**
   * Clear all storage (all users)
   * WARNING: This deletes all data!
   */
  async clearAll(): Promise<void> {
    if (!this.initialized) await this.init();
    this.state.users = {};
    this.userKeys.clear();
    await this.save();
  }

  /**
   * Get list of all user IDs with stored data
   */
  async listUsers(): Promise<string[]> {
    if (!this.initialized) await this.init();
    return Object.keys(this.state.users);
  }

  /**
   * Rotate the master key (re-encrypts all data)
   * Use this for key rotation policies
   */
  async rotateMasterKey(): Promise<void> {
    if (!this.initialized) await this.init();

    console.log('[storage] Starting master key rotation...');

    // Decrypt all data with old keys
    const allData: Map<string, Map<string, unknown>> = new Map();
    for (const userId of Object.keys(this.state.users)) {
      const userData = new Map<string, unknown>();
      for (const [key, encrypted] of Object.entries(this.state.users[userId])) {
        try {
          const value = await this.decryptValue(userId, encrypted);
          userData.set(key, value);
        } catch {
          console.warn(`[storage] Lost entry ${userId}/${key} during rotation`);
        }
      }
      allData.set(userId, userData);
    }

    // Generate new master key
    const oldMasterKey = this.masterKey;
    this.masterKey = null;
    this.userKeys.clear();
    
    try {
      await unlink(this.masterKeyPath);
    } catch {}
    
    await this.loadOrCreateMasterKey();

    // Re-encrypt all data with new keys
    this.state.users = {};
    for (const [userId, userData] of allData) {
      this.state.users[userId] = {};
      for (const [key, value] of userData) {
        this.state.users[userId][key] = await this.encryptValue(userId, value);
      }
    }

    await this.save();
    console.log('[storage] Master key rotation complete');
  }
}

/**
 * Legacy Storage class for backward compatibility.
 * Uses a single default user. Prefer EncryptedStorage for multi-tenant use.
 */
export class Storage {
  private encryptedStorage: EncryptedStorage;
  private userId = '__default__';

  constructor(dataDir: string) {
    this.encryptedStorage = new EncryptedStorage({ dataDir });
  }

  async init(): Promise<void> {
    await this.encryptedStorage.init();
  }

  async get<T = unknown>(key: string): Promise<T | undefined> {
    return this.encryptedStorage.get<T>(this.userId, key);
  }

  async set<T = unknown>(key: string, value: T): Promise<void> {
    return this.encryptedStorage.set(this.userId, key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.encryptedStorage.delete(this.userId, key);
  }

  async has(key: string): Promise<boolean> {
    return this.encryptedStorage.has(this.userId, key);
  }

  async keys(): Promise<string[]> {
    return this.encryptedStorage.keys(this.userId);
  }

  async entries(): Promise<StorageEntry[]> {
    return this.encryptedStorage.entries(this.userId);
  }

  async clear(): Promise<void> {
    return this.encryptedStorage.clearUser(this.userId);
  }
}

/** Create a new storage instance (backward compatible) */
export function createStorage(dataDir: string): Storage {
  return new Storage(dataDir);
}

/** Create a new multi-tenant encrypted storage */
export function createEncryptedStorage(config: EncryptedStorageConfig): EncryptedStorage {
  return new EncryptedStorage(config);
}
