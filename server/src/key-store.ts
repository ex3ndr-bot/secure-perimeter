/**
 * Replicated Key Store
 *
 * A versioned key store that supports replication between TEE nodes.
 * Keys are stored encrypted at rest and can be exported/imported
 * with session-key wrapping for secure transfer.
 */

import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { join } from 'node:path';
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  createHash,
} from 'node:crypto';
import type { ManagedKey, KeyInventoryEntry, WrappedKeyEnvelope } from './types.js';

const KEYSTORE_FILE = 'keystore.enc';
const ENCRYPTION_ALGO = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypted key entry stored on disk
 */
interface EncryptedKeyEntry {
  keyId: string;
  version: number;
  /** Encrypted key material (hex) */
  encryptedMaterial: string;
  /** IV used for encryption (hex) */
  iv: string;
  /** GCM auth tag (hex) */
  authTag: string;
  createdAt: number;
  updatedAt: number;
  metadata: Record<string, string>;
}

/**
 * Keystore state persisted to disk
 */
interface KeystoreState {
  version: number;
  keys: Record<string, EncryptedKeyEntry>;
}

/**
 * Configuration for the replicated key store
 */
export interface ReplicatedKeyStoreConfig {
  /** Directory for persistent storage */
  dataDir: string;
}

/**
 * Replicated key store with versioning and secure export/import
 */
export class ReplicatedKeyStore {
  private config: ReplicatedKeyStoreConfig;
  private keys: Map<string, ManagedKey> = new Map();
  private masterKey: Buffer | null = null;
  private initialized = false;

  constructor(config: ReplicatedKeyStoreConfig) {
    this.config = config;
  }

  /** Ensure data directory exists */
  private async ensureDir(): Promise<void> {
    try {
      await access(this.config.dataDir);
    } catch {
      await mkdir(this.config.dataDir, { recursive: true });
    }
  }

  /** Get path to keystore file */
  private get keystorePath(): string {
    return join(this.config.dataDir, KEYSTORE_FILE);
  }

  /** Get path to master key file */
  private get masterKeyPath(): string {
    return join(this.config.dataDir, 'keystore-master.key');
  }

  /**
   * Initialize the key store
   * @param masterKey - Optional master key for encryption. If not provided, generates or loads from disk.
   */
  async init(masterKey?: Buffer): Promise<void> {
    if (this.initialized) return;

    await this.ensureDir();

    if (masterKey) {
      this.masterKey = masterKey;
    } else {
      await this.loadOrCreateMasterKey();
    }

    await this.loadFromDisk();
    this.initialized = true;
  }

  /** Load or generate master key */
  private async loadOrCreateMasterKey(): Promise<void> {
    try {
      this.masterKey = await readFile(this.masterKeyPath);
      console.log('[keystore] Loaded master key');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        console.log('[keystore] Generating new master key');
        this.masterKey = randomBytes(32);
        await writeFile(this.masterKeyPath, this.masterKey);
      } else {
        throw err;
      }
    }
  }

  /** Encrypt key material with master key */
  private encryptMaterial(material: Buffer): { encrypted: Buffer; iv: Buffer; authTag: Buffer } {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ENCRYPTION_ALGO, this.masterKey!, iv);

    const encrypted = Buffer.concat([cipher.update(material), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return { encrypted, iv, authTag };
  }

  /** Decrypt key material with master key */
  private decryptMaterial(encrypted: Buffer, iv: Buffer, authTag: Buffer): Buffer {
    const decipher = createDecipheriv(ENCRYPTION_ALGO, this.masterKey!, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  /** Wrap key material with a session key for transfer */
  private wrapKey(material: Buffer, wrapKey: Buffer): Buffer {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ENCRYPTION_ALGO, wrapKey, iv);

    const encrypted = Buffer.concat([cipher.update(material), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Format: iv (12) + authTag (16) + ciphertext
    return Buffer.concat([iv, authTag, encrypted]);
  }

  /** Unwrap key material with a session key */
  private unwrapKey(wrapped: Buffer, unwrapKey: Buffer): Buffer {
    const iv = wrapped.subarray(0, IV_LENGTH);
    const authTag = wrapped.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
    const encrypted = wrapped.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

    const decipher = createDecipheriv(ENCRYPTION_ALGO, unwrapKey, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  /**
   * Get a key by ID
   */
  async getKey(keyId: string): Promise<ManagedKey | null> {
    if (!this.initialized) throw new Error('KeyStore not initialized');
    return this.keys.get(keyId) ?? null;
  }

  /**
   * Set (create or update) a key
   * If the key exists, version is incremented automatically
   */
  async setKey(key: Omit<ManagedKey, 'version' | 'updatedAt'> & { version?: number }): Promise<void> {
    if (!this.initialized) throw new Error('KeyStore not initialized');

    const existing = this.keys.get(key.keyId);
    const now = Date.now();

    const managedKey: ManagedKey = {
      keyId: key.keyId,
      version: key.version ?? (existing ? existing.version + 1 : 1),
      material: key.material,
      createdAt: existing?.createdAt ?? key.createdAt ?? now,
      updatedAt: now,
      metadata: key.metadata ?? {},
    };

    this.keys.set(key.keyId, managedKey);
    await this.persistToDisk();
  }

  /**
   * Delete a key
   */
  async deleteKey(keyId: string): Promise<boolean> {
    if (!this.initialized) throw new Error('KeyStore not initialized');

    const deleted = this.keys.delete(keyId);
    if (deleted) {
      await this.persistToDisk();
    }
    return deleted;
  }

  /**
   * List all keys (ID and version only, no material)
   */
  async listKeys(): Promise<KeyInventoryEntry[]> {
    if (!this.initialized) throw new Error('KeyStore not initialized');

    return Array.from(this.keys.values()).map((k) => ({
      keyId: k.keyId,
      version: k.version,
    }));
  }

  /**
   * Get the number of keys in the store
   */
  async count(): Promise<number> {
    if (!this.initialized) throw new Error('KeyStore not initialized');
    return this.keys.size;
  }

  /**
   * Export keys for sync transfer
   * Keys are wrapped with the provided session key
   */
  async exportForSync(keyIds: string[], wrapKey: Buffer): Promise<WrappedKeyEnvelope[]> {
    if (!this.initialized) throw new Error('KeyStore not initialized');
    if (wrapKey.length !== 32) {
      throw new Error('Wrap key must be 32 bytes');
    }

    const envelopes: WrappedKeyEnvelope[] = [];

    for (const keyId of keyIds) {
      const key = this.keys.get(keyId);
      if (!key) continue;

      const wrappedMaterial = this.wrapKey(key.material, wrapKey);

      envelopes.push({
        keyId: key.keyId,
        version: key.version,
        wrappedMaterial,
        createdAt: key.createdAt,
        updatedAt: key.updatedAt,
        metadata: key.metadata,
      });
    }

    return envelopes;
  }

  /**
   * Import keys from sync transfer
   * Returns the number of keys imported/updated
   * Uses conflict resolution: higher version wins
   */
  async importFromSync(envelopes: WrappedKeyEnvelope[], unwrapKey: Buffer): Promise<number> {
    if (!this.initialized) throw new Error('KeyStore not initialized');
    if (unwrapKey.length !== 32) {
      throw new Error('Unwrap key must be 32 bytes');
    }

    let imported = 0;

    for (const envelope of envelopes) {
      const existing = this.keys.get(envelope.keyId);

      // Conflict resolution: higher version wins
      if (existing && existing.version >= envelope.version) {
        continue;
      }

      const material = this.unwrapKey(envelope.wrappedMaterial, unwrapKey);

      const managedKey: ManagedKey = {
        keyId: envelope.keyId,
        version: envelope.version,
        material,
        createdAt: envelope.createdAt,
        updatedAt: envelope.updatedAt,
        metadata: envelope.metadata,
      };

      this.keys.set(envelope.keyId, managedKey);
      imported++;
    }

    if (imported > 0) {
      await this.persistToDisk();
    }

    return imported;
  }

  /**
   * Persist keys to disk (encrypted)
   */
  async persistToDisk(): Promise<void> {
    if (!this.masterKey) throw new Error('Master key not set');

    const state: KeystoreState = {
      version: 1,
      keys: {},
    };

    for (const [keyId, key] of this.keys) {
      const { encrypted, iv, authTag } = this.encryptMaterial(key.material);

      state.keys[keyId] = {
        keyId: key.keyId,
        version: key.version,
        encryptedMaterial: encrypted.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        createdAt: key.createdAt,
        updatedAt: key.updatedAt,
        metadata: key.metadata,
      };
    }

    await writeFile(this.keystorePath, JSON.stringify(state, null, 2));
  }

  /**
   * Load keys from disk
   */
  async loadFromDisk(): Promise<void> {
    if (!this.masterKey) throw new Error('Master key not set');

    try {
      const data = await readFile(this.keystorePath, 'utf-8');
      const state: KeystoreState = JSON.parse(data);

      this.keys.clear();

      for (const entry of Object.values(state.keys)) {
        const encrypted = Buffer.from(entry.encryptedMaterial, 'hex');
        const iv = Buffer.from(entry.iv, 'hex');
        const authTag = Buffer.from(entry.authTag, 'hex');

        const material = this.decryptMaterial(encrypted, iv, authTag);

        this.keys.set(entry.keyId, {
          keyId: entry.keyId,
          version: entry.version,
          material,
          createdAt: entry.createdAt,
          updatedAt: entry.updatedAt,
          metadata: entry.metadata,
        });
      }

      console.log(`[keystore] Loaded ${this.keys.size} keys from disk`);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        console.log('[keystore] No existing keystore found, starting fresh');
        this.keys.clear();
      } else {
        throw err;
      }
    }
  }

  /**
   * Clear all keys (for testing)
   */
  async clear(): Promise<void> {
    this.keys.clear();
    await this.persistToDisk();
  }
}

/**
 * Create a new replicated key store
 */
export function createReplicatedKeyStore(config: ReplicatedKeyStoreConfig): ReplicatedKeyStore {
  return new ReplicatedKeyStore(config);
}
