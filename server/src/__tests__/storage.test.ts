/**
 * Storage module tests - Multi-tenant encrypted storage
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createStorage, createEncryptedStorage, Storage, EncryptedStorage } from '../storage.js';
import { mkdir, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';

const TEST_DATA_DIR = '/tmp/sp-storage-test';

describe('EncryptedStorage', () => {
  let storage: EncryptedStorage;

  beforeEach(async () => {
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
    await mkdir(TEST_DATA_DIR, { recursive: true });
    storage = createEncryptedStorage({ dataDir: TEST_DATA_DIR });
    await storage.init();
  });

  afterEach(async () => {
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
  });

  describe('basic operations', () => {
    it('should set and get a value for a user', async () => {
      await storage.set('user1', 'key1', 'value1');
      const value = await storage.get<string>('user1', 'key1');
      expect(value).toBe('value1');
    });

    it('should return undefined for missing key', async () => {
      const value = await storage.get('user1', 'nonexistent');
      expect(value).toBeUndefined();
    });

    it('should return undefined for missing user', async () => {
      const value = await storage.get('nonexistent', 'key');
      expect(value).toBeUndefined();
    });

    it('should store complex objects', async () => {
      const obj = { name: 'test', count: 42, nested: { a: 1, b: [1, 2, 3] } };
      await storage.set('user1', 'complex', obj);
      const value = await storage.get<typeof obj>('user1', 'complex');
      expect(value).toEqual(obj);
    });

    it('should overwrite existing values', async () => {
      await storage.set('user1', 'key', 'first');
      await storage.set('user1', 'key', 'second');
      const value = await storage.get('user1', 'key');
      expect(value).toBe('second');
    });

    it('should delete a key', async () => {
      await storage.set('user1', 'toDelete', 'value');
      const deleted = await storage.delete('user1', 'toDelete');
      expect(deleted).toBe(true);
      const value = await storage.get('user1', 'toDelete');
      expect(value).toBeUndefined();
    });

    it('should return false when deleting nonexistent key', async () => {
      const deleted = await storage.delete('user1', 'nonexistent');
      expect(deleted).toBe(false);
    });

    it('should check if key exists', async () => {
      await storage.set('user1', 'exists', 'yes');
      expect(await storage.has('user1', 'exists')).toBe(true);
      expect(await storage.has('user1', 'doesNotExist')).toBe(false);
    });

    it('should list all keys for a user', async () => {
      await storage.set('user1', 'a', 1);
      await storage.set('user1', 'b', 2);
      await storage.set('user1', 'c', 3);
      const keys = await storage.keys('user1');
      expect(keys.sort()).toEqual(['a', 'b', 'c']);
    });

    it('should clear all entries for a user', async () => {
      await storage.set('user1', 'a', 1);
      await storage.set('user1', 'b', 2);
      await storage.clearUser('user1');
      const keys = await storage.keys('user1');
      expect(keys).toEqual([]);
    });
  });

  describe('multi-tenant isolation', () => {
    it('should isolate data between users', async () => {
      await storage.set('user1', 'secret', 'user1-secret');
      await storage.set('user2', 'secret', 'user2-secret');

      expect(await storage.get('user1', 'secret')).toBe('user1-secret');
      expect(await storage.get('user2', 'secret')).toBe('user2-secret');
    });

    it('should not allow one user to access another users data', async () => {
      await storage.set('user1', 'private', 'user1-only');
      
      // user2 should not see user1's data
      const value = await storage.get('user2', 'private');
      expect(value).toBeUndefined();
    });

    it('should list all users', async () => {
      await storage.set('alice', 'key', 'value');
      await storage.set('bob', 'key', 'value');
      await storage.set('charlie', 'key', 'value');

      const users = await storage.listUsers();
      expect(users.sort()).toEqual(['alice', 'bob', 'charlie']);
    });

    it('should clear one user without affecting others', async () => {
      await storage.set('user1', 'data', 'user1-data');
      await storage.set('user2', 'data', 'user2-data');

      await storage.clearUser('user1');

      expect(await storage.get('user1', 'data')).toBeUndefined();
      expect(await storage.get('user2', 'data')).toBe('user2-data');
    });
  });

  describe('encryption', () => {
    it('should encrypt data on disk', async () => {
      await storage.set('user1', 'secret', 'my-secret-value');

      // Read raw state file
      const stateFile = join(TEST_DATA_DIR, 'state.json');
      const rawData = await readFile(stateFile, 'utf-8');
      
      // The secret value should NOT appear in plaintext
      expect(rawData).not.toContain('my-secret-value');
      
      // But should contain encryption artifacts
      expect(rawData).toContain('ciphertext');
      expect(rawData).toContain('iv');
      expect(rawData).toContain('authTag');
    });

    it('should use different encrypted values for same data under different users', async () => {
      const sameValue = 'identical-secret';
      await storage.set('user1', 'key', sameValue);
      await storage.set('user2', 'key', sameValue);

      const stateFile = join(TEST_DATA_DIR, 'state.json');
      const rawData = JSON.parse(await readFile(stateFile, 'utf-8'));

      const user1Encrypted = rawData.users.user1.key.ciphertext;
      const user2Encrypted = rawData.users.user2.key.ciphertext;

      // Different users should have different ciphertext for same plaintext
      // (due to different derived keys)
      expect(user1Encrypted).not.toBe(user2Encrypted);
    });

    it('should persist master key on disk', async () => {
      // Master key file should exist after init
      const keyFile = join(TEST_DATA_DIR, 'master.key.sealed');
      const keyData = await readFile(keyFile);
      expect(keyData.length).toBe(32); // 256-bit key
    });

    it('should load existing master key on restart', async () => {
      await storage.set('user1', 'key', 'persistent');

      // Create new storage instance pointing to same directory
      const storage2 = createEncryptedStorage({ dataDir: TEST_DATA_DIR });
      await storage2.init();

      // Should be able to decrypt data with same keys
      const value = await storage2.get('user1', 'key');
      expect(value).toBe('persistent');
    });
  });

  describe('key rotation', () => {
    it('should rotate master key and re-encrypt all data', async () => {
      await storage.set('user1', 'data1', 'value1');
      await storage.set('user2', 'data2', 'value2');

      // Read current ciphertext
      const stateFile = join(TEST_DATA_DIR, 'state.json');
      const beforeRotation = JSON.parse(await readFile(stateFile, 'utf-8'));
      const oldCiphertext = beforeRotation.users.user1.data1.ciphertext;

      // Rotate key
      await storage.rotateMasterKey();

      // Read new ciphertext
      const afterRotation = JSON.parse(await readFile(stateFile, 'utf-8'));
      const newCiphertext = afterRotation.users.user1.data1.ciphertext;

      // Ciphertext should be different after rotation
      expect(newCiphertext).not.toBe(oldCiphertext);

      // But data should still be accessible
      expect(await storage.get('user1', 'data1')).toBe('value1');
      expect(await storage.get('user2', 'data2')).toBe('value2');
    });
  });
});

describe('Storage (backward compatible)', () => {
  let storage: Storage;

  beforeEach(async () => {
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
    await mkdir(TEST_DATA_DIR, { recursive: true });
    storage = createStorage(TEST_DATA_DIR);
    await storage.init();
  });

  afterEach(async () => {
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
  });

  it('should work with simple key-value API', async () => {
    await storage.set('key', 'value');
    expect(await storage.get('key')).toBe('value');
  });

  it('should persist across instances', async () => {
    await storage.set('persistent', 'data');
    
    const storage2 = createStorage(TEST_DATA_DIR);
    await storage2.init();
    
    expect(await storage2.get('persistent')).toBe('data');
  });

  it('should list keys', async () => {
    await storage.set('a', 1);
    await storage.set('b', 2);
    const keys = await storage.keys();
    expect(keys.sort()).toEqual(['a', 'b']);
  });

  it('should clear entries', async () => {
    await storage.set('x', 'y');
    await storage.clear();
    expect(await storage.keys()).toEqual([]);
  });
});
