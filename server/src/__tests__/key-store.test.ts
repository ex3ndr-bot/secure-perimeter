/**
 * Replicated Key Store tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createReplicatedKeyStore, ReplicatedKeyStore } from '../key-store.js';
import { mkdir, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const TEST_DATA_DIR = '/tmp/sp-keystore-test';

describe('ReplicatedKeyStore', () => {
  let keyStore: ReplicatedKeyStore;

  beforeEach(async () => {
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
    await mkdir(TEST_DATA_DIR, { recursive: true });
    keyStore = createReplicatedKeyStore({ dataDir: TEST_DATA_DIR });
    await keyStore.init();
  });

  afterEach(async () => {
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
  });

  describe('CRUD operations', () => {
    it('should create and retrieve a key', async () => {
      const material = randomBytes(32);

      await keyStore.setKey({
        keyId: 'key-1',
        material,
        createdAt: Date.now(),
        metadata: { purpose: 'encryption' },
      });

      const key = await keyStore.getKey('key-1');
      expect(key).not.toBeNull();
      expect(key!.keyId).toBe('key-1');
      expect(key!.material.equals(material)).toBe(true);
      expect(key!.version).toBe(1);
      expect(key!.metadata.purpose).toBe('encryption');
    });

    it('should return null for non-existent key', async () => {
      const key = await keyStore.getKey('non-existent');
      expect(key).toBeNull();
    });

    it('should update a key and increment version', async () => {
      const material1 = randomBytes(32);
      const material2 = randomBytes(32);

      await keyStore.setKey({
        keyId: 'key-1',
        material: material1,
        createdAt: Date.now(),
        metadata: {},
      });

      const key1 = await keyStore.getKey('key-1');
      expect(key1!.version).toBe(1);

      await keyStore.setKey({
        keyId: 'key-1',
        material: material2,
        createdAt: Date.now(),
        metadata: {},
      });

      const key2 = await keyStore.getKey('key-1');
      expect(key2!.version).toBe(2);
      expect(key2!.material.equals(material2)).toBe(true);
    });

    it('should delete a key', async () => {
      await keyStore.setKey({
        keyId: 'to-delete',
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });

      const deleted = await keyStore.deleteKey('to-delete');
      expect(deleted).toBe(true);

      const key = await keyStore.getKey('to-delete');
      expect(key).toBeNull();
    });

    it('should return false when deleting non-existent key', async () => {
      const deleted = await keyStore.deleteKey('non-existent');
      expect(deleted).toBe(false);
    });

    it('should list all keys with versions', async () => {
      await keyStore.setKey({
        keyId: 'key-a',
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });
      await keyStore.setKey({
        keyId: 'key-b',
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });
      // Update key-a to version 2
      await keyStore.setKey({
        keyId: 'key-a',
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });

      const inventory = await keyStore.listKeys();
      expect(inventory.length).toBe(2);

      const keyA = inventory.find((k) => k.keyId === 'key-a');
      const keyB = inventory.find((k) => k.keyId === 'key-b');
      expect(keyA!.version).toBe(2);
      expect(keyB!.version).toBe(1);
    });

    it('should count keys', async () => {
      expect(await keyStore.count()).toBe(0);

      await keyStore.setKey({
        keyId: 'key-1',
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });
      expect(await keyStore.count()).toBe(1);

      await keyStore.setKey({
        keyId: 'key-2',
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });
      expect(await keyStore.count()).toBe(2);
    });
  });

  describe('version tracking', () => {
    it('should preserve version when explicitly provided', async () => {
      await keyStore.setKey({
        keyId: 'key-1',
        version: 5,
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });

      const key = await keyStore.getKey('key-1');
      expect(key!.version).toBe(5);
    });

    it('should track createdAt from first version', async () => {
      const createdAt = Date.now() - 10000;

      await keyStore.setKey({
        keyId: 'key-1',
        material: randomBytes(32),
        createdAt,
        metadata: {},
      });

      // Update the key
      await keyStore.setKey({
        keyId: 'key-1',
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });

      const key = await keyStore.getKey('key-1');
      expect(key!.createdAt).toBe(createdAt);
      expect(key!.updatedAt).toBeGreaterThan(createdAt);
    });
  });

  describe('export/import with wrapping', () => {
    const wrapKey = randomBytes(32);

    it('should export keys wrapped with session key', async () => {
      const material = randomBytes(32);

      await keyStore.setKey({
        keyId: 'key-1',
        material,
        createdAt: Date.now(),
        metadata: { userId: 'user-123' },
      });

      const envelopes = await keyStore.exportForSync(['key-1'], wrapKey);
      expect(envelopes.length).toBe(1);

      const envelope = envelopes[0];
      expect(envelope.keyId).toBe('key-1');
      expect(envelope.version).toBe(1);
      expect(envelope.metadata.userId).toBe('user-123');

      // Wrapped material should be different from original
      expect(envelope.wrappedMaterial.equals(material)).toBe(false);
      // Should include IV (12) + authTag (16) + ciphertext
      expect(envelope.wrappedMaterial.length).toBeGreaterThan(material.length);
    });

    it('should import wrapped keys into empty store', async () => {
      // Create keys in a different store
      const store1 = createReplicatedKeyStore({ dataDir: TEST_DATA_DIR + '-1' });
      await store1.init();

      const material = randomBytes(32);
      await store1.setKey({
        keyId: 'imported-key',
        material,
        createdAt: Date.now(),
        metadata: { source: 'store1' },
      });

      const envelopes = await store1.exportForSync(['imported-key'], wrapKey);

      // Import into our store
      const imported = await keyStore.importFromSync(envelopes, wrapKey);
      expect(imported).toBe(1);

      const key = await keyStore.getKey('imported-key');
      expect(key).not.toBeNull();
      expect(key!.material.equals(material)).toBe(true);
      expect(key!.metadata.source).toBe('store1');

      // Cleanup
      await rm(TEST_DATA_DIR + '-1', { recursive: true });
    });

    it('should skip import if local version is higher', async () => {
      // Create local key with version 3
      const localMaterial = randomBytes(32);
      await keyStore.setKey({
        keyId: 'key-1',
        version: 3,
        material: localMaterial,
        createdAt: Date.now(),
        metadata: {},
      });

      // Create envelope with version 2
      const remoteMaterial = randomBytes(32);
      const store2 = createReplicatedKeyStore({ dataDir: TEST_DATA_DIR + '-2' });
      await store2.init();
      await store2.setKey({
        keyId: 'key-1',
        version: 2,
        material: remoteMaterial,
        createdAt: Date.now(),
        metadata: {},
      });
      const envelopes = await store2.exportForSync(['key-1'], wrapKey);

      // Should not import
      const imported = await keyStore.importFromSync(envelopes, wrapKey);
      expect(imported).toBe(0);

      // Local key should be unchanged
      const key = await keyStore.getKey('key-1');
      expect(key!.version).toBe(3);
      expect(key!.material.equals(localMaterial)).toBe(true);

      await rm(TEST_DATA_DIR + '-2', { recursive: true });
    });

    it('should import if remote version is higher', async () => {
      // Create local key with version 1
      await keyStore.setKey({
        keyId: 'key-1',
        version: 1,
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });

      // Create envelope with version 5
      const remoteMaterial = randomBytes(32);
      const store2 = createReplicatedKeyStore({ dataDir: TEST_DATA_DIR + '-2' });
      await store2.init();
      await store2.setKey({
        keyId: 'key-1',
        version: 5,
        material: remoteMaterial,
        createdAt: Date.now(),
        metadata: {},
      });
      const envelopes = await store2.exportForSync(['key-1'], wrapKey);

      // Should import
      const imported = await keyStore.importFromSync(envelopes, wrapKey);
      expect(imported).toBe(1);

      // Should have newer version
      const key = await keyStore.getKey('key-1');
      expect(key!.version).toBe(5);
      expect(key!.material.equals(remoteMaterial)).toBe(true);

      await rm(TEST_DATA_DIR + '-2', { recursive: true });
    });

    it('should reject invalid wrap key length', async () => {
      await expect(keyStore.exportForSync(['key-1'], Buffer.alloc(16))).rejects.toThrow(
        'Wrap key must be 32 bytes'
      );

      await expect(keyStore.importFromSync([], Buffer.alloc(64))).rejects.toThrow(
        'Unwrap key must be 32 bytes'
      );
    });
  });

  describe('persistence to encrypted disk', () => {
    it('should persist keys to disk encrypted', async () => {
      const material = randomBytes(32);

      await keyStore.setKey({
        keyId: 'secret-key',
        material,
        createdAt: Date.now(),
        metadata: {},
      });

      // Read raw file
      const filePath = join(TEST_DATA_DIR, 'keystore.enc');
      const raw = await readFile(filePath, 'utf-8');

      // Key material should not appear in plaintext
      expect(raw).not.toContain(material.toString('hex'));
      expect(raw).not.toContain(material.toString('base64'));

      // Should contain encryption artifacts
      expect(raw).toContain('encryptedMaterial');
      expect(raw).toContain('iv');
      expect(raw).toContain('authTag');
    });

    it('should load keys on restart', async () => {
      const material = randomBytes(32);

      await keyStore.setKey({
        keyId: 'persistent-key',
        material,
        createdAt: Date.now(),
        metadata: { test: 'value' },
      });

      // Create new store instance
      const store2 = createReplicatedKeyStore({ dataDir: TEST_DATA_DIR });
      await store2.init();

      const key = await store2.getKey('persistent-key');
      expect(key).not.toBeNull();
      expect(key!.material.equals(material)).toBe(true);
      expect(key!.metadata.test).toBe('value');
    });

    it('should persist master key on disk', async () => {
      const keyPath = join(TEST_DATA_DIR, 'keystore-master.key');
      const masterKey = await readFile(keyPath);
      expect(masterKey.length).toBe(32);
    });
  });

  describe('conflict resolution', () => {
    it('should apply higher version wins rule', async () => {
      const wrapKey = randomBytes(32);

      // Create two stores
      const store1 = createReplicatedKeyStore({ dataDir: TEST_DATA_DIR + '-store1' });
      const store2 = createReplicatedKeyStore({ dataDir: TEST_DATA_DIR + '-store2' });
      await store1.init();
      await store2.init();

      // Store1 has version 2
      const material1 = Buffer.from('store1-material-v2');
      await store1.setKey({
        keyId: 'key-conflict',
        version: 2,
        material: Buffer.alloc(32, material1.slice(0, 32)),
        createdAt: Date.now(),
        metadata: { from: 'store1' },
      });

      // Store2 has version 5
      const material2 = Buffer.from('store2-material-v5');
      await store2.setKey({
        keyId: 'key-conflict',
        version: 5,
        material: Buffer.alloc(32, material2.slice(0, 32)),
        createdAt: Date.now(),
        metadata: { from: 'store2' },
      });

      // Export from both
      const envelopes1 = await store1.exportForSync(['key-conflict'], wrapKey);
      const envelopes2 = await store2.exportForSync(['key-conflict'], wrapKey);

      // Import store2's version into store1
      const imported1 = await store1.importFromSync(envelopes2, wrapKey);
      expect(imported1).toBe(1);

      const key1 = await store1.getKey('key-conflict');
      expect(key1!.version).toBe(5);
      expect(key1!.metadata.from).toBe('store2');

      // Import store1's version (v2) into store2 - should be ignored
      const imported2 = await store2.importFromSync(envelopes1, wrapKey);
      expect(imported2).toBe(0);

      const key2 = await store2.getKey('key-conflict');
      expect(key2!.version).toBe(5);
      expect(key2!.metadata.from).toBe('store2');

      // Cleanup
      await rm(TEST_DATA_DIR + '-store1', { recursive: true });
      await rm(TEST_DATA_DIR + '-store2', { recursive: true });
    });
  });

  describe('clear', () => {
    it('should clear all keys', async () => {
      await keyStore.setKey({
        keyId: 'key-1',
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });
      await keyStore.setKey({
        keyId: 'key-2',
        material: randomBytes(32),
        createdAt: Date.now(),
        metadata: {},
      });

      expect(await keyStore.count()).toBe(2);

      await keyStore.clear();

      expect(await keyStore.count()).toBe(0);
      expect(await keyStore.getKey('key-1')).toBeNull();
    });
  });
});
