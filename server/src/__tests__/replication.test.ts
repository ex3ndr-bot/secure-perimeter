/**
 * Key Replication tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createKeyReplicator, KeyReplicator } from '../replication.js';
import { createReplicatedKeyStore, ReplicatedKeyStore } from '../key-store.js';
import { mkdir, rm } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import type { ReplicationConfig, PeerConfig } from '../types.js';

const TEST_BASE_DIR = '/tmp/sp-replication-test';
const BASE_PORT = 19500;

function makeConfig(nodeId: string, port: number, peers: PeerConfig[]): ReplicationConfig {
  return {
    nodeId,
    replicationPort: port,
    peers,
    expectedMeasurements: [],
    syncIntervalMs: 0, // Disable periodic sync for tests
    dataDir: `${TEST_BASE_DIR}/${nodeId}`,
    attestationEnabled: false,
  };
}

async function setupNode(
  nodeId: string,
  port: number,
  peers: PeerConfig[]
): Promise<{ keyStore: ReplicatedKeyStore; replicator: KeyReplicator }> {
  const dataDir = `${TEST_BASE_DIR}/${nodeId}`;
  await mkdir(dataDir, { recursive: true });

  const keyStore = createReplicatedKeyStore({ dataDir });
  await keyStore.init();

  const config = makeConfig(nodeId, port, peers);
  const replicator = createKeyReplicator(config, keyStore);

  return { keyStore, replicator };
}

describe('KeyReplicator', () => {
  beforeEach(async () => {
    try {
      await rm(TEST_BASE_DIR, { recursive: true });
    } catch {}
    await mkdir(TEST_BASE_DIR, { recursive: true });
  });

  afterEach(async () => {
    // Give time for sockets to close
    await new Promise((r) => setTimeout(r, 100));
    try {
      await rm(TEST_BASE_DIR, { recursive: true });
    } catch {}
  });

  describe('startup and shutdown', () => {
    it('should start and stop cleanly', async () => {
      const { replicator } = await setupNode('node-a', BASE_PORT, []);

      await replicator.start();
      expect(replicator.isRunning).toBe(true);
      expect(replicator.publicKey).not.toBeNull();

      await replicator.stop();
      expect(replicator.isRunning).toBe(false);
    });

    it('should generate and persist keypair', async () => {
      const { replicator } = await setupNode('node-a', BASE_PORT, []);

      await replicator.start();
      const pubKey1 = Buffer.from(replicator.publicKey!).toString('hex');
      await replicator.stop();

      // Restart - should use same keypair
      const { replicator: replicator2 } = await setupNode('node-a', BASE_PORT, []);
      await replicator2.start();
      const pubKey2 = Buffer.from(replicator2.publicKey!).toString('hex');
      await replicator2.stop();

      expect(pubKey1).toBe(pubKey2);
    });
  });

  describe('mutual attestation', { timeout: 30000 }, () => {
    it('should establish mutually attested channel between nodes', async () => {
      const portA = BASE_PORT;
      const portB = BASE_PORT + 1;

      const { keyStore: storeA, replicator: repA } = await setupNode('node-a', portA, [
        { nodeId: 'node-b', host: '127.0.0.1', port: portB },
      ]);

      const { keyStore: storeB, replicator: repB } = await setupNode('node-b', portB, [
        { nodeId: 'node-a', host: '127.0.0.1', port: portA },
      ]);

      await repA.start();
      await repB.start();

      // Sync should succeed with mock attestation
      const results = await repA.syncWithPeer({ nodeId: 'node-b', host: '127.0.0.1', port: portB });

      expect(results.success).toBe(true);
      expect(results.peerId).toBe('node-b');

      await repA.stop();
      await repB.stop();
    });
  });

  describe('key sync', { timeout: 30000 }, () => {
    it('should sync keys bidirectionally', async () => {
      const portA = BASE_PORT + 10;
      const portB = BASE_PORT + 11;

      const { keyStore: storeA, replicator: repA } = await setupNode('node-a', portA, [
        { nodeId: 'node-b', host: '127.0.0.1', port: portB },
      ]);

      const { keyStore: storeB, replicator: repB } = await setupNode('node-b', portB, [
        { nodeId: 'node-a', host: '127.0.0.1', port: portA },
      ]);

      // Add different keys to each store
      const materialA = randomBytes(32);
      const materialB = randomBytes(32);

      await storeA.setKey({
        keyId: 'key-from-a',
        material: materialA,
        createdAt: Date.now(),
        metadata: { source: 'node-a' },
      });

      await storeB.setKey({
        keyId: 'key-from-b',
        material: materialB,
        createdAt: Date.now(),
        metadata: { source: 'node-b' },
      });

      await repA.start();
      await repB.start();

      // Sync A -> B
      const result = await repA.syncWithPeer({ nodeId: 'node-b', host: '127.0.0.1', port: portB });

      expect(result.success).toBe(true);

      // Both stores should now have both keys
      const keyAinA = await storeA.getKey('key-from-a');
      const keyBinA = await storeA.getKey('key-from-b');
      const keyAinB = await storeB.getKey('key-from-a');
      const keyBinB = await storeB.getKey('key-from-b');

      expect(keyAinA).not.toBeNull();
      expect(keyBinA).not.toBeNull();
      expect(keyAinB).not.toBeNull();
      expect(keyBinB).not.toBeNull();

      expect(keyAinA!.material.equals(materialA)).toBe(true);
      expect(keyBinA!.material.equals(materialB)).toBe(true);
      expect(keyAinB!.material.equals(materialA)).toBe(true);
      expect(keyBinB!.material.equals(materialB)).toBe(true);

      await repA.stop();
      await repB.stop();
    });

    it('should send missing keys from one node to another', async () => {
      const portA = BASE_PORT + 20;
      const portB = BASE_PORT + 21;

      const { keyStore: storeA, replicator: repA } = await setupNode('node-a', portA, []);
      const { keyStore: storeB, replicator: repB } = await setupNode('node-b', portB, []);

      // Node A has 3 keys
      for (let i = 1; i <= 3; i++) {
        await storeA.setKey({
          keyId: `key-${i}`,
          material: randomBytes(32),
          createdAt: Date.now(),
          metadata: {},
        });
      }

      // Node B has no keys
      expect(await storeB.count()).toBe(0);

      await repA.start();
      await repB.start();

      // Sync
      const result = await repA.syncWithPeer({ nodeId: 'node-b', host: '127.0.0.1', port: portB });

      expect(result.success).toBe(true);
      expect(result.keysSent).toBe(3);
      expect(result.keysReceived).toBe(0);

      // Node B should now have all keys
      expect(await storeB.count()).toBe(3);
      expect(await storeB.getKey('key-1')).not.toBeNull();
      expect(await storeB.getKey('key-2')).not.toBeNull();
      expect(await storeB.getKey('key-3')).not.toBeNull();

      await repA.stop();
      await repB.stop();
    });

    it('should overwrite older versions with newer ones', async () => {
      const portA = BASE_PORT + 30;
      const portB = BASE_PORT + 31;

      const { keyStore: storeA, replicator: repA } = await setupNode('node-a', portA, []);
      const { keyStore: storeB, replicator: repB } = await setupNode('node-b', portB, []);

      const oldMaterial = randomBytes(32);
      const newMaterial = randomBytes(32);

      // Node A has version 1
      await storeA.setKey({
        keyId: 'shared-key',
        version: 1,
        material: oldMaterial,
        createdAt: Date.now(),
        metadata: { version: 'old' },
      });

      // Node B has version 5
      await storeB.setKey({
        keyId: 'shared-key',
        version: 5,
        material: newMaterial,
        createdAt: Date.now(),
        metadata: { version: 'new' },
      });

      await repA.start();
      await repB.start();

      // Sync A -> B
      const result = await repA.syncWithPeer({ nodeId: 'node-b', host: '127.0.0.1', port: portB });

      expect(result.success).toBe(true);

      // Node A should now have version 5
      const keyInA = await storeA.getKey('shared-key');
      expect(keyInA!.version).toBe(5);
      expect(keyInA!.material.equals(newMaterial)).toBe(true);
      expect(keyInA!.metadata.version).toBe('new');

      // Node B should still have version 5
      const keyInB = await storeB.getKey('shared-key');
      expect(keyInB!.version).toBe(5);

      await repA.stop();
      await repB.stop();
    });

    it('should wrap keys during transit (never plaintext)', async () => {
      const portA = BASE_PORT + 40;
      const portB = BASE_PORT + 41;

      const { keyStore: storeA, replicator: repA } = await setupNode('node-a', portA, []);
      const { keyStore: storeB, replicator: repB } = await setupNode('node-b', portB, []);

      // This is a spy test - we verify that exportForSync wraps keys
      const material = randomBytes(32);
      await storeA.setKey({
        keyId: 'secret-key',
        material,
        createdAt: Date.now(),
        metadata: {},
      });

      // Export with a wrap key
      const wrapKey = randomBytes(32);
      const envelopes = await storeA.exportForSync(['secret-key'], wrapKey);

      expect(envelopes.length).toBe(1);
      // Wrapped material should be different from original
      expect(envelopes[0].wrappedMaterial.equals(material)).toBe(false);
      // Should be larger due to IV + authTag
      expect(envelopes[0].wrappedMaterial.length).toBeGreaterThan(material.length);

      // Actually test replication
      await repA.start();
      await repB.start();

      await repA.syncWithPeer({ nodeId: 'node-b', host: '127.0.0.1', port: portB });

      // Verify B has the key with correct material
      const keyInB = await storeB.getKey('secret-key');
      expect(keyInB!.material.equals(material)).toBe(true);

      await repA.stop();
      await repB.stop();
    });
  });

  describe('late joining node', { timeout: 30000 }, () => {
    it('should catch up when joining existing cluster', async () => {
      const portA = BASE_PORT + 50;
      const portB = BASE_PORT + 51;
      const portC = BASE_PORT + 52;

      // Start with two nodes A and B
      const { keyStore: storeA, replicator: repA } = await setupNode('node-a', portA, [
        { nodeId: 'node-b', host: '127.0.0.1', port: portB },
      ]);

      const { keyStore: storeB, replicator: repB } = await setupNode('node-b', portB, [
        { nodeId: 'node-a', host: '127.0.0.1', port: portA },
      ]);

      // Add keys to A
      for (let i = 1; i <= 5; i++) {
        await storeA.setKey({
          keyId: `key-${i}`,
          material: randomBytes(32),
          createdAt: Date.now(),
          metadata: {},
        });
      }

      await repA.start();
      await repB.start();

      // Sync A -> B
      await repA.syncWithPeer({ nodeId: 'node-b', host: '127.0.0.1', port: portB });
      expect(await storeB.count()).toBe(5);

      // Now node C joins late
      const { keyStore: storeC, replicator: repC } = await setupNode('node-c', portC, [
        { nodeId: 'node-a', host: '127.0.0.1', port: portA },
      ]);

      expect(await storeC.count()).toBe(0);

      await repC.start();

      // Sync C -> A to catch up
      const result = await repC.syncWithPeer({ nodeId: 'node-a', host: '127.0.0.1', port: portA });

      expect(result.success).toBe(true);
      expect(result.keysReceived).toBe(5);
      expect(await storeC.count()).toBe(5);

      await repA.stop();
      await repB.stop();
      await repC.stop();
    });
  });

  describe('KBS upgrade simulation', { timeout: 30000 }, () => {
    it('should allow new KBS to sync with old KBS before old shuts down', async () => {
      const portOld = BASE_PORT + 60;
      const portNew = BASE_PORT + 61;

      // Old KBS has keys
      const { keyStore: storeOld, replicator: repOld } = await setupNode('kbs-old', portOld, []);

      const keyMaterials: Buffer[] = [];
      for (let i = 1; i <= 3; i++) {
        const material = randomBytes(32);
        keyMaterials.push(material);
        await storeOld.setKey({
          keyId: `user-key-${i}`,
          material,
          createdAt: Date.now(),
          metadata: { userId: `user-${i}` },
        });
      }

      await repOld.start();

      // New KBS starts fresh
      const { keyStore: storeNew, replicator: repNew } = await setupNode('kbs-new', portNew, [
        { nodeId: 'kbs-old', host: '127.0.0.1', port: portOld },
      ]);

      expect(await storeNew.count()).toBe(0);

      await repNew.start();

      // New KBS syncs with old KBS
      const result = await repNew.syncWithPeer({
        nodeId: 'kbs-old',
        host: '127.0.0.1',
        port: portOld,
      });

      expect(result.success).toBe(true);
      expect(result.keysReceived).toBe(3);

      // Verify all keys transferred correctly
      for (let i = 0; i < 3; i++) {
        const key = await storeNew.getKey(`user-key-${i + 1}`);
        expect(key).not.toBeNull();
        expect(key!.material.equals(keyMaterials[i])).toBe(true);
        expect(key!.metadata.userId).toBe(`user-${i + 1}`);
      }

      // Now old KBS can shut down
      await repOld.stop();

      // New KBS continues serving
      expect(await storeNew.count()).toBe(3);
      expect(repNew.isRunning).toBe(true);

      await repNew.stop();
    });
  });

  describe('error handling', () => {
    it('should handle connection failure gracefully', async () => {
      const { replicator } = await setupNode('node-a', BASE_PORT + 70, []);

      await replicator.start();

      // Try to sync with non-existent peer
      const result = await replicator.syncWithPeer({
        nodeId: 'ghost',
        host: '127.0.0.1',
        port: 59999,
      });

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.peerId).toBe('ghost');

      await replicator.stop();
    });
  });
});
