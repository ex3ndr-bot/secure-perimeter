/**
 * Secure Perimeter Server - Entry Point
 *
 * A TypeScript server that:
 * 1. Listens on a Noise Protocol socket (port 8443)
 * 2. During handshake, reads TEE attestation quote from hardware and embeds it
 * 3. Provides encrypted, attested communication channel
 * 4. Manages encrypted state (read/write to /data volume)
 * 5. Optionally replicates keys with peer TEE nodes
 */

import { createNoiseServer, EncryptedSession } from './noise.js';
import { createStorage } from './storage.js';
import { createReplicatedKeyStore, ReplicatedKeyStore } from './key-store.js';
import { createKeyReplicator, KeyReplicator } from './replication.js';
import { isAttested } from './attestation.js';
import type { ServerConfig, ReplicationConfig, PeerConfig } from './types.js';

/** Load configuration from environment variables */
function loadConfig(): ServerConfig {
  return {
    noisePort: parseInt(process.env['NOISE_PORT'] ?? '8443', 10),
    attestationEnabled: process.env['ATTESTATION_ENABLED'] !== 'false',
    dataDir: process.env['DATA_DIR'] ?? '/data',
  };
}

/**
 * Load replication configuration from environment variables
 * Returns null if replication is not configured
 */
function loadReplicationConfig(baseConfig: ServerConfig): ReplicationConfig | null {
  const nodeId = process.env['NODE_ID'];
  const replicationPort = process.env['REPLICATION_PORT'];
  const replicationPeers = process.env['REPLICATION_PEERS'];

  // Replication requires at minimum NODE_ID and REPLICATION_PORT
  if (!nodeId || !replicationPort) {
    return null;
  }

  // Parse peers: "nodeId@host:port,nodeId@host:port"
  const peers: PeerConfig[] = [];
  if (replicationPeers) {
    for (const peerStr of replicationPeers.split(',')) {
      const trimmed = peerStr.trim();
      if (!trimmed) continue;

      const match = trimmed.match(/^([^@]+)@([^:]+):(\d+)$/);
      if (match) {
        peers.push({
          nodeId: match[1],
          host: match[2],
          port: parseInt(match[3], 10),
        });
      } else {
        console.warn(`[main] Invalid peer format: ${trimmed} (expected nodeId@host:port)`);
      }
    }
  }

  // Parse expected measurements (comma-separated hex strings)
  const expectedMeasurements: Uint8Array[] = [];
  const measurementsEnv = process.env['EXPECTED_MEASUREMENTS'];
  if (measurementsEnv) {
    for (const hex of measurementsEnv.split(',')) {
      const trimmed = hex.trim();
      if (trimmed) {
        expectedMeasurements.push(Buffer.from(trimmed, 'hex'));
      }
    }
  }

  const syncIntervalMs = parseInt(process.env['REPLICATION_INTERVAL'] ?? '30000', 10);

  return {
    nodeId,
    replicationPort: parseInt(replicationPort, 10),
    peers,
    expectedMeasurements,
    syncIntervalMs,
    dataDir: baseConfig.dataDir,
    attestationEnabled: baseConfig.attestationEnabled,
  };
}

/** Convert Uint8Array to hex string */
function toHex(arr: Uint8Array): string {
  return Buffer.from(arr).toString('hex');
}

/** Handle an established encrypted session */
function handleSession(session: EncryptedSession, storage: ReturnType<typeof createStorage>): void {
  const pubKeyHex = toHex(session.remotePublicKey).slice(0, 16) + '...';
  console.log(`[main] New session with peer: ${pubKeyHex}`);

  if (session.remoteAttestation) {
    console.log(`[main] Peer attestation: ${session.remoteAttestation.teeType}`);
  }

  session.on('data', async (data: Buffer) => {
    try {
      // Parse incoming message as JSON command
      const message = JSON.parse(data.toString('utf-8')) as {
        type: string;
        key?: string;
        value?: unknown;
      };

      console.log(`[main] Received command: ${message.type}`);

      let response: { success: boolean; data?: unknown; error?: string };

      switch (message.type) {
        case 'ping':
          response = { success: true, data: { pong: Date.now() } };
          break;

        case 'get':
          if (!message.key) {
            response = { success: false, error: 'Missing key' };
          } else {
            const value = await storage.get(message.key);
            response = { success: true, data: { key: message.key, value } };
          }
          break;

        case 'set':
          if (!message.key) {
            response = { success: false, error: 'Missing key' };
          } else {
            await storage.set(message.key, message.value);
            response = { success: true, data: { key: message.key } };
          }
          break;

        case 'delete':
          if (!message.key) {
            response = { success: false, error: 'Missing key' };
          } else {
            const deleted = await storage.delete(message.key);
            response = { success: true, data: { key: message.key, deleted } };
          }
          break;

        case 'keys':
          const keys = await storage.keys();
          response = { success: true, data: { keys } };
          break;

        case 'status':
          response = {
            success: true,
            data: {
              attested: session.remoteAttestation?.isHardwareAttested ?? false,
              attestationType: session.remoteAttestation?.teeType ?? 'none',
              handshakeHash: toHex(session.handshakeHash),
            },
          };
          break;

        default:
          response = { success: false, error: `Unknown command: ${message.type}` };
      }

      session.send(Buffer.from(JSON.stringify(response)));
    } catch (err) {
      console.error('[main] Error handling message:', err);
      const response = { success: false, error: 'Invalid message format' };
      session.send(Buffer.from(JSON.stringify(response)));
    }
  });

  session.on('close', () => {
    console.log(`[main] Session closed: ${pubKeyHex}`);
  });

  session.on('error', (err: Error) => {
    console.error(`[main] Session error: ${pubKeyHex}:`, err.message);
  });
}

async function main(): Promise<void> {
  console.log('='.repeat(60));
  console.log('Secure Perimeter Server');
  console.log('='.repeat(60));

  const config = loadConfig();
  console.log('[main] Configuration:');
  console.log(`  - Noise port: ${config.noisePort}`);
  console.log(`  - Attestation enabled: ${config.attestationEnabled}`);
  console.log(`  - Data directory: ${config.dataDir}`);

  // Check TEE availability
  const hardwareAttested = await isAttested();
  console.log(`[main] Hardware TEE available: ${hardwareAttested}`);
  if (!hardwareAttested) {
    console.log('[main] Running in development mode with mock attestation');
  }

  // Initialize storage
  const storage = createStorage(config.dataDir);
  await storage.init();

  // Create and start Noise server
  const server = createNoiseServer(config);

  server.on('session', (session: EncryptedSession) => {
    handleSession(session, storage);
  });

  await server.start();

  // Initialize replication if configured
  let keyStore: ReplicatedKeyStore | null = null;
  let replicator: KeyReplicator | null = null;

  const replicationConfig = loadReplicationConfig(config);
  if (replicationConfig) {
    console.log('[main] Replication configuration:');
    console.log(`  - Node ID: ${replicationConfig.nodeId}`);
    console.log(`  - Replication port: ${replicationConfig.replicationPort}`);
    console.log(`  - Peers: ${replicationConfig.peers.length}`);
    for (const peer of replicationConfig.peers) {
      console.log(`    - ${peer.nodeId} @ ${peer.host}:${peer.port}`);
    }
    console.log(`  - Sync interval: ${replicationConfig.syncIntervalMs}ms`);

    // Initialize key store
    keyStore = createReplicatedKeyStore({ dataDir: config.dataDir });
    await keyStore.init();

    // Initialize replicator
    replicator = createKeyReplicator(replicationConfig, keyStore);

    replicator.on('sync', (result) => {
      if (result.success) {
        console.log(
          `[main] Sync with ${result.peerId}: sent=${result.keysSent}, received=${result.keysReceived}, duration=${result.durationMs}ms`
        );
      } else {
        console.warn(`[main] Sync with ${result.peerId} failed: ${result.error}`);
      }
    });

    await replicator.start();
    console.log('[main] Key replication enabled');
  } else {
    console.log('[main] Key replication disabled (set NODE_ID and REPLICATION_PORT to enable)');
  }

  console.log('='.repeat(60));
  console.log('Server ready. Press Ctrl+C to stop.');
  console.log('='.repeat(60));

  // Handle graceful shutdown
  const shutdown = async (): Promise<void> => {
    console.log('\n[main] Shutting down...');

    if (replicator) {
      await replicator.stop();
    }

    await server.stop();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error('[main] Fatal error:', err);
  process.exit(1);
});
