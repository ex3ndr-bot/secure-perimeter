/**
 * TEE-to-TEE Key Replication Module
 */

import { createServer, Socket, createConnection } from 'node:net';
import { EventEmitter } from 'node:events';
import { hkdfSync } from 'node:crypto';
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { join } from 'node:path';
import { getAttestationQuote, serializeQuote, deserializeQuote } from './attestation.js';
import { ReplicatedKeyStore } from './key-store.js';
import type {
  ReplicationConfig,
  PeerConfig,
  SyncResult,
  KeyInventoryEntry,
  WrappedKeyEnvelope,
  NoiseKeypair,
  AttestationQuote,
} from './types.js';

// @ts-expect-error - noise-handshake doesn't have types
import Noise from 'noise-handshake';
// @ts-expect-error
import Cipher from 'noise-handshake/cipher.js';

const KEYPAIR_FILE = 'replication-keypair.json';

interface NoiseCipher {
  encrypt: (plaintext: Uint8Array) => Uint8Array;
  decrypt: (ciphertext: Uint8Array) => Uint8Array;
}

interface SyncMessage {
  type: 'sync-request' | 'sync-response';
  nodeId: string;
  inventory: KeyInventoryEntry[];
  keys: SerializedKeyEnvelope[];
}

interface SerializedKeyEnvelope {
  keyId: string;
  version: number;
  wrappedMaterial: string;
  createdAt: number;
  updatedAt: number;
  metadata: Record<string, string>;
}

/**
 * BufferedSocket - captures data immediately when socket is created
 */
class BufferedSocket {
  private chunks: Buffer[] = [];
  private waiting: Array<(data: Buffer) => void> = [];
  
  constructor(private socket: Socket) {
    // Attach listener SYNCHRONOUSLY
    socket.on('data', (chunk: Buffer) => {
      if (this.waiting.length > 0) {
        const resolve = this.waiting.shift()!;
        resolve(chunk);
      } else {
        this.chunks.push(chunk);
      }
    });
  }

  async read(timeoutMs: number): Promise<Buffer> {
    // Check for buffered data first
    if (this.chunks.length > 0) {
      return this.chunks.shift()!;
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        const idx = this.waiting.indexOf(resolve);
        if (idx >= 0) this.waiting.splice(idx, 1);
        reject(new Error('Receive timeout'));
      }, timeoutMs);

      this.waiting.push((data: Buffer) => {
        clearTimeout(timeout);
        resolve(data);
      });
    });
  }

  write(data: Buffer): void {
    this.socket.write(data);
  }

  end(): void {
    this.socket.end();
  }

  destroy(): void {
    this.socket.destroy();
  }
}

/**
 * Key Replicator
 */
export class KeyReplicator extends EventEmitter {
  private config: ReplicationConfig;
  private keyStore: ReplicatedKeyStore;
  private keypair: NoiseKeypair | null = null;
  private server: ReturnType<typeof createServer> | null = null;
  private syncTimer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(config: ReplicationConfig, keyStore: ReplicatedKeyStore) {
    super();
    this.config = config;
    this.keyStore = keyStore;
  }

  private async loadOrCreateKeypair(): Promise<NoiseKeypair> {
    const keypairPath = join(this.config.dataDir, KEYPAIR_FILE);
    try {
      await access(keypairPath);
      const data = await readFile(keypairPath, 'utf-8');
      const parsed = JSON.parse(data);
      console.log('[replication] Loaded existing keypair');
      return {
        publicKey: Buffer.from(parsed.publicKey, 'hex'),
        secretKey: Buffer.from(parsed.secretKey, 'hex'),
      };
    } catch {
      const noise = new Noise('XX', true);
      noise.initialise(Buffer.alloc(0));
      const keypair: NoiseKeypair = {
        publicKey: Buffer.from(noise.s.publicKey),
        secretKey: Buffer.from(noise.s.secretKey),
      };
      await mkdir(this.config.dataDir, { recursive: true });
      await writeFile(keypairPath, JSON.stringify({
        publicKey: Buffer.from(keypair.publicKey).toString('hex'),
        secretKey: Buffer.from(keypair.secretKey).toString('hex'),
      }));
      console.log('[replication] Generated new keypair');
      return keypair;
    }
  }

  private verifyAttestation(attestation: AttestationQuote | null): boolean {
    if (!attestation) return this.config.expectedMeasurements.length === 0;
    if (attestation.teeType === 'mock' && !attestation.isHardwareAttested) return true;
    const measurementHex = Buffer.from(attestation.measurementHash).toString('hex');
    for (const expected of this.config.expectedMeasurements) {
      if (Buffer.from(expected).toString('hex') === measurementHex) return true;
    }
    return false;
  }

  private deriveSessionKey(tx: Uint8Array, rx: Uint8Array): Buffer {
    // Sort keys to ensure same ordering on both initiator and responder
    const txBuf = Buffer.from(tx);
    const rxBuf = Buffer.from(rx);
    const combined = txBuf.compare(rxBuf) < 0
      ? Buffer.concat([txBuf, rxBuf])
      : Buffer.concat([rxBuf, txBuf]);
    return Buffer.from(hkdfSync('sha256', combined, Buffer.alloc(0), Buffer.from('key-replication-wrap'), 32));
  }

  private sendEncrypted(buf: BufferedSocket, cipher: NoiseCipher, message: SyncMessage): void {
    const data = Buffer.from(JSON.stringify(message));
    const encrypted = cipher.encrypt(data);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(encrypted.length, 0);
    buf.write(Buffer.concat([lenBuf, Buffer.from(encrypted)]));
  }

  private async receiveEncrypted(buf: BufferedSocket, cipher: NoiseCipher, timeoutMs = 30000): Promise<SyncMessage> {
    let buffer = Buffer.alloc(0);
    const deadline = Date.now() + timeoutMs;

    while (true) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('Receive timeout');

      if (buffer.length >= 4) {
        const len = buffer.readUInt32BE(0);
        if (buffer.length >= 4 + len) {
          const encrypted = buffer.subarray(4, 4 + len);
          const decrypted = cipher.decrypt(encrypted);
          return JSON.parse(Buffer.from(decrypted).toString('utf-8')) as SyncMessage;
        }
      }

      const chunk = await buf.read(remaining);
      buffer = Buffer.concat([buffer, chunk]);
    }
  }

  private serializeEnvelopes(envelopes: WrappedKeyEnvelope[]): SerializedKeyEnvelope[] {
    return envelopes.map((e) => ({
      keyId: e.keyId, version: e.version,
      wrappedMaterial: e.wrappedMaterial.toString('base64'),
      createdAt: e.createdAt, updatedAt: e.updatedAt, metadata: e.metadata,
    }));
  }

  private deserializeEnvelopes(envelopes: SerializedKeyEnvelope[]): WrappedKeyEnvelope[] {
    return envelopes.map((e) => ({
      keyId: e.keyId, version: e.version,
      wrappedMaterial: Buffer.from(e.wrappedMaterial, 'base64'),
      createdAt: e.createdAt, updatedAt: e.updatedAt, metadata: e.metadata,
    }));
  }

  private computeKeysToSend(ours: KeyInventoryEntry[], theirs: KeyInventoryEntry[]): string[] {
    const theirMap = new Map(theirs.map((k) => [k.keyId, k.version]));
    return ours.filter((k) => {
      const theirVersion = theirMap.get(k.keyId);
      return theirVersion === undefined || k.version > theirVersion;
    }).map((k) => k.keyId);
  }

  private async handleIncomingConnection(socket: Socket, buf: BufferedSocket): Promise<void> {
    const addr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[replication] Incoming connection from ${addr}`);

    try {
      const noise = new Noise('XX', false, this.keypair);
      noise.initialise(Buffer.alloc(0));

      // msg1: -> e
      const msg1 = await buf.read(5000);
      noise.recv(msg1);

      // msg2: <- e, ee, s, es
      let payload: Uint8Array = Buffer.alloc(0);
      if (this.config.attestationEnabled) {
        const quote = await getAttestationQuote(Buffer.from(this.keypair!.publicKey));
        payload = serializeQuote(quote);
      }
      buf.write(Buffer.from(noise.send(payload)));

      // msg3: -> s, se
      const msg3 = await buf.read(5000);
      let remoteAttestation: AttestationQuote | null = null;
      const remotePayload = noise.recv(msg3);
      if (remotePayload && remotePayload.length > 0) {
        try { remoteAttestation = deserializeQuote(Buffer.from(remotePayload)); } catch {}
      }

      if (!noise.complete) throw new Error('Handshake failed');
      if (!this.verifyAttestation(remoteAttestation)) {
        buf.destroy();
        return;
      }

      console.log(`[replication] Handshake complete with ${addr}`);

      const sendCipher = new Cipher(noise.tx) as NoiseCipher;
      const recvCipher = new Cipher(noise.rx) as NoiseCipher;
      const sessionKey = this.deriveSessionKey(noise.tx, noise.rx);

      // Sync (responder)
      const request = await this.receiveEncrypted(buf, recvCipher);
      if (request.type !== 'sync-request') throw new Error(`Expected sync-request`);

      const ourInventory = await this.keyStore.listKeys();
      const keysToSend = this.computeKeysToSend(ourInventory, request.inventory);

      const importedKeys = this.deserializeEnvelopes(request.keys);
      const importedCount = await this.keyStore.importFromSync(importedKeys, sessionKey);
      console.log(`[replication] Imported ${importedCount} keys from initiator`);

      const envelopes = await this.keyStore.exportForSync(keysToSend, sessionKey);
      this.sendEncrypted(buf, sendCipher, {
        type: 'sync-response',
        nodeId: this.config.nodeId,
        inventory: ourInventory,
        keys: this.serializeEnvelopes(envelopes),
      });

      console.log(`[replication] Sent ${envelopes.length} keys to initiator`);
      buf.end();
    } catch (err) {
      console.error(`[replication] Connection error from ${addr}:`, (err as Error).message);
      buf.destroy();
    }
  }

  async syncWithPeer(peer: PeerConfig): Promise<SyncResult> {
    const startTime = Date.now();

    try {
      console.log(`[replication] Connecting to peer ${peer.nodeId} at ${peer.host}:${peer.port}`);

      const socket = createConnection({ host: peer.host, port: peer.port });
      const buf = new BufferedSocket(socket);

      await new Promise<void>((resolve, reject) => {
        const timeoutId = setTimeout(() => { cleanup(); socket.destroy(); reject(new Error('Connection timeout')); }, 5000);
        const onConnect = (): void => { cleanup(); resolve(); };
        const onError = (err: Error): void => { cleanup(); reject(err); };
        const cleanup = (): void => { clearTimeout(timeoutId); socket.removeListener('connect', onConnect); socket.removeListener('error', onError); };
        socket.on('connect', onConnect);
        socket.on('error', onError);
      });

      const noise = new Noise('XX', true, this.keypair);
      noise.initialise(Buffer.alloc(0));

      // msg1: -> e
      buf.write(Buffer.from(noise.send()));

      // msg2: <- e, ee, s, es
      const msg2 = await buf.read(5000);
      let peerAttestation: AttestationQuote | null = null;
      const peerPayload = noise.recv(msg2);
      if (peerPayload && peerPayload.length > 0) {
        try { peerAttestation = deserializeQuote(Buffer.from(peerPayload)); } catch {}
      }

      if (!this.verifyAttestation(peerAttestation)) {
        buf.destroy();
        return { peerId: peer.nodeId, success: false, keysSent: 0, keysReceived: 0, error: 'Attestation verification failed', durationMs: Date.now() - startTime };
      }

      // msg3: -> s, se
      let payload: Uint8Array = Buffer.alloc(0);
      if (this.config.attestationEnabled) {
        const quote = await getAttestationQuote(Buffer.from(this.keypair!.publicKey));
        payload = serializeQuote(quote);
      }
      buf.write(Buffer.from(noise.send(payload)));

      if (!noise.complete) {
        buf.destroy();
        return { peerId: peer.nodeId, success: false, keysSent: 0, keysReceived: 0, error: 'Handshake failed', durationMs: Date.now() - startTime };
      }

      console.log(`[replication] Handshake complete with peer ${peer.nodeId}`);

      const sendCipher = new Cipher(noise.tx) as NoiseCipher;
      const recvCipher = new Cipher(noise.rx) as NoiseCipher;
      const sessionKey = this.deriveSessionKey(noise.tx, noise.rx);

      // Sync (initiator)
      const ourInventory = await this.keyStore.listKeys();
      const allKeyIds = ourInventory.map((k) => k.keyId);
      const envelopes = await this.keyStore.exportForSync(allKeyIds, sessionKey);

      this.sendEncrypted(buf, sendCipher, {
        type: 'sync-request',
        nodeId: this.config.nodeId,
        inventory: ourInventory,
        keys: this.serializeEnvelopes(envelopes),
      });

      const syncResponse = await this.receiveEncrypted(buf, recvCipher);
      if (syncResponse.type !== 'sync-response') throw new Error(`Expected sync-response`);

      const importedKeys = this.deserializeEnvelopes(syncResponse.keys);
      const keysReceived = await this.keyStore.importFromSync(importedKeys, sessionKey);

      buf.end();

      console.log(`[replication] Sync complete with ${peer.nodeId}: sent=${envelopes.length}, received=${keysReceived}`);

      return { peerId: peer.nodeId, success: true, keysSent: envelopes.length, keysReceived, durationMs: Date.now() - startTime };
    } catch (err) {
      return { peerId: peer.nodeId, success: false, keysSent: 0, keysReceived: 0, error: (err as Error).message, durationMs: Date.now() - startTime };
    }
  }

  async start(): Promise<void> {
    if (this.running) return;
    console.log(`[replication] Starting replicator for node ${this.config.nodeId}`);
    this.keypair = await this.loadOrCreateKeypair();

    this.server = createServer((socket) => {
      // Create BufferedSocket SYNCHRONOUSLY to capture data immediately
      const buf = new BufferedSocket(socket);
      this.handleIncomingConnection(socket, buf).catch((err) => {
        console.error('[replication] Error handling connection:', err);
        socket.destroy();
      });
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.on('error', reject);
      this.server!.listen(this.config.replicationPort, () => {
        console.log(`[replication] Listening on port ${this.config.replicationPort}`);
        resolve();
      });
    });

    this.running = true;

    if (this.config.peers.length > 0 && this.config.syncIntervalMs > 0) {
      this.syncTimer = setInterval(() => this.syncAllPeers().catch(console.error), this.config.syncIntervalMs);
      setTimeout(() => this.syncAllPeers().catch(console.error), 1000);
    }

    this.emit('started');
  }

  async syncAllPeers(): Promise<SyncResult[]> {
    const results: SyncResult[] = [];
    for (const peer of this.config.peers) {
      const result = await this.syncWithPeer(peer);
      results.push(result);
      this.emit('sync', result);
    }
    return results;
  }

  async stop(): Promise<void> {
    if (!this.running) return;
    console.log('[replication] Stopping replicator');
    if (this.syncTimer) { clearInterval(this.syncTimer); this.syncTimer = null; }
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => { this.running = false; console.log('[replication] Stopped'); this.emit('stopped'); resolve(); });
      } else { this.running = false; resolve(); }
    });
  }

  get publicKey(): Uint8Array | null { return this.keypair?.publicKey ?? null; }
  get isRunning(): boolean { return this.running; }
}

export function createKeyReplicator(config: ReplicationConfig, keyStore: ReplicatedKeyStore): KeyReplicator {
  return new KeyReplicator(config, keyStore);
}
