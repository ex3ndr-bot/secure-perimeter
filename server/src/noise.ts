/**
 * Noise Protocol server implementation using XX handshake pattern.
 * Provides encrypted, attested communication channel.
 */

import { createServer, Socket } from 'node:net';
import { readFile, writeFile, access, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { EventEmitter } from 'node:events';
import { getAttestationQuote, serializeQuote, deserializeQuote } from './attestation.js';
import type { NoiseKeypair, NoiseSession, ServerConfig, AttestationQuote } from './types.js';

// Import noise-handshake (CommonJS module)
// @ts-expect-error - noise-handshake doesn't have types
import Noise from 'noise-handshake';
// @ts-expect-error - noise-handshake/cipher doesn't have types
import Cipher from 'noise-handshake/cipher.js';

const KEYPAIR_FILE = 'noise-keypair.json';

interface NoiseState {
  complete: boolean;
  tx: Uint8Array;
  rx: Uint8Array;
  rs: Uint8Array;
  hash: Uint8Array;
  s: { publicKey: Uint8Array; secretKey: Uint8Array };
  send: (payload?: Uint8Array) => Uint8Array;
  recv: (message: Uint8Array) => Uint8Array;
  initialise: (prologue: Uint8Array, remoteStatic?: Uint8Array) => void;
}

interface NoiseCipher {
  encrypt: (plaintext: Uint8Array) => Uint8Array;
  decrypt: (ciphertext: Uint8Array) => Uint8Array;
}

/**
 * Represents an active encrypted session with a peer.
 */
export class EncryptedSession extends EventEmitter {
  private socket: Socket;
  private sendCipher: NoiseCipher;
  private recvCipher: NoiseCipher;
  readonly remotePublicKey: Uint8Array;
  readonly handshakeHash: Uint8Array;
  readonly remoteAttestation: AttestationQuote | null;

  constructor(
    socket: Socket,
    session: NoiseSession,
    sendCipher: NoiseCipher,
    recvCipher: NoiseCipher,
    remoteAttestation: AttestationQuote | null
  ) {
    super();
    this.socket = socket;
    this.sendCipher = sendCipher;
    this.recvCipher = recvCipher;
    this.remotePublicKey = session.remotePublicKey;
    this.handshakeHash = session.handshakeHash;
    this.remoteAttestation = remoteAttestation;

    this.socket.on('data', (data) => this.handleData(data));
    this.socket.on('close', () => this.emit('close'));
    this.socket.on('error', (err) => this.emit('error', err));
  }

  private handleData(data: Buffer): void {
    try {
      // Read length-prefixed encrypted messages
      let offset = 0;
      while (offset < data.length) {
        if (offset + 4 > data.length) break;
        const len = data.readUInt32BE(offset);
        offset += 4;
        if (offset + len > data.length) break;
        
        const encrypted = data.subarray(offset, offset + len);
        offset += len;
        
        const decrypted = this.recvCipher.decrypt(encrypted);
        this.emit('data', Buffer.from(decrypted));
      }
    } catch (err) {
      this.emit('error', err);
    }
  }

  /** Send encrypted data to peer */
  send(data: Buffer): void {
    const encrypted = this.sendCipher.encrypt(data);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(encrypted.length, 0);
    this.socket.write(Buffer.concat([lenBuf, Buffer.from(encrypted)]));
  }

  /** Close the session */
  close(): void {
    this.socket.end();
  }
}

/**
 * Noise Protocol server using XX handshake pattern.
 */
export class NoiseServer extends EventEmitter {
  private config: ServerConfig;
  private keypair: NoiseKeypair | null = null;
  private server: ReturnType<typeof createServer> | null = null;

  constructor(config: ServerConfig) {
    super();
    this.config = config;
  }

  /** Load or generate static keypair */
  private async loadOrCreateKeypair(): Promise<NoiseKeypair> {
    const keypairPath = join(this.config.dataDir, KEYPAIR_FILE);

    try {
      await access(keypairPath);
      const data = await readFile(keypairPath, 'utf-8');
      const parsed = JSON.parse(data);
      console.log('[noise] Loaded existing static keypair');
      return {
        publicKey: Buffer.from(parsed.publicKey, 'hex'),
        secretKey: Buffer.from(parsed.secretKey, 'hex'),
      };
    } catch {
      // Generate new keypair using noise-handshake's internal curve
      const tempState = new Noise('XX', true) as NoiseState;
      const newKeypair: NoiseKeypair = {
        publicKey: Buffer.from(tempState.s.publicKey),
        secretKey: Buffer.from(tempState.s.secretKey),
      };

      // Persist keypair
      try {
        await mkdir(this.config.dataDir, { recursive: true });
      } catch { /* ignore if exists */ }
      
      await writeFile(keypairPath, JSON.stringify({
        publicKey: Buffer.from(newKeypair.publicKey).toString('hex'),
        secretKey: Buffer.from(newKeypair.secretKey).toString('hex'),
      }, null, 2));
      
      console.log('[noise] Generated and saved new static keypair');
      return newKeypair;
    }
  }

  /** Handle incoming connection and perform XX handshake */
  private async handleConnection(socket: Socket): Promise<void> {
    const addr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[noise] New connection from ${addr}`);

    if (!this.keypair) {
      socket.destroy(new Error('Server keypair not initialized'));
      return;
    }

    // Create responder state for XX pattern
    const state = new Noise('XX', false, {
      publicKey: Buffer.from(this.keypair.publicKey),
      secretKey: Buffer.from(this.keypair.secretKey),
    }) as NoiseState;
    const prologue = Buffer.alloc(0);
    state.initialise(prologue);

    let remoteAttestation: AttestationQuote | null = null;
    let handshakeStep = 0;

    // XX handshake has 3 messages: -> e, <- e,ee,s,es, -> s,se
    socket.on('data', async (data: Buffer) => {
      try {
        if (state.complete) {
          // Already completed, ignore (handled by EncryptedSession)
          return;
        }

        handshakeStep++;

        if (handshakeStep === 1) {
          // Receive: -> e (initiator's ephemeral)
          state.recv(data);

          // Send: <- e, ee, s, es (with attestation payload)
          let payload: Uint8Array = Buffer.alloc(0);
          if (this.config.attestationEnabled) {
            const quote = await getAttestationQuote(Buffer.from(this.keypair!.publicKey));
            payload = serializeQuote(quote);
          }
          const reply = state.send(payload);
          socket.write(Buffer.from(reply));
        } else if (handshakeStep === 2) {
          // Receive: -> s, se (initiator's static + payload)
          const payload = state.recv(data);
          
          // Try to parse remote attestation from payload
          if (payload && payload.length > 0) {
            try {
              remoteAttestation = deserializeQuote(Buffer.from(payload));
              console.log(`[noise] Remote attestation: ${remoteAttestation.teeType} (hardware: ${remoteAttestation.isHardwareAttested})`);
            } catch {
              console.log('[noise] Could not parse remote attestation payload');
            }
          }

          if (!state.complete) {
            console.error('[noise] Handshake not complete after final message');
            socket.destroy(new Error('Handshake failed'));
            return;
          }

          // Create session
          const session: NoiseSession = {
            tx: state.tx,
            rx: state.rx,
            remotePublicKey: state.rs,
            handshakeHash: state.hash,
          };

          // Create ciphers for encryption/decryption
          // tx for sending (we encrypt), rx for receiving (we decrypt)
          const sendCipher = new Cipher(state.tx) as NoiseCipher;
          const recvCipher = new Cipher(state.rx) as NoiseCipher;

          // Remove our handshake data handler before creating EncryptedSession
          // (EncryptedSession adds its own handler in constructor)
          socket.removeAllListeners('data');

          // Create encrypted session
          const encSession = new EncryptedSession(
            socket,
            session,
            sendCipher,
            recvCipher,
            remoteAttestation
          );

          console.log(`[noise] Handshake complete with ${addr}`);
          this.emit('session', encSession);
        }
      } catch (err) {
        console.error('[noise] Handshake error:', err);
        socket.destroy();
      }
    });

    socket.on('error', (err) => {
      console.error(`[noise] Connection error from ${addr}:`, err.message);
    });

    socket.on('close', () => {
      if (!state.complete) {
        console.log(`[noise] Connection closed during handshake: ${addr}`);
      }
    });
  }

  /** Get the server's public key */
  get publicKey(): Uint8Array | null {
    return this.keypair?.publicKey ?? null;
  }

  /** Start the Noise server */
  async start(): Promise<void> {
    this.keypair = await this.loadOrCreateKeypair();

    this.server = createServer((socket) => {
      this.handleConnection(socket).catch((err) => {
        console.error('[noise] Error handling connection:', err);
        socket.destroy();
      });
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.on('error', reject);
      this.server!.listen(this.config.noisePort, () => {
        console.log(`[noise] Server listening on port ${this.config.noisePort}`);
        console.log(`[noise] Public key: ${Buffer.from(this.keypair!.publicKey).toString('hex')}`);
        resolve();
      });
    });
  }

  /** Stop the server */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          console.log('[noise] Server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

/** Create a new Noise server */
export function createNoiseServer(config: ServerConfig): NoiseServer {
  return new NoiseServer(config);
}
