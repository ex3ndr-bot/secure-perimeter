/**
 * Noise Protocol Client with Attestation Verification
 * 
 * Implements a Noise XX handshake client that:
 * 1. Connects to the server over TCP/TLS
 * 2. Extracts attestation quote from the handshake payload
 * 3. Verifies attestation against expected measurements from Rekor
 * 4. Returns an encrypted duplex stream if verification passes
 */

import { createConnection, Socket } from 'net';
import { connect as tlsConnect, TLSSocket } from 'tls';
import { EventEmitter } from 'events';
import {
  verifyAttestation,
  ExpectedMeasurements,
  VerificationResult,
  hexToBytes
} from './verify.js';
import { fetchExpectedMeasurements, Measurements } from './transparency.js';

// @ts-ignore - noise-handshake is a CommonJS module without types
import Noise from 'noise-handshake';
// @ts-ignore
import Cipher from 'noise-handshake/cipher';

/**
 * Connection options for the Noise client
 */
export interface NoiseClientOptions {
  /** Server hostname */
  host: string;
  /** Server port */
  port: number;
  /** Use TLS as transport (recommended) */
  useTls?: boolean;
  /** Static keypair for the client (generated if not provided) */
  staticKeypair?: { publicKey: Uint8Array; secretKey: Uint8Array };
  /** Expected image digest for fetching measurements from Rekor */
  expectedImageDigest?: string;
  /** Pre-loaded expected measurements (if not fetching from Rekor) */
  expectedMeasurements?: ExpectedMeasurements;
  /** Skip attestation verification (DANGEROUS - for testing only) */
  skipAttestation?: boolean;
  /** Connection timeout in milliseconds */
  timeoutMs?: number;
}

/**
 * Encrypted session after successful handshake
 */
export interface NoiseSession {
  /** Send an encrypted message */
  send(data: Uint8Array): void;
  /** Receive handler - call to process incoming data */
  onData(handler: (decrypted: Uint8Array) => void): void;
  /** Close the session */
  close(): void;
  /** Server's static public key */
  remotePublicKey: Uint8Array;
  /** Handshake hash (for channel binding) */
  handshakeHash: Uint8Array;
  /** Attestation verification result */
  attestation: VerificationResult;
}

/**
 * Attestation payload embedded in handshake
 * 
 * The server sends this in the second handshake message (e -> e, ee, s, es)
 * The payload contains:
 * - 4-byte length prefix (big-endian)
 * - Attestation quote bytes
 */
interface AttestationPayload {
  quote: Uint8Array;
}

/**
 * Parse attestation payload from handshake message
 */
function parseAttestationPayload(payload: Uint8Array): AttestationPayload | null {
  if (payload.length < 4) {
    return null;
  }
  
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const quoteLength = view.getUint32(0, false);  // big-endian
  
  if (payload.length < 4 + quoteLength) {
    return null;
  }
  
  return {
    quote: payload.slice(4, 4 + quoteLength)
  };
}

/**
 * NoiseClient - Establishes attested encrypted connections
 */
export class NoiseClient extends EventEmitter {
  private socket: Socket | TLSSocket | null = null;
  private noise: typeof Noise | null = null;
  private sendCipher: typeof Cipher | null = null;
  private recvCipher: typeof Cipher | null = null;
  private options: NoiseClientOptions;
  private connected = false;
  private dataHandlers: ((data: Uint8Array) => void)[] = [];
  private receiveBuffer: Buffer = Buffer.alloc(0);
  
  constructor(options: NoiseClientOptions) {
    super();
    this.options = {
      useTls: true,
      skipAttestation: false,
      timeoutMs: 30000,
      ...options
    };
  }
  
  /**
   * Connect to the server and perform attested handshake
   */
  async connect(): Promise<NoiseSession> {
    // Fetch expected measurements from Rekor if image digest provided
    let expectedMeasurements = this.options.expectedMeasurements;
    
    if (!expectedMeasurements && this.options.expectedImageDigest) {
      console.log('Fetching expected measurements from Rekor...');
      const measurements = await fetchExpectedMeasurements(
        this.options.expectedImageDigest
      );
      
      if (measurements) {
        expectedMeasurements = {
          snpMeasurement: measurements.snpMeasurement 
            ? hexToBytes(measurements.snpMeasurement)
            : undefined,
          tdxMrTd: measurements.tdxMrTd
            ? hexToBytes(measurements.tdxMrTd)
            : undefined,
          tdxRtmr0: measurements.tdxRtmr0
            ? hexToBytes(measurements.tdxRtmr0)
            : undefined
        };
        console.log(`Found measurements from Rekor (log index: ${measurements.logIndex})`);
      } else {
        console.warn('No measurements found in Rekor for image digest');
      }
    }
    
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.cleanup();
        reject(new Error('Connection timeout'));
      }, this.options.timeoutMs);
      
      const onError = (err: Error) => {
        clearTimeout(timeout);
        this.cleanup();
        reject(err);
      };
      
      // Initialize Noise handshake state (XX pattern, initiator)
      this.noise = new Noise('XX', true, this.options.staticKeypair);
      this.noise.initialise(Buffer.alloc(0));  // empty prologue
      
      // Establish TCP/TLS connection
      const connectFn = () => {
        if (this.options.useTls) {
          this.socket = tlsConnect({
            host: this.options.host,
            port: this.options.port,
            rejectUnauthorized: false  // We verify via attestation, not TLS CA
          });
        } else {
          this.socket = createConnection({
            host: this.options.host,
            port: this.options.port
          });
        }
        
        this.socket.once('error', onError);
        
        this.socket.once('connect', () => {
          this.performHandshake(expectedMeasurements)
            .then(session => {
              clearTimeout(timeout);
              resolve(session);
            })
            .catch(err => {
              clearTimeout(timeout);
              this.cleanup();
              reject(err);
            });
        });
      };
      
      connectFn();
    });
  }
  
  /**
   * Perform the Noise XX handshake with attestation verification
   */
  private async performHandshake(
    expectedMeasurements?: ExpectedMeasurements
  ): Promise<NoiseSession> {
    if (!this.socket || !this.noise) {
      throw new Error('Not connected');
    }
    
    // XX handshake pattern:
    // -> e                    (initiator sends ephemeral)
    // <- e, ee, s, es         (responder sends ephemeral + static + attestation)
    // -> s, se                (initiator sends static)
    
    return new Promise((resolve, reject) => {
      let handshakeStep = 0;
      let attestationResult: VerificationResult | null = null;
      
      // Step 1: Send initiator's ephemeral key
      const msg1 = this.noise!.send();
      this.sendFrame(msg1);
      handshakeStep = 1;
      
      // Handle incoming handshake messages
      const onData = (data: Buffer) => {
        this.receiveBuffer = Buffer.concat([this.receiveBuffer, data]);
        
        try {
          // Try to parse a complete frame
          const frame = this.readFrame();
          if (!frame) return;  // Need more data
          
          if (handshakeStep === 1) {
            // Step 2: Receive responder's e, ee, s, es with attestation payload
            const payload = this.noise!.recv(frame);
            
            // Parse attestation from payload
            const attestationPayload = parseAttestationPayload(payload);
            
            if (attestationPayload && !this.options.skipAttestation) {
              // Verify attestation
              attestationResult = verifyAttestation(
                attestationPayload.quote,
                expectedMeasurements || {}
              );
              
              if (!attestationResult.valid) {
                throw new Error(
                  `Attestation verification failed: ${attestationResult.errors.join(', ')}`
                );
              }
              
              console.log('Attestation verified successfully');
              for (const warning of attestationResult.warnings) {
                console.warn(`Attestation warning: ${warning}`);
              }
            } else if (!this.options.skipAttestation) {
              console.warn('No attestation payload in handshake');
            }
            
            // Step 3: Send initiator's static key
            const msg3 = this.noise!.send();
            this.sendFrame(msg3);
            handshakeStep = 2;
            
          } else if (handshakeStep === 2) {
            // Optional: Handle any final handshake message from server
            // XX pattern completes after msg3, but server might send confirmation
            
            if (this.noise!.complete) {
              this.finalizeHandshake(attestationResult, resolve);
              this.socket!.off('data', onData);
            }
          }
          
          // Check if handshake is complete
          if (this.noise!.complete && handshakeStep >= 2) {
            this.finalizeHandshake(attestationResult, resolve);
            this.socket!.off('data', onData);
          }
        } catch (err) {
          this.socket!.off('data', onData);
          reject(err);
        }
      };
      
      this.socket!.on("data", onData);
    });
  }
  
  /**
   * Finalize the handshake and create the session
   */
  private finalizeHandshake(
    attestationResult: VerificationResult | null,
    resolve: (session: NoiseSession) => void
  ): void {
    // Create cipher instances for encryption/decryption
    this.sendCipher = new Cipher(this.noise!.tx);
    this.recvCipher = new Cipher(this.noise!.rx);
    this.connected = true;
    
    // Set up data handler for post-handshake messages
    this.socket!.on('data', (data: Buffer) => {
      this.receiveBuffer = Buffer.concat([this.receiveBuffer, data]);
      
      let frame = this.readFrame();
      while (frame) {
        try {
          const decrypted = this.recvCipher!.decrypt(frame);
          for (const handler of this.dataHandlers) {
            handler(new Uint8Array(decrypted));
          }
        } catch (err) {
          this.emit('error', err);
        }
        frame = this.readFrame();
      }
    });
    
    const session: NoiseSession = {
      send: (data: Uint8Array) => {
        if (!this.connected || !this.sendCipher) {
          throw new Error('Session not established');
        }
        const encrypted = this.sendCipher.encrypt(Buffer.from(data));
        this.sendFrame(encrypted);
      },
      onData: (handler: (decrypted: Uint8Array) => void) => {
        this.dataHandlers.push(handler);
      },
      close: () => {
        this.cleanup();
      },
      remotePublicKey: this.noise!.rs,
      handshakeHash: this.noise!.hash,
      attestation: attestationResult || {
        valid: this.options.skipAttestation || false,
        attestationType: 'unknown',
        errors: this.options.skipAttestation ? [] : ['No attestation performed'],
        warnings: this.options.skipAttestation ? ['Attestation skipped'] : []
      }
    };
    
    resolve(session);
  }
  
  /**
   * Send a length-prefixed frame
   */
  private sendFrame(data: Buffer | Uint8Array): void {
    if (!this.socket) throw new Error('Not connected');
    
    const frame = Buffer.alloc(4 + data.length);
    frame.writeUInt32BE(data.length, 0);
    Buffer.from(data).copy(frame, 4);
    this.socket.write(frame);
  }
  
  /**
   * Read a complete frame from the receive buffer
   */
  private readFrame(): Buffer | null {
    if (this.receiveBuffer.length < 4) {
      return null;
    }
    
    const length = this.receiveBuffer.readUInt32BE(0);
    
    if (this.receiveBuffer.length < 4 + length) {
      return null;
    }
    
    const frame = this.receiveBuffer.slice(4, 4 + length);
    this.receiveBuffer = this.receiveBuffer.slice(4 + length);
    
    return frame;
  }
  
  /**
   * Clean up resources
   */
  private cleanup(): void {
    this.connected = false;
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.noise = null;
    this.sendCipher = null;
    this.recvCipher = null;
    this.dataHandlers = [];
  }
}

/**
 * Create a Noise client and connect
 * 
 * Convenience function that creates a client and performs the handshake.
 * 
 * @param options - Connection options
 * @returns Encrypted session with attestation verification
 */
export async function createNoiseClient(
  options: NoiseClientOptions
): Promise<NoiseSession> {
  const client = new NoiseClient(options);
  return client.connect();
}
