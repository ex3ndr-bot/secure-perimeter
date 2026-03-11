/**
 * Type definitions for secure-perimeter server
 */

/**
 * Server configuration loaded from environment variables
 */
export interface ServerConfig {
  noisePort: number;
  attestationEnabled: boolean;
  dataDir: string;
}

/**
 * TEE attestation quote structure
 */
export interface AttestationQuote {
  /** Type of TEE: 'sev-snp' | 'tdx' | 'mock' */
  teeType: 'sev-snp' | 'tdx' | 'mock';
  /** Raw attestation report bytes */
  report: Uint8Array;
  /** Hash of enclave measurements */
  measurementHash: Uint8Array;
  /** Public key bound to this attestation */
  boundPublicKey: Uint8Array;
  /** Timestamp when quote was generated */
  timestamp: number;
  /** Whether this is a real hardware attestation */
  isHardwareAttested: boolean;
}

/**
 * Static keypair for Noise protocol
 */
export interface NoiseKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * State of an active Noise session after handshake completes
 */
export interface NoiseSession {
  /** Session key for transmitting (encrypting outbound) */
  tx: Uint8Array;
  /** Session key for receiving (decrypting inbound) */
  rx: Uint8Array;
  /** Remote peer's static public key */
  remotePublicKey: Uint8Array;
  /** Hash of entire handshake transcript */
  handshakeHash: Uint8Array;
}

/**
 * Key-value store entry
 */
export interface StorageEntry<T = unknown> {
  key: string;
  value: T;
  updatedAt: number;
}

/**
 * Storage state persisted to disk
 */
export interface StorageState {
  version: number;
  entries: Record<string, StorageEntry>;
}
