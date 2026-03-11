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

// =============================================================================
// Replication Types
// =============================================================================

/**
 * Configuration for a peer node in the replication cluster
 */
export interface PeerConfig {
  /** Unique identifier for the peer */
  nodeId: string;
  /** Hostname or IP address */
  host: string;
  /** Port for replication connections */
  port: number;
}

/**
 * Configuration for the key replicator
 */
export interface ReplicationConfig {
  /** This node's unique identifier */
  nodeId: string;
  /** Port to listen for incoming replication connections */
  replicationPort: number;
  /** List of peer nodes to replicate with */
  peers: PeerConfig[];
  /** Expected code measurements for peers (from transparency log) */
  expectedMeasurements: Uint8Array[];
  /** How often to sync with peers (ms) */
  syncIntervalMs: number;
  /** Data directory for replication state */
  dataDir: string;
  /** Whether attestation is enabled */
  attestationEnabled: boolean;
}

/**
 * A managed encryption key with versioning for replication
 */
export interface ManagedKey {
  /** Unique identifier for the key */
  keyId: string;
  /** Monotonically increasing version number */
  version: number;
  /** The actual key bytes (never stored in plaintext on disk) */
  material: Buffer;
  /** Unix timestamp when the key was created */
  createdAt: number;
  /** Unix timestamp when the key was last updated */
  updatedAt: number;
  /** Metadata associated with the key */
  metadata: Record<string, string>;
}

/**
 * Key inventory entry for sync negotiation (excludes key material)
 */
export interface KeyInventoryEntry {
  keyId: string;
  version: number;
}

/**
 * A key envelope for secure transfer during replication
 * The key material is wrapped (encrypted) with the session key
 */
export interface WrappedKeyEnvelope {
  /** Key identifier */
  keyId: string;
  /** Version of this key */
  version: number;
  /** Key material wrapped with session encryption */
  wrappedMaterial: Buffer;
  /** Creation timestamp */
  createdAt: number;
  /** Last update timestamp */
  updatedAt: number;
  /** Key metadata */
  metadata: Record<string, string>;
}

/**
 * Result of a sync operation with a peer
 */
export interface SyncResult {
  /** Peer that was synced with */
  peerId: string;
  /** Whether the sync was successful */
  success: boolean;
  /** Number of keys sent to peer */
  keysSent: number;
  /** Number of keys received from peer */
  keysReceived: number;
  /** Error message if sync failed */
  error?: string;
  /** Duration of sync in ms */
  durationMs: number;
}

/**
 * Replication protocol message types
 */
export type ReplicationMessageType =
  | 'inventory-request'
  | 'inventory-response'
  | 'keys-request'
  | 'keys-response'
  | 'sync-complete';

/**
 * Base replication message
 */
export interface ReplicationMessage {
  type: ReplicationMessageType;
  nodeId: string;
  timestamp: number;
}

/**
 * Request for key inventory from peer
 */
export interface InventoryRequestMessage extends ReplicationMessage {
  type: 'inventory-request';
}

/**
 * Response with key inventory
 */
export interface InventoryResponseMessage extends ReplicationMessage {
  type: 'inventory-response';
  inventory: KeyInventoryEntry[];
}

/**
 * Request for specific keys from peer
 */
export interface KeysRequestMessage extends ReplicationMessage {
  type: 'keys-request';
  keyIds: string[];
}

/**
 * Response with wrapped keys
 */
export interface KeysResponseMessage extends ReplicationMessage {
  type: 'keys-response';
  keys: WrappedKeyEnvelope[];
}

/**
 * Sync completion acknowledgment
 */
export interface SyncCompleteMessage extends ReplicationMessage {
  type: 'sync-complete';
  keysReceived: number;
  keysSent: number;
}
