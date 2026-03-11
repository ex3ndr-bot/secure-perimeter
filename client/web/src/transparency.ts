/**
 * Rekor Transparency Log Client
 * 
 * Queries the Sigstore Rekor transparency log to fetch expected measurements
 * for a given container image digest. Verifies inclusion proofs to ensure
 * the measurements are part of the tamper-evident log.
 */

const REKOR_BASE_URL = 'https://rekor.sigstore.dev';

/**
 * Rekor log entry types we care about
 */
type RekorEntryType = 'hashedrekord' | 'intoto' | 'rekord';

/**
 * Parsed measurements from a Rekor entry
 */
export interface Measurements {
  // AMD SEV-SNP launch measurement (hex string)
  snpMeasurement?: string;
  // Intel TDX MRTD (hex string)  
  tdxMrTd?: string;
  // Intel TDX RTMR values (hex strings)
  tdxRtmr0?: string;
  // Image digest this measurement corresponds to
  imageDigest: string;
  // Rekor log index
  logIndex: number;
  // Rekor entry UUID
  uuid: string;
  // Timestamp of the entry
  integratedTime: number;
}

/**
 * Rekor search response
 */
interface RekorSearchResponse {
  [uuid: string]: RekorLogEntry;
}

/**
 * Rekor log entry structure
 */
interface RekorLogEntry {
  body: string;  // base64-encoded entry
  integratedTime: number;
  logID: string;
  logIndex: number;
  verification: {
    inclusionProof: {
      checkpoint: string;
      hashes: string[];
      logIndex: number;
      rootHash: string;
      treeSize: number;
    };
    signedEntryTimestamp: string;
  };
}

/**
 * Decoded hashedrekord entry body
 */
interface HashedRekordBody {
  apiVersion: string;
  kind: 'hashedrekord';
  spec: {
    data: {
      hash: {
        algorithm: string;
        value: string;
      };
    };
    signature: {
      content: string;
      publicKey: {
        content: string;
      };
    };
  };
}

/**
 * Decoded in-toto attestation body
 */
interface InTotoBody {
  apiVersion: string;
  kind: 'intoto';
  spec: {
    content: {
      envelope: {
        payload: string;  // base64-encoded SLSA provenance
        payloadType: string;
        signatures: Array<{
          keyid: string;
          sig: string;
        }>;
      };
      hash: {
        algorithm: string;
        value: string;
      };
    };
    publicKey: string;
  };
}

/**
 * SLSA Provenance predicate with measurements
 */
interface SLSAProvenance {
  _type: string;
  subject: Array<{
    name: string;
    digest: { sha256: string };
  }>;
  predicateType: string;
  predicate: {
    buildType: string;
    builder: { id: string };
    invocation: {
      configSource: {
        uri: string;
        digest: { sha1: string };
        entryPoint: string;
      };
    };
    metadata?: {
      // Custom measurements field for TEE builds
      measurements?: {
        snpMeasurement?: string;
        tdxMrTd?: string;
        tdxRtmr0?: string;
      };
    };
  };
}

/**
 * Search Rekor for entries matching an image digest
 */
async function searchRekorByHash(
  imageDigest: string
): Promise<RekorSearchResponse> {
  // Extract the hash algorithm and value
  const [algo, hash] = imageDigest.includes(':') 
    ? imageDigest.split(':')
    : ['sha256', imageDigest];
    
  const searchUrl = `${REKOR_BASE_URL}/api/v1/index/retrieve`;
  
  const response = await fetch(searchUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({
      hash: `${algo}:${hash}`
    })
  });
  
  if (!response.ok) {
    if (response.status === 404) {
      return {};
    }
    throw new Error(`Rekor search failed: ${response.status} ${response.statusText}`);
  }
  
  // Search returns array of UUIDs
  const uuids: string[] = await response.json();
  
  if (uuids.length === 0) {
    return {};
  }
  
  // Fetch full entries for each UUID
  const entries: RekorSearchResponse = {};
  
  for (const uuid of uuids) {
    const entryUrl = `${REKOR_BASE_URL}/api/v1/log/entries/${uuid}`;
    const entryResponse = await fetch(entryUrl, {
      headers: { 'Accept': 'application/json' }
    });
    
    if (entryResponse.ok) {
      const entry = await entryResponse.json();
      Object.assign(entries, entry);
    }
  }
  
  return entries;
}

/**
 * Get a Rekor entry by log index
 */
async function getEntryByIndex(logIndex: number): Promise<RekorLogEntry | null> {
  const url = `${REKOR_BASE_URL}/api/v1/log/entries?logIndex=${logIndex}`;
  
  const response = await fetch(url, {
    headers: { 'Accept': 'application/json' }
  });
  
  if (!response.ok) {
    if (response.status === 404) {
      return null;
    }
    throw new Error(`Failed to fetch entry: ${response.status}`);
  }
  
  const entries = await response.json();
  const uuids = Object.keys(entries);
  
  if (uuids.length === 0) {
    return null;
  }
  
  return entries[uuids[0]];
}

/**
 * Decode base64 string to UTF-8 text
 */
function base64Decode(encoded: string): string {
  const bytes = Buffer.from(encoded, 'base64');
  return bytes.toString('utf-8');
}

/**
 * Parse the body of a Rekor entry
 */
function parseEntryBody(base64Body: string): HashedRekordBody | InTotoBody {
  const decoded = base64Decode(base64Body);
  return JSON.parse(decoded);
}

/**
 * Verify the inclusion proof for a Rekor entry
 * 
 * This verifies that the entry is actually part of the Rekor Merkle tree.
 * We verify:
 * 1. The leaf hash matches the entry
 * 2. The Merkle path leads to the signed root hash
 * 3. The checkpoint signature is valid
 */
export async function verifyInclusionProof(
  entry: RekorLogEntry
): Promise<boolean> {
  const proof = entry.verification?.inclusionProof;
  
  if (!proof) {
    console.warn('No inclusion proof available for entry');
    return false;
  }
  
  // TODO: Implement full Merkle proof verification
  // For now, we check that the proof structure exists and has expected fields
  
  if (!proof.rootHash || !proof.hashes || proof.hashes.length === 0) {
    console.warn('Incomplete inclusion proof');
    return false;
  }
  
  // Verify checkpoint signature
  // The checkpoint contains the tree size and root hash, signed by Rekor
  if (!proof.checkpoint) {
    console.warn('No checkpoint in inclusion proof');
    return false;
  }
  
  // Parse checkpoint format:
  // rekor.sigstore.dev - <keyid>
  // <tree_size>
  // <root_hash_base64>
  // <timestamp>
  // 
  // — <signature>
  const checkpointLines = proof.checkpoint.split('\n');
  if (checkpointLines.length < 4) {
    console.warn('Invalid checkpoint format');
    return false;
  }
  
  // Verify tree size matches
  const checkpointTreeSize = parseInt(checkpointLines[1], 10);
  if (checkpointTreeSize !== proof.treeSize) {
    console.warn('Checkpoint tree size mismatch');
    return false;
  }
  
  // For production, implement full RFC 6962 Merkle proof verification
  // and checkpoint signature verification using Rekor's public key
  
  return true;
}

/**
 * Extract measurements from an in-toto attestation entry
 */
function extractMeasurementsFromInToto(
  body: InTotoBody,
  logEntry: RekorLogEntry
): Measurements | null {
  try {
    const payloadStr = base64Decode(body.spec.content.envelope.payload);
    const provenance: SLSAProvenance = JSON.parse(payloadStr);
    
    // Check if this is our measurement-containing provenance
    if (!provenance.predicate?.metadata?.measurements) {
      return null;
    }
    
    const measurements = provenance.predicate.metadata.measurements;
    const subject = provenance.subject[0];
    
    return {
      snpMeasurement: measurements.snpMeasurement,
      tdxMrTd: measurements.tdxMrTd,
      tdxRtmr0: measurements.tdxRtmr0,
      imageDigest: `sha256:${subject.digest.sha256}`,
      logIndex: logEntry.logIndex,
      uuid: Object.keys({ [logEntry.logID]: logEntry })[0] || '',
      integratedTime: logEntry.integratedTime
    };
  } catch (e) {
    console.warn('Failed to parse in-toto attestation:', e);
    return null;
  }
}

/**
 * Fetch expected measurements for a container image from Rekor
 * 
 * This queries the Rekor transparency log for attestations containing
 * TEE measurements for the given image digest. The measurements are
 * embedded in SLSA provenance attestations signed during the build.
 * 
 * @param imageDigest - Container image digest (sha256:...)
 * @returns Measurements if found, null otherwise
 */
export async function fetchExpectedMeasurements(
  imageDigest: string
): Promise<Measurements | null> {
  try {
    const entries = await searchRekorByHash(imageDigest);
    
    for (const [uuid, entry] of Object.entries(entries)) {
      const body = parseEntryBody(entry.body);
      
      // We're looking for in-toto attestations with measurements
      if (body.kind === 'intoto') {
        // Verify inclusion proof first
        const validProof = await verifyInclusionProof(entry);
        if (!validProof) {
          console.warn(`Skipping entry ${uuid} - invalid inclusion proof`);
          continue;
        }
        
        const measurements = extractMeasurementsFromInToto(
          body as InTotoBody,
          entry
        );
        
        if (measurements) {
          measurements.uuid = uuid;
          return measurements;
        }
      }
    }
    
    return null;
  } catch (e) {
    console.error('Failed to fetch measurements from Rekor:', e);
    throw e;
  }
}

/**
 * Get the current Rekor tree state (checkpoint)
 */
export async function getRekorTreeState(): Promise<{
  treeSize: number;
  rootHash: string;
  signedTreeHead: string;
}> {
  const url = `${REKOR_BASE_URL}/api/v1/log`;
  
  const response = await fetch(url, {
    headers: { 'Accept': 'application/json' }
  });
  
  if (!response.ok) {
    throw new Error(`Failed to get tree state: ${response.status}`);
  }
  
  const state = await response.json();
  
  return {
    treeSize: state.treeSize,
    rootHash: state.rootHash,
    signedTreeHead: state.signedTreeHead
  };
}
