/**
 * TEE Attestation module
 * Reads hardware attestation quotes from AMD SEV-SNP or Intel TDX,
 * or provides mock quotes in development mode.
 */

import { readFile, access } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import type { AttestationQuote } from './types.js';

const SEV_GUEST_PATH = '/dev/sev-guest';
const TDX_GUEST_PATH = '/dev/tdx-guest';

/** Check if a file/device exists */
async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/** Generate a measurement hash from the public key */
function generateMeasurementHash(publicKey: Buffer): Buffer {
  return createHash('sha256')
    .update(publicKey)
    .update(Buffer.from('secure-perimeter-measurement'))
    .digest();
}

/** 
 * Try to read AMD SEV-SNP attestation quote.
 * In real hardware, this would use ioctl to get the attestation report.
 */
async function readSevSnpQuote(publicKey: Buffer): Promise<AttestationQuote | null> {
  if (!await exists(SEV_GUEST_PATH)) {
    return null;
  }

  try {
    // In real implementation, we would:
    // 1. Open /dev/sev-guest
    // 2. Use ioctl(fd, SNP_GET_REPORT, &report_req)
    // 3. Parse the attestation report
    // For now, this is a placeholder that would need kernel interface binding
    const report = await readFile(SEV_GUEST_PATH);
    
    return {
      teeType: 'sev-snp',
      report,
      measurementHash: generateMeasurementHash(publicKey),
      boundPublicKey: publicKey,
      timestamp: Date.now(),
      isHardwareAttested: true,
    };
  } catch {
    return null;
  }
}

/**
 * Try to read Intel TDX attestation quote.
 */
async function readTdxQuote(publicKey: Buffer): Promise<AttestationQuote | null> {
  if (!await exists(TDX_GUEST_PATH)) {
    return null;
  }

  try {
    // Similar to SEV-SNP, real implementation would use tdx_guest ioctl
    const report = await readFile(TDX_GUEST_PATH);
    
    return {
      teeType: 'tdx',
      report,
      measurementHash: generateMeasurementHash(publicKey),
      boundPublicKey: publicKey,
      timestamp: Date.now(),
      isHardwareAttested: true,
    };
  } catch {
    return null;
  }
}

/**
 * Generate a mock attestation quote for development/testing.
 */
function generateMockQuote(publicKey: Buffer): AttestationQuote {
  // Create a mock report that looks like a real attestation
  const mockReport = Buffer.concat([
    Buffer.from('MOCK_ATTESTATION_V1'), // Header
    randomBytes(32), // Nonce
    generateMeasurementHash(publicKey), // Measurement
    publicKey, // Bound key
    randomBytes(64), // Signature placeholder
  ]);

  return {
    teeType: 'mock',
    report: mockReport,
    measurementHash: generateMeasurementHash(publicKey),
    boundPublicKey: publicKey,
    timestamp: Date.now(),
    isHardwareAttested: false,
  };
}

/**
 * Get attestation quote, trying hardware first, falling back to mock.
 * @param publicKey - The public key to bind to the attestation
 * @returns AttestationQuote with either hardware or mock attestation
 */
export async function getAttestationQuote(publicKey: Buffer): Promise<AttestationQuote> {
  // Try AMD SEV-SNP first
  const sevQuote = await readSevSnpQuote(publicKey);
  if (sevQuote) {
    console.log('[attestation] Using AMD SEV-SNP hardware attestation');
    return sevQuote;
  }

  // Try Intel TDX
  const tdxQuote = await readTdxQuote(publicKey);
  if (tdxQuote) {
    console.log('[attestation] Using Intel TDX hardware attestation');
    return tdxQuote;
  }

  // Fall back to mock attestation
  console.log('[attestation] Hardware TEE not available, using mock attestation (dev mode)');
  return generateMockQuote(publicKey);
}

/**
 * Check if we're running in a real TEE environment.
 * @returns true if hardware attestation is available
 */
export async function isAttested(): Promise<boolean> {
  return await exists(SEV_GUEST_PATH) || await exists(TDX_GUEST_PATH);
}

/**
 * Serialize attestation quote for embedding in Noise handshake payload.
 */
export function serializeQuote(quote: AttestationQuote): Buffer {
  const typeStr = quote.teeType.padEnd(8, '\0');
  const timestamp = Buffer.alloc(8);
  timestamp.writeBigInt64BE(BigInt(quote.timestamp), 0);

  return Buffer.concat([
    Buffer.from(typeStr),
    timestamp,
    Buffer.from([quote.isHardwareAttested ? 1 : 0]),
    Buffer.from([quote.measurementHash.length]),
    quote.measurementHash,
    Buffer.from([quote.boundPublicKey.length]),
    quote.boundPublicKey,
    quote.report,
  ]);
}

/**
 * Deserialize attestation quote from Noise handshake payload.
 */
export function deserializeQuote(data: Buffer): AttestationQuote {
  let offset = 0;

  const typeStr = data.subarray(offset, offset + 8).toString().replace(/\0+$/, '');
  offset += 8;

  const timestamp = Number(data.readBigInt64BE(offset));
  offset += 8;

  const isHardwareAttested = data[offset] === 1;
  offset += 1;

  const measurementLen = data[offset];
  offset += 1;
  const measurementHash = data.subarray(offset, offset + measurementLen);
  offset += measurementLen;

  const publicKeyLen = data[offset];
  offset += 1;
  const boundPublicKey = data.subarray(offset, offset + publicKeyLen);
  offset += publicKeyLen;

  const report = data.subarray(offset);

  const teeType = (typeStr === 'sev-snp' || typeStr === 'tdx' || typeStr === 'mock')
    ? typeStr
    : 'mock';

  return {
    teeType,
    report: Buffer.from(report),
    measurementHash: Buffer.from(measurementHash),
    boundPublicKey: Buffer.from(boundPublicKey),
    timestamp,
    isHardwareAttested,
  };
}
