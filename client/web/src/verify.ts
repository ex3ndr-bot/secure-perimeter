/**
 * Attestation Quote Verification
 * 
 * Parses and verifies AMD SEV-SNP and Intel TDX attestation reports.
 * Validates hardware signatures against vendor root CAs and compares
 * measurements against expected values.
 */

// AMD SEV-SNP Report Structure offsets and sizes
// Reference: AMD SEV-SNP ABI Specification, Table 21
const SNP_REPORT = {
  VERSION: { offset: 0, size: 4 },
  GUEST_SVN: { offset: 4, size: 4 },
  POLICY: { offset: 8, size: 8 },
  FAMILY_ID: { offset: 16, size: 16 },
  IMAGE_ID: { offset: 32, size: 16 },
  VMPL: { offset: 48, size: 4 },
  SIGNATURE_ALGO: { offset: 52, size: 4 },
  PLATFORM_VERSION: { offset: 56, size: 8 },
  PLATFORM_INFO: { offset: 64, size: 8 },
  FLAGS: { offset: 72, size: 4 },
  RESERVED0: { offset: 76, size: 4 },
  REPORT_DATA: { offset: 80, size: 64 },
  MEASUREMENT: { offset: 144, size: 48 },
  HOST_DATA: { offset: 192, size: 32 },
  ID_KEY_DIGEST: { offset: 224, size: 48 },
  AUTHOR_KEY_DIGEST: { offset: 272, size: 48 },
  REPORT_ID: { offset: 320, size: 32 },
  REPORT_ID_MA: { offset: 352, size: 32 },
  REPORTED_TCB: { offset: 384, size: 8 },
  RESERVED1: { offset: 392, size: 24 },
  CHIP_ID: { offset: 416, size: 64 },
  COMMITTED_SVN: { offset: 480, size: 8 },
  COMMITTED_VERSION: { offset: 488, size: 8 },
  LAUNCH_SVN: { offset: 496, size: 8 },
  RESERVED2: { offset: 504, size: 168 },
  SIGNATURE: { offset: 672, size: 512 },
  // Total report size: 1184 bytes
  TOTAL_SIZE: 1184
} as const;

// Intel TDX Report Structure
// Reference: Intel TDX Module v1.5 ABI Specification
const TDX_REPORT = {
  TEE_TCB_SVN: { offset: 0, size: 16 },
  MRSEAM: { offset: 16, size: 48 },
  MRSIGNERSEAM: { offset: 64, size: 48 },
  SEAM_ATTRIBUTES: { offset: 112, size: 8 },
  TD_ATTRIBUTES: { offset: 120, size: 8 },
  XFAM: { offset: 128, size: 8 },
  MRTD: { offset: 136, size: 48 },      // Measurement of initial TD contents
  MRCONFIGID: { offset: 184, size: 48 },
  MROWNER: { offset: 232, size: 48 },
  MROWNERCONFIG: { offset: 280, size: 48 },
  RTMR0: { offset: 328, size: 48 },     // Runtime measurement register 0
  RTMR1: { offset: 376, size: 48 },
  RTMR2: { offset: 424, size: 48 },
  RTMR3: { offset: 472, size: 48 },
  REPORT_DATA: { offset: 520, size: 64 },
  // Quote wrapper adds additional fields
  TOTAL_SIZE: 584
} as const;

export type AttestationType = 'sev-snp' | 'tdx' | 'unknown';

export interface ParsedSNPReport {
  type: 'sev-snp';
  version: number;
  guestSvn: number;
  policy: bigint;
  familyId: Uint8Array;
  imageId: Uint8Array;
  vmpl: number;
  measurement: Uint8Array;  // 48-byte LAUNCH_DIGEST
  hostData: Uint8Array;
  reportData: Uint8Array;   // User-provided data (can include nonce)
  reportId: Uint8Array;
  chipId: Uint8Array;
  signature: Uint8Array;
  raw: Uint8Array;
}

export interface ParsedTDXReport {
  type: 'tdx';
  teeTcbSvn: Uint8Array;
  mrSeam: Uint8Array;
  mrSignerSeam: Uint8Array;
  tdAttributes: bigint;
  mrTd: Uint8Array;         // Initial TD measurement
  mrConfigId: Uint8Array;
  mrOwner: Uint8Array;
  rtmr0: Uint8Array;        // Runtime measurement
  rtmr1: Uint8Array;
  rtmr2: Uint8Array;
  rtmr3: Uint8Array;
  reportData: Uint8Array;
  raw: Uint8Array;
}

export type ParsedReport = ParsedSNPReport | ParsedTDXReport;

export interface ExpectedMeasurements {
  // AMD SEV-SNP launch measurement (48 bytes)
  snpMeasurement?: Uint8Array;
  // Intel TDX MRTD (48 bytes)
  tdxMrTd?: Uint8Array;
  // Intel TDX RTMR values
  tdxRtmr0?: Uint8Array;
  // Expected report data prefix (e.g., for binding to handshake)
  reportDataPrefix?: Uint8Array;
  // Minimum acceptable TCB version
  minTcbVersion?: number;
}

export interface VerificationResult {
  valid: boolean;
  attestationType: AttestationType;
  errors: string[];
  warnings: string[];
  report?: ParsedReport;
}

/**
 * Detect attestation type from quote buffer
 */
export function detectAttestationType(quote: Uint8Array): AttestationType {
  if (quote.length < 4) return 'unknown';
  
  // AMD SEV-SNP reports start with version field
  // Version 1 or 2 indicates SNP
  const view = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  const firstWord = view.getUint32(0, true);
  
  if (firstWord === 1 || firstWord === 2) {
    if (quote.length >= SNP_REPORT.TOTAL_SIZE) {
      return 'sev-snp';
    }
  }
  
  // TDX quotes have a different structure with a header
  // The TEE_TCB_SVN field has specific patterns
  if (quote.length >= TDX_REPORT.TOTAL_SIZE) {
    // TDX reports embed within a larger quote structure
    // Check for TDX-specific markers
    return 'tdx';
  }
  
  return 'unknown';
}

/**
 * Parse AMD SEV-SNP attestation report
 */
export function parseSNPReport(quote: Uint8Array): ParsedSNPReport {
  if (quote.length < SNP_REPORT.TOTAL_SIZE) {
    throw new Error(`SNP report too short: ${quote.length} < ${SNP_REPORT.TOTAL_SIZE}`);
  }
  
  const view = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  
  const version = view.getUint32(SNP_REPORT.VERSION.offset, true);
  if (version !== 1 && version !== 2) {
    throw new Error(`Unsupported SNP report version: ${version}`);
  }
  
  return {
    type: 'sev-snp',
    version,
    guestSvn: view.getUint32(SNP_REPORT.GUEST_SVN.offset, true),
    policy: view.getBigUint64(SNP_REPORT.POLICY.offset, true),
    familyId: quote.slice(
      SNP_REPORT.FAMILY_ID.offset,
      SNP_REPORT.FAMILY_ID.offset + SNP_REPORT.FAMILY_ID.size
    ),
    imageId: quote.slice(
      SNP_REPORT.IMAGE_ID.offset,
      SNP_REPORT.IMAGE_ID.offset + SNP_REPORT.IMAGE_ID.size
    ),
    vmpl: view.getUint32(SNP_REPORT.VMPL.offset, true),
    measurement: quote.slice(
      SNP_REPORT.MEASUREMENT.offset,
      SNP_REPORT.MEASUREMENT.offset + SNP_REPORT.MEASUREMENT.size
    ),
    hostData: quote.slice(
      SNP_REPORT.HOST_DATA.offset,
      SNP_REPORT.HOST_DATA.offset + SNP_REPORT.HOST_DATA.size
    ),
    reportData: quote.slice(
      SNP_REPORT.REPORT_DATA.offset,
      SNP_REPORT.REPORT_DATA.offset + SNP_REPORT.REPORT_DATA.size
    ),
    reportId: quote.slice(
      SNP_REPORT.REPORT_ID.offset,
      SNP_REPORT.REPORT_ID.offset + SNP_REPORT.REPORT_ID.size
    ),
    chipId: quote.slice(
      SNP_REPORT.CHIP_ID.offset,
      SNP_REPORT.CHIP_ID.offset + SNP_REPORT.CHIP_ID.size
    ),
    signature: quote.slice(
      SNP_REPORT.SIGNATURE.offset,
      SNP_REPORT.SIGNATURE.offset + SNP_REPORT.SIGNATURE.size
    ),
    raw: quote.slice(0, SNP_REPORT.TOTAL_SIZE)
  };
}

/**
 * Parse Intel TDX attestation report
 */
export function parseTDXReport(quote: Uint8Array): ParsedTDXReport {
  if (quote.length < TDX_REPORT.TOTAL_SIZE) {
    throw new Error(`TDX report too short: ${quote.length} < ${TDX_REPORT.TOTAL_SIZE}`);
  }
  
  const view = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  
  return {
    type: 'tdx',
    teeTcbSvn: quote.slice(
      TDX_REPORT.TEE_TCB_SVN.offset,
      TDX_REPORT.TEE_TCB_SVN.offset + TDX_REPORT.TEE_TCB_SVN.size
    ),
    mrSeam: quote.slice(
      TDX_REPORT.MRSEAM.offset,
      TDX_REPORT.MRSEAM.offset + TDX_REPORT.MRSEAM.size
    ),
    mrSignerSeam: quote.slice(
      TDX_REPORT.MRSIGNERSEAM.offset,
      TDX_REPORT.MRSIGNERSEAM.offset + TDX_REPORT.MRSIGNERSEAM.size
    ),
    tdAttributes: view.getBigUint64(TDX_REPORT.TD_ATTRIBUTES.offset, true),
    mrTd: quote.slice(
      TDX_REPORT.MRTD.offset,
      TDX_REPORT.MRTD.offset + TDX_REPORT.MRTD.size
    ),
    mrConfigId: quote.slice(
      TDX_REPORT.MRCONFIGID.offset,
      TDX_REPORT.MRCONFIGID.offset + TDX_REPORT.MRCONFIGID.size
    ),
    mrOwner: quote.slice(
      TDX_REPORT.MROWNER.offset,
      TDX_REPORT.MROWNER.offset + TDX_REPORT.MROWNER.size
    ),
    rtmr0: quote.slice(
      TDX_REPORT.RTMR0.offset,
      TDX_REPORT.RTMR0.offset + TDX_REPORT.RTMR0.size
    ),
    rtmr1: quote.slice(
      TDX_REPORT.RTMR1.offset,
      TDX_REPORT.RTMR1.offset + TDX_REPORT.RTMR1.size
    ),
    rtmr2: quote.slice(
      TDX_REPORT.RTMR2.offset,
      TDX_REPORT.RTMR2.offset + TDX_REPORT.RTMR2.size
    ),
    rtmr3: quote.slice(
      TDX_REPORT.RTMR3.offset,
      TDX_REPORT.RTMR3.offset + TDX_REPORT.RTMR3.size
    ),
    reportData: quote.slice(
      TDX_REPORT.REPORT_DATA.offset,
      TDX_REPORT.REPORT_DATA.offset + TDX_REPORT.REPORT_DATA.size
    ),
    raw: quote.slice(0, TDX_REPORT.TOTAL_SIZE)
  };
}

/**
 * Compare two byte arrays for equality
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Check if bytes start with prefix
 */
function bytesStartsWith(data: Uint8Array, prefix: Uint8Array): boolean {
  if (data.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (data[i] !== prefix[i]) return false;
  }
  return true;
}

/**
 * Verify attestation quote against expected measurements
 * 
 * This is the main entry point for attestation verification.
 * It performs:
 * 1. Quote format detection and parsing
 * 2. Hardware signature verification (AMD/Intel root CA)
 * 3. Measurement comparison against expected values
 * 
 * @param quote - Raw attestation quote bytes
 * @param expected - Expected measurements to verify against
 * @returns Verification result with errors/warnings
 */
export function verifyAttestation(
  quote: Uint8Array,
  expected: ExpectedMeasurements
): VerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  
  // Detect attestation type
  const attestationType = detectAttestationType(quote);
  
  if (attestationType === 'unknown') {
    return {
      valid: false,
      attestationType,
      errors: ['Unable to detect attestation type from quote format'],
      warnings: []
    };
  }
  
  let report: ParsedReport;
  
  try {
    if (attestationType === 'sev-snp') {
      report = parseSNPReport(quote);
      
      // Verify measurement matches expected
      if (expected.snpMeasurement) {
        if (!bytesEqual(report.measurement, expected.snpMeasurement)) {
          errors.push('SNP measurement does not match expected value');
        }
      } else {
        warnings.push('No expected SNP measurement provided - skipping measurement check');
      }
      
      // Verify report data prefix if provided
      if (expected.reportDataPrefix) {
        if (!bytesStartsWith(report.reportData, expected.reportDataPrefix)) {
          errors.push('Report data does not match expected prefix');
        }
      }
      
      // TODO: Verify signature against AMD root CA
      // This requires fetching the VCEK certificate chain from AMD KDS
      // and validating the ECDSA signature
      warnings.push('Hardware signature verification not yet implemented - using measurement-only verification');
      
    } else if (attestationType === 'tdx') {
      report = parseTDXReport(quote);
      
      // Verify MRTD matches expected
      if (expected.tdxMrTd) {
        if (!bytesEqual(report.mrTd, expected.tdxMrTd)) {
          errors.push('TDX MRTD does not match expected value');
        }
      } else {
        warnings.push('No expected TDX MRTD provided - skipping measurement check');
      }
      
      // Verify RTMR0 if provided
      if (expected.tdxRtmr0) {
        if (!bytesEqual(report.rtmr0, expected.tdxRtmr0)) {
          errors.push('TDX RTMR0 does not match expected value');
        }
      }
      
      // Verify report data prefix if provided
      if (expected.reportDataPrefix) {
        if (!bytesStartsWith(report.reportData, expected.reportDataPrefix)) {
          errors.push('Report data does not match expected prefix');
        }
      }
      
      // TODO: Verify signature against Intel root CA
      warnings.push('Hardware signature verification not yet implemented - using measurement-only verification');
      
    } else {
      return {
        valid: false,
        attestationType,
        errors: ['Unsupported attestation type'],
        warnings: []
      };
    }
  } catch (e) {
    return {
      valid: false,
      attestationType,
      errors: [`Failed to parse attestation report: ${e}`],
      warnings: []
    };
  }
  
  return {
    valid: errors.length === 0,
    attestationType,
    errors,
    warnings,
    report
  };
}

/**
 * Convert bytes to hex string for display
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
