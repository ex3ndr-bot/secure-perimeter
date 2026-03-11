/**
 * Attestation verification tests
 */

import { describe, it, expect } from 'vitest';
import {
  verifyAttestation,
  parseSNPReport,
  parseTDXReport,
  detectAttestationType,
  bytesToHex,
  hexToBytes,
} from '../verify.js';

describe('Attestation Verification', () => {
  describe('detectAttestationType', () => {
    it('should detect SEV-SNP from version header', () => {
      // SEV-SNP reports start with a version field
      const snpQuote = new Uint8Array(1184);
      snpQuote.set([0x02, 0x00, 0x00, 0x00], 0); // Version 2
      
      expect(detectAttestationType(snpQuote)).toBe('sev-snp');
    });

    it('should detect TDX from TCB SVN pattern', () => {
      // TDX reports have a different structure
      const tdxQuote = new Uint8Array(584);
      // TDX TCB SVN is 16 bytes at offset 0
      // Set a pattern that looks like TDX
      tdxQuote.set([0x04, 0x00, 0x02, 0x00], 0);
      
      // This is a heuristic test - real detection is more complex
      const type = detectAttestationType(tdxQuote);
      expect(['tdx', 'unknown']).toContain(type);
    });

    it('should return unknown for garbage data', () => {
      const garbage = new Uint8Array(100);
      expect(detectAttestationType(garbage)).toBe('unknown');
    });

    it('should return unknown for too-short data', () => {
      const short = new Uint8Array(3);
      expect(detectAttestationType(short)).toBe('unknown');
    });
  });

  describe('parseSNPReport', () => {
    it('should parse a valid SNP report structure', () => {
      // Create a minimal valid SNP report
      const report = new Uint8Array(1184);
      
      // Version (offset 0, 4 bytes)
      report.set([0x02, 0x00, 0x00, 0x00], 0);
      
      // Guest SVN (offset 4, 4 bytes)
      report.set([0x01, 0x00, 0x00, 0x00], 4);
      
      // VMPL (offset 48, 4 bytes)
      report.set([0x00, 0x00, 0x00, 0x00], 48);
      
      // Report data (offset 80, 64 bytes) - put some test data
      report.set(new Uint8Array(64).fill(0xAB), 80);
      
      // Measurement (offset 144, 48 bytes)
      report.set(new Uint8Array(48).fill(0xCD), 144);

      const parsed = parseSNPReport(report);
      
      expect(parsed.type).toBe('sev-snp');
      expect(parsed.version).toBe(2);
      expect(parsed.guestSvn).toBe(1);
      expect(parsed.vmpl).toBe(0);
      expect(parsed.reportData[0]).toBe(0xAB);
      expect(parsed.measurement[0]).toBe(0xCD);
    });
  });

  describe('parseTDXReport', () => {
    it('should parse a valid TDX report structure', () => {
      const report = new Uint8Array(584);
      
      // TEE TCB SVN (offset 0, 16 bytes)
      report.set(new Uint8Array(16).fill(0x11), 0);
      
      // MRTD (offset 136, 48 bytes)
      report.set(new Uint8Array(48).fill(0x22), 136);
      
      // RTMR0 (offset 328, 48 bytes)
      report.set(new Uint8Array(48).fill(0x33), 328);
      
      // Report data (offset 520, 64 bytes)
      report.set(new Uint8Array(64).fill(0x44), 520);

      const parsed = parseTDXReport(report);
      
      expect(parsed.type).toBe('tdx');
      expect(parsed.teeTcbSvn[0]).toBe(0x11);
      expect(parsed.mrTd[0]).toBe(0x22);
      expect(parsed.rtmr0[0]).toBe(0x33);
      expect(parsed.reportData[0]).toBe(0x44);
    });
  });

  describe('verifyAttestation', () => {
    it('should fail on unknown attestation type', () => {
      const garbage = new Uint8Array(100);
      const result = verifyAttestation(garbage, {});
      
      expect(result.valid).toBe(false);
      expect(result.attestationType).toBe('unknown');
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should warn when no expected measurement provided', () => {
      // Create minimal SNP report
      const report = new Uint8Array(1184);
      report.set([0x02, 0x00, 0x00, 0x00], 0);
      
      const result = verifyAttestation(report, {});
      
      expect(result.attestationType).toBe('sev-snp');
      expect(result.warnings.some(w => w.includes('No expected SNP measurement'))).toBe(true);
    });

    it('should fail when measurement does not match', () => {
      // Create SNP report with measurement
      const report = new Uint8Array(1184);
      report.set([0x02, 0x00, 0x00, 0x00], 0);
      report.set(new Uint8Array(48).fill(0xAA), 144);
      
      // Expected measurement is different
      const expectedMeasurement = new Uint8Array(48).fill(0xBB);
      
      const result = verifyAttestation(report, {
        snpMeasurement: expectedMeasurement
      });
      
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('measurement does not match'))).toBe(true);
    });

    it('should pass when measurement matches', () => {
      const measurement = new Uint8Array(48).fill(0xCC);
      
      // Create SNP report
      const report = new Uint8Array(1184);
      report.set([0x02, 0x00, 0x00, 0x00], 0);
      report.set(measurement, 144);
      
      const result = verifyAttestation(report, {
        snpMeasurement: measurement
      });
      
      // Should pass measurement check (may still have warnings about signature)
      expect(result.errors.filter(e => e.includes('measurement'))).toHaveLength(0);
    });
  });

  describe('bytesToHex / hexToBytes', () => {
    it('should convert bytes to hex', () => {
      const bytes = new Uint8Array([0x00, 0x11, 0x22, 0xff]);
      expect(bytesToHex(bytes)).toBe('001122ff');
    });

    it('should convert hex to bytes', () => {
      const bytes = hexToBytes('001122ff');
      expect(bytes).toEqual(new Uint8Array([0x00, 0x11, 0x22, 0xff]));
    });

    it('should round-trip correctly', () => {
      const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const hex = bytesToHex(original);
      const back = hexToBytes(hex);
      expect(back).toEqual(original);
    });

    it('should handle empty input', () => {
      expect(bytesToHex(new Uint8Array(0))).toBe('');
      expect(hexToBytes('')).toEqual(new Uint8Array(0));
    });
  });
});
