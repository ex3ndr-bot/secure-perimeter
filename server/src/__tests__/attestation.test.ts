/**
 * Attestation module tests
 */

import { describe, it, expect } from 'vitest';
import { 
  getAttestationQuote, 
  isAttested, 
  serializeQuote, 
  deserializeQuote 
} from '../attestation.js';

describe('Attestation', () => {
  describe('isAttested', () => {
    it('should return false in non-TEE environment', async () => {
      const result = await isAttested();
      // In test environment, we don't have real TEE hardware
      expect(result).toBe(false);
    });
  });

  describe('getAttestationQuote', () => {
    it('should generate mock quote in non-TEE environment', async () => {
      const publicKey = Buffer.from('a'.repeat(64), 'hex');
      const quote = await getAttestationQuote(publicKey);

      expect(quote.teeType).toBe('mock');
      expect(quote.isHardwareAttested).toBe(false);
      expect(quote.boundPublicKey).toEqual(publicKey);
      expect(typeof quote.timestamp).toBe('number');
      expect(quote.measurementHash.length).toBe(32);
      expect(quote.report.length).toBeGreaterThan(0);
    });

    it('should generate consistent measurement hash for same key', async () => {
      const publicKey = Buffer.from('b'.repeat(64), 'hex');
      const quote1 = await getAttestationQuote(publicKey);
      const quote2 = await getAttestationQuote(publicKey);

      expect(quote1.measurementHash).toEqual(quote2.measurementHash);
    });

    it('should generate different measurement hash for different keys', async () => {
      const key1 = Buffer.from('c'.repeat(64), 'hex');
      const key2 = Buffer.from('d'.repeat(64), 'hex');
      const quote1 = await getAttestationQuote(key1);
      const quote2 = await getAttestationQuote(key2);

      expect(Buffer.from(quote1.measurementHash).toString('hex')).not.toBe(
        Buffer.from(quote2.measurementHash).toString('hex')
      );
    });
  });

  describe('serializeQuote / deserializeQuote', () => {
    it('should round-trip a mock quote', async () => {
      const publicKey = Buffer.from('e'.repeat(64), 'hex');
      const original = await getAttestationQuote(publicKey);

      const serialized = serializeQuote(original);
      const deserialized = deserializeQuote(serialized);

      expect(deserialized.teeType).toBe(original.teeType);
      expect(deserialized.isHardwareAttested).toBe(original.isHardwareAttested);
      expect(deserialized.timestamp).toBe(original.timestamp);
      expect(Buffer.from(deserialized.boundPublicKey).toString('hex')).toBe(
        Buffer.from(original.boundPublicKey).toString('hex')
      );
      expect(Buffer.from(deserialized.measurementHash).toString('hex')).toBe(
        Buffer.from(original.measurementHash).toString('hex')
      );
    });

    it('should serialize to a Buffer', async () => {
      const publicKey = Buffer.from('f'.repeat(64), 'hex');
      const quote = await getAttestationQuote(publicKey);
      const serialized = serializeQuote(quote);

      expect(Buffer.isBuffer(serialized)).toBe(true);
      expect(serialized.length).toBeGreaterThan(0);
    });

    it('should preserve TEE type through serialization', async () => {
      // Test with mock TEE type
      const publicKey = Buffer.from('00'.repeat(32), 'hex');
      const quote = await getAttestationQuote(publicKey);

      const serialized = serializeQuote(quote);
      const deserialized = deserializeQuote(serialized);

      expect(deserialized.teeType).toBe('mock');
    });

    it('should handle various public key sizes', async () => {
      // 32 bytes (ed25519)
      const key32 = Buffer.from('a'.repeat(64), 'hex');
      const quote32 = await getAttestationQuote(key32);
      const serialized32 = serializeQuote(quote32);
      const deser32 = deserializeQuote(serialized32);
      expect(deser32.boundPublicKey.length).toBe(32);

      // 64 bytes
      const key64 = Buffer.from('b'.repeat(128), 'hex');
      const quote64 = await getAttestationQuote(key64);
      const serialized64 = serializeQuote(quote64);
      const deser64 = deserializeQuote(serialized64);
      expect(deser64.boundPublicKey.length).toBe(64);
    });
  });
});
