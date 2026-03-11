/**
 * Storage module tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createStorage, Storage } from '../storage.js';
import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';

const TEST_DATA_DIR = '/tmp/sp-storage-test';

describe('Storage', () => {
  let storage: Storage;

  beforeEach(async () => {
    // Clean up any existing test data
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
    await mkdir(TEST_DATA_DIR, { recursive: true });
    storage = createStorage(TEST_DATA_DIR);
    await storage.init();
  });

  afterEach(async () => {
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
  });

  it('should initialize with empty state', async () => {
    const keys = await storage.keys();
    expect(keys).toEqual([]);
  });

  it('should set and get a value', async () => {
    await storage.set('foo', 'bar');
    const value = await storage.get('foo');
    expect(value).toBe('bar');
  });

  it('should return undefined for missing key', async () => {
    const value = await storage.get('nonexistent');
    expect(value).toBeUndefined();
  });

  it('should store complex objects', async () => {
    const obj = { name: 'test', count: 42, nested: { a: 1, b: [1, 2, 3] } };
    await storage.set('complex', obj);
    const value = await storage.get<typeof obj>('complex');
    expect(value).toEqual(obj);
  });

  it('should overwrite existing values', async () => {
    await storage.set('key', 'first');
    await storage.set('key', 'second');
    const value = await storage.get('key');
    expect(value).toBe('second');
  });

  it('should delete a key', async () => {
    await storage.set('toDelete', 'value');
    const deleted = await storage.delete('toDelete');
    expect(deleted).toBe(true);
    const value = await storage.get('toDelete');
    expect(value).toBeUndefined();
  });

  it('should return false when deleting nonexistent key', async () => {
    const deleted = await storage.delete('nonexistent');
    expect(deleted).toBe(false);
  });

  it('should check if key exists', async () => {
    await storage.set('exists', 'yes');
    expect(await storage.has('exists')).toBe(true);
    expect(await storage.has('doesNotExist')).toBe(false);
  });

  it('should list all keys', async () => {
    await storage.set('a', 1);
    await storage.set('b', 2);
    await storage.set('c', 3);
    const keys = await storage.keys();
    expect(keys.sort()).toEqual(['a', 'b', 'c']);
  });

  it('should get all entries', async () => {
    await storage.set('x', 'X');
    await storage.set('y', 'Y');
    const entries = await storage.entries();
    expect(entries.length).toBe(2);
    expect(entries.map(e => e.key).sort()).toEqual(['x', 'y']);
    expect(entries.every(e => typeof e.updatedAt === 'number')).toBe(true);
  });

  it('should clear all entries', async () => {
    await storage.set('a', 1);
    await storage.set('b', 2);
    await storage.clear();
    const keys = await storage.keys();
    expect(keys).toEqual([]);
  });

  it('should persist state across instances', async () => {
    await storage.set('persistent', 'data');
    
    // Create new storage instance pointing to same directory
    const storage2 = createStorage(TEST_DATA_DIR);
    await storage2.init();
    
    const value = await storage2.get('persistent');
    expect(value).toBe('data');
  });
});
