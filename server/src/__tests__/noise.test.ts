/**
 * Noise Protocol server tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createNoiseServer, NoiseServer, EncryptedSession } from '../noise.js';
import { createConnection, Socket } from 'node:net';
import { mkdir, rm } from 'node:fs/promises';

// @ts-expect-error - noise-handshake doesn't have types
import Noise from 'noise-handshake';
// @ts-expect-error
import Cipher from 'noise-handshake/cipher.js';

const TEST_DATA_DIR = '/tmp/sp-noise-test';
const TEST_PORT = 19443;
// BLAKE2b uses 64-byte hash
const HASHLEN = 64;

describe('NoiseServer', () => {
  let server: NoiseServer;

  beforeEach(async () => {
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
    await mkdir(TEST_DATA_DIR, { recursive: true });

    server = createNoiseServer({
      noisePort: TEST_PORT,
      attestationEnabled: false,
      dataDir: TEST_DATA_DIR,
    });
  });

  afterEach(async () => {
    if (server) {
      await server.stop();
    }
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
  });

  it('should start and listen on configured port', async () => {
    await server.start();
    expect(server.publicKey).not.toBeNull();
    expect(server.publicKey?.length).toBe(32);
  });

  it('should generate keypair on first start', async () => {
    await server.start();
    const pubKey1 = Buffer.from(server.publicKey!).toString('hex');
    await server.stop();

    // Start again - should load same keypair
    const server2 = createNoiseServer({
      noisePort: TEST_PORT,
      attestationEnabled: false,
      dataDir: TEST_DATA_DIR,
    });
    await server2.start();
    const pubKey2 = Buffer.from(server2.publicKey!).toString('hex');
    await server2.stop();

    expect(pubKey1).toBe(pubKey2);
  });

  it('should accept a connection and complete handshake', { timeout: 15000 }, async () => {
    await server.start();

    const sessionPromise = new Promise<EncryptedSession>((resolve) => {
      server.on('session', resolve);
    });

    // Create client connection
    const client = createConnection({ port: TEST_PORT, host: '127.0.0.1' });

    await new Promise<void>((resolve, reject) => {
      client.on('connect', resolve);
      client.on('error', reject);
    });

    // Initialize client-side Noise handshake (XX pattern, initiator)
    const clientNoise = new Noise('XX', true);
    clientNoise.initialise(Buffer.alloc(0));

    // Send first message (-> e)
    const msg1 = clientNoise.send();
    client.write(Buffer.from(msg1));

    // Wait for server response (-> e, ee, s, es with payload)
    const serverReply = await new Promise<Buffer>((resolve) => {
      client.once('data', resolve);
    });

    // Process server response
    clientNoise.recv(serverReply);

    // Send final message (-> s, se)
    const msg3 = clientNoise.send();
    client.write(Buffer.from(msg3));

    // Handshake should be complete
    expect(clientNoise.complete).toBe(true);

    // Wait for server session
    const session = await sessionPromise;
    expect(session).toBeDefined();
    expect(session.remotePublicKey.length).toBe(32);
    // BLAKE2b hash is 64 bytes
    expect(session.handshakeHash.length).toBe(HASHLEN);

    client.destroy();
  });

  it('should allow encrypted communication after handshake', { timeout: 15000 }, async () => {
    await server.start();

    const sessionPromise = new Promise<EncryptedSession>((resolve) => {
      server.on('session', resolve);
    });

    // Establish connection and handshake
    const client = createConnection({ port: TEST_PORT, host: '127.0.0.1' });

    await new Promise<void>((resolve, reject) => {
      client.on('connect', resolve);
      client.on('error', reject);
    });

    const clientNoise = new Noise('XX', true);
    clientNoise.initialise(Buffer.alloc(0));

    const msg1 = clientNoise.send();
    client.write(Buffer.from(msg1));

    const serverReply = await new Promise<Buffer>((resolve) => {
      client.once('data', resolve);
    });
    clientNoise.recv(serverReply);

    const msg3 = clientNoise.send();
    client.write(Buffer.from(msg3));

    expect(clientNoise.complete).toBe(true);

    // Create ciphers
    const clientSendCipher = new Cipher(clientNoise.tx);
    const clientRecvCipher = new Cipher(clientNoise.rx);

    const session = await sessionPromise;

    // Set up to receive response from server
    const responsePromise = new Promise<string>((resolve) => {
      let buffer = Buffer.alloc(0);
      client.on('data', (data) => {
        buffer = Buffer.concat([buffer, data]);
        if (buffer.length >= 4) {
          const len = buffer.readUInt32BE(0);
          if (buffer.length >= 4 + len) {
            const encrypted = buffer.subarray(4, 4 + len);
            const decrypted = clientRecvCipher.decrypt(encrypted);
            resolve(Buffer.from(decrypted).toString('utf-8'));
          }
        }
      });
    });

    // Send encrypted message from client
    const testCommand = JSON.stringify({ type: 'ping' });
    const encrypted = clientSendCipher.encrypt(Buffer.from(testCommand));
    const frame = Buffer.alloc(4 + encrypted.length);
    frame.writeUInt32BE(encrypted.length, 0);
    Buffer.from(encrypted).copy(frame, 4);
    client.write(frame);

    // Wait for response
    const response = await responsePromise;
    const parsed = JSON.parse(response);

    expect(parsed.success).toBe(true);
    expect(parsed.data.pong).toBeDefined();
    expect(typeof parsed.data.pong).toBe('number');

    client.destroy();
  });
});
