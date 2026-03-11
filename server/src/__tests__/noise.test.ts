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
  }, 15000);

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
    // Create promise that will resolve when we get an echo response
    const echoPromise = new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Echo timeout')), 10000);
      
      // Set up handler BEFORE starting the server
      server.on('session', (session: EncryptedSession) => {
        session.on('data', (data: Buffer) => {
          // Echo back the data
          session.send(data);
        });
      });

      server.start().then(async () => {
        // Establish connection and handshake
        const client = createConnection({ port: TEST_PORT, host: '127.0.0.1' });

        await new Promise<void>((clientResolve, clientReject) => {
          client.on('connect', clientResolve);
          client.on('error', clientReject);
        });

        const clientNoise = new Noise('XX', true);
        clientNoise.initialise(Buffer.alloc(0));

        const msg1 = clientNoise.send();
        client.write(Buffer.from(msg1));

        const serverReply = await new Promise<Buffer>((r) => {
          client.once('data', r);
        });
        clientNoise.recv(serverReply);

        const msg3 = clientNoise.send();
        client.write(Buffer.from(msg3));

        if (!clientNoise.complete) {
          clearTimeout(timeout);
          reject(new Error('Handshake failed'));
          return;
        }

        // Create ciphers
        const clientSendCipher = new Cipher(clientNoise.tx);
        const clientRecvCipher = new Cipher(clientNoise.rx);

        // Set up receive handler
        let buffer = Buffer.alloc(0);
        client.on('data', (data) => {
          buffer = Buffer.concat([buffer, data]);
          if (buffer.length >= 4) {
            const len = buffer.readUInt32BE(0);
            if (buffer.length >= 4 + len) {
              const encrypted = buffer.subarray(4, 4 + len);
              const decrypted = clientRecvCipher.decrypt(encrypted);
              clearTimeout(timeout);
              client.destroy();
              resolve(Buffer.from(decrypted).toString('utf-8'));
            }
          }
        });

        // Send encrypted message from client
        const testMessage = 'Hello from test client!';
        const encrypted = clientSendCipher.encrypt(Buffer.from(testMessage));
        const frame = Buffer.alloc(4 + encrypted.length);
        frame.writeUInt32BE(encrypted.length, 0);
        Buffer.from(encrypted).copy(frame, 4);
        client.write(frame);
      }).catch(reject);
    });

    const response = await echoPromise;
    expect(response).toBe('Hello from test client!');
  });
});
