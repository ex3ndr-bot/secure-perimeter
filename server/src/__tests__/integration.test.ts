/**
 * Integration tests - full server + client communication
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createNoiseServer, NoiseServer, EncryptedSession } from '../noise.js';
import { createStorage } from '../storage.js';
import { createConnection, Socket } from 'node:net';
import { mkdir, rm } from 'node:fs/promises';

// @ts-expect-error - noise-handshake doesn't have types
import Noise from 'noise-handshake';
// @ts-expect-error
import Cipher from 'noise-handshake/cipher.js';

const TEST_DATA_DIR = '/tmp/sp-integration-test';
const TEST_PORT = 29443;

interface CommandResult {
  success: boolean;
  data?: unknown;
  error?: string;
}

class TestClient {
  private socket: Socket | null = null;
  private sendCipher: typeof Cipher | null = null;
  private recvCipher: typeof Cipher | null = null;
  private receiveBuffer = Buffer.alloc(0);
  private pendingResolvers: ((data: string) => void)[] = [];

  async connect(port: number): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = createConnection({ port, host: '127.0.0.1' });
      this.socket.on('connect', async () => {
        try {
          await this.doHandshake();
          resolve();
        } catch (err) {
          reject(err);
        }
      });
      this.socket.on('error', reject);
    });
  }

  private async doHandshake(): Promise<void> {
    const noise = new Noise('XX', true);
    noise.initialise(Buffer.alloc(0));

    // -> e
    this.socket!.write(Buffer.from(noise.send()));

    // <- e, ee, s, es
    const reply = await new Promise<Buffer>((resolve) => {
      this.socket!.once('data', resolve);
    });
    noise.recv(reply);

    // -> s, se
    this.socket!.write(Buffer.from(noise.send()));

    if (!noise.complete) {
      throw new Error('Handshake failed');
    }

    this.sendCipher = new Cipher(noise.tx);
    this.recvCipher = new Cipher(noise.rx);

    // Set up data handler
    this.socket!.on('data', (data) => {
      this.receiveBuffer = Buffer.concat([this.receiveBuffer, data]);
      this.processFrames();
    });
  }

  private processFrames(): void {
    while (this.receiveBuffer.length >= 4) {
      const len = this.receiveBuffer.readUInt32BE(0);
      if (this.receiveBuffer.length < 4 + len) break;

      const encrypted = this.receiveBuffer.subarray(4, 4 + len);
      this.receiveBuffer = this.receiveBuffer.subarray(4 + len);

      const decrypted = this.recvCipher!.decrypt(encrypted);
      const text = Buffer.from(decrypted).toString('utf-8');

      const resolver = this.pendingResolvers.shift();
      if (resolver) {
        resolver(text);
      }
    }
  }

  async send(command: object): Promise<CommandResult> {
    const text = JSON.stringify(command);
    const encrypted = this.sendCipher!.encrypt(Buffer.from(text));
    const frame = Buffer.alloc(4 + encrypted.length);
    frame.writeUInt32BE(encrypted.length, 0);
    Buffer.from(encrypted).copy(frame, 4);
    this.socket!.write(frame);

    // Wait for response
    const response = await new Promise<string>((resolve) => {
      this.pendingResolvers.push(resolve);
    });

    return JSON.parse(response) as CommandResult;
  }

  close(): void {
    this.socket?.destroy();
  }
}

describe('Integration', { timeout: 30000 }, () => {
  let server: NoiseServer;
  let storage: ReturnType<typeof createStorage>;

  beforeAll(async () => {
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
    await mkdir(TEST_DATA_DIR, { recursive: true });

    storage = createStorage(TEST_DATA_DIR);
    await storage.init();

    server = createNoiseServer({
      noisePort: TEST_PORT,
      attestationEnabled: false,
      dataDir: TEST_DATA_DIR,
    });

    server.on('session', (session: EncryptedSession) => {
      handleSession(session);
    });

    await server.start();
  });

  afterAll(async () => {
    await server.stop();
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
  });

  // Handler function (simplified from main.ts)
  function handleSession(session: EncryptedSession): void {
    session.on('data', async (data: Buffer) => {
      try {
        const message = JSON.parse(data.toString('utf-8'));
        let response: CommandResult;

        switch (message.type) {
          case 'ping':
            response = { success: true, data: { pong: Date.now() } };
            break;
          case 'get':
            if (!message.key) {
              response = { success: false, error: 'Missing key' };
            } else {
              const value = await storage.get(message.key);
              response = { success: true, data: { key: message.key, value } };
            }
            break;
          case 'set':
            if (!message.key) {
              response = { success: false, error: 'Missing key' };
            } else {
              await storage.set(message.key, message.value);
              response = { success: true, data: { key: message.key } };
            }
            break;
          case 'delete':
            if (!message.key) {
              response = { success: false, error: 'Missing key' };
            } else {
              const deleted = await storage.delete(message.key);
              response = { success: true, data: { key: message.key, deleted } };
            }
            break;
          case 'keys':
            const keys = await storage.keys();
            response = { success: true, data: { keys } };
            break;
          default:
            response = { success: false, error: `Unknown command: ${message.type}` };
        }

        session.send(Buffer.from(JSON.stringify(response)));
      } catch {
        session.send(Buffer.from(JSON.stringify({ success: false, error: 'Invalid message' })));
      }
    });
  }

  it('should respond to ping command', async () => {
    const client = new TestClient();
    await client.connect(TEST_PORT);

    const result = await client.send({ type: 'ping' });
    expect(result.success).toBe(true);
    expect(result.data).toHaveProperty('pong');

    client.close();
  });

  it('should set and get a value', async () => {
    const client = new TestClient();
    await client.connect(TEST_PORT);

    // Set
    const setResult = await client.send({ type: 'set', key: 'testKey', value: 'testValue' });
    expect(setResult.success).toBe(true);

    // Get
    const getResult = await client.send({ type: 'get', key: 'testKey' });
    expect(getResult.success).toBe(true);
    expect((getResult.data as any).value).toBe('testValue');

    client.close();
  });

  it('should store complex objects', async () => {
    const client = new TestClient();
    await client.connect(TEST_PORT);

    const complexValue = {
      name: 'test',
      numbers: [1, 2, 3],
      nested: { a: true, b: 'hello' }
    };

    await client.send({ type: 'set', key: 'complex', value: complexValue });
    const result = await client.send({ type: 'get', key: 'complex' });

    expect(result.success).toBe(true);
    expect((result.data as any).value).toEqual(complexValue);

    client.close();
  });

  it('should delete a key', async () => {
    const client = new TestClient();
    await client.connect(TEST_PORT);

    await client.send({ type: 'set', key: 'toDelete', value: 'delete me' });
    
    const deleteResult = await client.send({ type: 'delete', key: 'toDelete' });
    expect(deleteResult.success).toBe(true);
    expect((deleteResult.data as any).deleted).toBe(true);

    const getResult = await client.send({ type: 'get', key: 'toDelete' });
    expect((getResult.data as any).value).toBeUndefined();

    client.close();
  });

  it('should list all keys', async () => {
    const client = new TestClient();
    await client.connect(TEST_PORT);

    // Clear existing keys (by getting list and deleting each)
    const existingKeys = await client.send({ type: 'keys' });
    for (const key of (existingKeys.data as any).keys || []) {
      await client.send({ type: 'delete', key });
    }

    // Set some keys
    await client.send({ type: 'set', key: 'key1', value: 'v1' });
    await client.send({ type: 'set', key: 'key2', value: 'v2' });
    await client.send({ type: 'set', key: 'key3', value: 'v3' });

    const keysResult = await client.send({ type: 'keys' });
    expect(keysResult.success).toBe(true);
    const keys = (keysResult.data as any).keys;
    expect(keys).toContain('key1');
    expect(keys).toContain('key2');
    expect(keys).toContain('key3');

    client.close();
  });

  it('should handle unknown commands gracefully', async () => {
    const client = new TestClient();
    await client.connect(TEST_PORT);

    const result = await client.send({ type: 'unknown_command' });
    expect(result.success).toBe(false);
    expect(result.error).toContain('Unknown command');

    client.close();
  });

  it('should handle missing key parameter', async () => {
    const client = new TestClient();
    await client.connect(TEST_PORT);

    const getResult = await client.send({ type: 'get' });
    expect(getResult.success).toBe(false);
    expect(getResult.error).toBe('Missing key');

    const setResult = await client.send({ type: 'set', value: 'no key' });
    expect(setResult.success).toBe(false);
    expect(setResult.error).toBe('Missing key');

    client.close();
  });

  it('should support multiple concurrent clients', async () => {
    const client1 = new TestClient();
    const client2 = new TestClient();

    await client1.connect(TEST_PORT);
    await client2.connect(TEST_PORT);

    // Both clients write to the same storage
    await client1.send({ type: 'set', key: 'shared', value: 'from-client1' });
    
    // Client2 should see client1's data
    const result = await client2.send({ type: 'get', key: 'shared' });
    expect((result.data as any).value).toBe('from-client1');

    client1.close();
    client2.close();
  });
});
