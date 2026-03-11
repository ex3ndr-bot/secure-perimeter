#!/usr/bin/env npx tsx
/**
 * End-to-End Test Script
 * 
 * Tests the complete flow:
 * 1. Start server in mock attestation mode
 * 2. Connect with client
 * 3. Perform Noise handshake
 * 4. Send encrypted commands
 * 5. Verify responses
 * 6. Clean exit
 */

import { spawn, ChildProcess } from 'child_process';
import { createConnection, Socket } from 'net';
import { mkdir, rm } from 'fs/promises';
// @ts-expect-error - noise-handshake doesn't have types
import Noise from 'noise-handshake';
// @ts-expect-error
import Cipher from 'noise-handshake/cipher.js';

const TEST_PORT = 49443;
const TEST_DATA_DIR = '/tmp/sp-e2e-test';
const TIMEOUT_MS = 30000;

// Test results
interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
}

const results: TestResult[] = [];

function log(msg: string): void {
  console.log(`[E2E] ${msg}`);
}

function pass(name: string): void {
  results.push({ name, passed: true });
  console.log(`  ✓ ${name}`);
}

function fail(name: string, error: string): void {
  results.push({ name, passed: false, error });
  console.log(`  ✗ ${name}: ${error}`);
}

async function startServer(): Promise<ChildProcess> {
  log('Starting server...');
  
  await mkdir(TEST_DATA_DIR, { recursive: true });
  
  const server = spawn('node', ['dist/main.js'], {
    cwd: '/home/developer/secure-perimeter/server',
    env: {
      ...process.env,
      NOISE_PORT: String(TEST_PORT),
      ATTESTATION_ENABLED: 'false',
      DATA_DIR: TEST_DATA_DIR
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  // Wait for server to be ready
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Server start timeout')), 10000);
    
    server.stdout!.on('data', (data: Buffer) => {
      const text = data.toString();
      if (text.includes('Server ready')) {
        clearTimeout(timeout);
        resolve();
      }
    });
    
    server.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });

  log('Server started');
  return server;
}

async function connectAndHandshake(): Promise<{
  socket: Socket;
  sendCipher: typeof Cipher;
  recvCipher: typeof Cipher;
}> {
  log('Connecting to server...');
  
  const socket = createConnection({ port: TEST_PORT, host: '127.0.0.1' });
  
  await new Promise<void>((resolve, reject) => {
    socket.on('connect', resolve);
    socket.on('error', reject);
  });

  // Noise XX handshake
  const noise = new Noise('XX', true);
  noise.initialise(Buffer.alloc(0));

  // -> e
  socket.write(Buffer.from(noise.send()));

  // <- e, ee, s, es
  const reply = await new Promise<Buffer>((resolve) => {
    socket.once('data', resolve);
  });
  noise.recv(reply);

  // -> s, se
  socket.write(Buffer.from(noise.send()));

  if (!noise.complete) {
    throw new Error('Handshake failed');
  }

  log('Handshake complete');
  
  return {
    socket,
    sendCipher: new Cipher(noise.tx),
    recvCipher: new Cipher(noise.rx)
  };
}

async function sendCommand(
  socket: Socket,
  sendCipher: typeof Cipher,
  recvCipher: typeof Cipher,
  command: object
): Promise<{ success: boolean; data?: unknown; error?: string }> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Command timeout')), 5000);
    
    let buffer = Buffer.alloc(0);
    
    const handler = (data: Buffer) => {
      buffer = Buffer.concat([buffer, data]);
      
      if (buffer.length >= 4) {
        const len = buffer.readUInt32BE(0);
        if (buffer.length >= 4 + len) {
          clearTimeout(timeout);
          socket.off('data', handler);
          
          const encrypted = buffer.subarray(4, 4 + len);
          const decrypted = recvCipher.decrypt(encrypted);
          const response = JSON.parse(Buffer.from(decrypted).toString('utf-8'));
          resolve(response);
        }
      }
    };
    
    socket.on('data', handler);
    
    // Send encrypted command
    const text = JSON.stringify(command);
    const encrypted = sendCipher.encrypt(Buffer.from(text));
    const frame = Buffer.alloc(4 + encrypted.length);
    frame.writeUInt32BE(encrypted.length, 0);
    Buffer.from(encrypted).copy(frame, 4);
    socket.write(frame);
  });
}

async function runTests(): Promise<void> {
  let server: ChildProcess | null = null;
  let socket: Socket | null = null;
  let sendCipher: typeof Cipher | null = null;
  let recvCipher: typeof Cipher | null = null;

  try {
    // Clean up from previous runs
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}

    // Start server
    server = await startServer();
    pass('Server starts in mock attestation mode');

    // Connect and handshake
    const conn = await connectAndHandshake();
    socket = conn.socket;
    sendCipher = conn.sendCipher;
    recvCipher = conn.recvCipher;
    pass('Client connects and completes Noise handshake');

    // Test: ping
    const pingResult = await sendCommand(socket, sendCipher, recvCipher, { type: 'ping' });
    if (pingResult.success && typeof (pingResult.data as any)?.pong === 'number') {
      pass('Ping command returns pong timestamp');
    } else {
      fail('Ping command', JSON.stringify(pingResult));
    }

    // Test: set
    const setResult = await sendCommand(socket, sendCipher, recvCipher, {
      type: 'set',
      key: 'test-key',
      value: { message: 'hello world', count: 42 }
    });
    if (setResult.success) {
      pass('Set command stores data');
    } else {
      fail('Set command', setResult.error || 'Unknown error');
    }

    // Test: get
    const getResult = await sendCommand(socket, sendCipher, recvCipher, {
      type: 'get',
      key: 'test-key'
    });
    const value = (getResult.data as any)?.value;
    if (getResult.success && value?.message === 'hello world' && value?.count === 42) {
      pass('Get command retrieves stored data');
    } else {
      fail('Get command', JSON.stringify(getResult));
    }

    // Test: keys
    const keysResult = await sendCommand(socket, sendCipher, recvCipher, { type: 'keys' });
    const keys = (keysResult.data as any)?.keys;
    if (keysResult.success && Array.isArray(keys) && keys.includes('test-key')) {
      pass('Keys command lists stored keys');
    } else {
      fail('Keys command', JSON.stringify(keysResult));
    }

    // Test: delete
    const deleteResult = await sendCommand(socket, sendCipher, recvCipher, {
      type: 'delete',
      key: 'test-key'
    });
    if (deleteResult.success && (deleteResult.data as any)?.deleted === true) {
      pass('Delete command removes data');
    } else {
      fail('Delete command', JSON.stringify(deleteResult));
    }

    // Verify deletion
    const getAfterDelete = await sendCommand(socket, sendCipher, recvCipher, {
      type: 'get',
      key: 'test-key'
    });
    if (getAfterDelete.success && (getAfterDelete.data as any)?.value === undefined) {
      pass('Deleted data is no longer accessible');
    } else {
      fail('Delete verification', JSON.stringify(getAfterDelete));
    }

    // Test: status
    const statusResult = await sendCommand(socket, sendCipher, recvCipher, { type: 'status' });
    const status = statusResult.data as any;
    if (statusResult.success && (status?.attestationType === 'mock' || status?.attestationType === 'none')) {
      pass('Status command returns attestation info');
    } else {
      fail('Status command', JSON.stringify(statusResult));
    }

  } catch (err) {
    fail('Test execution', (err as Error).message);
  } finally {
    // Cleanup
    if (socket) {
      socket.destroy();
    }
    if (server) {
      server.kill('SIGTERM');
    }
    try {
      await rm(TEST_DATA_DIR, { recursive: true });
    } catch {}
  }
}

async function main(): Promise<void> {
  console.log('');
  console.log('='.repeat(60));
  console.log('Secure Perimeter End-to-End Tests');
  console.log('='.repeat(60));
  console.log('');

  const startTime = Date.now();
  
  try {
    await Promise.race([
      runTests(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Global timeout')), TIMEOUT_MS)
      )
    ]);
  } catch (err) {
    fail('Global', (err as Error).message);
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log('');
  console.log('='.repeat(60));
  
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;
  
  console.log(`Results: ${passed} passed, ${failed} failed (${duration}s)`);
  
  if (failed > 0) {
    console.log('');
    console.log('Failed tests:');
    for (const r of results.filter(r => !r.passed)) {
      console.log(`  - ${r.name}: ${r.error}`);
    }
  }
  
  console.log('='.repeat(60));
  console.log('');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});