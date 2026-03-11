/**
 * Secure Perimeter Client - Entry Point
 * 
 * Demonstrates connecting to a secure perimeter server,
 * verifying attestation, and establishing an encrypted channel.
 */

import { createNoiseClient, NoiseSession, NoiseClientOptions } from './noise-client.js';
import { verifyAttestation, bytesToHex, hexToBytes, ExpectedMeasurements } from './verify.js';
import { fetchExpectedMeasurements, getRekorTreeState } from './transparency.js';

// Re-export all public APIs
export { createNoiseClient, NoiseSession, NoiseClientOptions } from './noise-client.js';
export { 
  verifyAttestation, 
  bytesToHex, 
  hexToBytes,
  detectAttestationType,
  parseSNPReport,
  parseTDXReport,
  ExpectedMeasurements,
  VerificationResult,
  ParsedSNPReport,
  ParsedTDXReport
} from './verify.js';
export { 
  fetchExpectedMeasurements, 
  getRekorTreeState,
  verifyInclusionProof,
  Measurements
} from './transparency.js';

/**
 * Demo: Connect to server and verify attestation
 */
async function demo() {
  console.log('Secure Perimeter Client Demo\n');
  
  // Configuration
  const serverHost = process.env.SERVER_HOST || 'localhost';
  const serverPort = parseInt(process.env.SERVER_PORT || '9000', 10);
  const imageDigest = process.env.IMAGE_DIGEST;
  const skipAttestation = process.env.SKIP_ATTESTATION === 'true';
  
  console.log(`Configuration:`);
  console.log(`  Server: ${serverHost}:${serverPort}`);
  console.log(`  Image digest: ${imageDigest || '(not set)'}`);
  console.log(`  Skip attestation: ${skipAttestation}`);
  console.log('');
  
  // Check Rekor connectivity
  console.log('Checking Rekor transparency log...');
  try {
    const treeState = await getRekorTreeState();
    console.log(`  Tree size: ${treeState.treeSize} entries`);
    console.log(`  Root hash: ${treeState.rootHash.substring(0, 32)}...`);
  } catch (e) {
    console.warn(`  Warning: Could not reach Rekor: ${e}`);
  }
  console.log('');
  
  // Fetch measurements if image digest provided
  let expectedMeasurements: ExpectedMeasurements | undefined;
  
  if (imageDigest) {
    console.log('Fetching expected measurements from Rekor...');
    try {
      const measurements = await fetchExpectedMeasurements(imageDigest);
      if (measurements) {
        console.log(`  Found measurements (log index: ${measurements.logIndex})`);
        if (measurements.snpMeasurement) {
          console.log(`  SNP measurement: ${measurements.snpMeasurement.substring(0, 32)}...`);
        }
        if (measurements.tdxMrTd) {
          console.log(`  TDX MRTD: ${measurements.tdxMrTd.substring(0, 32)}...`);
        }
        
        expectedMeasurements = {
          snpMeasurement: measurements.snpMeasurement 
            ? hexToBytes(measurements.snpMeasurement)
            : undefined,
          tdxMrTd: measurements.tdxMrTd
            ? hexToBytes(measurements.tdxMrTd)
            : undefined,
          tdxRtmr0: measurements.tdxRtmr0
            ? hexToBytes(measurements.tdxRtmr0)
            : undefined
        };
      } else {
        console.log('  No measurements found for image');
      }
    } catch (e) {
      console.warn(`  Warning: Could not fetch measurements: ${e}`);
    }
    console.log('');
  }
  
  // Connect to server
  console.log(`Connecting to server at ${serverHost}:${serverPort}...`);
  
  try {
    const options: NoiseClientOptions = {
      host: serverHost,
      port: serverPort,
      useTls: false,  // Use plain TCP for demo (TLS adds another layer)
      skipAttestation: skipAttestation,
      expectedMeasurements,
      timeoutMs: 10000
    };
    
    const session = await createNoiseClient(options);
    
    console.log('\nConnected successfully!');
    console.log(`  Remote public key: ${bytesToHex(session.remotePublicKey).substring(0, 32)}...`);
    console.log(`  Handshake hash: ${bytesToHex(session.handshakeHash).substring(0, 32)}...`);
    console.log('');
    
    // Report attestation status
    console.log('Attestation Status:');
    console.log(`  Valid: ${session.attestation.valid}`);
    console.log(`  Type: ${session.attestation.attestationType}`);
    
    if (session.attestation.errors.length > 0) {
      console.log('  Errors:');
      for (const error of session.attestation.errors) {
        console.log(`    - ${error}`);
      }
    }
    
    if (session.attestation.warnings.length > 0) {
      console.log('  Warnings:');
      for (const warning of session.attestation.warnings) {
        console.log(`    - ${warning}`);
      }
    }
    console.log('');
    
    // Set up message handler
    session.onData((data) => {
      const text = new TextDecoder().decode(data);
      console.log(`Received: ${text}`);
    });
    
    // Send test message
    const testMessage = 'Hello from secure client!';
    console.log(`Sending: ${testMessage}`);
    session.send(new TextEncoder().encode(testMessage));
    
    // Wait a bit for response then close
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    console.log('\nClosing session...');
    session.close();
    console.log('Demo complete.');
    
  } catch (e) {
    console.error(`\nConnection failed: ${e}`);
    process.exit(1);
  }
}

// Run demo if this is the main module
const isMainModule = import.meta.url.endsWith(process.argv[1]?.replace(/^file:\/\//, '') || '');
if (isMainModule || process.argv[1]?.includes('index')) {
  demo().catch(console.error);
}
