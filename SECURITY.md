# Security Model: Operator Exclusion

## Goal

The operator (you, the deployer) **cannot access user data**. Even with root on the host,
physical access to hardware, and control of the deployment pipeline.

## How It Works

### 1. Hardware Isolation (AMD SEV-SNP)

The CPU encrypts all VM memory with AES-128 keys stored in the AMD Secure Processor.
The hypervisor sees encrypted garbage. Debug interfaces are disabled. Core dumps show ciphertext.

The attestation report is signed by AMD hardware, not the operator. Anyone can verify
the signature chain back to AMD's published root certificates.

### 2. No External Keys

Keys are **derived inside the TEE** using AMD's `MSG_KEY_REQ`:

```
root_key = HKDF(
    VCEK (chip-unique key from AMD Secure Processor) +
    MEASUREMENT (hash of running code) +
    REPORT_DATA (user-provided nonce)
)
```

Properties:
- Only recreatable by the **same code** on the **same physical CPU**
- Operator never possesses these keys
- Different code = different measurement = different key (can't backdoor)

### 3. Client-Side Verification (No Server Trust)

```
Client                                TEE
  |                                    |
  |--- Noise NK Handshake ----------->|
  |                                    |
  |<-- Response + Attestation Quote ---|
  |                                    |
  | 1. Verify quote signature          |
  |    (AMD root CA -> VCEK -> quote)  |
  |                                    |
  | 2. Extract measurements            |
  |    (hash of running code)          |
  |                                    |
  | 3. Check transparency log          |
  |    (Rekor: does this hash match    |
  |     a known reproducible build?)   |
  |                                    |
  | 4. Complete handshake ONLY if      |
  |    all checks pass                 |
  |                                    |
  |=== Encrypted session ==============|
```

The client trusts AMD hardware + the transparency log. NOT the operator.

### 4. Reproducible Builds (Anyone Can Verify)

```bash
# Anyone can clone, build, and get the exact same binary hash
git clone https://github.com/ex3ndr-bot/secure-perimeter
nix build .#workload
sha256sum result  # Must match what's in the transparency log
```

If the operator publishes code that doesn't match what's running, the attestation
quote measurements won't match the transparency log entry, and clients will reject.

### 5. Transparency Log (Append-Only, Publicly Auditable)

Every build is signed (Cosign/Sigstore keyless) and logged to Rekor:
- Append-only (can't delete or modify entries)
- Merkle tree proofs (efficient verification)
- Witness networks (independent parties cosign checkpoints)
- Anyone can audit the full history

### 6. Per-User Key Isolation

```
TEE-derived root key (from MSG_KEY_REQ)
    |
    +-> HKDF("user:" + user_id) -> User Data Key
    |       +-> AES-256-GCM encrypt user state
    |
    +-> HKDF("session:" + session_id) -> Session Key
            +-> Ephemeral, forward-secret
```

Even within a single TEE instance, each user's data is encrypted with a
cryptographically independent key. Compromising one user's session reveals
nothing about another user's data.

## What the Operator Can See

| Data | Operator Access |
|------|----------------|
| User plaintext data | ❌ Never |
| Encryption keys | ❌ Never (derived in TEE) |
| Network traffic content | ❌ Encrypted (Noise) |
| Which users connect | ⚠️ IP addresses visible unless Tor/VPN |
| Traffic volume/timing | ⚠️ Metadata visible |
| What code is deployed | ✅ (it's open source + reproducible) |

## What the Operator Cannot Do

| Attack | Why It Fails |
|--------|-------------|
| Read memory from host | SEV-SNP encrypts, hypervisor sees garbage |
| Deploy backdoored code | Measurements won't match transparency log |
| Intercept connections | Noise handshake bound to attested identity |
| Extract keys from TEE | Keys derived from hardware, never exported |
| Modify transparency log | Merkle proofs + witnesses detect tampering |
| MITM between client and TEE | Client verifies attestation before completing handshake |
| Swap the TEE VM with a fake | Attestation quote won't have valid AMD signature |

## The Irreducible Trust

You must still trust:
1. **AMD** didn't backdoor the Secure Processor
2. **Cryptographic algorithms** (AES, ECDSA, SHA) are sound
3. **Your own code** doesn't have vulnerabilities (but it's auditable)
4. **The client device** isn't compromised

## Verifier Deployment

The verifier runs **on the client device** (phone/browser). Not on a server.

Components:
- AMD root CA certificates (bundled in app, published by AMD)
- Rekor client (queries public transparency log at sigstore.dev)
- Attestation quote parser (AMD SEV-SNP report format)
- Noise Protocol library

No server-side verification service is needed. The entire trust chain
terminates at the client.

## Key Management Options

### Option A: TEE-Derived Keys (Recommended)
- Use `MSG_KEY_REQ` inside SEV-SNP guest
- Keys bound to code measurement + chip identity
- Zero external key management
- ⚠️ If code changes, key changes (must handle migration)

### Option B: Client-Owned Keys
- User's device generates and holds the master key
- Key sent to TEE only after attestation verification
- TEE processes data in memory, never persists key
- Maximum user control, but user must manage recovery

### Option C: Multi-Party Key Custody
- Shamir's Secret Sharing: 2-of-3 key holders
- No single party (including operator) can reconstruct
- Good for enterprise deployments

### Recommended: Option A + Option B Hybrid
- TEE derives a pod key for infrastructure operations
- User provides their own key for their personal data
- Both keys required to decrypt: `final_key = HKDF(tee_key + user_key)`
- Neither party alone can access data
