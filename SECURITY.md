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


## Server Crash Recovery

### What happens when the TEE server crashes?

**Scenario 1: Pod restarts on the SAME physical CPU**
- AMD SEV-SNP `MSG_KEY_REQ` derives the same key (same chip + same code measurement)
- Encrypted data on the LUKS volume is still readable
- Users reconnect, re-attest, continue normally
- **No data loss.**

**Scenario 2: Pod restarts on a DIFFERENT physical CPU**
- Different chip = different VCEK = different derived key
- Data encrypted with the old chip's key is **unreadable**
- This is the "sealing problem"

**Solutions to the sealing problem:**

#### A. KBS Key Escrow (Recommended for k3s)
```
Pod boots on new CPU -> attests to KBS -> KBS recognizes valid code
-> KBS releases the SAME master key it gave the old pod
-> Data is readable again
```
The KBS stores keys indexed by code measurement, not by chip.
Any pod running the correct code gets the same key.
The KBS itself runs inside a TEE (turtles all the way down).

#### B. Client-Held Recovery Keys
```
User's device holds an encrypted backup of their data key.
New pod boots -> user re-attests -> user sends recovery key -> data restored.
```
No dependency on KBS. User has full sovereignty.
Downside: user loses device + recovery key = data gone forever.

#### C. Replicated TEEs (High Availability)
```
3 TEE pods on 3 different CPUs, all running same code.
Each derives different chip-bound keys.
State replicated via E2E encrypted raft consensus BETWEEN TEEs.
If one dies, the other two continue.
```
Most complex but most resilient. The TEEs trust each other
because they mutually attest (each verifies the other's quote).

### What about in-flight requests during crash?

- Noise protocol sessions are ephemeral — they die with the pod
- Clients detect broken connection, re-handshake with new pod
- Client re-attests the new pod (could be different hardware)
- Forward secrecy means the crashed pod's session keys are gone forever
  (even if someone captures the crash dump, past sessions are unreadable)

### What about data consistency?

- Write-ahead logging: flush to encrypted volume before acknowledging
- If crash mid-write: recovery on restart via WAL replay
- If using KBS: pod comes back, gets same key, replays WAL
- If using client keys: client re-sends after re-attestation

### Worst case: total infrastructure loss

If ALL pods die and KBS is gone:
- **With client-held keys:** Users can recover their data from encrypted backups
- **With KBS only:** Data is lost unless KBS has its own backup (which should also be in a TEE)
- **With multi-party custody:** Reconstruct from key shares held by independent parties

### Recommendation

Use **KBS (inside TEE) + client recovery keys** together:
- Normal operation: KBS handles key distribution across pod migrations
- Disaster recovery: users restore from their own recovery keys
- Belt and suspenders.


## Cross-Vendor Replication & KBS Persistence

### KBS Key Persistence Across Reboots

KBS stores keys in an encrypted backend (etcd/Postgres), NOT derived from hardware.
Keys are random bytes. Hardware attestation controls ACCESS, not generation.

```
KBS cluster (3 nodes, all in TEEs, cross-AZ)
  +-- etcd (encrypted at rest, replicated)
  +-- keys = random bytes, vendor-agnostic
  +-- survives any individual node reboot/failure
```

### Cross-Vendor Attestation (AMD + Intel)

KBS accepts attestation from multiple hardware vendors:

```
KBS validates:
  AMD workload -> verify SNP quote against AMD root CA -> release key
  Intel workload -> verify TDX quote against Intel root CA -> release SAME key
```

The key is not tied to any specific hardware. Any pod running the correct code
(matching measurements) on any supported TEE vendor gets the same key.

### Chip Death Recovery

Hardware-derived keys (MSG_KEY_REQ) die with the chip. Therefore:

**Rule: Never derive user data keys from hardware.**

```
BAD:  user_key = MSG_KEY_REQ(chip, measurement)  // chip dies = key dies
GOOD: user_key = KBS.get(measurement, user_id)    // chip dies = get from KBS
```

KBS is the key store. Hardware attestation is the access control.

### Replication Topology

```
          KBS-1 (AMD, us-east)
            |
     etcd replication (E2E encrypted)
            |
          KBS-2 (Intel, us-west)
            |
     etcd replication (E2E encrypted)
            |
          KBS-3 (AMD, eu-west)

Any KBS node can serve any workload.
Any workload can run on any vendor.
Any single node can die without data loss.
```

### Mutual TEE Attestation (TEE-to-TEE)

KBS nodes verify each other before replicating:
1. KBS-1 (AMD) gets SNP quote, sends to KBS-2 (Intel)
2. KBS-2 verifies SNP quote against AMD root CA
3. KBS-2 (Intel) gets TDX quote, sends to KBS-1
4. KBS-1 verifies TDX quote against Intel root CA
5. Mutually attested -> Diffie-Hellman -> shared channel -> replicate keys


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
