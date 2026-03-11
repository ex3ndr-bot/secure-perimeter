# Secure Perimeter

Minimal infrastructure for running attested workloads with verifiable supply chain, 
designed for web and mobile clients that need to verify they're talking to genuine, 
unmodified code.

## Design Goals

1. **Minimal** — fewest possible moving parts, all off-the-shelf
2. **Verifiable** — every build is signed, logged, and reproducible
3. **Attested** — clients verify they're talking to real TEE hardware running expected code
4. **Stateful** — encrypted persistent storage, keys released only after attestation
5. **Updatable** — ship new code without exposing or losing data

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        BUILD (CI)                            │
│                                                              │
│  Source → Nix Build → Container Image → Cosign Sign          │
│                            │                                 │
│                            ▼                                 │
│                   Rekor Transparency Log                     │
│                   (digest + signature + measurements)        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      DEPLOY (k3s)                            │
│                                                              │
│  Kyverno admission → verify Cosign signature against Rekor   │
│         │                                                    │
│         ▼                                                    │
│  Kata Containers → Confidential VM (AMD SEV-SNP)            │
│         │                                                    │
│         ▼                                                    │
│  dm-verity root FS → hardware attestation quote generated    │
│         │                                                    │
│         ▼                                                    │
│  KBS releases LUKS key → encrypted volume mounted            │
│         │                                                    │
│         ▼                                                    │
│  Workload running with attested identity                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    VERIFY (Client)                            │
│                                                              │
│  Client → Noise handshake → server embeds attestation quote  │
│         → verify quote signature (AMD/Intel root CA)         │
│         → compare measurements to transparency log           │
│         → encrypted session with forward secrecy             │
└─────────────────────────────────────────────────────────────┘
```

## Components

| Component | Tool | Purpose |
|-----------|------|---------|
| Build system | Nix | Reproducible, deterministic builds |
| Container signing | Cosign (keyless via Fulcio) | Sign container images with OIDC identity |
| Transparency log | Rekor | Append-only log of signatures + measurements |
| Orchestrator | k3s | Lightweight Kubernetes |
| Admission | Kyverno | Enforce signature policy before pod admission |
| Runtime isolation | Kata Containers | VM-per-pod with TEE support |
| TEE | AMD SEV-SNP | Hardware-level memory encryption + attestation |
| Filesystem integrity | dm-verity | Immutable root filesystem with hash tree |
| Key management | KBS (Trustee) | Release secrets only to attested workloads |
| Storage encryption | LUKS CSI | Encrypted persistent volumes |
| Client protocol | Noise Protocol (Pipes) | Encrypted channels with embedded attestation |

## Project Structure

```
secure-perimeter/
├── README.md                      # This file
├── ARCHITECTURE.md                # Detailed architecture doc
├── nix/                           # Nix build system
│   ├── flake.nix                  # Nix flake for reproducible builds
│   ├── flake.lock
│   └── default.nix
├── images/                        # Container image definitions
│   └── workload/
│       ├── Dockerfile
│       └── dm-verity.conf
├── deploy/                        # k3s deployment manifests
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── kyverno-policy.yaml        # Signature verification policy
│   ├── kata-runtime-class.yaml    # RuntimeClass for confidential VMs
│   ├── workload.yaml              # Pod/Deployment spec
│   └── pvc-encrypted.yaml         # LUKS-encrypted PVC
├── attestation/                   # Attestation infrastructure
│   ├── kbs/                       # Key Broker Service config
│   │   ├── kbs-config.yaml
│   │   └── reference-values.yaml  # Expected measurements
│   └── transparency/
│       └── publish.sh             # Script to publish measurements to Rekor
├── server/                        # Server-side workload code
│   ├── src/
│   │   ├── main.ts                # Entry point
│   │   ├── noise.ts               # Noise Protocol server with attestation
│   │   ├── attestation.ts         # Read TEE quote, embed in handshake
│   │   └── storage.ts             # Encrypted state management
│   ├── package.json
│   └── tsconfig.json
├── client/                        # Client verification libraries
│   ├── web/
│   │   ├── src/
│   │   │   ├── index.ts           # Web client entry
│   │   │   ├── noise-client.ts    # Noise Protocol client
│   │   │   ├── verify.ts          # Attestation quote verification
│   │   │   └── transparency.ts    # Query Rekor for measurements
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── mobile/
│       ├── ios/
│       │   └── SecurePerimeter/
│       │       ├── NoiseClient.swift
│       │       └── AttestationVerifier.swift
│       └── android/
│           └── src/
│               └── SecurePerimeter.kt
├── ci/                            # CI/CD pipelines
│   └── .github/
│       └── workflows/
│           ├── build-sign.yml     # Build + Cosign + Rekor
│           └── deploy.yml         # Deploy to k3s
└── scripts/                       # Helper scripts
    ├── setup-k3s.sh               # k3s + kata + kyverno setup
    ├── setup-kbs.sh               # KBS deployment
    └── verify-local.sh            # Local attestation verification test
```

## Attestation Flow

### Build Time
1. Nix builds container image (deterministic hash)
2. GitHub Actions signs with Cosign (keyless via Fulcio OIDC)
3. Signature + image digest + expected measurements published to Rekor
4. SLSA provenance attached to the build

### Deploy Time
1. Image pushed to registry with Cosign signature
2. k3s admission (Kyverno) verifies signature against Rekor before allowing pod
3. Kata creates confidential VM (AMD SEV-SNP)
4. dm-verity locks root filesystem
5. Hardware generates attestation quote (CPU-signed)
6. Workload sends quote to KBS → KBS validates → releases LUKS key
7. Encrypted volume mounted, workload starts

### Runtime (Client Connection)
1. Client initiates Noise Pipes handshake
2. Server embeds attestation quote in handshake response
3. Client verifies:
   - Quote signature against AMD/Intel root certificate
   - Measurements match known-good values from Rekor
   - Public key is bound to the quote
4. Forward-secret encrypted session established

### Update Flow
1. New code merged → CI builds new image
2. Cosign signs → Rekor logs new measurements
3. Deploy new version to k3s
4. KBS reference values updated for new measurements
5. New pods attest with new measurements → get LUKS keys
6. Old pods drain → encrypted state accessible to new code (same LUKS key)
7. Clients verify new measurements from transparency log

## Stateful Storage

Encrypted persistent volumes using LUKS:
- Keys managed by KBS (Trustee) 
- Keys released ONLY after TEE attestation succeeds
- Key rotation supported (re-encrypt with new key)
- Data survives code updates (KBS releases key to new valid measurements)
- Host/orchestrator never sees plaintext keys

## Client Libraries

### Web (TypeScript)
- `@stablelib/noise` or `noise-protocol` for Noise handshake
- Custom attestation quote parser (AMD SEV-SNP report format)
- Rekor client for fetching expected measurements
- AMD/Intel root CA certificates bundled in app

### iOS (Swift)
- `NoiseSockets` for Noise Protocol
- Custom `AttestationVerifier` for TEE quote validation
- Keychain for storing verified session keys

### Android (Kotlin)
- `noise-java` for Noise Protocol
- Custom attestation verification
- Android Keystore for session keys



## Per-Pod Encryption (Key Isolation)

**Critical invariant: no shared encryption keys between users.**

Each pod gets its own encryption key hierarchy. Users' data is cryptographically isolated
even if pods share the same physical volume or the same TEE.

### Key Derivation Hierarchy

```
KBS Master Secret (released after attestation)
    |
    +-> HKDF(master, "pod:" + pod_id) -> Pod Root Key
    |       |
    |       +-> HKDF(pod_root, "user:" + user_id) -> User Data Key
    |       |       +-> Encrypts user's state (AES-256-GCM)
    |       |
    |       +-> HKDF(pod_root, "session:" + session_id) -> Session Key
    |               +-> Ephemeral, forward-secret per-connection
    |
    +-> Each pod attestation gets a UNIQUE master secret from KBS
        (KBS tracks which pod_id received which key)
```

### How It Works

1. **Pod boots** -> TEE generates attestation quote with unique pod identity
2. **Pod attests to KBS** -> KBS validates, generates unique master secret for this pod
3. **User connects** -> after Noise handshake, user provides user_id
4. **Key derivation** -> HKDF derives user-specific data key from pod master + user_id
5. **Storage** -> each user's data encrypted with their own derived key
6. **Key never shared** -> different pods get different masters; different users get different derived keys

### Implementation

```typescript
// Key derivation (HKDF-SHA256)
const podRootKey = hkdf(masterSecret, "pod:" + podId);
const userDataKey = hkdf(podRootKey, "user:" + userId);
const encrypted = aes256gcm.encrypt(userDataKey, plaintext);
```

### Properties
- **Pod isolation**: Each pod gets a unique master from KBS
- **User isolation**: HKDF ensures user keys are cryptographically independent
- **Forward secrecy**: Session keys are ephemeral
- **Key rotation**: KBS can issue new masters; pods re-derive user keys
- **No shared state**: Even if two pods serve the same user, they derive independently

## Quick Start

```bash
# 1. Setup k3s with Kata + Kyverno
./scripts/setup-k3s.sh

# 2. Setup KBS
./scripts/setup-kbs.sh

# 3. Build and sign
nix build .#workload
cosign sign --yes ghcr.io/yourorg/workload@sha256:...

# 4. Deploy
kubectl apply -k deploy/

# 5. Verify from client
cd client/web && npm run verify
```
