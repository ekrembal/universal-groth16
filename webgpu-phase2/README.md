# WebGPU Phase 2 Trusted Setup Ceremony

## Goal

Implement **Groth16 Phase 2 Trusted Setup Ceremony (TSC)** in the browser using WebGPU for acceleration. This enables a decentralized, web-based ceremony where participants contribute to the circuit-specific trusted setup from their browser—no native binary required.

## Context

- **Phase 1** (Powers of Tau): Pre-computed once, outside the browser. Participants receive the Phase 1 SRS.
- **Phase 2** (Circuit-specific): Each participant downloads the previous contribution, runs `Contribute()` in the browser, and uploads their updated contribution.

## Target Circuit

- **~1.6M R1CS constraints** (outer Groth16 PlonK verifier)
- **Curve**: BN254 (same as gnark's default)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser                                                         │
│  ┌─────────────┐  ┌──────────────────┐  ┌─────────────────────┐  │
│  │ Download    │  │ WebGPU Phase 2   │  │ Upload              │  │
│  │ prev contrib│→ │ Contribute()     │→ │ new contribution    │  │
│  └─────────────┘  └──────────────────┘  └─────────────────────┘  │
│                           │                                       │
│                           ▼                                       │
│                   ┌───────────────┐                                │
│                   │ BN254 crypto  │  ← WGSL compute shaders        │
│                   │ (G1 scalar   │                                │
│                   │  mul batch)   │                                │
│                   └───────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

## Deliverables

1. **BN254 via [demox-labs/webgpu-crypto](https://github.com/demox-labs/webgpu-crypto)** — Field math, curve ops, batch scalar mul (see [PRIMITIVES.md](./PRIMITIVES.md))
2. **Phase 2 Contribute** pipeline: load → update → serialize (with batching for WebGPU buffer limits)
3. **Outer TypeScript** — `scaleG1SliceBatched`, endian binding, Phase 2 orchestration (see [PLAN.md](./PLAN.md))
4. **Test harness** reusing gnark test vectors
5. **Web app** integration (auth, waitlist, download/upload)

## Test Vectors

Generate test vectors from gnark (run from repo root):

```bash
go run ./webgpu-phase2/cmd/generate-testvectors
```

Output: `webgpu-phase2/testvectors/phase2_vectors.json`

## References

- **webgpu-crypto**: [demox-labs/webgpu-crypto](https://github.com/demox-labs/webgpu-crypto) — BN254, MSM, NTT
- gnark Phase 2: `backend/groth16/bn254/mpcsetup/phase2.go`
- BN254 curve: [EIP-197](https://eips.ethereum.org/EIPS/eip-197), [gnark-crypto/ecc/bn254](https://github.com/Consensys/gnark-crypto/tree/master/ecc/bn254)
- Groth16 MPC: [BGM17](https://eprint.iacr.org/2017/1050.pdf)
