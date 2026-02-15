# groth16wrapper

A Groth16 (R1CS) outer circuit that verifies a gnark BN254 PlonK proof in-circuit.

This is the **core auditable circuit** of the Universal Groth16 project.

## What it does

Given a PlonK proof + verifying key + public inputs, the circuit:

1. Verifies the PlonK proof in-circuit using gnark's recursive PlonK verifier
2. Hashes all inner public inputs with MiMC and exposes the hash as `PublicInputsHash`
3. Hashes the full circuit-specific verifying key with MiMC and exposes the hash as `VkHash`

## Public inputs

The outer Groth16 proof has exactly **2 public inputs** (plus the implicit "one" wire):

| Public input | Description |
|---|---|
| `VkHash` | MiMC hash of the circuit-specific VK (Size, SizeInv, Generator, S[0..2], Ql, Qr, Qm, Qo, Qk) |
| `PublicInputsHash` | MiMC hash of the N inner public inputs |

## What is constant vs. witness

| Field | Role | What it binds |
|---|---|---|
| `BaseKey` | Constant (`gnark:"-"`) | KZG SRS, coset shift, number of public inputs |
| `CircuitKey` | Private witness | Selector commitments, domain size, generator |
| `Proof` | Private witness | The PlonK proof being verified |
| `InnerPublicInputs` | Private witness | The inner circuit's public inputs |
| `VkHash` | Public input | Commitment to the circuit-specific VK |
| `PublicInputsHash` | Public input | Commitment to the inner public inputs |

## Universality scope

The circuit verifies any PlonK proof that satisfies ALL of:

- Same curve (BN254)
- Same KZG SRS (baked into `BaseKey`)
- Same PlonK flavour and Fiat-Shamir transcript (gnark recursion-compatible MiMC)
- Same number of public inputs (fixed at compile time)
- 0 Bsb22 commitments (no `api.Commit` in the inner circuit)

Changing the inner circuit (different constraints, different VK) does NOT require a new Groth16 trusted setup -- only changing the SRS or the number of public inputs does.

## VkHash coverage

The VkHash binds every field of `CircuitVerifyingKey` that affects proof verification:

- `Size` (domain size, 256-bit big-endian)
- `SizeInv` (inverse of domain size, scalar marshal)
- `Generator` (root of unity, scalar marshal)
- `S[0], S[1], S[2]` (permutation polynomial commitments, G1 marshal)
- `Ql, Qr, Qm, Qo, Qk` (selector commitments, G1 marshal)

The `BaseVerifyingKey` fields are NOT hashed because they are baked into the circuit as constants and cannot differ between proofs verified by the same outer circuit.

## Constraint count

~1.33M R1CS constraints (BN254, 1 inner public input). Adding more inner public inputs increases constraints slightly.

## Native helpers

The test file exports `ComputeVkHash` and `ComputePublicInputsHash` -- native Go functions that compute the same hashes outside the circuit, for use by provers and verifiers.
