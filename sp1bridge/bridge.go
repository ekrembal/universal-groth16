// Package sp1bridge provides utilities for integrating SP1's gnark PlonK proofs
// with the universal PlonK-in-Groth16 verifier wrapper.
//
// SP1 (https://github.com/succinctlabs/sp1) compiles its recursive verification
// circuit into a gnark constraint system (SCS) and generates PlonK proofs on BN254.
//
// # SP1 Circuit Structure
//
//   - 2 public inputs: VkeyHash, CommittedValuesDigest
//   - Private witnesses: Vars (BN254 field elements), Felts (BabyBear), Exts (BabyBear extensions)
//   - Constraint opcodes read from a JSON file at compile time
//   - Uses Poseidon2 hash internally (both BN254 and BabyBear variants)
//
// # Key Integration Requirement
//
// SP1's default PlonK proofs use gnark's standard Fiat-Shamir transcript (SHA256-based).
// For recursive verification inside another gnark circuit, proofs MUST be generated with
// recursion-compatible options (MiMC-based transcript). This package provides utilities
// to re-prove SP1 circuits with the correct options.
//
// # Usage
//
//  1. Run SP1's compilation pipeline to get the constraint system (.bin) and witness (.json)
//  2. Use LoadSCS() to load SP1's compiled constraint system
//  3. Use ProvePlonkRecursive() to generate a recursion-compatible PlonK proof
//  4. Feed the proof + VK into PlonkVerifierGroth16Circuit
package sp1bridge

import (
	"bufio"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/recursion"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
)

// SP1PublicInputs holds the two public inputs from an SP1 proof.
type SP1PublicInputs struct {
	VkeyHash              *big.Int
	CommittedValuesDigest *big.Int
}

// SP1RecursiveProof holds everything needed to feed an SP1 proof into the
// universal PlonK-in-Groth16 wrapper.
type SP1RecursiveProof struct {
	ConstraintSystem constraint.ConstraintSystem
	VerifyingKey     plonk.VerifyingKey
	Proof            plonk.Proof
	PublicWitness    witness.Witness
	PublicInputs     SP1PublicInputs
}

// LoadSCS loads an SP1-compiled gnark constraint system from a binary file.
// The file is produced by SP1's BuildPlonk() and written via scs.WriteTo().
func LoadSCS(path string) (constraint.ConstraintSystem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open SCS file: %w", err)
	}
	defer f.Close()

	cs := plonk.NewCS(ecc.BN254)
	_, err = cs.ReadFrom(bufio.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("read SCS: %w", err)
	}
	return cs, nil
}

// LoadKeys loads PlonK proving and verifying keys from binary files.
func LoadKeys(pkPath, vkPath string) (plonk.ProvingKey, plonk.VerifyingKey, error) {
	pk := plonk.NewProvingKey(ecc.BN254)
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open PK file: %w", err)
	}
	defer pkFile.Close()
	if _, err := pk.UnsafeReadFrom(bufio.NewReaderSize(pkFile, 1024*1024)); err != nil {
		return nil, nil, fmt.Errorf("read PK: %w", err)
	}

	vk := plonk.NewVerifyingKey(ecc.BN254)
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open VK file: %w", err)
	}
	defer vkFile.Close()
	if _, err := vk.ReadFrom(vkFile); err != nil {
		return nil, nil, fmt.Errorf("read VK: %w", err)
	}

	return pk, vk, nil
}

// LoadSRS loads a KZG SRS from binary files (e.g., Aztec Ignition ceremony output).
func LoadSRS(srsPath, srsLagrangePath string) (kzg.SRS, kzg.SRS, error) {
	srsObj := kzg.NewSRS(ecc.BN254)
	srsFile, err := os.Open(srsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open SRS file: %w", err)
	}
	defer srsFile.Close()
	if _, err := srsObj.ReadFrom(srsFile); err != nil {
		return nil, nil, fmt.Errorf("read SRS: %w", err)
	}

	srsLagrangeObj := kzg.NewSRS(ecc.BN254)
	lagFile, err := os.Open(srsLagrangePath)
	if err != nil {
		return nil, nil, fmt.Errorf("open SRS Lagrange file: %w", err)
	}
	defer lagFile.Close()
	if _, err := srsLagrangeObj.ReadFrom(lagFile); err != nil {
		return nil, nil, fmt.Errorf("read SRS Lagrange: %w", err)
	}

	return srsObj, srsLagrangeObj, nil
}

// ProvePlonkRecursive generates a PlonK proof with recursion-compatible options
// (MiMC-based Fiat-Shamir transcript) so the proof can be verified inside another
// gnark circuit.
//
// This is the key difference from SP1's default ProvePlonk(): the prover and
// verifier options use GetNativeProverOptions/GetNativeVerifierOptions.
func ProvePlonkRecursive(
	cs constraint.ConstraintSystem,
	pk plonk.ProvingKey,
	vk plonk.VerifyingKey,
	fullWitness witness.Witness,
) (*SP1RecursiveProof, error) {
	field := ecc.BN254.ScalarField()

	// Prove with recursion-compatible MiMC transcript.
	proof, err := plonk.Prove(cs, pk, fullWitness,
		recursion_plonk.GetNativeProverOptions(field, field))
	if err != nil {
		return nil, fmt.Errorf("prove (recursive): %w", err)
	}

	// Verify natively to catch errors early.
	pubWitness, err := fullWitness.Public()
	if err != nil {
		return nil, fmt.Errorf("extract public witness: %w", err)
	}

	err = plonk.Verify(proof, vk, pubWitness,
		recursion_plonk.GetNativeVerifierOptions(field, field))
	if err != nil {
		return nil, fmt.Errorf("verify (recursive): %w", err)
	}

	// Extract SP1 public inputs (VkeyHash + CommittedValuesDigest).
	pubInputs, err := ExtractSP1PublicInputs(pubWitness)
	if err != nil {
		return nil, fmt.Errorf("extract public inputs: %w", err)
	}

	return &SP1RecursiveProof{
		ConstraintSystem: cs,
		VerifyingKey:     vk,
		Proof:            proof,
		PublicWitness:    pubWitness,
		PublicInputs:     *pubInputs,
	}, nil
}

// SetupAndProveRecursive compiles the circuit, sets up keys, and proves with
// recursion-compatible options. This is a convenience function for when you
// have the circuit definition and witness but haven't run setup yet.
//
// For production, you should pre-compute and cache the SRS, PK, and VK.
func SetupAndProveRecursive(
	circuit frontend.Circuit,
	assignment frontend.Circuit,
	srs kzg.SRS,
	srsLagrange kzg.SRS,
) (*SP1RecursiveProof, error) {
	field := ecc.BN254.ScalarField()

	// Compile to SCS (PlonK constraint system).
	cs, err := frontend.Compile(field, scs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	// Setup PlonK keys.
	pk, vk, err := plonk.Setup(cs, srs, srsLagrange)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}

	// Create witness.
	fullWitness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return nil, fmt.Errorf("new witness: %w", err)
	}

	return ProvePlonkRecursive(cs, pk, vk, fullWitness)
}

// ExtractSP1PublicInputs extracts VkeyHash and CommittedValuesDigest from
// an SP1 public witness.
func ExtractSP1PublicInputs(pubWitness witness.Witness) (*SP1PublicInputs, error) {
	vec := pubWitness.Vector()
	frVec, ok := vec.(fr_bn254.Vector)
	if !ok {
		return nil, fmt.Errorf("expected fr_bn254.Vector, got %T", vec)
	}
	if len(frVec) != 2 {
		return nil, fmt.Errorf("expected 2 public inputs (SP1), got %d", len(frVec))
	}

	vkeyHash := new(big.Int)
	frVec[0].BigInt(vkeyHash)

	committedValuesDigest := new(big.Int)
	frVec[1].BigInt(committedValuesDigest)

	return &SP1PublicInputs{
		VkeyHash:              vkeyHash,
		CommittedValuesDigest: committedValuesDigest,
	}, nil
}

// ComputePublicInputsHash hashes the public inputs of an SP1 proof using
// the recursion-compatible non-bitmode MiMC hash, matching the in-circuit
// computation in PlonkVerifierGroth16Circuit.
func ComputePublicInputsHash(pubWitness witness.Witness) (*big.Int, error) {
	field := ecc.BN254.ScalarField()

	vec := pubWitness.Vector()
	frVec, ok := vec.(fr_bn254.Vector)
	if !ok {
		return nil, fmt.Errorf("expected fr_bn254.Vector, got %T", vec)
	}

	h, err := recursion.NewShort(field, field)
	if err != nil {
		return nil, fmt.Errorf("new short hash: %w", err)
	}

	buf := make([]byte, (field.BitLen()+7)/8)
	for i := range frVec {
		bi := new(big.Int)
		frVec[i].BigInt(bi)
		bi.FillBytes(buf)
		h.Write(buf)
	}

	return new(big.Int).SetBytes(h.Sum(nil)), nil
}
