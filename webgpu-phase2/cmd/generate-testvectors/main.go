// Command generate-testvectors exports Phase 2 test vectors from gnark
// for WebGPU implementation validation.
//
// Usage (from gnark repo root):
//
//	go run ./webgpu-phase2/cmd/generate-testvectors
//
// Output: webgpu-phase2/testvectors/phase2_vectors.json
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	outDir := filepath.Join("webgpu-phase2", "testvectors")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		panic(err)
	}

	// BN254 constants
	fpModulus := fp.Modulus().String()
	frModulus := fr.Modulus().String()
	_, _, g1, g2 := curve.Generators()

	vectors := map[string]any{
		"fp_modulus":   fpModulus,
		"fr_modulus":   frModulus,
		"g1_generator": g1ToHex(&g1),
		"g2_generator": g2ToHex(&g2),
	}

	// ---------------------------------------------------------------
	// G1 scalar multiplication test vectors
	// ---------------------------------------------------------------
	g1ScalarMulTests := make([]map[string]string, 0)
	for _, s := range []int64{2, 3, 5, 7, 42, 1000} {
		var I big.Int
		I.SetInt64(s)
		result := new(curve.G1Affine)
		result.ScalarMultiplication(&g1, &I)
		g1ScalarMulTests = append(g1ScalarMulTests, map[string]string{
			"point":  g1ToHex(&g1),
			"scalar": fmt.Sprintf("%d", s),
			"result": g1ToHex(result),
		})
	}

	// Also test with a non-generator point: [2]G1
	var two big.Int
	two.SetInt64(2)
	g1Two := new(curve.G1Affine)
	g1Two.ScalarMultiplication(&g1, &two)
	{
		var five big.Int
		five.SetInt64(5)
		g1TwoTimesFive := new(curve.G1Affine)
		g1TwoTimesFive.ScalarMultiplication(g1Two, &five)
		g1ScalarMulTests = append(g1ScalarMulTests, map[string]string{
			"point":  g1ToHex(g1Two),
			"scalar": "5",
			"result": g1ToHex(g1TwoTimesFive),
		})
	}
	vectors["g1_scalar_mul"] = g1ScalarMulTests

	// ---------------------------------------------------------------
	// G2 scalar multiplication test vectors
	// ---------------------------------------------------------------
	g2ScalarMulTests := make([]map[string]string, 0)
	for _, s := range []int64{2, 5} {
		var I big.Int
		I.SetInt64(s)
		result := new(curve.G2Affine)
		result.ScalarMultiplication(&g2, &I)
		g2ScalarMulTests = append(g2ScalarMulTests, map[string]string{
			"point":  g2ToHex(&g2),
			"scalar": fmt.Sprintf("%d", s),
			"result": g2ToHex(result),
		})
	}
	vectors["g2_scalar_mul"] = g2ScalarMulTests

	// ---------------------------------------------------------------
	// Phase 2 small test: commons with N=8, tau=2, alpha=3, beta=4
	// ---------------------------------------------------------------
	const N = 8
	commons := commonsSmallValues(N, 2, 3, 4)

	// Export G1.Tau[0..7] for small batch test
	g1TauHex := make([]string, len(commons.G1.Tau))
	for i := range commons.G1.Tau {
		g1TauHex[i] = g1ToHex(&commons.G1.Tau[i])
	}
	vectors["commons_g1_tau"] = g1TauHex

	// Export G2.Tau[0..N-1]
	g2TauHex := make([]string, len(commons.G2.Tau))
	for i := range commons.G2.Tau {
		g2TauHex[i] = g2ToHex(&commons.G2.Tau[i])
	}
	vectors["commons_g2_tau"] = g2TauHex

	// ---------------------------------------------------------------
	// Batch scaling test: scale G1.Tau[0..3] by scalar 7
	// ---------------------------------------------------------------
	batchScalar := int64(7)
	var batchI big.Int
	batchI.SetInt64(batchScalar)
	batchInput := make([]string, 4)
	batchExpected := make([]string, 4)
	for i := 0; i < 4; i++ {
		batchInput[i] = g1ToHex(&commons.G1.Tau[i])
		scaled := new(curve.G1Affine)
		scaled.ScalarMultiplication(&commons.G1.Tau[i], &batchI)
		batchExpected[i] = g1ToHex(scaled)
	}
	vectors["batch_scale_g1"] = map[string]any{
		"points":   batchInput,
		"scalar":   fmt.Sprintf("%d", batchScalar),
		"expected": batchExpected,
	}

	// ---------------------------------------------------------------
	// Phase 2 full state: Initialize → export before/after update
	// ---------------------------------------------------------------
	ccs := getTinyCircuit()
	var p mpcsetup.Phase2
	_ = p.Initialize(ccs, &commons)

	// Export state before update
	beforeState := exportPhase2State(&p)
	vectors["phase2_before"] = beforeState

	// Serialize Phase2 state to binary (for parse/serialize roundtrip test)
	var buf bytes.Buffer
	if _, err := p.WriteTo(&buf); err != nil {
		panic(err)
	}
	vectors["phase2_binary_before"] = base64.StdEncoding.EncodeToString(buf.Bytes())

	// Apply update with delta=2, sigma (per number of commitments)
	delta := fr.Element{}
	delta.SetInt64(2)
	sigmas := make([]fr.Element, len(p.Parameters.G1.SigmaCKK))
	for i := range sigmas {
		sigmas[i].SetInt64(int64(3 + i))
	}
	applyUpdate(&p, &delta, sigmas)

	// Export state after update
	afterState := exportPhase2State(&p)
	afterState["delta_scalar"] = "2"
	sigmaScalars := make([]string, len(sigmas))
	for i := range sigmas {
		sigmaScalars[i] = fmt.Sprintf("%d", 3+i)
	}
	afterState["sigma_scalars"] = sigmaScalars
	vectors["phase2_after"] = afterState

	// Also export delta_inv (Fr inverse of 2) for verification
	var deltaInv fr.Element
	deltaInv.SetInt64(2)
	deltaInv.Inverse(&deltaInv)
	var deltaInvI big.Int
	deltaInv.BigInt(&deltaInvI)
	vectors["delta_inv_of_2"] = deltaInvI.String()

	// ---------------------------------------------------------------
	// Fr inverse test vectors
	// ---------------------------------------------------------------
	frInvTests := make([]map[string]string, 0)
	for _, v := range []int64{2, 3, 5, 7, 42} {
		var elem fr.Element
		elem.SetInt64(v)
		elem.Inverse(&elem)
		var I big.Int
		elem.BigInt(&I)
		frInvTests = append(frInvTests, map[string]string{
			"input":  fmt.Sprintf("%d", v),
			"result": I.String(),
		})
	}
	vectors["fr_inverse"] = frInvTests

	// ---------------------------------------------------------------
	// Write JSON
	// ---------------------------------------------------------------
	b, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		panic(err)
	}
	outPath := filepath.Join(outDir, "phase2_vectors.json")
	if err := os.WriteFile(outPath, b, 0644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", outPath)
}

// exportPhase2State returns a JSON-serializable map of Phase2 point data.
func exportPhase2State(p *mpcsetup.Phase2) map[string]any {
	state := map[string]any{
		"g1_delta": g1ToHex(&p.Parameters.G1.Delta),
	}

	g1Z := make([]string, len(p.Parameters.G1.Z))
	for i := range p.Parameters.G1.Z {
		g1Z[i] = g1ToHex(&p.Parameters.G1.Z[i])
	}
	state["g1_z"] = g1Z

	g1PKK := make([]string, len(p.Parameters.G1.PKK))
	for i := range p.Parameters.G1.PKK {
		g1PKK[i] = g1ToHex(&p.Parameters.G1.PKK[i])
	}
	state["g1_pkk"] = g1PKK

	state["g2_delta"] = g2ToHex(&p.Parameters.G2.Delta)

	g2Sigma := make([]string, len(p.Parameters.G2.Sigma))
	for i := range p.Parameters.G2.Sigma {
		g2Sigma[i] = g2ToHex(&p.Parameters.G2.Sigma[i])
	}
	state["g2_sigma"] = g2Sigma

	sigmaCKK := make([][]string, len(p.Parameters.G1.SigmaCKK))
	for i := range p.Parameters.G1.SigmaCKK {
		slice := make([]string, len(p.Parameters.G1.SigmaCKK[i]))
		for j := range p.Parameters.G1.SigmaCKK[i] {
			slice[j] = g1ToHex(&p.Parameters.G1.SigmaCKK[i][j])
		}
		sigmaCKK[i] = slice
	}
	state["g1_sigma_ckk"] = sigmaCKK

	return state
}

// applyUpdate replicates Phase2.update using public API (update is unexported).
func applyUpdate(p *mpcsetup.Phase2, delta *fr.Element, sigma []fr.Element) {
	var I big.Int

	scaleG1Slice := func(s []curve.G1Affine) {
		for i := range s {
			s[i].ScalarMultiplication(&s[i], &I)
		}
	}

	for i := range sigma {
		sigma[i].BigInt(&I)
		p.Parameters.G2.Sigma[i].ScalarMultiplication(&p.Parameters.G2.Sigma[i], &I)
		scaleG1Slice(p.Parameters.G1.SigmaCKK[i])
	}

	delta.BigInt(&I)
	p.Parameters.G2.Delta.ScalarMultiplication(&p.Parameters.G2.Delta, &I)
	p.Parameters.G1.Delta.ScalarMultiplication(&p.Parameters.G1.Delta, &I)

	delta.Inverse(delta)
	delta.BigInt(&I)
	scaleG1Slice(p.Parameters.G1.Z)
	scaleG1Slice(p.Parameters.G1.PKK)
}

func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2+2)
	out[0], out[1] = '0', 'x'
	for i, c := range b {
		out[2+i*2] = hex[c>>4]
		out[2+i*2+1] = hex[c&0xf]
	}
	return string(out)
}

func g1ToHex(p *curve.G1Affine) string {
	b := p.RawBytes()
	return hexEncode(b[:])
}

func g2ToHex(p *curve.G2Affine) string {
	b := p.RawBytes()
	return hexEncode(b[:])
}

func commonsSmallValues(N uint64, tau, alpha, beta int64) mpcsetup.SrsCommons {
	var (
		res   mpcsetup.SrsCommons
		I     big.Int
		coeff fr.Element
	)
	_, _, g1, g2 := curve.Generators()
	tauPowers := powersI(tau, int(2*N-1))
	res.G1.Tau = make([]curve.G1Affine, 2*N-1)
	for i := range res.G1.Tau {
		tauPowers[i].BigInt(&I)
		res.G1.Tau[i].ScalarMultiplication(&g1, &I)
	}
	res.G2.Tau = make([]curve.G2Affine, N)
	for i := range res.G2.Tau {
		tauPowers[i].BigInt(&I)
		res.G2.Tau[i].ScalarMultiplication(&g2, &I)
	}
	res.G1.AlphaTau = make([]curve.G1Affine, N)
	coeff.SetInt64(alpha)
	for i := range res.G1.AlphaTau {
		var x fr.Element
		x.Mul(&tauPowers[i], &coeff)
		x.BigInt(&I)
		res.G1.AlphaTau[i].ScalarMultiplication(&g1, &I)
	}
	res.G1.BetaTau = make([]curve.G1Affine, N)
	coeff.SetInt64(beta)
	for i := range res.G1.BetaTau {
		var x fr.Element
		x.Mul(&tauPowers[i], &coeff)
		x.BigInt(&I)
		res.G1.BetaTau[i].ScalarMultiplication(&g1, &I)
	}
	I.SetInt64(beta)
	res.G2.Beta.ScalarMultiplication(&g2, &I)
	return res
}

func powersI(x int64, n int) []fr.Element {
	var y fr.Element
	y.SetInt64(x)
	return powers(&y, n)
}

func powers(a *fr.Element, N int) []fr.Element {
	if N == 0 {
		return nil
	}
	result := make([]fr.Element, N)
	result[0].SetOne()
	for i := 1; i < N; i++ {
		result[i].Mul(&result[i-1], a)
	}
	return result
}

type tinyCircuit struct {
	X [4]frontend.Variable `gnark:",public"`
}

func (c *tinyCircuit) Define(api frontend.API) error {
	for i := range c.X {
		api.AssertIsEqual(c.X[i], i)
	}
	return nil
}

func getTinyCircuit() *cs.R1CS {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &tinyCircuit{})
	if err != nil {
		panic(err)
	}
	return ccs.(*cs.R1CS)
}
