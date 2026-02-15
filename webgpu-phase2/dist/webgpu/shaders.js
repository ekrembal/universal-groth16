/**
 * WGSL shader strings for BN254 G1 batch scalar multiplication.
 *
 * Ported from demox-labs/webgpu-crypto (MIT License) and adapted for
 * Phase 2 Trusted Setup Ceremony:
 *   - Full affine (x, y) normalization (webgpu-crypto only does x)
 *   - Same scalar broadcast to all points
 *   - Multipass approach: 4 passes × 64 bits to avoid GPU timeout
 *
 * Limb convention: 8 × u32, big-endian u32 order (components[0] = MSB).
 * This matches webgpu-crypto and our endian.ts conversion utilities.
 */
// ============================================================================
// Workgroup size — tuned for modern GPUs (64 is safe default)
// ============================================================================
export const WORKGROUP_SIZE = 64;
// ============================================================================
// U256 — 256-bit unsigned integer arithmetic
// ============================================================================
export const U256_WGSL = /* wgsl */ `
// big endian u32 limbs
struct u256 {
  components: array<u32, 8>
}

const U256_MAX: u256 = u256(
  array<u32, 8>(4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295)
);

const U256_ONE: u256 = u256(
  array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 1)
);

const U256_TWO: u256 = u256(
  array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 2)
);

const U256_THREE: u256 = u256(
  array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 3)
);

const U256_EIGHT: u256 = u256(
  array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 8)
);

const U256_ZERO: u256 = u256(
  array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 0)
);

fn add_components(a: u32, b: u32, carry_in: u32) -> vec2<u32> {
  var sum: vec2<u32>;
  let total = a + b + carry_in;
  sum[0] = total;
  sum[1] = 0u;
  if (total < a || (total - carry_in) < a) {
    sum[1] = 1u;
  }
  return sum;
}

fn sub_components(a: u32, b: u32, carry_in: u32) -> vec2<u32> {
  var sub: vec2<u32>;
  let total = a - b - carry_in;
  sub[0] = total;
  sub[1] = 0u;
  if (total > a || (total + carry_in) > a) {
    sub[1] = 1u;
  }
  return sub;
}

fn u256_add(a: u256, b: u256) -> u256 {
  var sum: u256;
  sum.components = array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 0);
  var carry: u32 = 0u;
  for (var i = 7i; i >= 0i; i--) {
    let componentResult = add_components(a.components[i], b.components[i], carry);
    sum.components[i] = componentResult[0];
    carry = componentResult[1];
  }
  return sum;
}

fn u256_rs1(a: u256) -> u256 {
  var right_shifted: u256 = u256(
    array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 0)
  );
  var carry: u32 = 0u;
  for (var i = 0u; i < 8u; i++) {
    var componentResult = a.components[i] >> 1u;
    componentResult = componentResult | carry;
    right_shifted.components[i] = componentResult;
    carry = a.components[i] << 31u;
  }
  return right_shifted;
}

fn is_even(a: u256) -> bool {
  return (a.components[7u] & 1u) == 0u;
}

fn is_odd(a: u256) -> bool {
  return (a.components[7u] & 1u) == 1u;
}

fn u256_sub(a: u256, b: u256) -> u256 {
  var sub: u256;
  sub.components = array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 0);
  var carry: u32 = 0u;
  for (var i = 7i; i >= 0i; i--) {
    let componentResult = sub_components(a.components[i], b.components[i], carry);
    sub.components[i] = componentResult[0];
    carry = componentResult[1];
  }
  return sub;
}

fn u256_subw(a: u256, b: u256) -> u256 {
  var sub: u256;
  if (gte(a, b)) {
    sub = u256_sub(a, b);
  } else {
    var b_minus_a: u256 = u256_sub(b, a);
    var b_minus_a_minus_one: u256 = u256_sub(b_minus_a, U256_ONE);
    sub = u256_sub(U256_MAX, b_minus_a_minus_one);
  }
  return sub;
}

fn equal(a: u256, b: u256) -> bool {
  for (var i = 0u; i < 8u; i++) {
    if (a.components[i] != b.components[i]) {
      return false;
    }
  }
  return true;
}

fn gt(a: u256, b: u256) -> bool {
  for (var i = 0u; i < 8u; i++) {
    if (a.components[i] != b.components[i]) {
      return a.components[i] > b.components[i];
    }
  }
  return false;
}

fn gte(a: u256, b: u256) -> bool {
  for (var i = 0u; i < 8u; i++) {
    if (a.components[i] != b.components[i]) {
      return a.components[i] > b.components[i];
    }
  }
  return true;
}

fn component_double(a: u32, carry: u32) -> vec2<u32> {
  var double: vec2<u32>;
  let total = a << 1u;
  double[0] = total + carry;
  double[1] = 0u;
  if (total < a) {
    double[1] = 1u;
  }
  return double;
}

fn u256_double(a: u256) -> u256 {
  var double: u256;
  double.components = array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 0);
  var carry: u32 = 0u;
  for (var i = 7i; i >= 0i; i--) {
    let componentResult = component_double(a.components[i], carry);
    double.components[i] = componentResult[0];
    carry = componentResult[1];
  }
  return double;
}

fn u256_right_shift(a: u256, shift: u32) -> u256 {
  var components_to_drop = shift / 32u;
  if (components_to_drop >= 8u) {
    return U256_ZERO;
  }
  var big_shift: u256 = u256(
    array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 0)
  );
  for (var i = components_to_drop; i < 8u; i++) {
    big_shift.components[i] = a.components[i - components_to_drop];
  }
  var shift_within_component = shift % 32u;
  if (shift_within_component == 0u) {
    return big_shift;
  }
  var carry: u32 = 0u;
  for (var i = components_to_drop; i < 8u; i++) {
    let shifted = big_shift.components[i] >> shift_within_component;
    let new_carry = big_shift.components[i] << (32u - shift_within_component);
    big_shift.components[i] = shifted | carry;
    carry = new_carry;
  }
  return big_shift;
}
`;
// ============================================================================
// BN254 Field Parameters
// ============================================================================
export const BN254_PARAMS_WGSL = /* wgsl */ `
// BN254 base field modulus p
// 21888242871839275222246405745257275088696311157297823662689037894645226208583
const FIELD_ORDER: Field = Field(
  array<u32, 8>(811880050, 3778125865, 3092268470, 2172737629, 2541841041, 1752287885, 1008765974, 3632069959)
);

const FIELD_ORDER_PLUS_ONE: Field = Field(
  array<u32, 8>(811880050, 3778125865, 3092268470, 2172737629, 2541841041, 1752287885, 1008765974, 3632069960)
);

const FIELD_ORDER_MINUS_ONE: Field = Field(
  array<u32, 8>(811880050, 3778125865, 3092268470, 2172737629, 2541841041, 1752287885, 1008765974, 3632069958)
);

const p: Field = FIELD_ORDER;

// (p + 1) / 4 — used for sqrt
const p_plus_one_div_4: Field = Field(
  array<u32, 8>(202970012, 3092015114, 1846808941, 2690668055, 1709202084, 1511813795, 1325933317, 3055501138)
);

fn field_sqrt(num: Field) -> Field {
  return field_pow(num, p_plus_one_div_4);
}
`;
// ============================================================================
// Field Modular Arithmetic
// ============================================================================
export const FIELD_MODULUS_WGSL = /* wgsl */ `
alias Field = u256;

fn field_reduce(a: u256) -> Field {
  var reduction: Field = a;
  var a_gte = gte(a, FIELD_ORDER);
  while (a_gte) {
    reduction = u256_sub(reduction, FIELD_ORDER);
    a_gte = gte(reduction, FIELD_ORDER);
  }
  return reduction;
}

fn field_add(a: Field, b: Field) -> Field {
  var sum = u256_add(a, b);
  var result = field_reduce(sum);
  return result;
}

fn field_sub(a: Field, b: Field) -> Field {
  var sub: Field;
  if (gte(a, b)) {
    sub = u256_sub(a, b);
  } else {
    var b_minus_a: Field = u256_sub(b, a);
    sub = u256_sub(FIELD_ORDER, b_minus_a);
  }
  return sub;
}

fn field_double(a: Field) -> Field {
  var double = u256_double(a);
  var result = field_reduce(double);
  return result;
}

fn field_multiply(a: Field, b: Field) -> Field {
  var accumulator: Field = Field(
    array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 0)
  );
  var newA: Field = a;
  var newB: Field = b;

  while (gt(newB, U256_ZERO)) {
    if ((newB.components[7] & 1u) == 1u) {
      accumulator = u256_add(accumulator, newA);
      if (gte(accumulator, FIELD_ORDER)) {
        accumulator = u256_sub(accumulator, FIELD_ORDER);
      }
    }
    newA = u256_double(newA);
    newA = field_reduce(newA);
    newB = u256_right_shift(newB, 1u);
  }

  return accumulator;
}

fn field_pow(base: Field, exponent: Field) -> Field {
  if (equal(exponent, U256_ZERO)) {
    return U256_ONE;
  }
  if (equal(exponent, U256_ONE)) {
    return base;
  }
  var exp = exponent;
  var bse = base;
  var result: u256 = u256(
    array<u32, 8>(0, 0, 0, 0, 0, 0, 0, 1)
  );
  while (gt(exp, U256_ZERO)) {
    if (is_odd(exp)) {
      result = field_multiply(result, bse);
    }
    exp = u256_rs1(exp);
    bse = field_multiply(bse, bse);
  }
  return result;
}

// GKPP algorithm (BEA for inversion in Fp)
fn field_inverse(num: Field) -> Field {
  var u: Field = num;
  var v: u256 = FIELD_ORDER;
  var b: Field = U256_ONE;
  var c: Field = U256_ZERO;

  while (!equal(u, U256_ONE) && !equal(v, U256_ONE)) {
    while (is_even(u)) {
      u = u256_rs1(u);
      if (is_even(b)) {
        b = u256_rs1(b);
      } else {
        b = u256_add(b, FIELD_ORDER);
        b = u256_rs1(b);
      }
    }
    while (is_even(v)) {
      v = u256_rs1(v);
      if (is_even(c)) {
        c = u256_rs1(c);
      } else {
        c = u256_add(c, FIELD_ORDER);
        c = u256_rs1(c);
      }
    }
    if (gte(u, v)) {
      u = u256_sub(u, v);
      b = field_sub(b, c);
    } else {
      v = u256_sub(v, u);
      c = field_sub(c, b);
    }
  }

  if (equal(u, U256_ONE)) {
    return field_reduce(b);
  } else {
    return field_reduce(c);
  }
}
`;
// ============================================================================
// BN254 Curve Operations — G1 add, double (Projective/Extended coordinates)
// ============================================================================
export const BN254_CURVE_WGSL = /* wgsl */ `
struct AffinePoint {
  x: Field,
  y: Field
}

struct Point {
  x: Field,
  y: Field,
  t: Field,
  z: Field
}

struct MulPointIntermediate {
  result: Point,
  temp: Point,
  scalar: Field
}

const ZERO_POINT: Point = Point(U256_ZERO, U256_ONE, U256_ZERO, U256_ZERO);
const ZERO_AFFINE: AffinePoint = AffinePoint(U256_ZERO, U256_ONE);

// Jacobian-style addition following aztec protocol implementation
fn add_points(p1: Point, p2: Point) -> Point {
  if (equal(p1.x, U256_ZERO) && equal(p1.y, U256_ONE) && equal(p1.z, U256_ZERO)) {
    return p2;
  }
  if (equal(p2.x, U256_ZERO) && equal(p2.y, U256_ONE) && equal(p2.z, U256_ZERO)) {
    return p1;
  }
  var z1z1 = field_multiply(p1.z, p1.z);
  var z2z2 = field_multiply(p2.z, p2.z);
  var s2 = field_multiply(z1z1, p1.z);
  var u2 = field_multiply(z1z1, p2.x);
  s2 = field_multiply(s2, p2.y);
  var u1 = field_multiply(z2z2, p1.x);
  var s1 = field_multiply(z2z2, p2.z);
  s1 = field_multiply(s1, p1.y);
  var f = field_double(field_sub(s2, s1));
  if (equal(f, U256_ZERO)) {
    return double_point(p1);
  }
  var h = field_sub(u2, u1);
  var i = field_double(h);
  i = field_multiply(i, i);
  var j = field_multiply(h, i);
  u1 = field_multiply(u1, i);
  u2 = field_double(u1);
  u2 = field_add(u2, j);
  var x_result = field_multiply(f, f);
  x_result = field_sub(x_result, u2);
  j = field_multiply(j, s1);
  j = field_double(j);
  var y_result = field_sub(u1, x_result);
  y_result = field_multiply(f, y_result);
  y_result = field_sub(y_result, j);
  var z_result = field_add(p1.z, p2.z);
  z1z1 = field_add(z1z1, z2z2);
  z_result = field_multiply(z_result, z_result);
  z_result = field_sub(z_result, z1z1);
  z_result = field_multiply(z_result, h);
  var t_result = field_multiply(x_result, y_result);
  return Point(x_result, y_result, t_result, z_result);
}

// Doubling following aztec protocol implementation
fn double_point(p: Point) -> Point {
  var T0 = field_multiply(p.x, p.x);
  var T1 = field_multiply(p.y, p.y);
  var T2 = field_multiply(T1, T1);
  T1 = field_add(p.x, T1);
  T1 = field_multiply(T1, T1);
  var T3 = field_add(T0, T2);
  T1 = field_sub(T1, T3);
  T1 = field_double(T1);
  T3 = field_double(T0);
  T3 = field_add(T3, T0);
  var z_result = field_double(p.z);
  z_result = field_multiply(z_result, p.y);
  T0 = field_double(T1);
  var x_result = field_multiply(T3, T3);
  x_result = field_sub(x_result, T0);
  T2 = field_double(T2);
  T2 = field_double(T2);
  T2 = field_double(T2);
  var y_result = field_sub(T1, x_result);
  y_result = field_multiply(T3, y_result);
  y_result = field_sub(y_result, T2);
  var t_result = field_multiply(x_result, y_result);
  return Point(x_result, y_result, t_result, z_result);
}

// Multipass scalar multiplication: process 64 bits at a time
fn mul_point_64_bits_start(p: Point, scalar: Field) -> MulPointIntermediate {
  var result: Point = ZERO_POINT;
  var temp = p;
  var scalar_iter = scalar;
  for (var i = 0u; i < 64u; i = i + 1u) {
    if (equal(scalar_iter, U256_ZERO)) {
      break;
    }
    if (is_odd(scalar_iter)) {
      result = add_points(result, temp);
    }
    temp = double_point(temp);
    scalar_iter = u256_rs1(scalar_iter);
  }
  return MulPointIntermediate(result, temp, scalar_iter);
}

fn mul_point_64_bits(p: Point, scalar: Field, t: Point) -> MulPointIntermediate {
  if (equal(scalar, U256_ZERO)) {
    return MulPointIntermediate(p, t, scalar);
  }
  var result: Point = p;
  var temp = t;
  var scalar_iter = scalar;
  for (var i = 0u; i < 64u; i = i + 1u) {
    if (equal(scalar_iter, U256_ZERO)) {
      break;
    }
    if (is_odd(scalar_iter)) {
      result = add_points(result, temp);
    }
    temp = double_point(temp);
    scalar_iter = u256_rs1(scalar_iter);
  }
  return MulPointIntermediate(result, temp, scalar_iter);
}

// Normalize projective → affine: (x/z², y/z³)
fn normalize_point(p: Point) -> AffinePoint {
  if (equal(p.z, U256_ZERO)) {
    return AffinePoint(U256_ZERO, U256_ZERO);
  }
  var z_inv = field_inverse(p.z);
  var z_inv_sq = field_multiply(z_inv, z_inv);
  var z_inv_cu = field_multiply(z_inv_sq, z_inv);
  var x_aff = field_multiply(p.x, z_inv_sq);
  var y_aff = field_multiply(p.y, z_inv_cu);
  return AffinePoint(x_aff, y_aff);
}
`;
// ============================================================================
// Entry Point Shaders — one per compute pass
// ============================================================================
/**
 * Pass 1: Convert affine points to extended projective and run first 64 bits
 * of scalar multiplication.
 *
 * Inputs:  binding 0 = affine points (AffinePoint[]), binding 1 = scalar (Field)
 * Outputs: binding 2 = result points (Point[]), binding 3 = temp points (Point[]),
 *          binding 4 = updated scalars (Field[])
 */
export function makePass1Entry(workgroupSize) {
    return /* wgsl */ `
@group(0) @binding(0)
var<storage, read> inputPoints: array<AffinePoint>;
@group(0) @binding(1)
var<storage, read> scalarBuf: Field;
@group(0) @binding(2)
var<storage, read_write> resultPoints: array<Point>;
@group(0) @binding(3)
var<storage, read_write> tempPoints: array<Point>;
@group(0) @binding(4)
var<storage, read_write> updatedScalars: array<Field>;

@compute @workgroup_size(${workgroupSize})
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
  let idx = global_id.x;
  if (idx >= arrayLength(&inputPoints)) {
    return;
  }

  let affine = inputPoints[idx];
  // Convert affine to extended projective: (x, y, x*y, 1)
  var ext_p = Point(affine.x, affine.y, field_multiply(affine.x, affine.y), U256_ONE);

  // Handle point at infinity (x=0, y=0 in gnark convention)
  if (equal(affine.x, U256_ZERO) && equal(affine.y, U256_ZERO)) {
    ext_p = ZERO_POINT;
  }

  let intermediate = mul_point_64_bits_start(ext_p, scalarBuf);
  resultPoints[idx] = intermediate.result;
  tempPoints[idx] = intermediate.temp;
  updatedScalars[idx] = intermediate.scalar;
}
`;
}
/**
 * Pass 2/3: Intermediate passes — process next 64 bits of scalar.
 *
 * Inputs:  binding 0 = result points, binding 1 = scalars, binding 2 = temp points
 * Outputs: binding 3 = new result, binding 4 = new temp, binding 5 = new scalars
 */
export function makeIntermediateEntry(workgroupSize) {
    return /* wgsl */ `
@group(0) @binding(0)
var<storage, read> inResults: array<Point>;
@group(0) @binding(1)
var<storage, read> inScalars: array<Field>;
@group(0) @binding(2)
var<storage, read> inTemps: array<Point>;
@group(0) @binding(3)
var<storage, read_write> outResults: array<Point>;
@group(0) @binding(4)
var<storage, read_write> outTemps: array<Point>;
@group(0) @binding(5)
var<storage, read_write> outScalars: array<Field>;

@compute @workgroup_size(${workgroupSize})
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
  let idx = global_id.x;
  if (idx >= arrayLength(&inResults)) {
    return;
  }

  let intermediate = mul_point_64_bits(inResults[idx], inScalars[idx], inTemps[idx]);
  outResults[idx] = intermediate.result;
  outTemps[idx] = intermediate.temp;
  outScalars[idx] = intermediate.scalar;
}
`;
}
/**
 * Pass 4 (final): Last 64 bits of scalar multiplication + normalize to affine.
 *
 * Inputs:  binding 0 = result points, binding 1 = scalars, binding 2 = temp points
 * Outputs: binding 3 = affine output points
 */
export function makeFinalEntry(workgroupSize) {
    return /* wgsl */ `
@group(0) @binding(0)
var<storage, read> inResults: array<Point>;
@group(0) @binding(1)
var<storage, read> inScalars: array<Field>;
@group(0) @binding(2)
var<storage, read> inTemps: array<Point>;
@group(0) @binding(3)
var<storage, read_write> outAffine: array<AffinePoint>;

@compute @workgroup_size(${workgroupSize})
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
  let idx = global_id.x;
  if (idx >= arrayLength(&inResults)) {
    return;
  }

  let intermediate = mul_point_64_bits(inResults[idx], inScalars[idx], inTemps[idx]);
  outAffine[idx] = normalize_point(intermediate.result);
}
`;
}
// ============================================================================
// Composed shader strings — concatenate modules for each pass
// ============================================================================
const BASE_MODULES = U256_WGSL + BN254_PARAMS_WGSL + FIELD_MODULUS_WGSL + BN254_CURVE_WGSL;
/** Full shader code for pass 1 (affine → projective + first 64 scalar bits). */
export function getPass1Shader(workgroupSize = WORKGROUP_SIZE) {
    return BASE_MODULES + makePass1Entry(workgroupSize);
}
/** Full shader code for intermediate passes (next 64 scalar bits). */
export function getIntermediateShader(workgroupSize = WORKGROUP_SIZE) {
    return BASE_MODULES + makeIntermediateEntry(workgroupSize);
}
/** Full shader code for final pass (last 64 scalar bits + normalize to affine). */
export function getFinalShader(workgroupSize = WORKGROUP_SIZE) {
    return BASE_MODULES + makeFinalEntry(workgroupSize);
}
//# sourceMappingURL=shaders.js.map