/**
 * Type definitions for Phase 2 Trusted Setup Ceremony data structures.
 *
 * These mirror gnark's bn254/mpcsetup.Phase2 struct and related types.
 */
/**
 * A zero (infinity) G1 point — used as identity element.
 */
export const G1_INFINITY = { x: 0n, y: 0n };
/**
 * A zero (infinity) G2 point — used as identity element.
 */
export const G2_INFINITY = {
    x: { c0: 0n, c1: 0n },
    y: { c0: 0n, c1: 0n },
};
//# sourceMappingURL=types.js.map