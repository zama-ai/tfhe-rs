//! [`HlInstructionSet`] — the high-level dialect's instruction set for `zhc_ir`.

use zhc_ir::{sig, DialectInstructionSet, Format, FormatContext, Signature};
use zhc_utils::svec;

use crate::MatchValues;

use super::kinds::{ClearKind, FheIntKind, FheKind};
use super::type_system::{KvKey, KvKeyKind, OprfMode, ScalarValue, ValueKind};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HlInstructionSet {
    // Boundary
    /// Circuit input. `pos` is the index in the input list.
    /// Produces one value of `kind`.
    Input {
        pos: u32,
        kind: ValueKind,
    },
    /// Circuit output. `pos` is the index in the output list.
    /// Consumes one value of `kind`
    Output {
        pos: u32,
        kind: ValueKind,
    },
    /// Create a trivial encryption of the input clear value into the desired
    /// type.  
    ///
    /// Signature: `(clear-kind-of(kind)) -> kind`. The clear operand is
    /// typically produced by a [`Self::Constant`] op for compile-time
    /// literals, or by an [`Self::Input`] of clear type for runtime values.
    EncryptTrivial {
        kind: FheKind,
    },
    /// Produces a clear constant value of `kind` from the embedded `value`.
    ///
    /// Literal scalars passed to polymorphic builder methods like `fhe_add(fhe, 7u32)`
    /// are lowered to a `Constant`.
    ///
    /// Construct via [`HlInstructionSet::constant`] so the value is normalized
    /// for the kind (rejects malformed combinations like
    /// `Constant { kind: Uint(8), value: ScalarValue::Signed(-1) }`).
    Constant {
        kind: ClearKind,
        value: ScalarValue,
    },

    // Arithmetic — FheIntKind
    /// Add two FHE values of the same kind (a + b)
    FheAdd {
        kind: FheIntKind,
    },
    /// Sub two FHE values of the same kind (a - b)
    FheSub {
        kind: FheIntKind,
    },
    /// Mul two FHE values of the same kind (a * b)
    FheMul {
        kind: FheIntKind,
    },
    /// Div two FHE values of the same kind (a / b)
    FheDiv {
        kind: FheIntKind,
    },
    /// Remainder of two FHE values of the same kind (a % b)
    FheRem {
        kind: FheIntKind,
    },
    /// Returns the min (lowest/smallest) of two FHE values of the same kind
    FheMin {
        kind: FheIntKind,
    },
    /// Returns the max (highest/biggest) of two FHE values of the same kind
    FheMax {
        kind: FheIntKind,
    },
    /// Negates an FHE value (-a)
    FheNeg {
        kind: FheIntKind,
    },
    /// Sums all the input values.
    ///
    /// All inputs have the same type
    FheSum {
        kind: FheIntKind,
        n: u32,
    },
    // Unary integer inspection / transformation
    /// Parity predicate: `(t) -> FheBool`. True iff value is even.
    FheIsEven {
        kind: FheIntKind,
    },
    /// Parity predicate: `(t) -> FheBool`. True iff value is odd.
    FheIsOdd {
        kind: FheIntKind,
    },
    /// Counts the number of leading zeros.
    ///
    /// i.e. the number of bits set to `0` until the first bit set to `1`, from MSB to LSB
    ///
    /// `(t) -> FheUint(32)`
    FheLeadingZeros {
        kind: FheIntKind,
    },
    /// Counts the number of leading ones.
    ///
    /// i.e. the number of bits set to `1` until the first bit set to `0`, from MSB to LSB
    ///
    /// `(t) -> FheUint(32)`
    FheLeadingOnes {
        kind: FheIntKind,
    },
    /// Counts the number of trailing zeros.
    ///
    /// i.e. the number of bits set to `0` until the first bit set to `1`, from LSB to MSB
    ///
    /// `(t) -> FheUint(32)`
    FheTrailingZeros {
        kind: FheIntKind,
    },
    /// Counts the number of trailing ones.
    ///
    /// i.e. the number of bits set to `1` until the first bit set to `0`, from LSB to MSB
    ///
    /// `(t) -> FheUint(32)`
    FheTrailingOnes {
        kind: FheIntKind,
    },
    /// Counts the number of bit set to `1`
    ///
    /// `(t) -> FheUint(32)`
    FheCountOnes {
        kind: FheIntKind,
    },
    /// Counts the number of bit set to `0`
    ///
    /// `(t) -> FheUint(32)`
    FheCountZeros {
        kind: FheIntKind,
    },
    /// Integer base-2 log, rounded down
    ///
    /// `(t) -> FheUint(32)`.
    FheIlog2 {
        kind: FheIntKind,
    },
    /// Integer base-2 log with validity bit
    ///
    /// `(t) -> (FheUint(32), FheBool)`.
    /// The bool is true iff the input was > 0 (and thus the log result is valid).
    FheCheckedIlog2 {
        kind: FheIntKind,
    },

    /// Reverse the bit order of the value
    ///
    /// `(t) -> t`.
    FheReverseBits {
        kind: FheIntKind,
    },
    /// Absolute value
    ///
    ///**Signed-only** — the builder rejects `FheIntKind::Uint(_)` inputs.
    ///
    /// `(t) -> t`.
    FheAbs {
        kind: FheIntKind,
    },

    /// Bitwise AND of two FHE values of the same kind (a & b)
    FheBitAnd {
        kind: FheKind,
    },
    /// Bitwise OR of two FHE values of the same kind (a | b)
    FheBitOr {
        kind: FheKind,
    },
    /// Bitwise XOR of two FHE values of the same kind (a ^ b)
    FheBitXor {
        kind: FheKind,
    },
    /// Bitwise NOT of an FHE value (!a)
    FheNot {
        kind: FheKind,
    },

    // Equality — FheKind, returns FheBool
    FheEq {
        kind: FheKind,
    },
    FheNe {
        kind: FheKind,
    },

    // Ordering — FheIntKind, returns FheBool
    FheLt {
        kind: FheIntKind,
    },
    FheLe {
        kind: FheIntKind,
    },
    FheGt {
        kind: FheIntKind,
    },
    FheGe {
        kind: FheIntKind,
    },

    // Shift/rotate — FheIntKind for lhs, rhs is FheUint(rhs_bits)
    FheShl {
        lhs_kind: FheIntKind,
        rhs_bits: u32,
    },
    FheShr {
        lhs_kind: FheIntKind,
        rhs_bits: u32,
    },
    FheRotateLeft {
        lhs_kind: FheIntKind,
        rhs_bits: u32,
    },
    FheRotateRight {
        lhs_kind: FheIntKind,
        rhs_bits: u32,
    },

    // Overflowing
    /// FHE addition between two operands of the same type.
    /// returns (result, overflowed): (FheIntKind, FheBool)
    /// where:
    /// - result is the result of the addition (wrapped around)
    /// - overflowed encrypts whether overflow occurred
    FheOverflowingAdd {
        kind: FheIntKind,
    },
    /// FHE subtraction between two operands of the same type.
    /// returns (result, overflowed): (FheIntKind, FheBool)
    /// where:
    /// - result is the result of the subtraction (wrapped around)
    /// - overflowed encrypts whether overflow occurred
    FheOverflowingSub {
        kind: FheIntKind,
    },
    /// FHE multiplication between two operands of the same type.
    /// returns (result, overflowed): (FheIntKind, FheBool)
    /// where:
    /// - result is the result of the multiplication (wrapped around)
    /// - overflowed encrypts whether overflow occurred
    FheOverflowingMul {
        kind: FheIntKind,
    },
    /// Unary overflowing negation. Signature: `(t) -> (t, FheBool)`.
    /// The bool is `true` iff negation overflowed (e.g., `i32::MIN.neg()`,
    /// or any non-zero unsigned value).
    FheOverflowingNeg {
        kind: FheIntKind,
    },
    /// FHE + clear overflowing add. Signature: `(t, t_clear) -> (t, FheBool)`.
    /// Clear operand is on the right (commutative — caller is free to flip).
    FheScalarOverflowingAdd {
        kind: FheIntKind,
    },
    /// FHE - clear overflowing sub. Signature: `(t, t_clear) -> (t, FheBool)`.
    /// Clear - FHE form is not supported by the integer layer; rejected at
    /// builder time.
    FheScalarOverflowingSub {
        kind: FheIntKind,
    },

    /// Fused div/rem: returns `(quotient, remainder)` in a single op so the
    /// backend can compute them together. Signature: `(t, t) -> (t, t)`.
    FheDivRem {
        kind: FheIntKind,
    },

    // Cast / control / compression — flexible types
    /// Cast between FHE types. Excludes `CompressedList` / `KVStore`
    /// (which aren't FHE ciphertexts you can cast between).
    FheCast {
        from: FheKind,
        to: FheKind,
    },
    /// Branch values must be integer (builder rejects Bool/CompressedList branches).
    Select {
        kind: FheIntKind,
    },
    /// Paired select: `if cond { (b, a) } else { (a, b) }`. Returns two
    /// values of the same kind. Mirrors
    /// `ServerKey::unchecked_flip_parallelized` — one fused op is cheaper
    /// than two independent selects (shared per-block bivariate PBS).
    FheFlip {
        kind: FheIntKind,
    },
    /// Both branches are clear values. Signature:
    /// `(FheBool, clear, clear) -> kind`. Mirrors
    /// `ServerKey::scalar_if_then_else_parallelized`. Kept distinct from
    /// `Select` because the integer-layer call is different (no PBS on the
    /// clear sides).
    SelectScalarScalar {
        kind: FheIntKind,
    },
    /// Then-branch FHE, else-branch clear. Signature:
    /// `(FheBool, kind, clear) -> kind`. Mirrors
    /// `ServerKey::if_then_else_parallelized(cond, true_ct, false_scalar)`.
    SelectFheScalar {
        kind: FheIntKind,
    },
    /// Then-branch clear, else-branch FHE. Signature:
    /// `(FheBool, clear, kind) -> kind`. Mirrors
    /// `ServerKey::if_then_else_parallelized(cond, true_scalar, false_ct)`.
    SelectScalarFhe {
        kind: FheIntKind,
    },
    Compress {
        input_kinds: Vec<FheKind>,
    },
    /// Decompress specific items from a `CompressedList` into individual
    /// FHE values. Each pick is `(index_in_list, output_kind)`. Outputs
    /// are produced in the order `picks` are listed;
    Decompress {
        picks: Vec<(u32, FheKind)>,
    },

    // Scalar arithmetic / shift / rotate / min-max — FheIntKind. The clear
    // operand is the *second* input (for `FheScalar*` ops) or the *first*
    // input (for `ScalarFhe*` ops); the producing op is typically a
    // [`Self::Constant`] for compile-time literals or an `Input` of clear
    // type for runtime values.
    FheScalarAdd {
        kind: FheIntKind,
    },
    FheScalarSub {
        kind: FheIntKind,
    },
    ScalarFheSub {
        kind: FheIntKind,
    },
    FheScalarMul {
        kind: FheIntKind,
    },
    FheScalarDiv {
        kind: FheIntKind,
    },
    FheScalarRem {
        kind: FheIntKind,
    },
    FheScalarMin {
        kind: FheIntKind,
    },
    FheScalarMax {
        kind: FheIntKind,
    },
    FheScalarShl {
        kind: FheIntKind,
    },
    FheScalarShr {
        kind: FheIntKind,
    },
    FheScalarRotateLeft {
        kind: FheIntKind,
    },
    FheScalarRotateRight {
        kind: FheIntKind,
    },

    // Scalar bitwise — FheKind. Clear operand flows in as the
    // second input (typically produced by a `Constant` op).
    FheScalarBitAnd {
        kind: FheKind,
    },
    FheScalarBitOr {
        kind: FheKind,
    },
    FheScalarBitXor {
        kind: FheKind,
    },

    // Scalar equality — FheKind, returns FheBool. Clear operand
    // flows in as the second input.
    FheScalarEq {
        kind: FheKind,
    },
    FheScalarNe {
        kind: FheKind,
    },

    // Scalar ordering — FheIntKind, returns FheBool. `FheScalar*` variants put
    // the clear operand second; `ScalarFhe*` variants put it first (to
    // capture the `clear OP fhe` direction).
    FheScalarLt {
        kind: FheIntKind,
    },
    FheScalarLe {
        kind: FheIntKind,
    },
    FheScalarGt {
        kind: FheIntKind,
    },
    FheScalarGe {
        kind: FheIntKind,
    },
    ScalarFheLt {
        kind: FheIntKind,
    },
    ScalarFheLe {
        kind: FheIntKind,
    },
    ScalarFheGt {
        kind: FheIntKind,
    },
    ScalarFheGe {
        kind: FheIntKind,
    },

    /// LUT-based match: returns the LUT-mapped output and a `FheBool` that
    /// is `true` iff the input matched one of the LUT keys. Only unsigned
    /// values are supported. `input_bits` is the input `FheUint` width;
    /// `output_bits` is the output `FheUint` width — sized by the builder
    /// to fit the LUT's maximum output value (rounded up to a whole number
    /// of message blocks), mirroring `match_value_parallelized`'s runtime
    /// output sizing.
    MatchValue {
        // u128 should be enough; more than 2**10 LUT entries is impractical anyway.
        lut: MatchValues<u128>,
        input_bits: usize,
        output_bits: usize,
    },

    /// Oblivious pseudo-random generation: arity-1 op producing a random
    /// ciphertext of the given `value_kind` from a runtime `Seed` input and a
    /// `mode` (full / bounded / custom-range).
    /// Signature: `(Seed) -> value_kind`.
    /// The seed is a runtime value (not an op field) so a fresh seed can be
    /// supplied per execution without rebuilding the circuit.
    /// Validity of `(value_kind, mode)` is enforced by the builder.
    FheOprf {
        value_kind: ValueKind,
        mode: OprfMode,
    },

    /// Membership test against an encrypted haystack with an encrypted needle.
    /// Signature: `(needle, h_0, h_1, ..., h_{n-1}) -> FheBool`.
    /// All `n + 1` inputs must share the same `kind`. Maps to integer-layer
    /// `contains_parallelized`. Builder rejects `n == 0`.
    FheContains {
        kind: FheIntKind,
        n: u32,
    },
    /// Membership test against an encrypted haystack with a clear needle.
    /// Signature: `(clear_needle, h_0, h_1, ..., h_{n-1}) -> FheBool`
    /// (needle-first, mirroring `FheContains`).
    /// Maps to integer-layer `contains_clear_parallelized`. Builder rejects
    /// `n == 0`.
    FheContainsScalar {
        kind: FheIntKind,
        n: u32,
    },

    /// KVStore:
    ///
    /// A 'specialized' HashMap that maps clear values (u32, u64, etc) to encrypted integers
    /// and allows querying and modifying using an encrypted key.

    /// Create an empty store with the given types
    KVStoreCreate {
        key_kind: KvKeyKind,
        value_kind: FheIntKind,
    },

    /// Insert `value` at the clear-key payload, replacing any existing
    /// entry. Signature: `(store, value) -> (store')`.
    KVStoreInsertWithClearKey {
        key_kind: KvKeyKind,
        value_kind: FheIntKind,
        clear_key: KvKey,
    },

    /// Read the slot at the clear-key payload. Returns `(value, was_present)`
    /// — when the key isn't present, `value` is implementation-defined
    /// (executor's default ciphertext). `was_present` is a *clear* `Bool`,
    /// since the lookup is on a clear key. Signature: `(store) -> (value, Bool)`.
    KVStoreGetWithClearKey {
        key_kind: KvKeyKind,
        value_kind: FheIntKind,
        clear_key: KvKey,
    },

    /// Remove the entry at the clear-key payload (no-op if absent).
    /// Signature: `(store) -> (store')`.
    KVStoreRemoveWithClearKey {
        key_kind: KvKeyKind,
        value_kind: FheIntKind,
        clear_key: KvKey,
    },

    /// Read the slot addressed by an encrypted key. Returns
    /// `(value, was_present)`. Signature: `(store, FheUint(N)) -> (value, FheBool)`
    /// where N matches `key_kind.fhe_uint_bits()`.
    KVStoreGet {
        key_kind: KvKeyKind,
        value_kind: FheIntKind,
    },

    /// Replace the value at the slot addressed by an encrypted key.
    /// `was_present` is true iff the key was found in the store; otherwise
    /// the store is unchanged. Signature:
    /// `(store, FheUint(N), new_value) -> (store', FheBool)`.
    KVStoreUpdate {
        key_kind: KvKeyKind,
        value_kind: FheIntKind,
    },
}

impl HlInstructionSet {
    /// Construct a [`HlInstructionSet::Constant`] op, normalizing `value`
    /// for the requested clear `kind`.
    ///
    /// Returns `None` if `value` does not fit `kind` (e.g.
    /// `ScalarValue::Signed(-1)` is rejected for `ClearKind::Uint(8)`).
    pub fn constant(kind: ClearKind, value: ScalarValue) -> Option<Self> {
        let normalized = value.normalize_for(kind.into())?;
        Some(Self::Constant {
            kind,
            value: normalized,
        })
    }

    /// Stable diagnostic name for logs and panic messages.
    pub fn name(&self) -> &'static str {
        #[allow(clippy::enum_glob_use, reason = "Glob is fine here")]
        use HlInstructionSet::*;
        match self {
            Input { .. } => "Input",
            Output { .. } => "Output",
            EncryptTrivial { .. } => "EncryptTrivial",
            Constant { .. } => "Constant",
            FheAdd { .. } => "FheAdd",
            FheSub { .. } => "FheSub",
            FheMul { .. } => "FheMul",
            FheDiv { .. } => "FheDiv",
            FheRem { .. } => "FheRem",
            FheMin { .. } => "FheMin",
            FheMax { .. } => "FheMax",
            FheNeg { .. } => "FheNeg",
            FheSum { .. } => "FheSum",
            FheIsEven { .. } => "FheIsEven",
            FheIsOdd { .. } => "FheIsOdd",
            FheLeadingZeros { .. } => "FheLeadingZeros",
            FheLeadingOnes { .. } => "FheLeadingOnes",
            FheTrailingZeros { .. } => "FheTrailingZeros",
            FheTrailingOnes { .. } => "FheTrailingOnes",
            FheCountOnes { .. } => "FheCountOnes",
            FheCountZeros { .. } => "FheCountZeros",
            FheIlog2 { .. } => "FheIlog2",
            FheCheckedIlog2 { .. } => "FheCheckedIlog2",
            FheReverseBits { .. } => "FheReverseBits",
            FheAbs { .. } => "FheAbs",
            FheBitAnd { .. } => "FheBitAnd",
            FheBitOr { .. } => "FheBitOr",
            FheBitXor { .. } => "FheBitXor",
            FheNot { .. } => "FheNot",
            FheEq { .. } => "FheEq",
            FheNe { .. } => "FheNe",
            FheLt { .. } => "FheLt",
            FheLe { .. } => "FheLe",
            FheGt { .. } => "FheGt",
            FheGe { .. } => "FheGe",
            FheShl { .. } => "FheShl",
            FheShr { .. } => "FheShr",
            FheRotateLeft { .. } => "FheRotateLeft",
            FheRotateRight { .. } => "FheRotateRight",
            FheOverflowingAdd { .. } => "FheOverflowingAdd",
            FheOverflowingSub { .. } => "FheOverflowingSub",
            FheOverflowingMul { .. } => "FheOverflowingMul",
            FheOverflowingNeg { .. } => "FheOverflowingNeg",
            FheScalarOverflowingAdd { .. } => "FheScalarOverflowingAdd",
            FheScalarOverflowingSub { .. } => "FheScalarOverflowingSub",
            FheDivRem { .. } => "FheDivRem",
            FheCast { .. } => "FheCast",
            Select { .. } => "Select",
            FheFlip { .. } => "FheFlip",
            SelectScalarScalar { .. } => "SelectScalarScalar",
            SelectFheScalar { .. } => "SelectFheScalar",
            SelectScalarFhe { .. } => "SelectScalarFhe",
            Compress { .. } => "Compress",
            Decompress { .. } => "Decompress",
            FheScalarAdd { .. } => "FheScalarAdd",
            FheScalarSub { .. } => "FheScalarSub",
            ScalarFheSub { .. } => "ScalarFheSub",
            FheScalarMul { .. } => "FheScalarMul",
            FheScalarDiv { .. } => "FheScalarDiv",
            FheScalarRem { .. } => "FheScalarRem",
            FheScalarMin { .. } => "FheScalarMin",
            FheScalarMax { .. } => "FheScalarMax",
            FheScalarShl { .. } => "FheScalarShl",
            FheScalarShr { .. } => "FheScalarShr",
            FheScalarRotateLeft { .. } => "FheScalarRotateLeft",
            FheScalarRotateRight { .. } => "FheScalarRotateRight",
            FheScalarBitAnd { .. } => "FheScalarBitAnd",
            FheScalarBitOr { .. } => "FheScalarBitOr",
            FheScalarBitXor { .. } => "FheScalarBitXor",
            FheScalarEq { .. } => "FheScalarEq",
            FheScalarNe { .. } => "FheScalarNe",
            FheScalarLt { .. } => "FheScalarLt",
            FheScalarLe { .. } => "FheScalarLe",
            FheScalarGt { .. } => "FheScalarGt",
            FheScalarGe { .. } => "FheScalarGe",
            ScalarFheLt { .. } => "ScalarFheLt",
            ScalarFheLe { .. } => "ScalarFheLe",
            ScalarFheGt { .. } => "ScalarFheGt",
            ScalarFheGe { .. } => "ScalarFheGe",
            MatchValue { .. } => "MatchValue",
            FheOprf { .. } => "FheOprf",
            FheContains { .. } => "FheContains",
            FheContainsScalar { .. } => "FheContainsScalar",
            KVStoreCreate { .. } => "KVStoreCreate",
            KVStoreInsertWithClearKey { .. } => "KVStoreInsertWithClearKey",
            KVStoreGetWithClearKey { .. } => "KVStoreGetWithClearKey",
            KVStoreRemoveWithClearKey { .. } => "KVStoreRemoveWithClearKey",
            KVStoreGet { .. } => "KVStoreGet",
            KVStoreUpdate { .. } => "KVStoreUpdate",
        }
    }
}

impl DialectInstructionSet for HlInstructionSet {
    type TypeSystem = ValueKind;

    fn get_signature(&self) -> Signature<ValueKind> {
        #[allow(clippy::enum_glob_use, reason = "Glob is fine here")]
        use HlInstructionSet::*;
        match self {
            // Boundary
            Input { kind, .. } => sig![() -> (*kind)],
            Output { kind, .. } => sig![(*kind) -> ()],
            EncryptTrivial { kind } => {
                sig![(kind.as_clear_value_kind()) -> ((*kind).into())]
            }
            Constant { kind, .. } => sig![() -> ((*kind).into())],

            // Binary arithmetic / min-max — same in/out type
            FheAdd { kind }
            | FheSub { kind }
            | FheMul { kind }
            | FheDiv { kind }
            | FheRem { kind }
            | FheMin { kind }
            | FheMax { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t, t) -> (t)]
            }

            // Unary arithmetic
            FheNeg { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t) -> (t)]
            }

            // Unary parity predicates — return FheBool
            FheIsEven { kind } | FheIsOdd { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t) -> (ValueKind::FheBool)]
            }

            // Bit-counting / log ops — return FheUint(32)
            FheLeadingZeros { kind }
            | FheLeadingOnes { kind }
            | FheTrailingZeros { kind }
            | FheTrailingOnes { kind }
            | FheCountOnes { kind }
            | FheCountZeros { kind }
            | FheIlog2 { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t) -> (ValueKind::FheUint(32))]
            }

            // checked_ilog2 — (FheUint(32), FheBool)
            FheCheckedIlog2 { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t) -> (ValueKind::FheUint(32), ValueKind::FheBool)]
            }

            // Same input/output type
            FheReverseBits { kind } | FheAbs { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t) -> (t)]
            }

            // Variadic sum — n same-typed inputs, one output of same type
            FheSum { kind, n } => {
                let t: ValueKind = (*kind).into();
                let args: zhc_utils::small::SmallVec<ValueKind> =
                    std::iter::repeat_n(t, *n as usize).collect();
                let rets = svec![t];
                Signature(args, rets)
            }

            // Binary bitwise — same in/out type
            FheBitAnd { kind } | FheBitOr { kind } | FheBitXor { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t, t) -> (t)]
            }

            // Unary bitwise
            FheNot { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t) -> (t)]
            }

            // Equality — input pair → FheBool
            FheEq { kind } | FheNe { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t, t) -> (ValueKind::FheBool)]
            }

            // Ordering — FheIntKind pair → FheBool
            FheLt { kind } | FheLe { kind } | FheGt { kind } | FheGe { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t, t) -> (ValueKind::FheBool)]
            }

            // Shifts/rotates — (lhs_kind, FheUint(rhs_bits)) → lhs_kind
            FheShl { lhs_kind, rhs_bits }
            | FheShr { lhs_kind, rhs_bits }
            | FheRotateLeft { lhs_kind, rhs_bits }
            | FheRotateRight { lhs_kind, rhs_bits } => {
                let t: ValueKind = (*lhs_kind).into();
                let rhs = ValueKind::FheUint(*rhs_bits as usize);
                sig![(t, rhs) -> (t)]
            }

            // Overflowing — pair → (kind, FheBool)
            FheOverflowingAdd { kind }
            | FheOverflowingSub { kind }
            | FheOverflowingMul { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t, t) -> (t, ValueKind::FheBool)]
            }

            // Unary overflowing → (kind, FheBool)
            FheOverflowingNeg { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t) -> (t, ValueKind::FheBool)]
            }

            // Scalar overflowing → (fhe, clear) -> (kind, FheBool).
            FheScalarOverflowingAdd { kind } | FheScalarOverflowingSub { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(t, c) -> (t, ValueKind::FheBool)]
            }

            // Fused div+rem — (t, t) -> (t, t)
            FheDivRem { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(t, t) -> (t, t)]
            }

            // Cast
            FheCast { from, to } => sig![((*from).into()) -> ((*to).into())],

            // Select — (FheBool, kind, kind) → kind
            Select { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(ValueKind::FheBool, t, t) -> (t)]
            }
            // FheFlip — (FheBool, kind, kind) → (kind, kind)
            FheFlip { kind } => {
                let t: ValueKind = (*kind).into();
                sig![(ValueKind::FheBool, t, t) -> (t, t)]
            }
            // SelectScalarScalar — (FheBool, clear, clear) → kind
            SelectScalarScalar { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(ValueKind::FheBool, c, c) -> (t)]
            }
            // SelectFheScalar — (FheBool, kind, clear) → kind
            SelectFheScalar { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(ValueKind::FheBool, t, c) -> (t)]
            }
            // SelectScalarFhe — (FheBool, clear, kind) → kind
            SelectScalarFhe { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(ValueKind::FheBool, c, t) -> (t)]
            }

            // Compress — N inputs → CompressedList
            Compress { input_kinds } => {
                let args: zhc_utils::small::SmallVec<ValueKind> =
                    input_kinds.iter().map(|k| (*k).into()).collect();
                let rets = svec![ValueKind::CompressedList];
                Signature(args, rets)
            }

            // Decompress — CompressedList → N outputs (one per pick)
            Decompress { picks } => {
                let args = svec![ValueKind::CompressedList];
                let rets: zhc_utils::small::SmallVec<ValueKind> =
                    picks.iter().map(|(_, k)| (*k).into()).collect();
                Signature(args, rets)
            }

            // Scalar arithmetic / shift / rotate / min-max — (fhe, clear) → fhe
            FheScalarAdd { kind }
            | FheScalarSub { kind }
            | FheScalarMul { kind }
            | FheScalarDiv { kind }
            | FheScalarRem { kind }
            | FheScalarMin { kind }
            | FheScalarMax { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(t, c) -> (t)]
            }
            // Shift/rotate amounts are unsigned counts, see
            // `FheIntKind::as_unsigned_clear_kind`.
            FheScalarShl { kind }
            | FheScalarShr { kind }
            | FheScalarRotateLeft { kind }
            | FheScalarRotateRight { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_unsigned_clear_value_kind();
                sig![(t, c) -> (t)]
            }
            // `clear - fhe` — clear operand first, fhe second
            ScalarFheSub { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(c, t) -> (t)]
            }

            // Scalar bitwise — (fhe, clear) → fhe
            FheScalarBitAnd { kind } | FheScalarBitOr { kind } | FheScalarBitXor { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(t, c) -> (t)]
            }

            // Scalar equality — (fhe, clear) → FheBool
            FheScalarEq { kind } | FheScalarNe { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(t, c) -> (ValueKind::FheBool)]
            }

            // `FheScalar*` ordering — (fhe, clear) → FheBool
            FheScalarLt { kind }
            | FheScalarLe { kind }
            | FheScalarGt { kind }
            | FheScalarGe { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(t, c) -> (ValueKind::FheBool)]
            }
            // `ScalarFhe*` ordering — (clear, fhe) → FheBool
            ScalarFheLt { kind }
            | ScalarFheLe { kind }
            | ScalarFheGt { kind }
            | ScalarFheGe { kind } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                sig![(c, t) -> (ValueKind::FheBool)]
            }
            MatchValue {
                input_bits,
                output_bits,
                ..
            } => {
                let i = ValueKind::FheUint(*input_bits);
                let o = ValueKind::FheUint(*output_bits);
                sig![(i) -> (o, ValueKind::FheBool)]
            }
            FheOprf { value_kind, .. } => sig![(ValueKind::Seed) -> (*value_kind)],
            FheContains { kind, n } => {
                let t: ValueKind = (*kind).into();
                let mut args: zhc_utils::small::SmallVec<ValueKind> = svec![t];
                for _ in 0..*n {
                    args.push(t);
                }
                Signature(args, svec![ValueKind::FheBool])
            }
            FheContainsScalar { kind, n } => {
                let t: ValueKind = (*kind).into();
                let c: ValueKind = kind.as_clear_value_kind();
                let mut args: zhc_utils::small::SmallVec<ValueKind> = svec![c];
                for _ in 0..*n {
                    args.push(t);
                }
                Signature(args, svec![ValueKind::FheBool])
            }
            KVStoreCreate {
                key_kind,
                value_kind,
            } => {
                sig![() -> (ValueKind::KVStore { key: *key_kind, value: *value_kind })]
            }
            KVStoreInsertWithClearKey {
                key_kind,
                value_kind,
                ..
            } => {
                let store = ValueKind::KVStore {
                    key: *key_kind,
                    value: *value_kind,
                };
                let v: ValueKind = (*value_kind).into();
                sig![(store, v) -> (store)]
            }
            KVStoreGetWithClearKey {
                key_kind,
                value_kind,
                ..
            } => {
                let store = ValueKind::KVStore {
                    key: *key_kind,
                    value: *value_kind,
                };
                let v: ValueKind = (*value_kind).into();
                // Clear `Bool` for the was-present signal — the lookup is on a
                // clear key, so the answer is known clear-side and doesn't need
                // a trivially-encrypted FheBool.
                sig![(store) -> (v, ValueKind::Bool)]
            }
            KVStoreRemoveWithClearKey {
                key_kind,
                value_kind,
                ..
            } => {
                let store = ValueKind::KVStore {
                    key: *key_kind,
                    value: *value_kind,
                };
                sig![(store) -> (store)]
            }
            KVStoreGet {
                key_kind,
                value_kind,
            } => {
                let store = ValueKind::KVStore {
                    key: *key_kind,
                    value: *value_kind,
                };
                let encrypted_key = ValueKind::FheUint(key_kind.bits());
                let v: ValueKind = (*value_kind).into();
                sig![(store, encrypted_key) -> (v, ValueKind::FheBool)]
            }
            KVStoreUpdate {
                key_kind,
                value_kind,
            } => {
                let store = ValueKind::KVStore {
                    key: *key_kind,
                    value: *value_kind,
                };
                let encrypted_key = ValueKind::FheUint(key_kind.bits());
                let v: ValueKind = (*value_kind).into();
                sig![(store, encrypted_key, v) -> (store, ValueKind::FheBool)]
            }
        }
    }
}

impl Format for ValueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _ctx: &FormatContext) -> std::fmt::Result {
        match self {
            Self::FheUint(bits) => write!(f, "FheUint<{bits}>"),
            Self::FheInt(bits) => write!(f, "FheInt<{bits}>"),
            Self::FheBool => write!(f, "FheBool"),
            Self::Bool => write!(f, "Bool"),
            Self::Uint(bits) => write!(f, "Uint<{bits}>"),
            Self::Int(bits) => write!(f, "Int<{bits}>"),
            Self::CompressedList => write!(f, "CompressedList"),
            Self::KVStore { key, value } => write!(f, "KVStore<{key:?}, {value:?}>"),
            Self::Seed => write!(f, "Seed"),
        }
    }
}

impl Format for ScalarValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _ctx: &FormatContext) -> std::fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "bool:{v}"),
            Self::Unsigned(v) => write!(f, "u:{v}"),
            Self::Signed(v) => write!(f, "i:{v}"),
        }
    }
}

impl Format for FheIntKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _ctx: &FormatContext) -> std::fmt::Result {
        match self {
            Self::Uint(n) => write!(f, "Uint<{n}>"),
            Self::Int(n) => write!(f, "Int<{n}>"),
        }
    }
}

impl Format for FheKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _ctx: &FormatContext) -> std::fmt::Result {
        match self {
            Self::Uint(n) => write!(f, "Uint<{n}>"),
            Self::Int(n) => write!(f, "Int<{n}>"),
            Self::Bool => write!(f, "Bool"),
        }
    }
}

impl Format for ClearKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _ctx: &FormatContext) -> std::fmt::Result {
        match self {
            Self::Uint(n) => write!(f, "Uint<{n}>"),
            Self::Int(n) => write!(f, "Int<{n}>"),
            Self::Bool => write!(f, "Bool"),
        }
    }
}

impl Format for HlInstructionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, ctx: &FormatContext) -> std::fmt::Result {
        #[allow(clippy::enum_glob_use, reason = "Glob is fine here")]
        use HlInstructionSet::*;
        let name = self.name();
        match self {
            // Boundary
            Input { pos, kind } => {
                write!(f, "{name}<{pos}, ")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }
            Output { pos, kind } => {
                write!(f, "{name}<{pos}, ")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }
            EncryptTrivial { kind } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }
            Constant { kind, value } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ", ")?;
                Format::fmt(value, f, ctx)?;
                write!(f, ">")
            }

            // FheIntKind-only payload
            FheAdd { kind }
            | FheSub { kind }
            | FheMul { kind }
            | FheDiv { kind }
            | FheRem { kind }
            | FheMin { kind }
            | FheMax { kind }
            | FheNeg { kind }
            | FheLt { kind }
            | FheLe { kind }
            | FheGt { kind }
            | FheGe { kind }
            | FheOverflowingAdd { kind }
            | FheOverflowingSub { kind }
            | FheOverflowingMul { kind }
            | FheOverflowingNeg { kind }
            | FheDivRem { kind }
            | FheIsEven { kind }
            | FheIsOdd { kind }
            | FheLeadingZeros { kind }
            | FheLeadingOnes { kind }
            | FheTrailingZeros { kind }
            | FheTrailingOnes { kind }
            | FheCountOnes { kind }
            | FheCountZeros { kind }
            | FheIlog2 { kind }
            | FheCheckedIlog2 { kind }
            | FheReverseBits { kind }
            | FheAbs { kind }
            | Select { kind }
            | FheFlip { kind } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }

            // FheSum: kind + arity
            FheSum { kind, n } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ", {n}>")
            }

            // FheKind-only payload
            FheBitAnd { kind }
            | FheBitOr { kind }
            | FheBitXor { kind }
            | FheNot { kind }
            | FheEq { kind }
            | FheNe { kind } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }

            // Shifts: lhs_kind + rhs_bits
            FheShl { lhs_kind, rhs_bits }
            | FheShr { lhs_kind, rhs_bits }
            | FheRotateLeft { lhs_kind, rhs_bits }
            | FheRotateRight { lhs_kind, rhs_bits } => {
                write!(f, "{name}<")?;
                Format::fmt(lhs_kind, f, ctx)?;
                write!(f, ", {rhs_bits}>")
            }

            FheCast { from, to } => {
                write!(f, "{name}<")?;
                Format::fmt(from, f, ctx)?;
                write!(f, " -> ")?;
                Format::fmt(to, f, ctx)?;
                write!(f, ">")
            }

            Compress { input_kinds } => {
                write!(f, "{name}<")?;
                let mut first = true;
                for k in input_kinds {
                    if !first {
                        write!(f, ", ")?;
                    }
                    first = false;
                    Format::fmt(k, f, ctx)?;
                }
                write!(f, ">")
            }
            Decompress { picks } => {
                write!(f, "{name}<")?;
                let mut first = true;
                for (idx, k) in picks {
                    if !first {
                        write!(f, ", ")?;
                    }
                    first = false;
                    write!(f, "{idx}:")?;
                    Format::fmt(k, f, ctx)?;
                }
                write!(f, ">")
            }

            // Scalar variants — kind only (clear operand flows in as input)
            FheScalarAdd { kind }
            | FheScalarSub { kind }
            | ScalarFheSub { kind }
            | FheScalarMul { kind }
            | FheScalarDiv { kind }
            | FheScalarRem { kind }
            | FheScalarMin { kind }
            | FheScalarMax { kind }
            | FheScalarShl { kind }
            | FheScalarShr { kind }
            | FheScalarRotateLeft { kind }
            | FheScalarRotateRight { kind } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }

            // Scalar ordering — kind only (clear operand flows in as input)
            FheScalarLt { kind }
            | FheScalarLe { kind }
            | FheScalarGt { kind }
            | FheScalarGe { kind }
            | ScalarFheLt { kind }
            | ScalarFheLe { kind }
            | ScalarFheGt { kind }
            | ScalarFheGe { kind } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }

            // Scalar overflowing — kind only
            FheScalarOverflowingAdd { kind } | FheScalarOverflowingSub { kind } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }

            // Scalar bitwise — kind only
            FheScalarBitAnd { kind } | FheScalarBitOr { kind } | FheScalarBitXor { kind } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }

            // Scalar equality — kind only
            FheScalarEq { kind } | FheScalarNe { kind } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }
            SelectScalarScalar { kind } | SelectFheScalar { kind } | SelectScalarFhe { kind } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ">")
            }
            MatchValue {
                input_bits,
                output_bits,
                ..
            } => {
                write!(f, "{name}<FheUint<{input_bits}> -> FheUint<{output_bits}>>")
            }
            FheOprf { value_kind, mode } => {
                write!(f, "{name}<")?;
                Format::fmt(value_kind, f, ctx)?;
                write!(f, ", mode:{}>", mode.name())
            }
            FheContains { kind, n } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ", n={n}>")
            }
            FheContainsScalar { kind, n } => {
                write!(f, "{name}<")?;
                Format::fmt(kind, f, ctx)?;
                write!(f, ", n={n}>")
            }
            KVStoreCreate {
                key_kind,
                value_kind,
            } => {
                write!(f, "{name}<")?;
                Format::fmt(
                    &ValueKind::KVStore {
                        key: *key_kind,
                        value: *value_kind,
                    },
                    f,
                    ctx,
                )?;
                write!(f, ">")
            }
            KVStoreInsertWithClearKey {
                key_kind,
                value_kind,
                clear_key,
            }
            | KVStoreGetWithClearKey {
                key_kind,
                value_kind,
                clear_key,
            }
            | KVStoreRemoveWithClearKey {
                key_kind,
                value_kind,
                clear_key,
            } => {
                write!(f, "{name}<")?;
                Format::fmt(
                    &ValueKind::KVStore {
                        key: *key_kind,
                        value: *value_kind,
                    },
                    f,
                    ctx,
                )?;
                write!(f, ", {clear_key:?}>")
            }
            KVStoreGet {
                key_kind,
                value_kind,
            }
            | KVStoreUpdate {
                key_kind,
                value_kind,
            } => {
                write!(f, "{name}<")?;
                Format::fmt(
                    &ValueKind::KVStore {
                        key: *key_kind,
                        value: *value_kind,
                    },
                    f,
                    ctx,
                )?;
                write!(f, ">")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zhc_ir::DisplayFormat;

    #[test]
    fn fhe_add_signature() {
        let op = HlInstructionSet::FheAdd {
            kind: FheIntKind::Uint(32),
        };
        let sig = op.get_signature();
        assert_eq!(
            sig,
            sig![(ValueKind::FheUint(32), ValueKind::FheUint(32)) -> (ValueKind::FheUint(32))]
        );
    }

    #[test]
    fn fhe_eq_bool_signature() {
        let op = HlInstructionSet::FheEq {
            kind: FheKind::Bool,
        };
        let sig = op.get_signature();
        assert_eq!(
            sig,
            sig![(ValueKind::FheBool, ValueKind::FheBool) -> (ValueKind::FheBool)]
        );
    }

    #[test]
    fn fhe_shl_mixed_signature() {
        let op = HlInstructionSet::FheShl {
            lhs_kind: FheIntKind::Int(64),
            rhs_bits: 32,
        };
        let sig = op.get_signature();
        assert_eq!(
            sig,
            sig![(ValueKind::FheInt(64), ValueKind::FheUint(32)) -> (ValueKind::FheInt(64))]
        );
    }

    #[test]
    fn fhe_overflowing_add_signature() {
        let op = HlInstructionSet::FheOverflowingAdd {
            kind: FheIntKind::Uint(8),
        };
        let sig = op.get_signature();
        assert_eq!(
            sig,
            sig![(ValueKind::FheUint(8), ValueKind::FheUint(8)) -> (ValueKind::FheUint(8), ValueKind::FheBool)]
        );
    }

    #[test]
    fn fhe_sum_variadic_signature() {
        let op = HlInstructionSet::FheSum {
            kind: FheIntKind::Int(16),
            n: 5,
        };
        let sig = op.get_signature();
        assert_eq!(sig.get_args_arity(), 5);
        assert_eq!(sig.get_returns_arity(), 1);
        assert!(sig.get_args().iter().all(|t| *t == ValueKind::FheInt(16)));
        assert_eq!(sig.get_returns()[0], ValueKind::FheInt(16));
    }

    #[test]
    fn compress_signature() {
        let op = HlInstructionSet::Compress {
            input_kinds: vec![FheKind::Uint(32), FheKind::Bool],
        };
        let sig = op.get_signature();
        assert_eq!(
            sig,
            sig![(ValueKind::FheUint(32), ValueKind::FheBool) -> (ValueKind::CompressedList)]
        );
    }

    #[test]
    fn decompress_signature() {
        // Pick item 0 as Bool, item 3 as Int(16); outputs are produced in pick order.
        let op = HlInstructionSet::Decompress {
            picks: vec![(0, FheKind::Bool), (3, FheKind::Int(16))],
        };
        let sig = op.get_signature();
        assert_eq!(
            sig,
            sig![(ValueKind::CompressedList) -> (ValueKind::FheBool, ValueKind::FheInt(16))]
        );
    }

    #[test]
    fn cast_signature() {
        let op = HlInstructionSet::FheCast {
            from: FheKind::Bool,
            to: FheKind::Uint(32),
        };
        let sig = op.get_signature();
        assert_eq!(sig, sig![(ValueKind::FheBool) -> (ValueKind::FheUint(32))]);
    }

    #[test]
    fn if_then_else_signature() {
        let op = HlInstructionSet::Select {
            kind: FheIntKind::Int(64),
        };
        let sig = op.get_signature();
        assert_eq!(
            sig,
            sig![(ValueKind::FheBool, ValueKind::FheInt(64), ValueKind::FheInt(64)) -> (ValueKind::FheInt(64))]
        );
    }

    #[test]
    fn match_value_signature() {
        // u8 -> u8 LUT (e.g. an AES S-box shape). max output 200 fits in 8 bits.
        let lut =
            MatchValues::new(vec![(0u128, 5u128), (1u128, 200u128), (42u128, 17u128)]).unwrap();
        let op = HlInstructionSet::MatchValue {
            lut,
            input_bits: 8,
            output_bits: 8,
        };
        let sig = op.get_signature();
        assert_eq!(
            sig,
            sig![(ValueKind::FheUint(8)) -> (ValueKind::FheUint(8), ValueKind::FheBool)]
        );
    }

    #[test]
    fn scalar_eq_bool_signature() {
        let op = HlInstructionSet::FheScalarEq {
            kind: FheKind::Bool,
        };
        let sig = op.get_signature();
        assert_eq!(
            sig,
            sig![(ValueKind::FheBool, ValueKind::Bool) -> (ValueKind::FheBool)]
        );
    }

    #[test]
    fn format_renders_meaningfully() {
        let op = HlInstructionSet::FheAdd {
            kind: FheIntKind::Uint(32),
        };
        let s = format!("{}", DisplayFormat(&op));
        assert!(s.contains("FheAdd"));
        assert!(s.contains("Uint<32>"));
    }
}
