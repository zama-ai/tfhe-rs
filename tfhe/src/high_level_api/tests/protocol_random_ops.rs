//! Random operation sequence version of the protocol stress test.
//!
//! Where `gpu_protocol_long_run` runs the fixed ERC-7984 transfer graph, this test draws every
//! transaction as a random straight-line program over the operations the FHEVM host executor
//! accepts, and runs it through the same protocol workflow: inputs are encrypted with metadata,
//! stored compressed, loaded back, every node re-randomizes its own operands before being
//! evaluated, the whole graph is evaluated twice to check determinism, and the results travel
//! through compression and noise squashing before the final decryption.
//!
//! Every node is mirrored by a clear evaluation, and every produced value is decrypted and
//! compared against its clear counterpart, so a failure names the exact node that diverged.
//!
//! The operation pool covers the whole host executor registry: the binary, comparison and unary
//! operators (opcodes 0 to 21), cast (23), trivial encryption (24), selection (25), randomness
//! (26 and 27), sum (28), set membership (29) and the fused multiply-divide (30). The
//! executor's typing rules are enforced throughout: a binary operation takes either two
//! encrypted operands of exactly the same type or an encrypted operand and a clear scalar of
//! that type, division, remainder and the fused divisor only accept nonzero clear scalars, and
//! the per-type operator sets follow the registry. U256 only exists for bitwise operations,
//! shifts and rotations, equality, negation, not, selection, membership, casts and trivial
//! encryption; U160 (eaddress) only for equality, selection, membership and trivial encryption.
//! Width mixing happens the way the executor allows it, through explicit cast nodes; the FHE
//! calls mirror the coprocessor dispatch in `fhevm-engine-common/src/tfhe_ops.rs` (`select`,
//! `cast_into`, `try_encrypt_trivial`, iterator sum, `contains`, `fused_mul_scalar_div`,
//! `generate_oblivious_pseudo_random(_bounded)`).
//!
//! Randomness has no clear oracle: a rand node is checked for range (strictly below the bound,
//! which the registry restricts to a positive power of two — the executor's `floor(log2)` bound
//! decoding is only correct for those) and for determinism, the same seed producing the very
//! same ciphertext in the double evaluation. The decrypted rand value then seeds the clear
//! evaluation, so every node downstream of a rand node is still checked exactly.
//!
//! # Reproducibility
//!
//! A whole run replays from `TFHE_RS_LONGRUN_TESTS_SEED`, like the other long run tests. On top
//! of that, every transaction encrypts under its own seed, and when a transaction fails the test
//! writes a self contained JSON report: the parameter set name, the key generation seeds, the
//! transaction encryption seed, and the full graph with its clear input values and scalars.
//! Pointing `TFHE_RS_PROTOCOL_REPLAY` at that file and running the replay test re-executes that
//! single transaction, keys included, without re-running the whole campaign. Next to the failure
//! reports, every run also keeps a rolling trace of its most recent transactions
//! (`protocol_random_ops_recent_slot*.json`), written before each transaction runs and in the
//! same replayable format, so a crash that never reaches the failure path still leaves the
//! executing graphs behind. A replay runs step
//! by step: it decrypts right after every node and prints the decrypted value against the clear
//! one, so the first node that diverges is named even when later nodes consume its corrupted
//! result.

use super::protocol_workflow_common::{
    generate_protocol_keys, install_seeded_engine, node_re_randomization_context, num_transactions,
    random_bytes, re_randomize_operand, run_duration, ProtocolKeys, METADATA_LEN,
};
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::high_level_api::prelude::*;
use crate::integer::server_key::radix_parallel::tests_long_run::get_user_defined_seed;
use crate::integer::U256 as TfheU256;
use crate::shortint::parameters::test_params::{
    TEST_LEGACY_RERAND_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_LEGACY_RERAND_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::MetaParameters;
use crate::{
    ClientKey, CompactPublicKey, CompressedCiphertextListBuilder, CompressedServerKey,
    CompressedSquashedNoiseCiphertextListBuilder, Config, FheBool, FheUint128, FheUint16,
    FheUint160, FheUint256, FheUint32, FheUint64, FheUint8, ReRandomizationContext,
    ReRandomizationSeedGen, SquashedNoiseFheBool, SquashedNoiseFheUint,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::{Seed, Seeder};

/// The bit widths the transaction inputs can be drawn over: the executor's arithmetic type set
/// `A`. The other value types (Bool, U160, U256) enter a transaction through comparisons, casts
/// and trivial encryptions.
pub(crate) const INPUT_WIDTHS: [u32; 5] = [8, 16, 32, 64, 128];

/// Encrypted inputs of a transaction, all of the transaction's primary width.
const NUM_INPUTS: usize = 3;
/// Bounds on the number of operations of a transaction.
const MIN_NODES: usize = 5;
const MAX_NODES: usize = 10;

/// The eight value types the host executor exposes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ValueType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U160,
    U256,
}

impl ValueType {
    fn bits(self) -> u32 {
        match self {
            Self::Bool => 1,
            Self::U8 => 8,
            Self::U16 => 16,
            Self::U32 => 32,
            Self::U64 => 64,
            Self::U128 => 128,
            Self::U160 => 160,
            Self::U256 => 256,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::U160 => "u160",
            Self::U256 => "u256",
        }
    }

    fn from_width(width: u32) -> Option<Self> {
        match width {
            8 => Some(Self::U8),
            16 => Some(Self::U16),
            32 => Some(Self::U32),
            64 => Some(Self::U64),
            128 => Some(Self::U128),
            _ => None,
        }
    }

    fn mask(self) -> ClearInt {
        match self {
            Self::Bool => ClearInt { lo: 1, hi: 0 },
            Self::U256 => ClearInt {
                lo: u128::MAX,
                hi: u128::MAX,
            },
            Self::U160 => ClearInt {
                lo: u128::MAX,
                hi: (1u128 << 32) - 1,
            },
            other => ClearInt {
                lo: if other.bits() == 128 {
                    u128::MAX
                } else {
                    (1u128 << other.bits()) - 1
                },
                hi: 0,
            },
        }
    }

    /// The executor's arithmetic type set `A`, also the admissible sum element types.
    fn is_arithmetic(self) -> bool {
        matches!(
            self,
            Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::U128
        )
    }

    /// The admissible membership value types: `N ∪ {U160}`.
    fn is_membership(self) -> bool {
        self.is_arithmetic() || matches!(self, Self::U160 | Self::U256)
    }

    fn is_mul_div(self) -> bool {
        matches!(self, Self::U8 | Self::U16 | Self::U32 | Self::U64)
    }

    /// The admissible cast destinations: `N`.
    fn is_cast_target(self) -> bool {
        self.is_arithmetic() || self == Self::U256
    }

    /// The admissible bounded randomness types: `N`. Unbounded randomness also exists on Bool.
    fn is_rand_int(self) -> bool {
        self.is_arithmetic() || self == Self::U256
    }

    /// Sum and membership collection limits: 100 for the narrow types, 60 for the wide ones.
    fn collection_limit(self) -> usize {
        match self {
            Self::U8 | Self::U16 | Self::U32 => 100,
            _ => 60,
        }
    }
}

/// A clear value of any exposed type, as 256 bits: `lo` holds the low 128 bits, `hi` the high
/// ones. Types up to 128 bits only ever use `lo`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct ClearInt {
    pub(crate) lo: u128,
    pub(crate) hi: u128,
}

impl ClearInt {
    const ZERO: Self = Self { lo: 0, hi: 0 };

    fn from_lo(lo: u128) -> Self {
        Self { lo, hi: 0 }
    }

    fn masked(self, ty: ValueType) -> Self {
        let mask = ty.mask();
        Self {
            lo: self.lo & mask.lo,
            hi: self.hi & mask.hi,
        }
    }

    fn fits(self, ty: ValueType) -> bool {
        self == self.masked(ty)
    }

    fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    fn is_power_of_two(self) -> bool {
        self.lo.count_ones() + self.hi.count_ones() == 1
    }

    /// `floor(log2(self))`; the caller guarantees a nonzero value.
    fn floor_log2(self) -> u32 {
        if self.hi != 0 {
            255 - self.hi.leading_zeros()
        } else {
            127 - self.lo.leading_zeros()
        }
    }

    /// Whether the value is strictly below `2^bits`.
    fn fits_bits(self, bits: u32) -> bool {
        match bits {
            0..=127 => self.hi == 0 && self.lo < (1u128 << bits),
            128 => self.hi == 0,
            129..=255 => self.hi < (1u128 << (bits - 128)),
            _ => true,
        }
    }

    fn to_u256(self) -> TfheU256 {
        TfheU256::from((self.lo, self.hi))
    }

    fn from_u256(v: TfheU256) -> Self {
        let (lo, hi) = v.to_low_high_u128();
        Self { lo, hi }
    }

    fn bitand(self, rhs: Self) -> Self {
        Self {
            lo: self.lo & rhs.lo,
            hi: self.hi & rhs.hi,
        }
    }

    fn bitor(self, rhs: Self) -> Self {
        Self {
            lo: self.lo | rhs.lo,
            hi: self.hi | rhs.hi,
        }
    }

    fn bitxor(self, rhs: Self) -> Self {
        Self {
            lo: self.lo ^ rhs.lo,
            hi: self.hi ^ rhs.hi,
        }
    }

    fn not(self, ty: ValueType) -> Self {
        Self {
            lo: !self.lo,
            hi: !self.hi,
        }
        .masked(ty)
    }

    fn wrapping_add(self, rhs: Self, ty: ValueType) -> Self {
        let (lo, carry) = self.lo.overflowing_add(rhs.lo);
        let hi = self.hi.wrapping_add(rhs.hi).wrapping_add(u128::from(carry));
        Self { lo, hi }.masked(ty)
    }

    fn wrapping_neg(self, ty: ValueType) -> Self {
        Self {
            lo: !self.lo,
            hi: !self.hi,
        }
        .wrapping_add(Self::from_lo(1), ty)
    }

    /// Raw 256 bit left shift, `k` in `[0, 256)`.
    fn shl256(self, k: u32) -> Self {
        if k == 0 {
            self
        } else if k < 128 {
            Self {
                lo: self.lo << k,
                hi: (self.hi << k) | (self.lo >> (128 - k)),
            }
        } else {
            Self {
                lo: 0,
                hi: self.lo << (k - 128),
            }
        }
    }

    /// Raw 256 bit right shift, `k` in `[0, 256)`.
    fn shr256(self, k: u32) -> Self {
        if k == 0 {
            self
        } else if k < 128 {
            Self {
                lo: (self.lo >> k) | (self.hi << (128 - k)),
                hi: self.hi >> k,
            }
        } else {
            Self {
                lo: self.hi >> (k - 128),
                hi: 0,
            }
        }
    }

    /// Whether this value, read as a shift amount, reaches the type's width. TFHE-rs overshift
    /// semantics make the result zero in that case.
    fn is_overshift(self, ty: ValueType) -> bool {
        self.hi != 0 || self.lo >= u128::from(ty.bits())
    }

    fn shl(self, amount: Self, ty: ValueType) -> Self {
        if amount.is_overshift(ty) {
            Self::ZERO
        } else {
            self.shl256(amount.lo as u32).masked(ty)
        }
    }

    fn shr(self, amount: Self, ty: ValueType) -> Self {
        if amount.is_overshift(ty) {
            Self::ZERO
        } else {
            self.masked(ty).shr256(amount.lo as u32)
        }
    }

    /// Rotations take the amount modulo the width. Every rotatable width is a power of two that
    /// divides 2^128, so the modulo only involves the low limb.
    fn rotl(self, amount: Self, ty: ValueType) -> Self {
        let width = ty.bits();
        let k = (amount.lo % u128::from(width)) as u32;
        if k == 0 {
            self.masked(ty)
        } else {
            let v = self.masked(ty);
            v.shl256(k).bitor(v.shr256(width - k)).masked(ty)
        }
    }

    fn rotr(self, amount: Self, ty: ValueType) -> Self {
        let width = ty.bits();
        let k = (amount.lo % u128::from(width)) as u32;
        if k == 0 {
            self.masked(ty)
        } else {
            let v = self.masked(ty);
            v.shr256(k).bitor(v.shl256(width - k)).masked(ty)
        }
    }
}

impl std::fmt::Display for ClearInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.hi == 0 {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "0x{:x}{:032x}", self.hi, self.lo)
        }
    }
}

/// The operation pool. The discriminant comments are the host executor opcodes, which are also
/// what each node mixes into its re-randomization context.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OpKind {
    Add,            // 0
    Sub,            // 1
    Mul,            // 2
    Div,            // 3, scalar divisor only
    Rem,            // 4, scalar divisor only
    BitAnd,         // 5
    BitOr,          // 6
    BitXor,         // 7
    Shl,            // 8
    Shr,            // 9
    Rotl,           // 10
    Rotr,           // 11
    Eq,             // 12
    Ne,             // 13
    Ge,             // 14
    Gt,             // 15
    Le,             // 16
    Lt,             // 17
    Min,            // 18
    Max,            // 19
    Neg,            // 20
    Not,            // 21
    Cast,           // 23, destination in `target`
    TrivialEncrypt, // 24, type in `target`, clear value as the single scalar operand
    Select,         // 25
    Rand,           // 26, type in `target`, the seed as the single scalar operand
    RandBounded,    // 27, type in `target`, the seed and the power of two bound as scalars
    Sum,            // 28, output type in `target`
    IsIn,           // 29
    MulDiv,         // 30
}

impl OpKind {
    /// The host executor opcode, fed to the node's re-randomization context exactly like the
    /// transfer test feeds its own node opcodes.
    fn opcode(self) -> u32 {
        match self {
            Self::Add => 0,
            Self::Sub => 1,
            Self::Mul => 2,
            Self::Div => 3,
            Self::Rem => 4,
            Self::BitAnd => 5,
            Self::BitOr => 6,
            Self::BitXor => 7,
            Self::Shl => 8,
            Self::Shr => 9,
            Self::Rotl => 10,
            Self::Rotr => 11,
            Self::Eq => 12,
            Self::Ne => 13,
            Self::Ge => 14,
            Self::Gt => 15,
            Self::Le => 16,
            Self::Lt => 17,
            Self::Min => 18,
            Self::Max => 19,
            Self::Neg => 20,
            Self::Not => 21,
            Self::Cast => 23,
            Self::TrivialEncrypt => 24,
            Self::Select => 25,
            Self::Rand => 26,
            Self::RandBounded => 27,
            Self::Sum => 28,
            Self::IsIn => 29,
            Self::MulDiv => 30,
        }
    }
}

/// Which simple operations a value type admits through the host executor. The structural
/// operators (cast, selection, sum, membership, MulDiv, trivial encryption) have their own type
/// rules and are checked where they are evaluated.
fn int_op_allowed(op: OpKind, ty: ValueType) -> bool {
    use OpKind::*;
    match ty {
        ValueType::U8 | ValueType::U16 | ValueType::U32 | ValueType::U64 | ValueType::U128 => {
            matches!(
                op,
                Add | Sub
                    | Mul
                    | Div
                    | Rem
                    | BitAnd
                    | BitOr
                    | BitXor
                    | Shl
                    | Shr
                    | Rotl
                    | Rotr
                    | Eq
                    | Ne
                    | Ge
                    | Gt
                    | Le
                    | Lt
                    | Min
                    | Max
                    | Neg
                    | Not
            )
        }
        ValueType::U256 => matches!(
            op,
            BitAnd | BitOr | BitXor | Shl | Shr | Rotl | Rotr | Eq | Ne | Neg | Not
        ),
        ValueType::U160 => matches!(op, Eq | Ne),
        ValueType::Bool => false,
    }
}

/// One operand of a node. `Ct` and `BoolCt` index the pools of previously produced encrypted
/// values, inputs included for the integer pool; `Scalar` and `BigScalar` are the clear scalar
/// forms the executor accepts, the latter for values above 128 bits.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Operand {
    Ct(usize),
    BoolCt(usize),
    Scalar(u128),
    BigScalar { lo: u128, hi: u128 },
    BoolScalar(bool),
}

impl Operand {
    fn as_clear_scalar(&self) -> Option<ClearInt> {
        match self {
            Self::Scalar(s) => Some(ClearInt::from_lo(*s)),
            Self::BigScalar { lo, hi } => Some(ClearInt { lo: *lo, hi: *hi }),
            _ => None,
        }
    }
}

/// One operation of a transaction. `target` carries the clear type argument of the operations
/// that take one: the cast destination, the trivial encryption type, and the sum output type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Node {
    pub(crate) op: OpKind,
    pub(crate) operands: Vec<Operand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) target: Option<ValueType>,
}

/// One encrypted input: its clear value and the metadata that ties it to its origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InputDesc {
    pub(crate) value: u128,
    pub(crate) metadata: Vec<u8>,
}

/// The complete clear description of one transaction: enough to re-run it, and small enough to
/// end up verbatim in a failure report. `width` is the primary width: the type the inputs are
/// encrypted at; other value types appear through casts and trivial encryptions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TransactionDescription {
    pub(crate) width: u32,
    pub(crate) inputs: Vec<InputDesc>,
    pub(crate) nodes: Vec<Node>,
}

/// Everything needed to replay one failing transaction on its own: regenerate the keys from the
/// two seeds, seed the encryption engine with the transaction seed, and run the description.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FailureReport {
    /// Name of the meta parameters constant the run used.
    pub(crate) params: String,
    /// Seed of `ClientKey::generate_with_seed`.
    pub(crate) key_seed: u128,
    /// Engine seed covering the server key and compact public key generation.
    pub(crate) setup_seed: u128,
    /// Engine seed covering this transaction's input encryptions.
    pub(crate) transaction_seed: u128,
    pub(crate) transaction_index: usize,
    /// The assertion message of the original failure.
    pub(crate) error: String,
    pub(crate) description: TransactionDescription,
}

/// Identity of a run, copied into every failure report it produces.
pub(crate) struct RunIdentity<'a> {
    pub(crate) params_name: &'a str,
    pub(crate) key_seed: Seed,
    pub(crate) setup_seed: Seed,
}

/// Looks a meta parameters constant up by the name a failure report stores.
pub(crate) fn meta_params_by_name(name: &str) -> Option<MetaParameters> {
    match name {
        "TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128" => {
            Some(TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128)
        }
        "TEST_LEGACY_RERAND_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128" => Some(
            TEST_LEGACY_RERAND_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
        ),
        "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128" => {
            Some(TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128)
        }
        "TEST_LEGACY_RERAND_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128" => {
            Some(TEST_LEGACY_RERAND_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128)
        }
        _ => None,
    }
}

//
// Transaction generation
//

fn draw_u64(datagen: &mut RandomGenerator<DefaultRandomGenerator>) -> u64 {
    datagen.random_uniform::<u64>()
}

fn draw_u128(datagen: &mut RandomGenerator<DefaultRandomGenerator>) -> u128 {
    (u128::from(draw_u64(datagen)) << 64) | u128::from(draw_u64(datagen))
}

/// Draws a clear value biased toward the boundary patterns the fuzzing registry asks for: zero,
/// one, the maximum value and bit patterns, with uniform draws filling the rest.
///
/// Two pattern families, aimed at the 2_2 compute parameters the protocol runs on: `0xAA`/`0x55`
/// alternate bits inside every 2 bit block (each block holds the same value, 2 or 1), while
/// `0x33`/`0xCC` alternate at the block level, saturated blocks interleaved with zero blocks,
/// which is what stresses carry and borrow propagation across empty blocks.
fn draw_biased_value(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ty: ValueType,
) -> ClearInt {
    const ALTERNATING_HIGH: u128 = 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA;
    const ALTERNATING_LOW: u128 = 0x5555_5555_5555_5555_5555_5555_5555_5555;
    const BLOCK_LOW: u128 = 0x3333_3333_3333_3333_3333_3333_3333_3333;
    const BLOCK_HIGH: u128 = 0xCCCC_CCCC_CCCC_CCCC_CCCC_CCCC_CCCC_CCCC;

    let pattern = |p: u128| ClearInt { lo: p, hi: p }.masked(ty);

    let mask = ty.mask();
    match draw_u64(datagen) % 10 {
        0 => ClearInt::ZERO,
        1 => ClearInt::from_lo(1),
        2 => mask,
        3 => pattern(ALTERNATING_HIGH),
        4 => pattern(ALTERNATING_LOW),
        5 => pattern(BLOCK_LOW),
        6 => pattern(BLOCK_HIGH),
        _ => ClearInt {
            lo: draw_u128(datagen),
            hi: if mask.hi == 0 { 0 } else { draw_u128(datagen) },
        }
        .masked(ty),
    }
}

/// Draws a shift or rotate amount biased toward 0, 1, width−1, width, width+1 and the maximum
/// valid scalar: the executor does not clamp amounts to the width, so the overshift behavior has
/// to stay covered.
fn draw_shift_amount(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ty: ValueType,
) -> ClearInt {
    let width = ty.bits();
    match draw_u64(datagen) % 8 {
        0 => ClearInt::ZERO,
        1 => ClearInt::from_lo(1),
        2 => ClearInt::from_lo(u128::from(width - 1)),
        3 => ClearInt::from_lo(u128::from(width)),
        4 => ClearInt::from_lo(u128::from(width) + 1),
        5 => ty.mask(),
        _ => draw_biased_value(datagen, ty),
    }
}

fn draw_nonzero_scalar(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ty: ValueType,
) -> ClearInt {
    loop {
        let value = draw_biased_value(datagen, ty);
        if !value.is_zero() {
            return value;
        }
    }
}

fn scalar_operand(value: ClearInt) -> Operand {
    if value.hi == 0 {
        Operand::Scalar(value.lo)
    } else {
        Operand::BigScalar {
            lo: value.lo,
            hi: value.hi,
        }
    }
}

const SMALL_INT_OPS: [OpKind; 22] = [
    OpKind::Add,
    OpKind::Sub,
    OpKind::Mul,
    OpKind::Div,
    OpKind::Rem,
    OpKind::BitAnd,
    OpKind::BitOr,
    OpKind::BitXor,
    OpKind::Shl,
    OpKind::Shr,
    OpKind::Rotl,
    OpKind::Rotr,
    OpKind::Eq,
    OpKind::Ne,
    OpKind::Ge,
    OpKind::Gt,
    OpKind::Le,
    OpKind::Lt,
    OpKind::Min,
    OpKind::Max,
    OpKind::Neg,
    OpKind::Not,
];

const U256_OPS: [OpKind; 11] = [
    OpKind::BitAnd,
    OpKind::BitOr,
    OpKind::BitXor,
    OpKind::Shl,
    OpKind::Shr,
    OpKind::Rotl,
    OpKind::Rotr,
    OpKind::Eq,
    OpKind::Ne,
    OpKind::Neg,
    OpKind::Not,
];

const U160_OPS: [OpKind; 2] = [OpKind::Eq, OpKind::Ne];

/// What the executor accepts on encrypted booleans: the bitwise operators, equality and not.
const BOOL_OPS: [OpKind; 6] = [
    OpKind::BitAnd,
    OpKind::BitOr,
    OpKind::BitXor,
    OpKind::Eq,
    OpKind::Ne,
    OpKind::Not,
];

/// The cast destinations, the executor's `N` set.
const CAST_TARGETS: [ValueType; 6] = [
    ValueType::U8,
    ValueType::U16,
    ValueType::U32,
    ValueType::U64,
    ValueType::U128,
    ValueType::U256,
];

/// The bounded randomness types, the executor's `N` set; unbounded randomness adds Bool.
const RAND_INT_TYPES: [ValueType; 6] = [
    ValueType::U8,
    ValueType::U16,
    ValueType::U32,
    ValueType::U64,
    ValueType::U128,
    ValueType::U256,
];

const ALL_TYPES: [ValueType; 8] = [
    ValueType::Bool,
    ValueType::U8,
    ValueType::U16,
    ValueType::U32,
    ValueType::U64,
    ValueType::U128,
    ValueType::U160,
    ValueType::U256,
];

/// Live typed value pools of a transaction being drawn.
struct GenState {
    /// The type of each integer pool slot, inputs first.
    int_types: Vec<ValueType>,
    bool_count: usize,
}

impl GenState {
    fn slots_of(&self, ty: ValueType) -> Vec<usize> {
        self.int_types
            .iter()
            .enumerate()
            .filter_map(|(i, t)| (*t == ty).then_some(i))
            .collect()
    }

    fn pick_slot(
        &self,
        datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ) -> (usize, ValueType) {
        let i = (draw_u64(datagen) as usize) % self.int_types.len();
        (i, self.int_types[i])
    }
}

/// Draws a collection size for sum and membership nodes: the registry asks for 0, 1, 2 and the
/// limits to be covered, but a limit sized node is two orders of magnitude more work than the
/// rest of the transaction, so the limits stay rare.
fn draw_collection_size(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ty: ValueType,
) -> usize {
    let limit = ty.collection_limit();
    match draw_u64(datagen) % 64 {
        0 => 0,
        1 => 1,
        2 => 2,
        62 => limit - 1,
        63 => limit,
        _ => 3 + (draw_u64(datagen) as usize) % 4,
    }
}

fn draw_plain_int_node(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    state: &GenState,
) -> Node {
    let (lhs, ty) = state.pick_slot(datagen);
    let ops: &[OpKind] = match ty {
        ValueType::U256 => &U256_OPS,
        ValueType::U160 => &U160_OPS,
        _ => &SMALL_INT_OPS,
    };
    let op = ops[(draw_u64(datagen) % ops.len() as u64) as usize];

    let operands = match op {
        OpKind::Neg | OpKind::Not => vec![Operand::Ct(lhs)],
        // Division and remainder only exist with a nonzero clear scalar divisor.
        OpKind::Div | OpKind::Rem => vec![
            Operand::Ct(lhs),
            scalar_operand(draw_nonzero_scalar(datagen, ty)),
        ],
        _ => {
            let rhs = if draw_u64(datagen) % 2 == 0 {
                let scalar = if matches!(op, OpKind::Shl | OpKind::Shr | OpKind::Rotl | OpKind::Rotr)
                {
                    draw_shift_amount(datagen, ty)
                } else {
                    draw_biased_value(datagen, ty)
                };
                scalar_operand(scalar)
            } else {
                // Aliased operands, the same handle on both sides, are singled out by the fuzzing
                // registry, so they are drawn more often than uniform picking would.
                let same_ty = state.slots_of(ty);
                let rhs_index = if draw_u64(datagen) % 8 == 0 {
                    lhs
                } else {
                    same_ty[(draw_u64(datagen) as usize) % same_ty.len()]
                };
                Operand::Ct(rhs_index)
            };
            vec![Operand::Ct(lhs), rhs]
        }
    };

    Node {
        op,
        operands,
        target: None,
    }
}

fn draw_bool_node(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    bool_count: usize,
) -> Node {
    let op = BOOL_OPS[(draw_u64(datagen) % BOOL_OPS.len() as u64) as usize];
    let lhs = (draw_u64(datagen) as usize) % bool_count;

    let operands = match op {
        OpKind::Not => vec![Operand::BoolCt(lhs)],
        _ => {
            let rhs = if draw_u64(datagen) % 2 == 0 {
                Operand::BoolScalar(draw_u64(datagen) % 2 == 0)
            } else {
                Operand::BoolCt((draw_u64(datagen) as usize) % bool_count)
            };
            vec![Operand::BoolCt(lhs), rhs]
        }
    };

    Node {
        op,
        operands,
        target: None,
    }
}

/// Draws a randomness node. The seed is drawn here and stored in the description, so a replay
/// regenerates the very same encrypted value. Bounds are powers of two, like the registry asks:
/// the bound exponent is biased toward 0, 1, width−1 and just over the width (where the executor
/// caps it), and a bound above 255 bits is not representable in an operand, so u256 never draws
/// an over-width bound.
fn draw_rand_node(datagen: &mut RandomGenerator<DefaultRandomGenerator>) -> (Node, ValueType) {
    let seed = Operand::Scalar(draw_u128(datagen));
    if draw_u64(datagen) % 2 == 0 {
        let target = if draw_u64(datagen) % 7 == 0 {
            ValueType::Bool
        } else {
            RAND_INT_TYPES[(draw_u64(datagen) % RAND_INT_TYPES.len() as u64) as usize]
        };
        (
            Node {
                op: OpKind::Rand,
                operands: vec![seed],
                target: Some(target),
            },
            target,
        )
    } else {
        let target = RAND_INT_TYPES[(draw_u64(datagen) % RAND_INT_TYPES.len() as u64) as usize];
        let width = target.bits();
        let exponent = match draw_u64(datagen) % 16 {
            0 => 0,
            1 => 1,
            2 => width - 1,
            3 => width + 1,
            _ => 1 + (draw_u64(datagen) as u32) % width,
        }
        .min(255);
        let bound = ClearInt::from_lo(1).shl256(exponent);
        (
            Node {
                op: OpKind::RandBounded,
                operands: vec![seed, scalar_operand(bound)],
                target: Some(target),
            },
            target,
        )
    }
}

/// Draws one node. Returns the node and the type of its result, `None` standing for the boolean
/// pool. Categories that need values the pools do not hold yet fall back to a plain node.
fn draw_node(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    state: &GenState,
) -> (Node, Option<ValueType>) {
    let category = draw_u64(datagen) % 16;
    match category {
        // Cast: any non-U160 encrypted value to a different type of N.
        0 => {
            let (source, source_ty) = if state.bool_count > 0 && draw_u64(datagen) % 4 == 0 {
                (
                    Operand::BoolCt((draw_u64(datagen) as usize) % state.bool_count),
                    ValueType::Bool,
                )
            } else {
                let (slot, ty) = state.pick_slot(datagen);
                if ty == ValueType::U160 {
                    return (draw_plain_int_node(datagen, state), None);
                }
                (Operand::Ct(slot), ty)
            };
            let target = loop {
                let t = CAST_TARGETS[(draw_u64(datagen) % CAST_TARGETS.len() as u64) as usize];
                if t != source_ty {
                    break t;
                }
            };
            (
                Node {
                    op: OpKind::Cast,
                    operands: vec![source],
                    target: Some(target),
                },
                Some(target),
            )
        }
        // Trivial encryption of any exposed type.
        1 => {
            let target = ALL_TYPES[(draw_u64(datagen) % ALL_TYPES.len() as u64) as usize];
            let value = if target == ValueType::Bool {
                ClearInt::from_lo(draw_u64(datagen) as u128 % 2)
            } else {
                draw_biased_value(datagen, target)
            };
            (
                Node {
                    op: OpKind::TrivialEncrypt,
                    operands: vec![scalar_operand(value)],
                    target: Some(target),
                },
                Some(target),
            )
        }
        // Selection, over any exposed type including booleans.
        2 if state.bool_count > 0 => {
            let condition = Operand::BoolCt((draw_u64(datagen) as usize) % state.bool_count);
            if draw_u64(datagen) % 5 == 0 {
                let a = (draw_u64(datagen) as usize) % state.bool_count;
                let b = (draw_u64(datagen) as usize) % state.bool_count;
                (
                    Node {
                        op: OpKind::Select,
                        operands: vec![condition, Operand::BoolCt(a), Operand::BoolCt(b)],
                        target: None,
                    },
                    Some(ValueType::Bool),
                )
            } else {
                let (_, ty) = state.pick_slot(datagen);
                let same_ty = state.slots_of(ty);
                let a = same_ty[(draw_u64(datagen) as usize) % same_ty.len()];
                let b = same_ty[(draw_u64(datagen) as usize) % same_ty.len()];
                (
                    Node {
                        op: OpKind::Select,
                        operands: vec![condition, Operand::Ct(a), Operand::Ct(b)],
                        target: None,
                    },
                    Some(ty),
                )
            }
        }
        // Sum over one of the arithmetic types; elements may repeat.
        3 => {
            let (_, ty) = state.pick_slot(datagen);
            if !ty.is_arithmetic() {
                return (draw_plain_int_node(datagen, state), None);
            }
            let same_ty = state.slots_of(ty);
            let n = draw_collection_size(datagen, ty);
            let operands = (0..n)
                .map(|_| Operand::Ct(same_ty[(draw_u64(datagen) as usize) % same_ty.len()]))
                .collect();
            (
                Node {
                    op: OpKind::Sum,
                    operands,
                    target: Some(ty),
                },
                Some(ty),
            )
        }
        // Membership over N ∪ {U160}; the set may be empty and elements may repeat.
        4 => {
            let (value, ty) = state.pick_slot(datagen);
            if !ty.is_membership() {
                return (draw_plain_int_node(datagen, state), None);
            }
            let same_ty = state.slots_of(ty);
            let n = draw_collection_size(datagen, ty);
            let mut operands = vec![Operand::Ct(value)];
            operands.extend(
                (0..n).map(|_| Operand::Ct(same_ty[(draw_u64(datagen) as usize) % same_ty.len()])),
            );
            (
                Node {
                    op: OpKind::IsIn,
                    operands,
                    target: None,
                },
                Some(ValueType::Bool),
            )
        }
        // Fused multiply-divide, widths up to 64 bits.
        5 => {
            let (a, ty) = state.pick_slot(datagen);
            if !ty.is_mul_div() {
                return (draw_plain_int_node(datagen, state), None);
            }
            let same_ty = state.slots_of(ty);
            let factor2 = if draw_u64(datagen) % 2 == 0 {
                scalar_operand(draw_biased_value(datagen, ty))
            } else {
                Operand::Ct(same_ty[(draw_u64(datagen) as usize) % same_ty.len()])
            };
            let divisor = scalar_operand(draw_nonzero_scalar(datagen, ty));
            (
                Node {
                    op: OpKind::MulDiv,
                    operands: vec![Operand::Ct(a), factor2, divisor],
                    target: None,
                },
                Some(ty),
            )
        }
        // Randomness, with the seed drawn and pinned here.
        6 => {
            let (node, ty) = draw_rand_node(datagen);
            (node, Some(ty))
        }
        // Once comparisons have produced booleans, some nodes consume them.
        7 | 8 if state.bool_count > 0 => (draw_bool_node(datagen, state.bool_count), None),
        _ => (draw_plain_int_node(datagen, state), None),
    }
}

/// Draws one transaction: a primary width, the clear inputs with their metadata, and a
/// straight-line program whose operands are picked among the values live at that point.
pub(crate) fn draw_transaction(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
) -> TransactionDescription {
    let width = INPUT_WIDTHS[(draw_u64(datagen) % INPUT_WIDTHS.len() as u64) as usize];
    let primary_ty = ValueType::from_width(width).unwrap();

    let inputs = (0..NUM_INPUTS)
        .map(|_| InputDesc {
            value: draw_biased_value(datagen, primary_ty).lo,
            metadata: random_bytes::<METADATA_LEN>(datagen).to_vec(),
        })
        .collect();

    let num_nodes = MIN_NODES + (draw_u64(datagen) as usize) % (MAX_NODES - MIN_NODES + 1);
    let mut nodes = Vec::with_capacity(num_nodes);
    let mut state = GenState {
        int_types: vec![primary_ty; NUM_INPUTS],
        bool_count: 0,
    };

    for _ in 0..num_nodes {
        let (node, explicit_ty) = draw_node(datagen, &mut state);
        // Bool results go to the boolean pool; everything else to the typed integer pool. Nodes
        // drawn by `draw_plain_int_node`/`draw_bool_node` return no explicit type: a comparison
        // or a boolean operation produces a boolean, anything else keeps its left operand type.
        let result_ty = explicit_ty.unwrap_or_else(|| match node.operands.first() {
            Some(Operand::BoolCt(_)) => ValueType::Bool,
            Some(Operand::Ct(i)) => match node.op {
                OpKind::Eq | OpKind::Ne | OpKind::Ge | OpKind::Gt | OpKind::Le | OpKind::Lt => {
                    ValueType::Bool
                }
                _ => state.int_types[*i],
            },
            _ => unreachable!("drawn nodes always start with an encrypted operand"),
        });
        if result_ty == ValueType::Bool {
            state.bool_count += 1;
        } else {
            state.int_types.push(result_ty);
        }
        nodes.push(node);
    }

    TransactionDescription {
        width,
        inputs,
        nodes,
    }
}

//
// Clear oracle
//

enum ClearResult {
    Int(ValueType, ClearInt),
    Bool(bool),
}

fn node_err(node_index: usize, node: &Node, msg: &str) -> String {
    format!("node {node_index} {node:?}: {msg}")
}

/// A binary operation between two clear values of the same type. The type legality is checked by
/// the caller through [`int_op_allowed`].
fn clear_int_binary(op: OpKind, a: ClearInt, b: ClearInt, ty: ValueType) -> Result<ClearResult, String> {
    use ClearResult::{Bool, Int};
    Ok(match op {
        OpKind::Add => Int(ty, a.wrapping_add(b, ty)),
        OpKind::Sub => Int(ty, a.wrapping_add(b.wrapping_neg(ty), ty)),
        OpKind::Mul => Int(ty, ClearInt::from_lo(a.lo.wrapping_mul(b.lo)).masked(ty)),
        OpKind::Div => {
            if b.is_zero() {
                return Err("zero divisor, the executor only accepts nonzero scalars".to_string());
            }
            Int(ty, ClearInt::from_lo(a.lo / b.lo))
        }
        OpKind::Rem => {
            if b.is_zero() {
                return Err("zero divisor, the executor only accepts nonzero scalars".to_string());
            }
            Int(ty, ClearInt::from_lo(a.lo % b.lo))
        }
        OpKind::BitAnd => Int(ty, a.bitand(b)),
        OpKind::BitOr => Int(ty, a.bitor(b)),
        OpKind::BitXor => Int(ty, a.bitxor(b)),
        OpKind::Shl => Int(ty, a.shl(b, ty)),
        OpKind::Shr => Int(ty, a.shr(b, ty)),
        OpKind::Rotl => Int(ty, a.rotl(b, ty)),
        OpKind::Rotr => Int(ty, a.rotr(b, ty)),
        OpKind::Eq => Bool(a == b),
        OpKind::Ne => Bool(a != b),
        // Ordered comparisons and min/max only exist on the arithmetic types, whose values live
        // entirely in the low limb.
        OpKind::Ge => Bool(a.lo >= b.lo),
        OpKind::Gt => Bool(a.lo > b.lo),
        OpKind::Le => Bool(a.lo <= b.lo),
        OpKind::Lt => Bool(a.lo < b.lo),
        OpKind::Min => Int(ty, ClearInt::from_lo(a.lo.min(b.lo))),
        OpKind::Max => Int(ty, ClearInt::from_lo(a.lo.max(b.lo))),
        _ => return Err(format!("{op:?} is not a binary operation")),
    })
}

/// The decrypted output of one randomness node, keyed by node index. Randomness has no clear
/// oracle: the FHE evaluation decrypts each rand node once and the clear evaluation takes the
/// value from here, checking its range, so everything downstream of a rand node stays checked.
#[derive(Copy, Clone)]
pub(crate) enum RandValue {
    Int(ClearInt),
    Bool(bool),
}

pub(crate) type RandValues = BTreeMap<usize, RandValue>;

/// The result of evaluating a whole transaction in the clear: the full typed value pools (the
/// integer pool starts with the inputs), the node that produced each value, and one coverage
/// signature per node.
pub(crate) struct ClearEvaluation {
    ints: Vec<(ValueType, ClearInt)>,
    bools: Vec<bool>,
    int_node_map: Vec<usize>,
    bool_node_map: Vec<usize>,
    signatures: Vec<String>,
}

/// Evaluates the whole transaction in the clear. This also validates the description, which is
/// what sanitizes a hand-edited replay file.
///
/// Rand nodes take their value from `rand_values`; without an entry (the validation pass, before
/// any FHE work) they evaluate to a placeholder zero, which no validation rule depends on: a
/// rand output can reach any encrypted operand position but never a scalar one, and the nonzero
/// divisor rules only constrain scalars.
pub(crate) fn evaluate_clear(
    desc: &TransactionDescription,
    rand_values: &RandValues,
) -> Result<ClearEvaluation, String> {
    let primary_ty = ValueType::from_width(desc.width)
        .ok_or_else(|| format!("unsupported input width {}", desc.width))?;

    let mut ints: Vec<(ValueType, ClearInt)> =
        Vec::with_capacity(desc.inputs.len() + desc.nodes.len());
    for (pos, input) in desc.inputs.iter().enumerate() {
        let value = ClearInt::from_lo(input.value);
        if !value.fits(primary_ty) {
            return Err(format!(
                "input {pos} value {} does not fit {} bits",
                input.value, desc.width
            ));
        }
        if input.metadata.len() != METADATA_LEN {
            return Err(format!(
                "input {pos} metadata must be {METADATA_LEN} bytes, got {}",
                input.metadata.len()
            ));
        }
        ints.push((primary_ty, value));
    }
    let mut bools: Vec<bool> = Vec::new();
    let mut int_node_map: Vec<usize> = Vec::new();
    let mut bool_node_map: Vec<usize> = Vec::new();
    let mut signatures: Vec<String> = Vec::new();

    for (node_index, node) in desc.nodes.iter().enumerate() {
        let get_int = |i: usize| {
            ints.get(i)
                .copied()
                .ok_or_else(|| node_err(node_index, node, "integer operand out of range"))
        };
        let get_bool = |i: usize| {
            bools
                .get(i)
                .copied()
                .ok_or_else(|| node_err(node_index, node, "boolean operand out of range"))
        };
        // A scalar in position 1 must fit the type of the encrypted operand in position 0.
        let get_scalar = |operand: &Operand, ty: ValueType| {
            let s = operand
                .as_clear_scalar()
                .ok_or_else(|| node_err(node_index, node, "expected a clear scalar operand"))?;
            if !s.fits(ty) {
                return Err(node_err(
                    node_index,
                    node,
                    &format!("scalar {s} does not fit {}", ty.name()),
                ));
            }
            Ok(s)
        };

        let (result, signature) = match node.op {
            OpKind::Cast => {
                let (source_ty, value) = match node.operands.as_slice() {
                    [Operand::Ct(i)] => {
                        let (ty, v) = get_int(*i)?;
                        if ty == ValueType::U160 {
                            return Err(node_err(node_index, node, "U160 cannot be cast"));
                        }
                        (ty, v)
                    }
                    [Operand::BoolCt(i)] => (
                        ValueType::Bool,
                        ClearInt::from_lo(u128::from(get_bool(*i)?)),
                    ),
                    _ => return Err(node_err(node_index, node, "cast takes one encrypted operand")),
                };
                let target = node
                    .target
                    .ok_or_else(|| node_err(node_index, node, "cast needs a target type"))?;
                if !target.is_cast_target() || target == source_ty {
                    return Err(node_err(
                        node_index,
                        node,
                        "cast destination must be a different type of N",
                    ));
                }
                (
                    ClearResult::Int(target, value.masked(target)),
                    format!("Cast/{}->{}", source_ty.name(), target.name()),
                )
            }
            OpKind::TrivialEncrypt => {
                let target = node.target.ok_or_else(|| {
                    node_err(node_index, node, "trivial encryption needs a target type")
                })?;
                let [operand] = node.operands.as_slice() else {
                    return Err(node_err(
                        node_index,
                        node,
                        "trivial encryption takes one clear operand",
                    ));
                };
                let value = get_scalar(operand, target)?;
                let result = if target == ValueType::Bool {
                    ClearResult::Bool(value.lo != 0)
                } else {
                    ClearResult::Int(target, value)
                };
                (result, format!("TrivialEncrypt/{}", target.name()))
            }
            OpKind::Select => match node.operands.as_slice() {
                [Operand::BoolCt(c), Operand::Ct(i), Operand::Ct(j)] => {
                    let c = get_bool(*c)?;
                    let (ty_a, a) = get_int(*i)?;
                    let (ty_b, b) = get_int(*j)?;
                    if ty_a != ty_b {
                        return Err(node_err(node_index, node, "branch types differ"));
                    }
                    (
                        ClearResult::Int(ty_a, if c { a } else { b }),
                        format!("Select/{}", ty_a.name()),
                    )
                }
                [Operand::BoolCt(c), Operand::BoolCt(i), Operand::BoolCt(j)] => {
                    let c = get_bool(*c)?;
                    let (a, b) = (get_bool(*i)?, get_bool(*j)?);
                    (
                        ClearResult::Bool(if c { a } else { b }),
                        "Select/bool".to_string(),
                    )
                }
                _ => {
                    return Err(node_err(
                        node_index,
                        node,
                        "selection takes an encrypted condition and two encrypted branches",
                    ))
                }
            },
            OpKind::Rand | OpKind::RandBounded => {
                let ty = node
                    .target
                    .ok_or_else(|| node_err(node_index, node, "randomness needs a type"))?;
                let [Operand::Scalar(_seed), bound @ ..] = node.operands.as_slice() else {
                    return Err(node_err(node_index, node, "randomness takes a scalar seed"));
                };
                // The number of random bits the executor derives from the bound; without one,
                // the full width. The executor's bound decoding is only `floor(log2)` for powers
                // of two, which is why the registry restricts bounds to those.
                let (random_bits, signature) = match (node.op, bound) {
                    (OpKind::Rand, []) => {
                        if ty != ValueType::Bool && !ty.is_rand_int() {
                            return Err(node_err(node_index, node, "rand type must be in B ∪ N"));
                        }
                        (ty.bits(), format!("Rand/{}", ty.name()))
                    }
                    (OpKind::RandBounded, [bound]) => {
                        if !ty.is_rand_int() {
                            return Err(node_err(
                                node_index,
                                node,
                                "bounded rand type must be in N",
                            ));
                        }
                        let bound = bound.as_clear_scalar().ok_or_else(|| {
                            node_err(node_index, node, "the bound must be a clear scalar")
                        })?;
                        if !bound.is_power_of_two() {
                            return Err(node_err(
                                node_index,
                                node,
                                "the bound must be a positive power of two",
                            ));
                        }
                        let random_bits = bound.floor_log2().min(ty.bits());
                        (random_bits, format!("RandBounded/{}/b{random_bits}", ty.name()))
                    }
                    _ => return Err(node_err(node_index, node, "malformed operand list")),
                };
                let result = match rand_values.get(&node_index) {
                    None => {
                        // Validation pass: the value is not known yet.
                        if ty == ValueType::Bool {
                            ClearResult::Bool(false)
                        } else {
                            ClearResult::Int(ty, ClearInt::ZERO)
                        }
                    }
                    Some(RandValue::Bool(b)) if ty == ValueType::Bool => ClearResult::Bool(*b),
                    Some(RandValue::Int(v)) if ty != ValueType::Bool => {
                        if !v.fits_bits(random_bits) {
                            return Err(node_err(
                                node_index,
                                node,
                                &format!("rand result {v} is not below 2^{random_bits}"),
                            ));
                        }
                        ClearResult::Int(ty, *v)
                    }
                    Some(_) => {
                        return Err(node_err(node_index, node, "rand value kind mismatch"));
                    }
                };
                (result, signature)
            }
            OpKind::Sum => {
                let ty = node
                    .target
                    .ok_or_else(|| node_err(node_index, node, "sum needs an output type"))?;
                if !ty.is_arithmetic() {
                    return Err(node_err(node_index, node, "sum output type must be in A"));
                }
                if node.operands.len() > ty.collection_limit() {
                    return Err(node_err(
                        node_index,
                        node,
                        &format!("sum takes at most {} operands", ty.collection_limit()),
                    ));
                }
                let mut acc = ClearInt::ZERO;
                for operand in node.operands.iter() {
                    let Operand::Ct(i) = operand else {
                        return Err(node_err(node_index, node, "sum takes no scalar elements"));
                    };
                    let (element_ty, v) = get_int(*i)?;
                    if element_ty != ty {
                        return Err(node_err(node_index, node, "sum element type mismatch"));
                    }
                    acc = acc.wrapping_add(v, ty);
                }
                (
                    ClearResult::Int(ty, acc),
                    format!("Sum/{}/n{}", ty.name(), node.operands.len()),
                )
            }
            OpKind::IsIn => {
                let [value_operand, set @ ..] = node.operands.as_slice() else {
                    return Err(node_err(node_index, node, "membership needs a value operand"));
                };
                let Operand::Ct(i) = value_operand else {
                    return Err(node_err(node_index, node, "membership value must be encrypted"));
                };
                let (ty, value) = get_int(*i)?;
                if !ty.is_membership() {
                    return Err(node_err(
                        node_index,
                        node,
                        "membership type must be in N ∪ {U160}",
                    ));
                }
                if set.len() > ty.collection_limit() {
                    return Err(node_err(
                        node_index,
                        node,
                        &format!("membership set holds at most {} elements", ty.collection_limit()),
                    ));
                }
                let mut found = false;
                for operand in set {
                    let Operand::Ct(j) = operand else {
                        return Err(node_err(node_index, node, "set elements must be encrypted"));
                    };
                    let (element_ty, v) = get_int(*j)?;
                    if element_ty != ty {
                        return Err(node_err(node_index, node, "set element type mismatch"));
                    }
                    found |= v == value;
                }
                (
                    ClearResult::Bool(found),
                    format!("IsIn/{}/n{}", ty.name(), set.len()),
                )
            }
            OpKind::MulDiv => {
                let [Operand::Ct(a), factor2, divisor] = node.operands.as_slice() else {
                    return Err(node_err(
                        node_index,
                        node,
                        "MulDiv takes an encrypted factor, a factor and a scalar divisor",
                    ));
                };
                let (ty, a) = get_int(*a)?;
                if !ty.is_mul_div() {
                    return Err(node_err(node_index, node, "MulDiv stops at 64 bits"));
                }
                let (b, mode) = match factor2 {
                    Operand::Ct(j) => {
                        let (element_ty, v) = get_int(*j)?;
                        if element_ty != ty {
                            return Err(node_err(node_index, node, "MulDiv factor type mismatch"));
                        }
                        (v, "encrypted")
                    }
                    operand => (get_scalar(operand, ty)?, "scalar"),
                };
                let d = get_scalar(divisor, ty)?;
                if d.is_zero() {
                    return Err(node_err(node_index, node, "MulDiv divisor must be nonzero"));
                }
                // The widened product of two values up to 64 bits fits in the low limb; the
                // division result is truncated back to the original width.
                let result = ClearInt::from_lo((a.lo * b.lo) / d.lo).masked(ty);
                (
                    ClearResult::Int(ty, result),
                    format!("MulDiv/{}/{mode}", ty.name()),
                )
            }
            _ => match node.operands.as_slice() {
                [Operand::Ct(i)] => {
                    let (ty, a) = get_int(*i)?;
                    if !int_op_allowed(node.op, ty) {
                        return Err(node_err(
                            node_index,
                            node,
                            &format!("{:?} is not admissible on {}", node.op, ty.name()),
                        ));
                    }
                    let result = match node.op {
                        OpKind::Neg => a.wrapping_neg(ty),
                        OpKind::Not => a.not(ty),
                        _ => {
                            return Err(node_err(node_index, node, "malformed operand list"));
                        }
                    };
                    (
                        ClearResult::Int(ty, result),
                        format!("{:?}/{}/unary", node.op, ty.name()),
                    )
                }
                [Operand::BoolCt(i)] if node.op == OpKind::Not => (
                    ClearResult::Bool(!get_bool(*i)?),
                    "Not/bool/unary".to_string(),
                ),
                [Operand::Ct(i), rhs] => {
                    let (ty, a) = get_int(*i)?;
                    if !int_op_allowed(node.op, ty) {
                        return Err(node_err(
                            node_index,
                            node,
                            &format!("{:?} is not admissible on {}", node.op, ty.name()),
                        ));
                    }
                    let (b, mode) = match rhs {
                        Operand::Ct(j) => {
                            if matches!(node.op, OpKind::Div | OpKind::Rem) {
                                return Err(node_err(
                                    node_index,
                                    node,
                                    "the host executor only accepts a clear scalar divisor",
                                ));
                            }
                            let (rhs_ty, v) = get_int(*j)?;
                            if rhs_ty != ty {
                                return Err(node_err(node_index, node, "operand types differ"));
                            }
                            (v, "encrypted")
                        }
                        operand => (get_scalar(operand, ty)?, "scalar"),
                    };
                    (
                        clear_int_binary(node.op, a, b, ty)
                            .map_err(|e| node_err(node_index, node, &e))?,
                        format!("{:?}/{}/{mode}", node.op, ty.name()),
                    )
                }
                [Operand::BoolCt(i), rhs @ (Operand::BoolCt(_) | Operand::BoolScalar(_))] => {
                    let a = get_bool(*i)?;
                    let (b, mode) = match rhs {
                        Operand::BoolCt(j) => (get_bool(*j)?, "encrypted"),
                        Operand::BoolScalar(b) => (*b, "scalar"),
                        _ => unreachable!(),
                    };
                    let result = match node.op {
                        OpKind::BitAnd => a & b,
                        OpKind::BitOr => a | b,
                        OpKind::BitXor => a ^ b,
                        OpKind::Eq => a == b,
                        OpKind::Ne => a != b,
                        _ => {
                            return Err(node_err(
                                node_index,
                                node,
                                "operation not supported on encrypted booleans",
                            ))
                        }
                    };
                    (
                        ClearResult::Bool(result),
                        format!("{:?}/bool/{mode}", node.op),
                    )
                }
                _ => return Err(node_err(node_index, node, "malformed operand list")),
            },
        };

        match result {
            ClearResult::Int(ty, v) => {
                debug_assert!(v.fits(ty));
                ints.push((ty, v));
                int_node_map.push(node_index);
            }
            ClearResult::Bool(b) => {
                bools.push(b);
                bool_node_map.push(node_index);
            }
        }
        signatures.push(signature);
    }

    Ok(ClearEvaluation {
        ints,
        bools,
        int_node_map,
        bool_node_map,
        signatures,
    })
}

//
// FHE execution
//

/// One encrypted integer value of the graph, of any of the exposed integer types.
#[derive(Clone)]
enum IntCt {
    U8(FheUint8),
    U16(FheUint16),
    U32(FheUint32),
    U64(FheUint64),
    U128(FheUint128),
    U160(FheUint160),
    U256(FheUint256),
}

/// Applies `$f` to the inner ciphertext of an [`IntCt`], whatever its variant.
macro_rules! for_int_ct {
    ($value:expr, |$ct:ident| $body:expr) => {
        match $value {
            IntCt::U8($ct) => $body,
            IntCt::U16($ct) => $body,
            IntCt::U32($ct) => $body,
            IntCt::U64($ct) => $body,
            IntCt::U128($ct) => $body,
            IntCt::U160($ct) => $body,
            IntCt::U256($ct) => $body,
        }
    };
}

impl IntCt {
    fn ty(&self) -> ValueType {
        match self {
            Self::U8(_) => ValueType::U8,
            Self::U16(_) => ValueType::U16,
            Self::U32(_) => ValueType::U32,
            Self::U64(_) => ValueType::U64,
            Self::U128(_) => ValueType::U128,
            Self::U160(_) => ValueType::U160,
            Self::U256(_) => ValueType::U256,
        }
    }

    fn absorb(&self, ctx: &mut ReRandomizationContext) {
        for_int_ct!(self, |ct| ctx.add_ciphertext(ct));
    }

    fn rerand(&mut self, cpk: &CompactPublicKey, seed_gen: &mut ReRandomizationSeedGen) {
        for_int_ct!(self, |ct| re_randomize_operand(ct, cpk, seed_gen));
    }

    fn decrypt_clear(&self, cks: &ClientKey) -> ClearInt {
        match self {
            Self::U8(ct) => {
                let v: u8 = ct.decrypt(cks);
                ClearInt::from_lo(u128::from(v))
            }
            Self::U16(ct) => {
                let v: u16 = ct.decrypt(cks);
                ClearInt::from_lo(u128::from(v))
            }
            Self::U32(ct) => {
                let v: u32 = ct.decrypt(cks);
                ClearInt::from_lo(u128::from(v))
            }
            Self::U64(ct) => {
                let v: u64 = ct.decrypt(cks);
                ClearInt::from_lo(u128::from(v))
            }
            Self::U128(ct) => {
                let v: u128 = ct.decrypt(cks);
                ClearInt::from_lo(v)
            }
            Self::U160(ct) => {
                let v: TfheU256 = ct.decrypt(cks);
                ClearInt::from_u256(v)
            }
            Self::U256(ct) => {
                let v: TfheU256 = ct.decrypt(cks);
                ClearInt::from_u256(v)
            }
        }
    }

    fn serialize_bytes(&self) -> Vec<u8> {
        for_int_ct!(self, |ct| bincode::serialize(ct).unwrap())
    }

    fn push_into(&self, builder: &mut CompressedCiphertextListBuilder) {
        for_int_ct!(self, |ct| {
            builder.push(ct.clone());
        });
    }

    fn get_from(
        list: &crate::CompressedCiphertextList,
        pos: usize,
        ty: ValueType,
    ) -> Result<Self, String> {
        fn fetch<T: crate::HlExpandable + Tagged>(
            list: &crate::CompressedCiphertextList,
            pos: usize,
        ) -> Result<T, String> {
            list.get::<T>(pos)
                .map_err(|e| format!("failed to decompress value {pos}: {e}"))?
                .ok_or_else(|| format!("value {pos} missing from the compressed list"))
        }
        Ok(match ty {
            ValueType::U8 => Self::U8(fetch(list, pos)?),
            ValueType::U16 => Self::U16(fetch(list, pos)?),
            ValueType::U32 => Self::U32(fetch(list, pos)?),
            ValueType::U64 => Self::U64(fetch(list, pos)?),
            ValueType::U128 => Self::U128(fetch(list, pos)?),
            ValueType::U160 => Self::U160(fetch(list, pos)?),
            ValueType::U256 => Self::U256(fetch(list, pos)?),
            ValueType::Bool => return Err("booleans live in their own pool".to_string()),
        })
    }

    fn squash_noise(&self) -> Result<SquashedNoiseFheUint, String> {
        for_int_ct!(self, |ct| ct
            .squash_noise()
            .map_err(|e| format!("noise squashing failed: {e}")))
    }

    fn set_metadata(&mut self, data: &[u8]) {
        for_int_ct!(self, |ct| ct.re_randomization_metadata_mut().set_data(data));
    }

    fn metadata(&self) -> &[u8] {
        for_int_ct!(self, |ct| ct.re_randomization_metadata().data())
    }
}

fn decrypt_squashed(ns: &SquashedNoiseFheUint, ty: ValueType, cks: &ClientKey) -> ClearInt {
    match ty {
        ValueType::U8 => {
            let v: u8 = ns.decrypt(cks);
            ClearInt::from_lo(u128::from(v))
        }
        ValueType::U16 => {
            let v: u16 = ns.decrypt(cks);
            ClearInt::from_lo(u128::from(v))
        }
        ValueType::U32 => {
            let v: u32 = ns.decrypt(cks);
            ClearInt::from_lo(u128::from(v))
        }
        ValueType::U64 => {
            let v: u64 = ns.decrypt(cks);
            ClearInt::from_lo(u128::from(v))
        }
        ValueType::U128 => {
            let v: u128 = ns.decrypt(cks);
            ClearInt::from_lo(v)
        }
        _ => {
            let v: TfheU256 = ns.decrypt(cks);
            ClearInt::from_u256(v)
        }
    }
}

/// A value produced by a graph node.
enum GraphValue {
    Int(IntCt),
    Bool(FheBool),
}

macro_rules! define_small_width_eval {
    ($bin:ident, $bin_scalar:ident, $unary:ident, $Fhe:ty, $Clear:ty, $V:ident) => {
        fn $bin(op: OpKind, lhs: &$Fhe, rhs: &$Fhe) -> Result<GraphValue, String> {
            use GraphValue as G;
            Ok(match op {
                OpKind::Add => G::Int(IntCt::$V(lhs + rhs)),
                OpKind::Sub => G::Int(IntCt::$V(lhs - rhs)),
                OpKind::Mul => G::Int(IntCt::$V(lhs * rhs)),
                OpKind::BitAnd => G::Int(IntCt::$V(lhs & rhs)),
                OpKind::BitOr => G::Int(IntCt::$V(lhs | rhs)),
                OpKind::BitXor => G::Int(IntCt::$V(lhs ^ rhs)),
                OpKind::Shl => G::Int(IntCt::$V(lhs << rhs)),
                OpKind::Shr => G::Int(IntCt::$V(lhs >> rhs)),
                OpKind::Rotl => G::Int(IntCt::$V(lhs.rotate_left(rhs))),
                OpKind::Rotr => G::Int(IntCt::$V(lhs.rotate_right(rhs))),
                OpKind::Min => G::Int(IntCt::$V(lhs.min(rhs))),
                OpKind::Max => G::Int(IntCt::$V(lhs.max(rhs))),
                OpKind::Eq => G::Bool(lhs.eq(rhs)),
                OpKind::Ne => G::Bool(lhs.ne(rhs)),
                OpKind::Ge => G::Bool(lhs.ge(rhs)),
                OpKind::Gt => G::Bool(lhs.gt(rhs)),
                OpKind::Le => G::Bool(lhs.le(rhs)),
                OpKind::Lt => G::Bool(lhs.lt(rhs)),
                _ => {
                    return Err(format!(
                        "{op:?} is not an encrypted binary operation on this type"
                    ))
                }
            })
        }

        fn $bin_scalar(op: OpKind, lhs: &$Fhe, scalar: ClearInt) -> Result<GraphValue, String> {
            use GraphValue as G;
            let s = <$Clear>::try_from(scalar.lo)
                .ok()
                .filter(|_| scalar.hi == 0)
                .ok_or_else(|| format!("scalar {scalar} does not fit the operand type"))?;
            Ok(match op {
                OpKind::Add => G::Int(IntCt::$V(lhs + s)),
                OpKind::Sub => G::Int(IntCt::$V(lhs - s)),
                OpKind::Mul => G::Int(IntCt::$V(lhs * s)),
                OpKind::Div => G::Int(IntCt::$V(lhs / s)),
                OpKind::Rem => G::Int(IntCt::$V(lhs % s)),
                OpKind::BitAnd => G::Int(IntCt::$V(lhs & s)),
                OpKind::BitOr => G::Int(IntCt::$V(lhs | s)),
                OpKind::BitXor => G::Int(IntCt::$V(lhs ^ s)),
                OpKind::Shl => G::Int(IntCt::$V(lhs << s)),
                OpKind::Shr => G::Int(IntCt::$V(lhs >> s)),
                OpKind::Rotl => G::Int(IntCt::$V(lhs.rotate_left(s))),
                OpKind::Rotr => G::Int(IntCt::$V(lhs.rotate_right(s))),
                OpKind::Min => G::Int(IntCt::$V(lhs.min(s))),
                OpKind::Max => G::Int(IntCt::$V(lhs.max(s))),
                OpKind::Eq => G::Bool(lhs.eq(s)),
                OpKind::Ne => G::Bool(lhs.ne(s)),
                OpKind::Ge => G::Bool(lhs.ge(s)),
                OpKind::Gt => G::Bool(lhs.gt(s)),
                OpKind::Le => G::Bool(lhs.le(s)),
                OpKind::Lt => G::Bool(lhs.lt(s)),
                _ => {
                    return Err(format!(
                        "{op:?} is not a scalar binary operation on this type"
                    ))
                }
            })
        }

        fn $unary(op: OpKind, a: &$Fhe) -> Result<GraphValue, String> {
            Ok(match op {
                OpKind::Neg => GraphValue::Int(IntCt::$V(-a)),
                OpKind::Not => GraphValue::Int(IntCt::$V(!a)),
                _ => return Err(format!("{op:?} is not a unary operation")),
            })
        }
    };
}

define_small_width_eval!(bin_u8, bin_scalar_u8, unary_u8, FheUint8, u8, U8);
define_small_width_eval!(bin_u16, bin_scalar_u16, unary_u16, FheUint16, u16, U16);
define_small_width_eval!(bin_u32, bin_scalar_u32, unary_u32, FheUint32, u32, U32);
define_small_width_eval!(bin_u64, bin_scalar_u64, unary_u64, FheUint64, u64, U64);
define_small_width_eval!(bin_u128, bin_scalar_u128, unary_u128, FheUint128, u128, U128);

fn bin_u256(op: OpKind, lhs: &FheUint256, rhs: &FheUint256) -> Result<GraphValue, String> {
    use GraphValue as G;
    Ok(match op {
        OpKind::BitAnd => G::Int(IntCt::U256(lhs & rhs)),
        OpKind::BitOr => G::Int(IntCt::U256(lhs | rhs)),
        OpKind::BitXor => G::Int(IntCt::U256(lhs ^ rhs)),
        OpKind::Shl => G::Int(IntCt::U256(lhs << rhs)),
        OpKind::Shr => G::Int(IntCt::U256(lhs >> rhs)),
        OpKind::Rotl => G::Int(IntCt::U256(lhs.rotate_left(rhs))),
        OpKind::Rotr => G::Int(IntCt::U256(lhs.rotate_right(rhs))),
        OpKind::Eq => G::Bool(lhs.eq(rhs)),
        OpKind::Ne => G::Bool(lhs.ne(rhs)),
        _ => return Err(format!("{op:?} is not admissible on u256")),
    })
}

fn bin_scalar_u256(op: OpKind, lhs: &FheUint256, scalar: ClearInt) -> Result<GraphValue, String> {
    use GraphValue as G;
    let s = scalar.to_u256();
    Ok(match op {
        OpKind::BitAnd => G::Int(IntCt::U256(lhs & s)),
        OpKind::BitOr => G::Int(IntCt::U256(lhs | s)),
        OpKind::BitXor => G::Int(IntCt::U256(lhs ^ s)),
        OpKind::Shl => G::Int(IntCt::U256(lhs << s)),
        OpKind::Shr => G::Int(IntCt::U256(lhs >> s)),
        OpKind::Rotl => G::Int(IntCt::U256(lhs.rotate_left(s))),
        OpKind::Rotr => G::Int(IntCt::U256(lhs.rotate_right(s))),
        OpKind::Eq => G::Bool(lhs.eq(s)),
        OpKind::Ne => G::Bool(lhs.ne(s)),
        _ => return Err(format!("{op:?} is not admissible on u256")),
    })
}

fn unary_u256(op: OpKind, a: &FheUint256) -> Result<GraphValue, String> {
    Ok(match op {
        OpKind::Neg => GraphValue::Int(IntCt::U256(-a)),
        OpKind::Not => GraphValue::Int(IntCt::U256(!a)),
        _ => return Err(format!("{op:?} is not a unary operation")),
    })
}

fn bin_u160(op: OpKind, lhs: &FheUint160, rhs: &FheUint160) -> Result<GraphValue, String> {
    Ok(match op {
        OpKind::Eq => GraphValue::Bool(lhs.eq(rhs)),
        OpKind::Ne => GraphValue::Bool(lhs.ne(rhs)),
        _ => return Err(format!("{op:?} is not admissible on u160")),
    })
}

fn bin_scalar_u160(op: OpKind, lhs: &FheUint160, scalar: ClearInt) -> Result<GraphValue, String> {
    let s = scalar.to_u256();
    Ok(match op {
        OpKind::Eq => GraphValue::Bool(lhs.eq(s)),
        OpKind::Ne => GraphValue::Bool(lhs.ne(s)),
        _ => return Err(format!("{op:?} is not admissible on u160")),
    })
}

fn eval_int_binary(op: OpKind, lhs: &IntCt, rhs: &IntCt) -> Result<GraphValue, String> {
    match (lhs, rhs) {
        (IntCt::U8(a), IntCt::U8(b)) => bin_u8(op, a, b),
        (IntCt::U16(a), IntCt::U16(b)) => bin_u16(op, a, b),
        (IntCt::U32(a), IntCt::U32(b)) => bin_u32(op, a, b),
        (IntCt::U64(a), IntCt::U64(b)) => bin_u64(op, a, b),
        (IntCt::U128(a), IntCt::U128(b)) => bin_u128(op, a, b),
        (IntCt::U160(a), IntCt::U160(b)) => bin_u160(op, a, b),
        (IntCt::U256(a), IntCt::U256(b)) => bin_u256(op, a, b),
        _ => Err("operand types differ".to_string()),
    }
}

fn eval_int_binary_scalar(op: OpKind, lhs: &IntCt, scalar: ClearInt) -> Result<GraphValue, String> {
    match lhs {
        IntCt::U8(a) => bin_scalar_u8(op, a, scalar),
        IntCt::U16(a) => bin_scalar_u16(op, a, scalar),
        IntCt::U32(a) => bin_scalar_u32(op, a, scalar),
        IntCt::U64(a) => bin_scalar_u64(op, a, scalar),
        IntCt::U128(a) => bin_scalar_u128(op, a, scalar),
        IntCt::U160(a) => bin_scalar_u160(op, a, scalar),
        IntCt::U256(a) => bin_scalar_u256(op, a, scalar),
    }
}

fn eval_int_unary(op: OpKind, a: &IntCt) -> Result<GraphValue, String> {
    match a {
        IntCt::U8(a) => unary_u8(op, a),
        IntCt::U16(a) => unary_u16(op, a),
        IntCt::U32(a) => unary_u32(op, a),
        IntCt::U64(a) => unary_u64(op, a),
        IntCt::U128(a) => unary_u128(op, a),
        IntCt::U160(_) => Err(format!("{op:?} is not admissible on u160")),
        IntCt::U256(a) => unary_u256(op, a),
    }
}

/// Casts an encrypted integer into the target type, mirroring the coprocessor's `cast_into`
/// dispatch.
fn cast_int(src: &IntCt, target: ValueType) -> Result<IntCt, String> {
    macro_rules! cast_from {
        ($v:expr) => {
            match target {
                ValueType::U8 => IntCt::U8(FheUint8::cast_from($v.clone())),
                ValueType::U16 => IntCt::U16(FheUint16::cast_from($v.clone())),
                ValueType::U32 => IntCt::U32(FheUint32::cast_from($v.clone())),
                ValueType::U64 => IntCt::U64(FheUint64::cast_from($v.clone())),
                ValueType::U128 => IntCt::U128(FheUint128::cast_from($v.clone())),
                ValueType::U256 => IntCt::U256(FheUint256::cast_from($v.clone())),
                ValueType::Bool | ValueType::U160 => {
                    return Err("invalid cast destination".to_string())
                }
            }
        };
    }
    Ok(match src {
        IntCt::U8(v) => cast_from!(v),
        IntCt::U16(v) => cast_from!(v),
        IntCt::U32(v) => cast_from!(v),
        IntCt::U64(v) => cast_from!(v),
        IntCt::U128(v) => cast_from!(v),
        IntCt::U256(v) => cast_from!(v),
        IntCt::U160(_) => return Err("U160 cannot be cast".to_string()),
    })
}

fn cast_bool(src: &FheBool, target: ValueType) -> Result<IntCt, String> {
    Ok(match target {
        ValueType::U8 => IntCt::U8(FheUint8::cast_from(src.clone())),
        ValueType::U16 => IntCt::U16(FheUint16::cast_from(src.clone())),
        ValueType::U32 => IntCt::U32(FheUint32::cast_from(src.clone())),
        ValueType::U64 => IntCt::U64(FheUint64::cast_from(src.clone())),
        ValueType::U128 => IntCt::U128(FheUint128::cast_from(src.clone())),
        ValueType::U256 => IntCt::U256(FheUint256::cast_from(src.clone())),
        ValueType::Bool | ValueType::U160 => return Err("invalid cast destination".to_string()),
    })
}

/// Trivially encrypts a clear value, mirroring the coprocessor: U160 goes through a trivial U256
/// followed by a cast.
fn trivial_encrypt(value: ClearInt, target: ValueType) -> Result<GraphValue, String> {
    use GraphValue as G;
    Ok(match target {
        ValueType::Bool => G::Bool(FheBool::encrypt_trivial(value.lo != 0)),
        ValueType::U8 => G::Int(IntCt::U8(FheUint8::encrypt_trivial(value.lo as u8))),
        ValueType::U16 => G::Int(IntCt::U16(FheUint16::encrypt_trivial(value.lo as u16))),
        ValueType::U32 => G::Int(IntCt::U32(FheUint32::encrypt_trivial(value.lo as u32))),
        ValueType::U64 => G::Int(IntCt::U64(FheUint64::encrypt_trivial(value.lo as u64))),
        ValueType::U128 => G::Int(IntCt::U128(FheUint128::encrypt_trivial(value.lo))),
        ValueType::U160 => G::Int(IntCt::U160(FheUint160::cast_from(
            FheUint256::encrypt_trivial(value.to_u256()),
        ))),
        ValueType::U256 => G::Int(IntCt::U256(FheUint256::encrypt_trivial(value.to_u256()))),
    })
}

/// Randomness, through the same entry points the coprocessor uses: it always calls the bounded
/// generator, with the full width as the bit count when the operation carries no bound.
fn eval_rand_int(ty: ValueType, seed: Seed, random_bits: u32) -> Result<IntCt, String> {
    let bits = u64::from(random_bits);
    Ok(match ty {
        ValueType::U8 => IntCt::U8(FheUint8::generate_oblivious_pseudo_random_bounded(seed, bits)),
        ValueType::U16 => {
            IntCt::U16(FheUint16::generate_oblivious_pseudo_random_bounded(seed, bits))
        }
        ValueType::U32 => {
            IntCt::U32(FheUint32::generate_oblivious_pseudo_random_bounded(seed, bits))
        }
        ValueType::U64 => {
            IntCt::U64(FheUint64::generate_oblivious_pseudo_random_bounded(seed, bits))
        }
        ValueType::U128 => {
            IntCt::U128(FheUint128::generate_oblivious_pseudo_random_bounded(seed, bits))
        }
        ValueType::U256 => {
            IntCt::U256(FheUint256::generate_oblivious_pseudo_random_bounded(seed, bits))
        }
        ValueType::Bool | ValueType::U160 => {
            return Err("integer randomness only exists on N".to_string())
        }
    })
}

/// The selection, over branches of any exposed type.
fn eval_select(condition: &FheBool, a: &IntCt, b: &IntCt) -> Result<IntCt, String> {
    Ok(match (a, b) {
        (IntCt::U8(a), IntCt::U8(b)) => IntCt::U8(condition.select(a, b)),
        (IntCt::U16(a), IntCt::U16(b)) => IntCt::U16(condition.select(a, b)),
        (IntCt::U32(a), IntCt::U32(b)) => IntCt::U32(condition.select(a, b)),
        (IntCt::U64(a), IntCt::U64(b)) => IntCt::U64(condition.select(a, b)),
        (IntCt::U128(a), IntCt::U128(b)) => IntCt::U128(condition.select(a, b)),
        (IntCt::U160(a), IntCt::U160(b)) => IntCt::U160(condition.select(a, b)),
        (IntCt::U256(a), IntCt::U256(b)) => IntCt::U256(condition.select(a, b)),
        _ => return Err("branch types differ".to_string()),
    })
}

/// The sum of re-randomized operands, through the same iterator sum the coprocessor uses. The
/// operands are guaranteed nonempty and homogeneous by the clear validation.
fn eval_sum(operands: &[IntCt]) -> Result<IntCt, String> {
    macro_rules! sum_arm {
        ($V:ident, $Fhe:ty) => {{
            let refs: Vec<&$Fhe> = operands
                .iter()
                .map(|v| match v {
                    IntCt::$V(ct) => Ok(ct),
                    _ => Err("sum element type mismatch".to_string()),
                })
                .collect::<Result<_, _>>()?;
            IntCt::$V(refs.into_iter().sum())
        }};
    }
    Ok(match operands[0] {
        IntCt::U8(_) => sum_arm!(U8, FheUint8),
        IntCt::U16(_) => sum_arm!(U16, FheUint16),
        IntCt::U32(_) => sum_arm!(U32, FheUint32),
        IntCt::U64(_) => sum_arm!(U64, FheUint64),
        IntCt::U128(_) => sum_arm!(U128, FheUint128),
        _ => return Err("sum only exists on the arithmetic types".to_string()),
    })
}

/// Membership through the same `contains` entry point the coprocessor uses. The set is
/// guaranteed nonempty and homogeneous by the clear validation.
fn eval_is_in(value: &IntCt, set: &[IntCt]) -> Result<FheBool, String> {
    macro_rules! is_in_arm {
        ($V:ident, $Fhe:ty, $value:expr) => {{
            let set: Vec<$Fhe> = set
                .iter()
                .map(|v| match v {
                    IntCt::$V(ct) => Ok(ct.clone()),
                    _ => Err("set element type mismatch".to_string()),
                })
                .collect::<Result<_, _>>()?;
            <$Fhe>::contains(&set, $value)
        }};
    }
    Ok(match value {
        IntCt::U8(v) => is_in_arm!(U8, FheUint8, v),
        IntCt::U16(v) => is_in_arm!(U16, FheUint16, v),
        IntCt::U32(v) => is_in_arm!(U32, FheUint32, v),
        IntCt::U64(v) => is_in_arm!(U64, FheUint64, v),
        IntCt::U128(v) => is_in_arm!(U128, FheUint128, v),
        IntCt::U160(v) => is_in_arm!(U160, FheUint160, v),
        IntCt::U256(v) => is_in_arm!(U256, FheUint256, v),
    })
}

/// The fused multiply-divide, through the same entry points the coprocessor uses.
fn eval_mul_div(a: &IntCt, factor2: Option<&IntCt>, scalar2: ClearInt, divisor: ClearInt) -> Result<IntCt, String> {
    macro_rules! mul_div_arm {
        ($V:ident, $Fhe:ty, $Clear:ty, $a:expr) => {{
            let d = <$Clear>::try_from(divisor.lo)
                .map_err(|_| "divisor does not fit the operand type".to_string())?;
            match factor2 {
                Some(IntCt::$V(b)) => IntCt::$V($a.fused_mul_scalar_div(b, d)),
                Some(_) => return Err("MulDiv factor type mismatch".to_string()),
                None => {
                    let s = <$Clear>::try_from(scalar2.lo)
                        .map_err(|_| "scalar factor does not fit the operand type".to_string())?;
                    IntCt::$V($a.fused_scalar_mul_scalar_div(s, d))
                }
            }
        }};
    }
    Ok(match a {
        IntCt::U8(a) => mul_div_arm!(U8, FheUint8, u8, a),
        IntCt::U16(a) => mul_div_arm!(U16, FheUint16, u16, a),
        IntCt::U32(a) => mul_div_arm!(U32, FheUint32, u32, a),
        IntCt::U64(a) => mul_div_arm!(U64, FheUint64, u64, a),
        _ => return Err("MulDiv stops at 64 bits".to_string()),
    })
}

/// The protocol's pre-evaluation step for one node: absorb every encrypted operand into the node
/// context in operand order, finalize the context once, then re-randomize each operand with its
/// own seed, in that same order. Clear scalars take part in neither loop.
enum NodeOperand<'a> {
    Int(&'a mut IntCt),
    Bool(&'a mut FheBool),
}

fn rerand_node(opcode: u32, operands: &mut [NodeOperand<'_>], cpk: &CompactPublicKey) {
    let mut ctx = node_re_randomization_context(opcode);
    for operand in operands.iter() {
        match operand {
            NodeOperand::Int(v) => v.absorb(&mut ctx),
            NodeOperand::Bool(v) => ctx.add_ciphertext(&**v),
        }
    }
    let mut seed_gen = ctx.finalize();
    for operand in operands.iter_mut() {
        match operand {
            NodeOperand::Int(v) => v.rerand(cpk, &mut seed_gen),
            NodeOperand::Bool(v) => re_randomize_operand(&mut **v, cpk, &mut seed_gen),
        }
    }
}

/// Decrypts every value the graph produced and compares it to its clear counterpart, so a
/// failure names the node that diverged instead of the transaction as a whole.
fn check_produced_values(
    desc: &TransactionDescription,
    clear: &ClearEvaluation,
    ints: &[IntCt],
    bools: &[FheBool],
    cks: &ClientKey,
) -> Result<(), String> {
    for (pos, ct) in ints.iter().enumerate().skip(desc.inputs.len()) {
        let got = ct.decrypt_clear(cks);
        let (expected_ty, expected) = clear.ints[pos];
        if ct.ty() != expected_ty || got != expected {
            let node_index = clear.int_node_map[pos - desc.inputs.len()];
            return Err(format!(
                "{}: expected {} {expected}, got {} {got}",
                node_err(node_index, &desc.nodes[node_index], "wrong result"),
                expected_ty.name(),
                ct.ty().name(),
            ));
        }
    }
    for (pos, ct) in bools.iter().enumerate() {
        let got: bool = ct.decrypt(cks);
        let expected = clear.bools[pos];
        if got != expected {
            let node_index = clear.bool_node_map[pos];
            return Err(format!(
                "{}: expected {expected}, got {got}",
                node_err(node_index, &desc.nodes[node_index], "wrong result")
            ));
        }
    }
    Ok(())
}

/// Runs one transaction through the whole protocol workflow. `step_by_step` is the replay mode:
/// decrypt and print every node as it is evaluated.
///
/// Expects a server key on the calling thread and the transaction's encryption engine already
/// installed; see [`run_transaction_or_dump`] for the usual entry point.
pub(crate) fn run_transaction(
    desc: &TransactionDescription,
    cks: &ClientKey,
    cpk: &CompactPublicKey,
    step_by_step: bool,
) -> Result<(), String> {
    // Validation pass, before any FHE work: rand values are not known yet, their nodes evaluate
    // to placeholders. The real clear evaluation runs after the first graph evaluation has
    // decrypted them.
    evaluate_clear(desc, &RandValues::new())?;
    let primary_ty = ValueType::from_width(desc.width).unwrap();

    // The user encrypts the transaction inputs, each tied to its origin by metadata, and they
    // are stored compressed.
    let mut builder = CompressedCiphertextListBuilder::new();
    for input in desc.inputs.iter() {
        let mut ct = match primary_ty {
            ValueType::U8 => IntCt::U8(FheUint8::encrypt(input.value as u8, cks)),
            ValueType::U16 => IntCt::U16(FheUint16::encrypt(input.value as u16, cks)),
            ValueType::U32 => IntCt::U32(FheUint32::encrypt(input.value as u32, cks)),
            ValueType::U64 => IntCt::U64(FheUint64::encrypt(input.value as u64, cks)),
            ValueType::U128 => IntCt::U128(FheUint128::encrypt(input.value, cks)),
            _ => return Err(format!("unsupported input width {}", desc.width)),
        };
        ct.set_metadata(&input.metadata);
        ct.push_into(&mut builder);
    }
    let compressed_inputs = builder
        .build()
        .map_err(|e| format!("failed to compress the inputs: {e}"))?;

    // And loaded back before the transaction is evaluated.
    let mut inputs: Vec<IntCt> = Vec::with_capacity(desc.inputs.len());
    for (pos, input) in desc.inputs.iter().enumerate() {
        let ct = IntCt::get_from(&compressed_inputs, pos, primary_ty)?;
        if ct.metadata() != input.metadata.as_slice() {
            return Err(format!(
                "input {pos} lost its re-randomization metadata through compression"
            ));
        }
        let decrypted = ct.decrypt_clear(cks);
        if decrypted != ClearInt::from_lo(input.value) {
            return Err(format!(
                "input {pos} changed value through compression/decompression: \
                 expected {}, got {decrypted}",
                input.value
            ));
        }
        inputs.push(ct);
    }

    // The transaction itself: every node re-randomizes its own operands, evaluates, and appends
    // its result to its pool. Operands are cloned per node on purpose, a value feeding several
    // nodes is re-randomized independently in each of them, exactly like a handle read several
    // times by a transaction would be.
    //
    // With `check`, the replay mode, every node is decrypted and compared to its clear value
    // right after being evaluated, and the whole trace is printed: the first diverging node is
    // named even when later nodes consume its corrupted result.
    //
    // Rand nodes are decrypted as they are produced and their values recorded once, keyed by
    // node index: the first evaluation fills the map and seeds the clear oracle with it, the
    // second one finds the entries taken.
    let rand_values: std::cell::RefCell<RandValues> = std::cell::RefCell::new(RandValues::new());
    let run_graph = |inputs: &[IntCt],
                     check: Option<&ClearEvaluation>|
     -> Result<(Vec<IntCt>, Vec<FheBool>), String> {
        let mut ints: Vec<IntCt> = inputs.to_vec();
        let mut bools: Vec<FheBool> = Vec::new();

        for (node_index, node) in desc.nodes.iter().enumerate() {
            let op = node.op;
            let opcode = op.opcode();
            let ints_before = ints.len();

            let get_int = |i: &usize| -> Result<IntCt, String> {
                ints.get(*i)
                    .cloned()
                    .ok_or_else(|| node_err(node_index, node, "integer operand out of range"))
            };
            let get_bool = |i: &usize| -> Result<FheBool, String> {
                bools
                    .get(*i)
                    .cloned()
                    .ok_or_else(|| node_err(node_index, node, "boolean operand out of range"))
            };

            let result: GraphValue = match op {
                OpKind::Cast => {
                    let target = node
                        .target
                        .ok_or_else(|| node_err(node_index, node, "cast needs a target type"))?;
                    match node.operands.as_slice() {
                        [Operand::Ct(i)] => {
                            let mut src = get_int(i)?;
                            rerand_node(opcode, &mut [NodeOperand::Int(&mut src)], cpk);
                            GraphValue::Int(
                                cast_int(&src, target)
                                    .map_err(|e| node_err(node_index, node, &e))?,
                            )
                        }
                        [Operand::BoolCt(i)] => {
                            let mut src = get_bool(i)?;
                            rerand_node(opcode, &mut [NodeOperand::Bool(&mut src)], cpk);
                            GraphValue::Int(
                                cast_bool(&src, target)
                                    .map_err(|e| node_err(node_index, node, &e))?,
                            )
                        }
                        _ => return Err(node_err(node_index, node, "malformed operand list")),
                    }
                }
                OpKind::TrivialEncrypt => {
                    let target = node.target.ok_or_else(|| {
                        node_err(node_index, node, "trivial encryption needs a target type")
                    })?;
                    let value = node.operands[0]
                        .as_clear_scalar()
                        .ok_or_else(|| node_err(node_index, node, "expected a clear operand"))?;
                    // No encrypted operand: nothing to re-randomize.
                    trivial_encrypt(value, target).map_err(|e| node_err(node_index, node, &e))?
                }
                OpKind::Select => match node.operands.as_slice() {
                    [Operand::BoolCt(c), Operand::Ct(i), Operand::Ct(j)] => {
                        let mut condition = get_bool(c)?;
                        let mut a = get_int(i)?;
                        let mut b = get_int(j)?;
                        rerand_node(
                            opcode,
                            &mut [
                                NodeOperand::Bool(&mut condition),
                                NodeOperand::Int(&mut a),
                                NodeOperand::Int(&mut b),
                            ],
                            cpk,
                        );
                        GraphValue::Int(
                            eval_select(&condition, &a, &b)
                                .map_err(|e| node_err(node_index, node, &e))?,
                        )
                    }
                    [Operand::BoolCt(c), Operand::BoolCt(i), Operand::BoolCt(j)] => {
                        let mut condition = get_bool(c)?;
                        let mut a = get_bool(i)?;
                        let mut b = get_bool(j)?;
                        rerand_node(
                            opcode,
                            &mut [
                                NodeOperand::Bool(&mut condition),
                                NodeOperand::Bool(&mut a),
                                NodeOperand::Bool(&mut b),
                            ],
                            cpk,
                        );
                        GraphValue::Bool(condition.select(&a, &b))
                    }
                    _ => return Err(node_err(node_index, node, "malformed operand list")),
                },
                OpKind::Rand | OpKind::RandBounded => {
                    let target = node.target.ok_or_else(|| {
                        node_err(node_index, node, "randomness needs a type")
                    })?;
                    let [Operand::Scalar(seed), bound @ ..] = node.operands.as_slice() else {
                        return Err(node_err(node_index, node, "malformed operand list"));
                    };
                    let seed = Seed(*seed);
                    // All inputs are clear scalars: nothing to re-randomize, like the executor.
                    match (node.op, bound, target) {
                        (OpKind::Rand, [], ValueType::Bool) => {
                            GraphValue::Bool(FheBool::generate_oblivious_pseudo_random(seed))
                        }
                        (OpKind::Rand, [], ty) => GraphValue::Int(
                            eval_rand_int(ty, seed, ty.bits())
                                .map_err(|e| node_err(node_index, node, &e))?,
                        ),
                        (OpKind::RandBounded, [bound], ty) => {
                            let bound = bound.as_clear_scalar().ok_or_else(|| {
                                node_err(node_index, node, "expected a clear scalar bound")
                            })?;
                            let random_bits = bound.floor_log2().min(ty.bits());
                            GraphValue::Int(
                                eval_rand_int(ty, seed, random_bits)
                                    .map_err(|e| node_err(node_index, node, &e))?,
                            )
                        }
                        _ => return Err(node_err(node_index, node, "malformed operand list")),
                    }
                }
                OpKind::Sum => {
                    if node.operands.is_empty() {
                        // An empty sum is an encrypted zero of the declared output type, like
                        // the coprocessor produces.
                        let target = node.target.ok_or_else(|| {
                            node_err(node_index, node, "sum needs an output type")
                        })?;
                        trivial_encrypt(ClearInt::ZERO, target)
                            .map_err(|e| node_err(node_index, node, &e))?
                    } else {
                        let mut operands: Vec<IntCt> = node
                            .operands
                            .iter()
                            .map(|operand| match operand {
                                Operand::Ct(i) => get_int(i),
                                _ => Err(node_err(node_index, node, "sum takes no scalars")),
                            })
                            .collect::<Result<_, _>>()?;
                        let mut handles: Vec<NodeOperand<'_>> =
                            operands.iter_mut().map(NodeOperand::Int).collect();
                        rerand_node(opcode, &mut handles, cpk);
                        GraphValue::Int(
                            eval_sum(&operands).map_err(|e| node_err(node_index, node, &e))?,
                        )
                    }
                }
                OpKind::IsIn => {
                    let mut operands: Vec<IntCt> = node
                        .operands
                        .iter()
                        .map(|operand| match operand {
                            Operand::Ct(i) => get_int(i),
                            _ => Err(node_err(node_index, node, "membership takes no scalars")),
                        })
                        .collect::<Result<_, _>>()?;
                    if operands.len() == 1 {
                        // Empty membership is trivially false, like the coprocessor produces,
                        // but the value operand still goes through the node context.
                        let mut handles: Vec<NodeOperand<'_>> =
                            operands.iter_mut().map(NodeOperand::Int).collect();
                        rerand_node(opcode, &mut handles, cpk);
                        GraphValue::Bool(FheBool::encrypt_trivial(false))
                    } else {
                        let mut handles: Vec<NodeOperand<'_>> =
                            operands.iter_mut().map(NodeOperand::Int).collect();
                        rerand_node(opcode, &mut handles, cpk);
                        let (value, set) = operands.split_first().unwrap();
                        GraphValue::Bool(
                            eval_is_in(value, set).map_err(|e| node_err(node_index, node, &e))?,
                        )
                    }
                }
                OpKind::MulDiv => {
                    let [Operand::Ct(a), factor2, divisor] = node.operands.as_slice() else {
                        return Err(node_err(node_index, node, "malformed operand list"));
                    };
                    let divisor = divisor
                        .as_clear_scalar()
                        .ok_or_else(|| node_err(node_index, node, "expected a scalar divisor"))?;
                    let mut a = get_int(a)?;
                    match factor2 {
                        Operand::Ct(j) => {
                            let mut b = get_int(j)?;
                            rerand_node(
                                opcode,
                                &mut [NodeOperand::Int(&mut a), NodeOperand::Int(&mut b)],
                                cpk,
                            );
                            GraphValue::Int(
                                eval_mul_div(&a, Some(&b), ClearInt::ZERO, divisor)
                                    .map_err(|e| node_err(node_index, node, &e))?,
                            )
                        }
                        operand => {
                            let s = operand.as_clear_scalar().ok_or_else(|| {
                                node_err(node_index, node, "expected a scalar factor")
                            })?;
                            rerand_node(opcode, &mut [NodeOperand::Int(&mut a)], cpk);
                            GraphValue::Int(
                                eval_mul_div(&a, None, s, divisor)
                                    .map_err(|e| node_err(node_index, node, &e))?,
                            )
                        }
                    }
                }
                _ => match node.operands.as_slice() {
                    [Operand::Ct(i)] => {
                        let mut a = get_int(i)?;
                        rerand_node(opcode, &mut [NodeOperand::Int(&mut a)], cpk);
                        eval_int_unary(op, &a).map_err(|e| node_err(node_index, node, &e))?
                    }
                    [Operand::BoolCt(i)] if op == OpKind::Not => {
                        let mut a = get_bool(i)?;
                        rerand_node(opcode, &mut [NodeOperand::Bool(&mut a)], cpk);
                        GraphValue::Bool(!&a)
                    }
                    [Operand::Ct(i), Operand::Ct(j)] => {
                        if matches!(op, OpKind::Div | OpKind::Rem) {
                            return Err(node_err(
                                node_index,
                                node,
                                "the host executor only accepts a clear scalar divisor",
                            ));
                        }
                        let mut lhs = get_int(i)?;
                        let mut rhs = get_int(j)?;
                        rerand_node(
                            opcode,
                            &mut [NodeOperand::Int(&mut lhs), NodeOperand::Int(&mut rhs)],
                            cpk,
                        );
                        eval_int_binary(op, &lhs, &rhs)
                            .map_err(|e| node_err(node_index, node, &e))?
                    }
                    [Operand::Ct(i), rhs @ (Operand::Scalar(_) | Operand::BigScalar { .. })] => {
                        let mut lhs = get_int(i)?;
                        let scalar = rhs.as_clear_scalar().unwrap();
                        rerand_node(opcode, &mut [NodeOperand::Int(&mut lhs)], cpk);
                        eval_int_binary_scalar(op, &lhs, scalar)
                            .map_err(|e| node_err(node_index, node, &e))?
                    }
                    [Operand::BoolCt(i), Operand::BoolCt(j)] => {
                        let mut lhs = get_bool(i)?;
                        let mut rhs = get_bool(j)?;
                        rerand_node(
                            opcode,
                            &mut [NodeOperand::Bool(&mut lhs), NodeOperand::Bool(&mut rhs)],
                            cpk,
                        );
                        GraphValue::Bool(match op {
                            OpKind::BitAnd => &lhs & &rhs,
                            OpKind::BitOr => &lhs | &rhs,
                            OpKind::BitXor => &lhs ^ &rhs,
                            OpKind::Eq => lhs.eq(&rhs),
                            OpKind::Ne => lhs.ne(&rhs),
                            _ => {
                                return Err(node_err(
                                    node_index,
                                    node,
                                    "operation not supported on encrypted booleans",
                                ))
                            }
                        })
                    }
                    [Operand::BoolCt(i), Operand::BoolScalar(b)] => {
                        let mut lhs = get_bool(i)?;
                        rerand_node(opcode, &mut [NodeOperand::Bool(&mut lhs)], cpk);
                        GraphValue::Bool(match op {
                            OpKind::BitAnd => &lhs & *b,
                            OpKind::BitOr => &lhs | *b,
                            OpKind::BitXor => &lhs ^ *b,
                            OpKind::Eq => lhs.eq(*b),
                            OpKind::Ne => lhs.ne(*b),
                            _ => {
                                return Err(node_err(
                                    node_index,
                                    node,
                                    "operation not supported on encrypted booleans",
                                ))
                            }
                        })
                    }
                    _ => return Err(node_err(node_index, node, "malformed operand list")),
                },
            };

            match result {
                GraphValue::Int(v) => ints.push(v),
                GraphValue::Bool(b) => bools.push(b),
            }

            if matches!(op, OpKind::Rand | OpKind::RandBounded) {
                rand_values
                    .borrow_mut()
                    .entry(node_index)
                    .or_insert_with(|| {
                        if ints.len() > ints_before {
                            RandValue::Int(ints.last().unwrap().decrypt_clear(cks))
                        } else {
                            RandValue::Bool(bools.last().unwrap().decrypt(cks))
                        }
                    });
            }

            if let Some(clear) = check {
                if ints.len() > ints_before {
                    let got = ints.last().unwrap().decrypt_clear(cks);
                    let expected = clear.ints[ints.len() - 1].1;
                    let ok = got == expected;
                    println!(
                        "  node {node_index} {node:?}: clear {expected}, decrypted {got} [{}]",
                        if ok { "ok" } else { "MISMATCH" }
                    );
                    if !ok {
                        return Err(node_err(
                            node_index,
                            node,
                            &format!("first diverging step: expected {expected}, got {got}"),
                        ));
                    }
                } else {
                    let got: bool = bools.last().unwrap().decrypt(cks);
                    let expected = clear.bools[bools.len() - 1];
                    let ok = got == expected;
                    println!(
                        "  node {node_index} {node:?}: clear {expected}, decrypted {got} [{}]",
                        if ok { "ok" } else { "MISMATCH" }
                    );
                    if !ok {
                        return Err(node_err(
                            node_index,
                            node,
                            &format!("first diverging step: expected {expected}, got {got}"),
                        ));
                    }
                }
            }
        }

        Ok((ints, bools))
    };

    let (ints, bools) = run_graph(&inputs, None)?;

    // The real clear evaluation, seeded with the decrypted rand values; this is also where the
    // range of every rand value is checked against its bound.
    let clear = evaluate_clear(desc, &rand_values.borrow())?;

    // Every produced value is checked right after the graph, so a failure names the node that
    // diverged instead of the transaction as a whole. In replay mode this is left to the second
    // evaluation just below, which prints the whole decrypted trace while checking it.
    if !step_by_step {
        check_produced_values(desc, &clear, &ints, &bools, cks)?;
    }

    // Re-randomization seeds only depend on the node opcode and on the node operands, and the
    // oblivious randomness only on its stored seed, so evaluating the same transaction again has
    // to produce the very same ciphertexts.
    {
        let (ints_bis, bools_bis) = run_graph(&inputs, step_by_step.then_some(&clear))?;
        let same_ints = ints.len() == ints_bis.len()
            && ints
                .iter()
                .zip(ints_bis.iter())
                .all(|(a, b)| a.serialize_bytes() == b.serialize_bytes());
        let same_bools =
            bincode::serialize(&bools).unwrap() == bincode::serialize(&bools_bis).unwrap();
        if !same_ints || !same_bools {
            return Err("determinism check failed: the second evaluation produced different \
                        ciphertexts"
                .to_string());
        }
    }
    // Results are stored back compressed.
    let produced_ints = &ints[desc.inputs.len()..];
    if !produced_ints.is_empty() || !bools.is_empty() {
        let mut builder = CompressedCiphertextListBuilder::new();
        for ct in produced_ints.iter() {
            ct.push_into(&mut builder);
        }
        for ct in bools.iter() {
            builder.push(ct.clone());
        }
        let compressed_outputs = builder
            .build()
            .map_err(|e| format!("failed to compress the results: {e}"))?;

        for (pos, original) in produced_ints.iter().enumerate() {
            let ct = IntCt::get_from(&compressed_outputs, pos, original.ty())?;
            if ct.decrypt_clear(cks) != clear.ints[desc.inputs.len() + pos].1 {
                return Err(format!(
                    "integer result {pos} changed value through compression/decompression"
                ));
            }
        }
        for pos in 0..bools.len() {
            let list_pos = produced_ints.len() + pos;
            let ct: FheBool = compressed_outputs
                .get(list_pos)
                .map_err(|e| format!("failed to decompress result {list_pos}: {e}"))?
                .ok_or_else(|| format!("result {list_pos} missing from the compressed list"))?;
            let got: bool = ct.decrypt(cks);
            if got != clear.bools[pos] {
                return Err(format!(
                    "boolean result {pos} changed value through compression/decompression"
                ));
            }
        }
    }

    // Before being handed to threshold decryption, results are noise squashed, and the squashed
    // ciphertexts are compressed too. One value per pool is enough to keep the squashing stage
    // covered without doubling the cost of the transaction.
    {
        let last_int = ints.last().unwrap();
        let (last_ty, expected_int) = *clear.ints.last().unwrap();
        let ns_int = last_int.squash_noise()?;
        let got = decrypt_squashed(&ns_int, last_ty, cks);
        if got != expected_int {
            return Err(format!(
                "last integer value changed through noise squashing: \
                 expected {expected_int}, got {got}"
            ));
        }

        let ns_bool = match bools.last() {
            Some(last_bool) => {
                let ns_bool = last_bool
                    .squash_noise()
                    .map_err(|e| format!("boolean noise squashing failed: {e}"))?;
                let got: bool = ns_bool.decrypt(cks);
                if got != *clear.bools.last().unwrap() {
                    return Err("last boolean value changed through noise squashing".to_string());
                }
                Some(ns_bool)
            }
            None => None,
        };

        let mut builder = CompressedSquashedNoiseCiphertextListBuilder::new();
        builder.push(ns_int);
        let has_bool = ns_bool.is_some();
        if let Some(ns_bool) = ns_bool {
            builder.push(ns_bool);
        }
        let compressed_ns = builder
            .build()
            .map_err(|e| format!("failed to compress the squashed results: {e}"))?;

        let ns_int: SquashedNoiseFheUint = compressed_ns
            .get(0)
            .map_err(|e| format!("failed to decompress the squashed integer: {e}"))?
            .ok_or_else(|| "squashed integer missing from the compressed list".to_string())?;
        let got = decrypt_squashed(&ns_int, last_ty, cks);
        if got != expected_int {
            return Err(format!(
                "invalid end to end integer result: expected {expected_int}, got {got}"
            ));
        }
        if has_bool {
            let ns_bool: SquashedNoiseFheBool = compressed_ns
                .get(1)
                .map_err(|e| format!("failed to decompress the squashed boolean: {e}"))?
                .ok_or_else(|| "squashed boolean missing from the compressed list".to_string())?;
            let got: bool = ns_bool.decrypt(cks);
            if got != *clear.bools.last().unwrap() {
                return Err(format!(
                    "invalid end to end boolean result: expected {}, got {got}",
                    clear.bools.last().unwrap()
                ));
            }
        }
    }

    Ok(())
}

//
// Failure reports and replay
//

fn failure_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("TFHE_RS_PROTOCOL_FAILURE_DIR").unwrap_or_else(|_| ".".to_string()),
    )
}

fn failure_report_path(transaction_index: usize) -> std::path::PathBuf {
    failure_dir().join(format!("protocol_random_ops_failure_tx{transaction_index}.json"))
}

/// A rolling trace of the most recent transactions, written next to the failure reports as
/// `protocol_random_ops_recent_slot<n>.json`. Each file is a complete failure report (with a
/// placeholder error), written *before* its transaction runs: when a run dies without reaching
/// the failure path at all, a crash or a device fault, the graphs that were executing are
/// already on disk, each replayable on its own through `TFHE_RS_PROTOCOL_REPLAY`. The slot is
/// the transaction index modulo the capacity, so the files rotate by themselves; the index
/// inside each file says which ones are the newest.
pub(crate) struct RecentLog {
    dir: std::path::PathBuf,
    capacity: usize,
}

impl RecentLog {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            dir: failure_dir(),
            capacity,
        }
    }

    pub(crate) fn record(
        &self,
        desc: &TransactionDescription,
        transaction_seed: Seed,
        index: usize,
        identity: &RunIdentity<'_>,
    ) {
        let report = FailureReport {
            params: identity.params_name.to_string(),
            key_seed: identity.key_seed.0,
            setup_seed: identity.setup_seed.0,
            transaction_seed: transaction_seed.0,
            transaction_index: index,
            error: "recent transaction trace, not a failure".to_string(),
            description: desc.clone(),
        };
        let path = self
            .dir
            .join(format!("protocol_random_ops_recent_slot{}.json", index % self.capacity));
        // Best effort: the trace must never take a healthy run down.
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap());
    }
}

/// Seeds the transaction's encryption engine, runs the transaction, and on failure writes the
/// self contained JSON report before panicking with the replay instructions.
pub(crate) fn run_transaction_or_dump(
    desc: &TransactionDescription,
    transaction_seed: Seed,
    index: usize,
    keys: &ProtocolKeys,
    identity: &RunIdentity<'_>,
    step_by_step: bool,
) {
    install_seeded_engine(transaction_seed);

    if let Err(error) = run_transaction(desc, &keys.cks, &keys.cpk, step_by_step) {
        let report = FailureReport {
            params: identity.params_name.to_string(),
            key_seed: identity.key_seed.0,
            setup_seed: identity.setup_seed.0,
            transaction_seed: transaction_seed.0,
            transaction_index: index,
            error: error.clone(),
            description: desc.clone(),
        };
        let path = failure_report_path(index);
        std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap())
            .unwrap_or_else(|e| panic!("failed to write the failure report to {path:?}: {e}"));

        panic!(
            "transaction {index}: {error}\n\
             failing graph written to {path:?}\n\
             replay it alone with TFHE_RS_PROTOCOL_REPLAY={path:?} and the replay test of the \
             backend the run used",
        );
    }
}

pub(crate) fn load_failure_report(path: &str) -> FailureReport {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read the failure report {path}: {e}"));
    serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("failed to parse the failure report {path}: {e}"))
}

/// Replays one failure report: rebuilds the keys from the stored seeds, installs the server key
/// through the backend specific closure, and re-runs the stored transaction. Panics again, with
/// a fresh report, if the transaction still fails.
pub(crate) fn replay_from_report(
    report: &FailureReport,
    install_server_key: impl FnOnce(&CompressedServerKey),
) {
    let meta_params = meta_params_by_name(&report.params)
        .unwrap_or_else(|| panic!("unknown parameter set {}", report.params));

    let keys = generate_protocol_keys(
        Config::from(meta_params),
        Seed(report.key_seed),
        Seed(report.setup_seed),
    );
    install_server_key(&keys.compressed_sks);

    println!(
        "replaying transaction {} step by step, decrypting after every node:",
        report.transaction_index
    );
    run_transaction_or_dump(
        &report.description,
        Seed(report.transaction_seed),
        report.transaction_index,
        &keys,
        &RunIdentity {
            params_name: &report.params,
            key_seed: Seed(report.key_seed),
            setup_seed: Seed(report.setup_seed),
        },
        true,
    );

    println!(
        "replay of transaction {} succeeded, the failure did not reproduce",
        report.transaction_index
    );
}

//
// Run loop
//

/// Per signature hit counters, printed at the end of a run so the coverage of the
/// (operation, type, operand mode) matrix is visible.
#[derive(Default)]
pub(crate) struct Coverage {
    hits: BTreeMap<String, u64>,
}

impl Coverage {
    pub(crate) fn record(&mut self, evaluation: &ClearEvaluation) {
        for signature in evaluation.signatures.iter() {
            *self.hits.entry(signature.clone()).or_default() += 1;
        }
    }

    pub(crate) fn print(&self) {
        for (signature, count) in self.hits.iter() {
            println!("  {signature}: {count}");
        }
    }
}

/// The complete run: seeded setup, then transactions drawn and verified until the transaction
/// count, or the wall clock budget when `TFHE_RS_PROTOCOL_DURATION_SECS` is set, is spent.
///
/// `install_server_key` is the backend specific part: decompressing the server key to the CPU or
/// to a GPU and installing it on whatever threads evaluate transactions.
pub(crate) fn protocol_random_ops_run(
    meta_params: MetaParameters,
    params_name: &str,
    test_name: &str,
    install_server_key: impl FnOnce(&CompressedServerKey),
) {
    let seed = get_user_defined_seed().unwrap_or_else(|| {
        let mut seeder = crate::core_crypto::prelude::new_seeder();
        seeder.seed()
    });
    println!("{test_name}::seed = {}", seed.0);
    println!(
        "{test_name}: replay the whole run with TFHE_RS_LONGRUN_TESTS_SEED={}",
        seed.0
    );

    // Everything a run consumes hangs off this one seed: the keys, each transaction's encryption
    // engine, and the transaction stream.
    let mut root = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
    let key_seed = root.seed();
    let setup_seed = root.seed();
    let data_seed = root.seed();

    let keys = generate_protocol_keys(Config::from(meta_params), key_seed, setup_seed);
    install_server_key(&keys.compressed_sks);

    let identity = RunIdentity {
        params_name,
        key_seed,
        setup_seed,
    };
    let mut datagen = RandomGenerator::<DefaultRandomGenerator>::new(data_seed);

    let duration = run_duration();
    let count = num_transactions();
    match duration {
        Some(budget) => println!(
            "{test_name}: running for {} seconds of wall clock",
            budget.as_secs()
        ),
        None => println!("{test_name}: running {count} transactions"),
    }

    let start = Instant::now();
    let mut coverage = Coverage::default();
    let recent = RecentLog::new(10);
    let mut index = 0usize;
    loop {
        match duration {
            Some(budget) => {
                if start.elapsed() >= budget {
                    break;
                }
            }
            None => {
                if index >= count {
                    break;
                }
            }
        }

        // Each transaction encrypts under its own seed, so one failing transaction replays alone
        // from its JSON report, whatever ran before it.
        let transaction_seed = root.seed();
        let desc = draw_transaction(&mut datagen);
        if let Ok(evaluation) = evaluate_clear(&desc, &RandValues::new()) {
            coverage.record(&evaluation);
        }

        recent.record(&desc, transaction_seed, index, &identity);
        run_transaction_or_dump(&desc, transaction_seed, index, &keys, &identity, false);

        index += 1;
        if index.is_multiple_of(100) {
            println!(
                "{test_name}: {index} transactions, {} seconds elapsed",
                start.elapsed().as_secs()
            );
        }
    }

    println!("{test_name}: done, {index} transactions, signature coverage:");
    coverage.print();
}

//
// Forced coverage
//

/// Builds one forced transaction: the two u8 inputs occupy the first integer pool slots, and
/// every pushed node declares which pool its result extends, returning the slot it lands in.
struct ForcedTransaction {
    nodes: Vec<Node>,
    num_ints: usize,
    num_bools: usize,
}

impl ForcedTransaction {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            num_ints: 2,
            num_bools: 0,
        }
    }

    fn push_int(&mut self, op: OpKind, operands: Vec<Operand>, target: Option<ValueType>) -> usize {
        self.nodes.push(Node {
            op,
            operands,
            target,
        });
        self.num_ints += 1;
        self.num_ints - 1
    }

    fn push_bool(&mut self, op: OpKind, operands: Vec<Operand>, target: Option<ValueType>) -> usize {
        self.nodes.push(Node {
            op,
            operands,
            target,
        });
        self.num_bools += 1;
        self.num_bools - 1
    }

    fn into_description(self) -> TransactionDescription {
        TransactionDescription {
            width: 8,
            inputs: vec![
                InputDesc {
                    value: 170,
                    metadata: vec![0x5A; METADATA_LEN],
                },
                InputDesc {
                    value: 3,
                    metadata: vec![0xA5; METADATA_LEN],
                },
            ],
            nodes: self.nodes,
        }
    }
}

/// The admissible plain operations of an integer type, the tables the generator draws from.
fn plain_ops_for(ty: ValueType) -> &'static [OpKind] {
    match ty {
        ValueType::U256 => &U256_OPS,
        ValueType::U160 => &U160_OPS,
        _ => &SMALL_INT_OPS,
    }
}

/// The bound exponents the forced pass exercises for one bounded rand type: the degenerate bound
/// of one, two, just under the width, and just over it, where the executor caps the bit count.
/// Bounds cannot exceed 255 bits, the largest power of two an operand can carry.
fn forced_rand_exponents(ty: ValueType) -> [u32; 4] {
    [0, 1, ty.bits() - 1, (ty.bits() + 1).min(255)]
}

/// The deterministic coverage pass: one handcrafted transaction per value type, running every
/// admissible operation of that type once per operand mode, plus the cast matrix, the collection
/// sizes 0, 1 and 3, the collection limits on one narrow and one wide type, and the rand bound
/// edges. Where the random generator covers the matrix statistically over a long run, this pass
/// covers it exhaustively in one short one.
pub(crate) fn forced_coverage_descriptions() -> Vec<TransactionDescription> {
    // The first operand alternates bits inside every 2 bit block, the second alternates at the
    // block level, zero blocks between saturated ones, so every forced operation sees both
    // pattern families at once.
    const ALTERNATING_HIGH: u128 = 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA;
    const BLOCK_LOW: u128 = 0x3333_3333_3333_3333_3333_3333_3333_3333;

    let mut descriptions = Vec::new();

    for ty in [
        ValueType::U8,
        ValueType::U16,
        ValueType::U32,
        ValueType::U64,
        ValueType::U128,
        ValueType::U160,
        ValueType::U256,
    ] {
        let a_val = ClearInt {
            lo: ALTERNATING_HIGH,
            hi: ALTERNATING_HIGH,
        }
        .masked(ty);
        let b_val = ClearInt {
            lo: BLOCK_LOW,
            hi: BLOCK_LOW,
        }
        .masked(ty);

        let mut t = ForcedTransaction::new();
        let a = t.push_int(
            OpKind::TrivialEncrypt,
            vec![scalar_operand(a_val)],
            Some(ty),
        );
        let b = t.push_int(
            OpKind::TrivialEncrypt,
            vec![scalar_operand(b_val)],
            Some(ty),
        );
        let flag = t.push_bool(OpKind::Eq, vec![Operand::Ct(a), Operand::Ct(b)], None);

        for &op in plain_ops_for(ty) {
            match op {
                OpKind::Neg | OpKind::Not => {
                    t.push_int(op, vec![Operand::Ct(a)], None);
                }
                // Division and remainder only exist with a clear scalar divisor.
                OpKind::Div | OpKind::Rem => {
                    t.push_int(op, vec![Operand::Ct(a), scalar_operand(b_val)], None);
                }
                OpKind::Eq | OpKind::Ne | OpKind::Ge | OpKind::Gt | OpKind::Le | OpKind::Lt => {
                    t.push_bool(op, vec![Operand::Ct(a), Operand::Ct(b)], None);
                    t.push_bool(op, vec![Operand::Ct(a), scalar_operand(b_val)], None);
                }
                _ => {
                    t.push_int(op, vec![Operand::Ct(a), Operand::Ct(b)], None);
                    t.push_int(op, vec![Operand::Ct(a), scalar_operand(b_val)], None);
                }
            }
        }

        // The select result is consumed by a follow-up operation on purpose: a result that only
        // gets decrypted can hide broken ciphertext metadata that explodes the first time
        // another operation reads it, which is exactly how the GPU boolean select degree bug
        // surfaced.
        let sel = t.push_int(
            OpKind::Select,
            vec![Operand::BoolCt(flag), Operand::Ct(a), Operand::Ct(b)],
            None,
        );
        match ty {
            ValueType::U160 => {
                t.push_bool(OpKind::Eq, vec![Operand::Ct(sel), Operand::Ct(a)], None);
            }
            ValueType::U256 => {
                t.push_int(OpKind::BitAnd, vec![Operand::Ct(sel), Operand::Ct(a)], None);
            }
            _ => {
                t.push_int(OpKind::Add, vec![Operand::Ct(sel), Operand::Ct(a)], None);
            }
        }

        if ty != ValueType::U160 {
            for target in CAST_TARGETS {
                if target != ty {
                    t.push_int(OpKind::Cast, vec![Operand::Ct(a)], Some(target));
                }
            }
        }

        if ty.is_arithmetic() {
            t.push_int(OpKind::Sum, vec![], Some(ty));
            t.push_int(OpKind::Sum, vec![Operand::Ct(a)], Some(ty));
            t.push_int(
                OpKind::Sum,
                vec![Operand::Ct(a), Operand::Ct(b), Operand::Ct(a)],
                Some(ty),
            );
        }

        if ty.is_membership() {
            t.push_bool(OpKind::IsIn, vec![Operand::Ct(a)], None);
            t.push_bool(OpKind::IsIn, vec![Operand::Ct(a), Operand::Ct(b)], None);
            t.push_bool(
                OpKind::IsIn,
                vec![
                    Operand::Ct(a),
                    Operand::Ct(b),
                    Operand::Ct(a),
                    Operand::Ct(b),
                ],
                None,
            );
        }

        if ty.is_mul_div() {
            t.push_int(
                OpKind::MulDiv,
                vec![Operand::Ct(a), Operand::Ct(b), Operand::Scalar(3)],
                None,
            );
            t.push_int(
                OpKind::MulDiv,
                vec![Operand::Ct(a), Operand::Scalar(7), Operand::Scalar(3)],
                None,
            );
        }

        if ty.is_rand_int() {
            t.push_int(OpKind::Rand, vec![Operand::Scalar(41)], Some(ty));
            for exponent in forced_rand_exponents(ty) {
                t.push_int(
                    OpKind::RandBounded,
                    vec![
                        Operand::Scalar(43 + u128::from(exponent)),
                        scalar_operand(ClearInt::from_lo(1).shl256(exponent)),
                    ],
                    Some(ty),
                );
            }
        }

        // The collection limits, exercised once on a narrow type and once on a wide one: a limit
        // sized node costs as much as a whole ordinary transaction, covering every type at the
        // limit would dominate the pass without covering anything new.
        if matches!(ty, ValueType::U8 | ValueType::U64) {
            let limit = ty.collection_limit();
            t.push_int(OpKind::Sum, vec![Operand::Ct(a); limit], Some(ty));
            let mut membership = vec![Operand::Ct(a)];
            membership.extend(std::iter::repeat_n(Operand::Ct(b), limit));
            t.push_bool(OpKind::IsIn, membership, None);
        }

        descriptions.push(t.into_description());
    }

    // The boolean transaction: the encrypted boolean operators in both modes, the boolean
    // selection, the boolean cast sources, and the boolean trivial encryption and randomness.
    let mut t = ForcedTransaction::new();
    let b0 = t.push_bool(OpKind::Eq, vec![Operand::Ct(0), Operand::Ct(1)], None);
    let b1 = t.push_bool(OpKind::Ne, vec![Operand::Ct(0), Operand::Ct(1)], None);
    for &op in BOOL_OPS.iter() {
        match op {
            OpKind::Not => {
                t.push_bool(op, vec![Operand::BoolCt(b0)], None);
            }
            _ => {
                t.push_bool(op, vec![Operand::BoolCt(b0), Operand::BoolCt(b1)], None);
                t.push_bool(
                    op,
                    vec![Operand::BoolCt(b0), Operand::BoolScalar(true)],
                    None,
                );
            }
        }
    }
    // Consumed by the OR below: the boolean select is the known trigger of the GPU degree bug.
    let b_sel = t.push_bool(
        OpKind::Select,
        vec![
            Operand::BoolCt(b0),
            Operand::BoolCt(b0),
            Operand::BoolCt(b1),
        ],
        None,
    );
    t.push_bool(
        OpKind::BitOr,
        vec![Operand::BoolCt(b0), Operand::BoolCt(b_sel)],
        None,
    );
    t.push_bool(OpKind::TrivialEncrypt, vec![Operand::Scalar(1)], Some(ValueType::Bool));
    for target in CAST_TARGETS {
        t.push_int(OpKind::Cast, vec![Operand::BoolCt(b0)], Some(target));
    }
    t.push_bool(OpKind::Rand, vec![Operand::Scalar(47)], Some(ValueType::Bool));
    descriptions.push(t.into_description());

    descriptions
}

/// Runs the forced coverage pass: the fixed transactions of [`forced_coverage_descriptions`],
/// through the same seeded keys, reporting and replay machinery as the random run. Setting
/// `TFHE_RS_PROTOCOL_TRANSACTIONS` truncates the pass to its first transactions.
pub(crate) fn protocol_random_ops_forced_coverage_run(
    meta_params: MetaParameters,
    params_name: &str,
    test_name: &str,
    install_server_key: impl FnOnce(&CompressedServerKey),
) {
    let seed = get_user_defined_seed().unwrap_or_else(|| {
        let mut seeder = crate::core_crypto::prelude::new_seeder();
        seeder.seed()
    });
    println!("{test_name}::seed = {}", seed.0);
    println!(
        "{test_name}: replay the whole run with TFHE_RS_LONGRUN_TESTS_SEED={}",
        seed.0
    );

    // The graphs are fixed; the seed only covers the keys and the encryption noise.
    let mut root = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
    let key_seed = root.seed();
    let setup_seed = root.seed();

    let keys = generate_protocol_keys(Config::from(meta_params), key_seed, setup_seed);
    install_server_key(&keys.compressed_sks);

    let identity = RunIdentity {
        params_name,
        key_seed,
        setup_seed,
    };

    let mut descriptions = forced_coverage_descriptions();
    if let Ok(cap) = std::env::var("TFHE_RS_PROTOCOL_TRANSACTIONS") {
        if let Ok(cap) = cap.parse::<usize>() {
            descriptions.truncate(cap);
        }
    }
    println!(
        "{test_name}: running {} forced coverage transactions",
        descriptions.len()
    );

    let start = Instant::now();
    let mut coverage = Coverage::default();
    let recent = RecentLog::new(10);
    for (index, desc) in descriptions.iter().enumerate() {
        let transaction_seed = root.seed();
        if let Ok(evaluation) = evaluate_clear(desc, &RandValues::new()) {
            coverage.record(&evaluation);
        }

        recent.record(desc, transaction_seed, index, &identity);
        run_transaction_or_dump(desc, transaction_seed, index, &keys, &identity, false);
        println!(
            "{test_name}: transaction {index} done ({} nodes, {} seconds elapsed)",
            desc.nodes.len(),
            start.elapsed().as_secs()
        );
    }

    println!(
        "{test_name}: done, {} transactions, signature coverage:",
        descriptions.len()
    );
    coverage.print();
}

//
// CPU drivers
//
// Ignored by default: these are long run tests, run them explicitly with `--ignored`. They are
// mostly useful to debug the harness, or a failure report, without a GPU in the loop; the
// production runs are the GPU tests of `gpu_protocol_random_ops_long_run`.
//

fn cpu_install_server_key(compressed_sks: &CompressedServerKey) {
    crate::set_server_key(compressed_sks.decompress());
}

#[test]
#[ignore = "long running protocol test, run explicitly"]
fn test_cpu_protocol_random_ops_classical() {
    protocol_random_ops_run(
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128",
        "test_cpu_protocol_random_ops_classical",
        cpu_install_server_key,
    );
}

#[test]
#[ignore = "long running protocol test, run explicitly"]
fn test_cpu_protocol_random_ops_forced_coverage() {
    protocol_random_ops_forced_coverage_run(
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128",
        "test_cpu_protocol_random_ops_forced_coverage",
        cpu_install_server_key,
    );
}

#[test]
#[ignore = "replay driver, set TFHE_RS_PROTOCOL_REPLAY to a failure report"]
fn test_cpu_protocol_random_ops_replay() {
    let Ok(path) = std::env::var("TFHE_RS_PROTOCOL_REPLAY") else {
        println!("TFHE_RS_PROTOCOL_REPLAY is not set, nothing to replay");
        return;
    };
    replay_from_report(&load_failure_report(&path), cpu_install_server_key);
}

//
// Fast harness self tests, run with the ordinary test suite: no FHE involved.
//

#[cfg(test)]
mod harness_tests {
    use super::*;

    fn metadata() -> Vec<u8> {
        vec![0; METADATA_LEN]
    }

    fn desc(width: u32, nodes: Vec<Node>) -> TransactionDescription {
        TransactionDescription {
            width,
            inputs: vec![
                InputDesc {
                    value: 200,
                    metadata: metadata(),
                },
                InputDesc {
                    value: 3,
                    metadata: metadata(),
                },
            ],
            nodes,
        }
    }

    fn node(op: OpKind, operands: Vec<Operand>) -> Node {
        Node {
            op,
            operands,
            target: None,
        }
    }

    fn typed_node(op: OpKind, operands: Vec<Operand>, target: ValueType) -> Node {
        Node {
            op,
            operands,
            target: Some(target),
        }
    }

    fn last_int(nodes: Vec<Node>) -> (ValueType, ClearInt) {
        let eval = evaluate_clear(&desc(8, nodes), &RandValues::new()).unwrap();
        *eval.ints.last().unwrap()
    }

    fn last_bool(nodes: Vec<Node>) -> bool {
        let eval = evaluate_clear(&desc(8, nodes), &RandValues::new()).unwrap();
        *eval.bools.last().unwrap()
    }

    #[test]
    fn test_protocol_random_ops_clear_oracle() {
        let enc = vec![Operand::Ct(0), Operand::Ct(1)];
        let int_result =
            |op, operands: Vec<Operand>| last_int(vec![node(op, operands)]).1.lo;
        let bool_result = |op, operands: Vec<Operand>| last_bool(vec![node(op, operands)]);

        assert_eq!(int_result(OpKind::Add, enc.clone()), u128::from(200u8.wrapping_add(3)));
        assert_eq!(int_result(OpKind::Sub, enc.clone()), u128::from(200u8.wrapping_sub(3)));
        assert_eq!(int_result(OpKind::Mul, enc.clone()), u128::from(200u8.wrapping_mul(3)));
        assert_eq!(
            int_result(OpKind::Div, vec![Operand::Ct(0), Operand::Scalar(3)]),
            u128::from(200u8 / 3)
        );
        assert_eq!(
            int_result(OpKind::Rem, vec![Operand::Ct(0), Operand::Scalar(3)]),
            u128::from(200u8 % 3)
        );
        assert_eq!(int_result(OpKind::BitAnd, enc.clone()), u128::from(200u8 & 3));
        assert_eq!(int_result(OpKind::BitOr, enc.clone()), u128::from(200u8 | 3));
        assert_eq!(int_result(OpKind::BitXor, enc.clone()), u128::from(200u8 ^ 3));
        assert_eq!(int_result(OpKind::Shl, enc.clone()), u128::from(200u8 << 3));
        assert_eq!(int_result(OpKind::Shr, enc.clone()), u128::from(200u8 >> 3));
        // Overshift yields zero, unlike a rotation of the same amount.
        assert_eq!(int_result(OpKind::Shl, vec![Operand::Ct(0), Operand::Scalar(8)]), 0);
        assert_eq!(int_result(OpKind::Shr, vec![Operand::Ct(0), Operand::Scalar(255)]), 0);
        assert_eq!(
            int_result(OpKind::Rotl, enc.clone()),
            u128::from(200u8.rotate_left(3))
        );
        assert_eq!(
            int_result(OpKind::Rotr, enc.clone()),
            u128::from(200u8.rotate_right(3))
        );
        assert_eq!(
            int_result(OpKind::Rotl, vec![Operand::Ct(0), Operand::Scalar(11)]),
            u128::from(200u8.rotate_left(11))
        );
        assert_eq!(int_result(OpKind::Min, enc.clone()), 3);
        assert_eq!(int_result(OpKind::Max, enc.clone()), 200);
        assert_eq!(
            int_result(OpKind::Neg, vec![Operand::Ct(0)]),
            u128::from(200u8.wrapping_neg())
        );
        assert_eq!(int_result(OpKind::Not, vec![Operand::Ct(0)]), u128::from(!200u8));
        assert!(!bool_result(OpKind::Eq, enc.clone()));
        assert!(bool_result(OpKind::Ne, enc.clone()));
        assert!(bool_result(OpKind::Ge, enc.clone()));
        assert!(bool_result(OpKind::Gt, enc.clone()));
        assert!(!bool_result(OpKind::Le, enc.clone()));
        assert!(!bool_result(OpKind::Lt, enc));

        // The malformed cases a hand-edited replay file could contain are rejected.
        let invalid = |op, operands| {
            evaluate_clear(&desc(8, vec![node(op, operands)]), &RandValues::new()).is_err()
        };
        assert!(invalid(OpKind::Div, vec![Operand::Ct(0), Operand::Scalar(0)]));
        assert!(invalid(OpKind::Div, vec![Operand::Ct(0), Operand::Ct(1)]));
        assert!(invalid(OpKind::Add, vec![Operand::Ct(0), Operand::Scalar(256)]));
        assert!(invalid(OpKind::Add, vec![Operand::Ct(0), Operand::Ct(7)]));
    }

    #[test]
    fn test_protocol_random_ops_clear_oracle_structural() {
        // Cast: widen, then narrow back, then to u256 and onto the u256 operator set.
        let (ty, v) = last_int(vec![typed_node(
            OpKind::Cast,
            vec![Operand::Ct(0)],
            ValueType::U32,
        )]);
        assert_eq!((ty, v.lo), (ValueType::U32, 200));
        let (ty, v) = last_int(vec![
            typed_node(OpKind::Cast, vec![Operand::Ct(0)], ValueType::U32),
            node(OpKind::Add, vec![Operand::Ct(2), Operand::Scalar(100)]),
            typed_node(OpKind::Cast, vec![Operand::Ct(3)], ValueType::U8),
        ]);
        assert_eq!((ty, v.lo), (ValueType::U8, 300 % 256));

        // U256: not of zero is the full mask, rotation across the limb boundary works.
        let u256_not = last_int(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(0)],
                ValueType::U256,
            ),
            node(OpKind::Not, vec![Operand::Ct(2)]),
        ]);
        assert_eq!(u256_not.1, ValueType::U256.mask());
        let rotated = last_int(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(1)],
                ValueType::U256,
            ),
            node(OpKind::Rotl, vec![Operand::Ct(2), Operand::Scalar(200)]),
        ]);
        assert_eq!(
            rotated.1,
            ClearInt {
                lo: 0,
                hi: 1u128 << 72
            }
        );
        let neg_one = last_int(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(1)],
                ValueType::U256,
            ),
            node(OpKind::Neg, vec![Operand::Ct(2)]),
        ]);
        assert_eq!(neg_one.1, ValueType::U256.mask());

        // U160 equality against a scalar, through a trivial encryption.
        let eq = last_bool(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::BigScalar { lo: 7, hi: 5 }],
                ValueType::U160,
            ),
            node(
                OpKind::Eq,
                vec![Operand::Ct(2), Operand::BigScalar { lo: 7, hi: 5 }],
            ),
        ]);
        assert!(eq);

        // Select, sum (empty included), membership and MulDiv.
        let selected = last_int(vec![
            node(OpKind::Ge, vec![Operand::Ct(0), Operand::Ct(1)]),
            node(
                OpKind::Select,
                vec![Operand::BoolCt(0), Operand::Ct(0), Operand::Ct(1)],
            ),
        ]);
        assert_eq!(selected.1.lo, 200);
        let sum = last_int(vec![typed_node(
            OpKind::Sum,
            vec![Operand::Ct(0), Operand::Ct(0), Operand::Ct(1)],
            ValueType::U8,
        )]);
        assert_eq!(sum.1.lo, u128::from(200u8.wrapping_add(200).wrapping_add(3)));
        let empty_sum = last_int(vec![typed_node(OpKind::Sum, vec![], ValueType::U8)]);
        assert_eq!(empty_sum.1.lo, 0);
        assert!(last_bool(vec![node(
            OpKind::IsIn,
            vec![Operand::Ct(0), Operand::Ct(1), Operand::Ct(0)],
        )]));
        assert!(!last_bool(vec![node(OpKind::IsIn, vec![Operand::Ct(0)])]));
        let mul_div = last_int(vec![node(
            OpKind::MulDiv,
            vec![Operand::Ct(0), Operand::Ct(0), Operand::Scalar(100)],
        )]);
        assert_eq!(mul_div.1.lo, (200 * 200 / 100) % 256);

        // Type rules: U256 arithmetic, U160 casts, identity casts and oversized collections are
        // rejected.
        let invalid = |nodes: Vec<Node>| evaluate_clear(&desc(8, nodes), &RandValues::new()).is_err();
        assert!(invalid(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(1)],
                ValueType::U256
            ),
            node(OpKind::Add, vec![Operand::Ct(2), Operand::Scalar(1)]),
        ]));
        assert!(invalid(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(1)],
                ValueType::U160
            ),
            typed_node(OpKind::Cast, vec![Operand::Ct(2)], ValueType::U64),
        ]));
        assert!(invalid(vec![typed_node(
            OpKind::Cast,
            vec![Operand::Ct(0)],
            ValueType::U8
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::Sum,
            vec![Operand::Ct(0); 101],
            ValueType::U8,
        )]));
        assert!(invalid(vec![node(
            OpKind::MulDiv,
            vec![Operand::Ct(0), Operand::Ct(1), Operand::Scalar(0)],
        )]));
    }

    #[test]
    fn test_protocol_random_ops_forced_coverage_matrix() {
        // Every forced transaction is a valid description, and the union of their signatures
        // covers the whole (operation, type, operand mode) matrix.
        let mut signatures = std::collections::BTreeSet::new();
        for (index, desc) in forced_coverage_descriptions().iter().enumerate() {
            let evaluation = evaluate_clear(desc, &RandValues::new())
                .unwrap_or_else(|e| panic!("forced transaction {index} is invalid: {e}"));
            signatures.extend(evaluation.signatures);
        }
        let expect = |s: &str| {
            assert!(signatures.contains(s), "missing forced signature {s}");
        };

        let int_types = [
            ValueType::U8,
            ValueType::U16,
            ValueType::U32,
            ValueType::U64,
            ValueType::U128,
            ValueType::U160,
            ValueType::U256,
        ];
        for ty in int_types {
            for &op in plain_ops_for(ty) {
                match op {
                    OpKind::Neg | OpKind::Not => expect(&format!("{op:?}/{}/unary", ty.name())),
                    OpKind::Div | OpKind::Rem => expect(&format!("{op:?}/{}/scalar", ty.name())),
                    _ => {
                        expect(&format!("{op:?}/{}/encrypted", ty.name()));
                        expect(&format!("{op:?}/{}/scalar", ty.name()));
                    }
                }
            }
            expect(&format!("Select/{}", ty.name()));
            expect(&format!("TrivialEncrypt/{}", ty.name()));
            if ty != ValueType::U160 {
                for target in CAST_TARGETS {
                    if target != ty {
                        expect(&format!("Cast/{}->{}", ty.name(), target.name()));
                    }
                }
            }
            if ty.is_arithmetic() {
                for n in [0, 1, 3] {
                    expect(&format!("Sum/{}/n{n}", ty.name()));
                }
            }
            if ty.is_membership() {
                for n in [0, 1, 3] {
                    expect(&format!("IsIn/{}/n{n}", ty.name()));
                }
            }
            if ty.is_mul_div() {
                expect(&format!("MulDiv/{}/encrypted", ty.name()));
                expect(&format!("MulDiv/{}/scalar", ty.name()));
            }
            if ty.is_rand_int() {
                expect(&format!("Rand/{}", ty.name()));
                for exponent in forced_rand_exponents(ty) {
                    let random_bits = exponent.min(ty.bits());
                    expect(&format!("RandBounded/{}/b{random_bits}", ty.name()));
                }
            }
        }
        for (ty, limit) in [(ValueType::U8, 100), (ValueType::U64, 60)] {
            expect(&format!("Sum/{}/n{limit}", ty.name()));
            expect(&format!("IsIn/{}/n{limit}", ty.name()));
        }
        for op in ["BitAnd", "BitOr", "BitXor", "Eq", "Ne"] {
            expect(&format!("{op}/bool/encrypted"));
            expect(&format!("{op}/bool/scalar"));
        }
        expect("Not/bool/unary");
        expect("Select/bool");
        expect("TrivialEncrypt/bool");
        expect("Rand/bool");
        for target in CAST_TARGETS {
            expect(&format!("Cast/bool->{}", target.name()));
        }
    }

    #[test]
    fn test_protocol_random_ops_clear_oracle_rand() {
        // Without a recorded value, the validation pass, a rand node evaluates to a placeholder.
        let (ty, v) = last_int(vec![typed_node(
            OpKind::Rand,
            vec![Operand::Scalar(42)],
            ValueType::U32,
        )]);
        assert_eq!((ty, v), (ValueType::U32, ClearInt::ZERO));
        assert!(!last_bool(vec![typed_node(
            OpKind::Rand,
            vec![Operand::Scalar(42)],
            ValueType::Bool,
        )]));

        // With a recorded value, the value flows into the pool and its range is checked against
        // the bound: 7 < 2^3 passes and feeds the next node, 8 does not.
        let bounded = desc(
            8,
            vec![
                typed_node(
                    OpKind::RandBounded,
                    vec![Operand::Scalar(42), Operand::Scalar(8)],
                    ValueType::U8,
                ),
                node(OpKind::Add, vec![Operand::Ct(2), Operand::Ct(0)]),
            ],
        );
        let values = |v: u128| RandValues::from([(0, RandValue::Int(ClearInt::from_lo(v)))]);
        let eval = evaluate_clear(&bounded, &values(7)).unwrap();
        assert_eq!(eval.ints.last().unwrap().1.lo, 207);
        assert_eq!(eval.signatures[0], "RandBounded/u8/b3");
        assert!(evaluate_clear(&bounded, &values(8)).is_err());

        // A bound above the width is capped to it, like the executor caps the bit count.
        let over_width = desc(
            8,
            vec![typed_node(
                OpKind::RandBounded,
                vec![Operand::Scalar(42), Operand::Scalar(65536)],
                ValueType::U8,
            )],
        );
        let eval = evaluate_clear(&over_width, &values(255)).unwrap();
        assert_eq!(eval.signatures[0], "RandBounded/u8/b8");

        // Rejections: a bound that is not a positive power of two, a bounded boolean, a U160
        // target, and a missing bound.
        let invalid = |nodes: Vec<Node>| evaluate_clear(&desc(8, nodes), &RandValues::new()).is_err();
        assert!(invalid(vec![typed_node(
            OpKind::RandBounded,
            vec![Operand::Scalar(42), Operand::Scalar(6)],
            ValueType::U8,
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::RandBounded,
            vec![Operand::Scalar(42), Operand::Scalar(0)],
            ValueType::U8,
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::RandBounded,
            vec![Operand::Scalar(42), Operand::Scalar(8)],
            ValueType::Bool,
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::Rand,
            vec![Operand::Scalar(42)],
            ValueType::U160,
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::RandBounded,
            vec![Operand::Scalar(42)],
            ValueType::U8,
        )]));

        // The 256 bit helpers behind the range check.
        assert!(ClearInt { lo: 0, hi: 1 }.is_power_of_two());
        assert!(!ClearInt { lo: 1, hi: 1 }.is_power_of_two());
        assert_eq!(ClearInt { lo: 0, hi: 1 }.floor_log2(), 128);
        assert_eq!(ClearInt::from_lo(1).shl256(255).floor_log2(), 255);
        assert!(ClearInt { lo: u128::MAX, hi: 0 }.fits_bits(128));
        assert!(!ClearInt { lo: 0, hi: 1 }.fits_bits(128));
        assert!(ClearInt { lo: 0, hi: 1 }.fits_bits(129));
        assert!(!ClearInt::from_lo(1).fits_bits(0));
    }

    #[test]
    fn test_protocol_random_ops_generator_and_report_roundtrip() {
        let mut datagen = RandomGenerator::<DefaultRandomGenerator>::new(Seed(42));

        for index in 0..1000 {
            let desc = draw_transaction(&mut datagen);

            // Every drawn transaction is a valid description: the clear oracle accepts it.
            evaluate_clear(&desc, &RandValues::new())
                .unwrap_or_else(|e| panic!("drawn transaction {index} is invalid: {e}"));

            // And it survives the failure report JSON roundtrip unchanged.
            let report = FailureReport {
                params: "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128"
                    .to_string(),
                key_seed: 1,
                setup_seed: 2,
                transaction_seed: u128::MAX,
                transaction_index: index,
                error: String::new(),
                description: desc.clone(),
            };
            let json = serde_json::to_string(&report).unwrap();
            let parsed: FailureReport = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.description, desc);
            assert_eq!(parsed.transaction_seed, u128::MAX);
        }
    }
}
