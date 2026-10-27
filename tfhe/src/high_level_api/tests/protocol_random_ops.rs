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
//! Every node result also has to carry the noise level metadata compression asks for, nominal or
//! zero, right as it is produced.
//!
//! Inputs are of any of the eight exposed types. Transactions chain: each one stores its last
//! integer and its last boolean, compressed, and later transactions take some of their inputs
//! from those stored values instead of fresh encryptions, so values go through decompression,
//! further operations and compression again across many transactions.
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
//! Type mixing happens the way the executor allows it, through explicit cast nodes; the FHE
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
//! transaction encryption seed, and the full graph with its clear input values and scalars, and
//! the bytes of the stored values it takes as inputs.
//! Pointing `TFHE_RS_PROTOCOL_REPLAY` at that file and running the replay test re-executes that
//! single transaction, keys included, without re-running the whole campaign. Next to the failure
//! reports, every run also keeps a rolling trace of its most recent transactions
//! (`<test name>_<run start time>_recent_slot*.json`), written before each transaction runs and in
//! the same replayable format, so a crash that never reaches the failure path still leaves the
//! executing graphs behind. Reports and traces go to `TFHE_RS_PROTOCOL_FAILURE_DIR`, by default
//! the working directory (`tfhe/` under `cargo test`); every run prints the directory it uses. A
//! replay runs step by step: it decrypts right after every node and prints the decrypted value
//! against the clear one, so the first node that diverges is named even when later nodes consume
//! its corrupted result.

use super::protocol_workflow_common::{
    generate_protocol_keys, install_seeded_engine, node_re_randomization_context, num_transactions,
    random_bytes, re_randomize_operand, requested_transactions, run_duration, run_seed,
    ProtocolKeys, METADATA_LEN,
};
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::high_level_api::booleans::InnerBoolean;
use crate::high_level_api::integers::unsigned::RadixCiphertext as InnerRadixCiphertext;
use crate::high_level_api::prelude::*;
use crate::integer::U256 as TfheU256;
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::parameters::test_params::{
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::MetaParameters;
use crate::{
    ClientKey, CompactPublicKey, CompressedCiphertextList, CompressedCiphertextListBuilder,
    CompressedServerKey, CompressedSquashedNoiseCiphertextListBuilder, Config, FheBool, FheTypes,
    FheUint128, FheUint16, FheUint160, FheUint256, FheUint32, FheUint64, FheUint8,
    ReRandomizationContext, ReRandomizationSeedGen, SquashedNoiseFheBool, SquashedNoiseFheUint,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::{Seed, Seeder};

/// Encrypted inputs of a transaction.
const NUM_INPUTS: usize = 3;
/// Bounds on the number of operations of a transaction.
const MIN_NODES: usize = 5;
const MAX_NODES: usize = 10;

/// The eight value types the host executor exposes.
const ALL_TYPES: [FheTypes; 8] = [
    FheTypes::Bool,
    FheTypes::Uint8,
    FheTypes::Uint16,
    FheTypes::Uint32,
    FheTypes::Uint64,
    FheTypes::Uint128,
    FheTypes::Uint160,
    FheTypes::Uint256,
];

/// The executor's `N` set: the cast destinations and the bounded randomness types (unbounded
/// randomness also exists on Bool).
const N_TYPES: [FheTypes; 6] = [
    FheTypes::Uint8,
    FheTypes::Uint16,
    FheTypes::Uint32,
    FheTypes::Uint64,
    FheTypes::Uint128,
    FheTypes::Uint256,
];

/// The host executor's view of a value type. Only meant for the members of [`ALL_TYPES`]: a
/// description cannot name any other type, see [`type_name`].
trait ExposedType: Copy {
    fn bits(self) -> u32;
    fn name(self) -> &'static str;
    fn mask(self) -> ClearInt;
    /// The executor's arithmetic type set `A`, also the admissible sum element types.
    fn is_arithmetic(self) -> bool;
    /// The admissible membership value types: `N ∪ {U160}`.
    fn is_membership(self) -> bool;
    fn is_mul_div(self) -> bool;
    /// The executor's `N` set, see [`N_TYPES`].
    fn is_n(self) -> bool;
    /// Sum and membership collection limits: 100 for the narrow types, 60 for the wide ones.
    fn collection_limit(self) -> usize;
}

impl ExposedType for FheTypes {
    fn bits(self) -> u32 {
        match self {
            Self::Bool => 1,
            Self::Uint8 => 8,
            Self::Uint16 => 16,
            Self::Uint32 => 32,
            Self::Uint64 => 64,
            Self::Uint128 => 128,
            Self::Uint160 => 160,
            Self::Uint256 => 256,
            other => panic!("{other:?} is not a host executor type"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Uint8 => "u8",
            Self::Uint16 => "u16",
            Self::Uint32 => "u32",
            Self::Uint64 => "u64",
            Self::Uint128 => "u128",
            Self::Uint160 => "u160",
            Self::Uint256 => "u256",
            other => panic!("{other:?} is not a host executor type"),
        }
    }

    fn mask(self) -> ClearInt {
        // Shift `MAX` down rather than `ONE` up: `ONE << 256` is not the u256 modulus.
        ClearInt::MAX >> (ClearInt::BITS - self.bits())
    }

    fn is_arithmetic(self) -> bool {
        matches!(
            self,
            Self::Uint8 | Self::Uint16 | Self::Uint32 | Self::Uint64 | Self::Uint128
        )
    }

    fn is_membership(self) -> bool {
        self.is_n() || self == Self::Uint160
    }

    fn is_mul_div(self) -> bool {
        matches!(
            self,
            Self::Uint8 | Self::Uint16 | Self::Uint32 | Self::Uint64
        )
    }

    fn is_n(self) -> bool {
        N_TYPES.contains(&self)
    }

    fn collection_limit(self) -> usize {
        match self {
            Self::Uint8 | Self::Uint16 | Self::Uint32 => 100,
            _ => 60,
        }
    }
}

/// Descriptions name a type by its [`ExposedType::name`]: [`FheTypes`] has no serde form.
// The signatures are the ones `#[serde(with)]` expects.
#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
mod type_name {
    use super::{ExposedType, FheTypes, ALL_TYPES};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn parse<E: Error>(name: &str) -> Result<FheTypes, E> {
        ALL_TYPES
            .into_iter()
            .find(|ty| ty.name() == name)
            .ok_or_else(|| E::custom(format!("unknown value type {name}")))
    }

    pub(super) fn serialize<S: Serializer>(ty: &FheTypes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(ty.name())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<FheTypes, D::Error> {
        parse(&String::deserialize(d)?)
    }
}

/// [`type_name`] for an optional type.
// The signatures are the ones `#[serde(with)]` expects.
#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
mod opt_type_name {
    use super::{ExposedType, FheTypes};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(ty: &Option<FheTypes>, s: S) -> Result<S::Ok, S::Error> {
        match ty {
            Some(ty) => s.serialize_some(ty.name()),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<FheTypes>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|name| super::type_name::parse(&name))
            .transpose()
    }
}

/// Optional bytes as a hexadecimal string, compact enough for the reports.
// The signatures are the ones `#[serde(with)]` expects.
#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
mod opt_hex {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => s.serialize_some(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|text| hex::decode(text).map_err(D::Error::custom))
            .transpose()
    }
}

/// A clear value of any exposed type. Every type fits in 256 bits, and `U256` is already the
/// clear type TFHE-rs uses for `FheUint160` and `FheUint256`.
pub(crate) type ClearInt = TfheU256;

/// What the clear oracle needs on top of the `U256` arithmetic: the typed views of a value, and
/// the shifts and rotations with the semantics TFHE-rs gives them.
trait ClearIntExt: Sized {
    fn masked(self, ty: FheTypes) -> Self;
    fn fits(self, ty: FheTypes) -> bool;
    /// Whether the value is strictly below `2^bits`.
    fn fits_bits(self, bits: u32) -> bool;
    /// The low 128 bits, the whole value for the types up to 128 bits.
    fn low(self) -> u128;
    /// An amount that reaches the type's width shifts everything out: the result is zero.
    fn shl(self, amount: Self, ty: FheTypes) -> Self;
    fn shr(self, amount: Self, ty: FheTypes) -> Self;
    /// Rotations take the amount modulo the width.
    fn rotl(self, amount: Self, ty: FheTypes) -> Self;
    fn rotr(self, amount: Self, ty: FheTypes) -> Self;
    fn show(self) -> String;
}

impl ClearIntExt for ClearInt {
    fn masked(self, ty: FheTypes) -> Self {
        self & ty.mask()
    }

    fn fits(self, ty: FheTypes) -> bool {
        self == self.masked(ty)
    }

    fn fits_bits(self, bits: u32) -> bool {
        bits >= Self::BITS || self < (Self::ONE << bits)
    }

    fn low(self) -> u128 {
        self.to_low_high_u128().0
    }

    fn shl(self, amount: Self, ty: FheTypes) -> Self {
        if amount >= Self::from(ty.bits()) {
            Self::ZERO
        } else {
            (self << amount.low() as u32).masked(ty)
        }
    }

    fn shr(self, amount: Self, ty: FheTypes) -> Self {
        if amount >= Self::from(ty.bits()) {
            Self::ZERO
        } else {
            self.masked(ty) >> amount.low() as u32
        }
    }

    fn rotl(self, amount: Self, ty: FheTypes) -> Self {
        let width = ty.bits();
        let k = (amount % Self::from(width)).low() as u32;
        let v = self.masked(ty);
        if k == 0 {
            v
        } else {
            ((v << k) | (v >> (width - k))).masked(ty)
        }
    }

    fn rotr(self, amount: Self, ty: FheTypes) -> Self {
        let width = ty.bits();
        let k = (amount % Self::from(width)).low() as u32;
        let v = self.masked(ty);
        if k == 0 {
            v
        } else {
            ((v >> k) | (v << (width - k))).masked(ty)
        }
    }

    fn show(self) -> String {
        let (lo, hi) = self.to_low_high_u128();
        if hi == 0 {
            lo.to_string()
        } else {
            format!("0x{hi:x}{lo:032x}")
        }
    }
}

/// The operation pool. The discriminants are the host executor opcodes, which are also what each
/// node mixes into its re-randomization context. Reports store the variant names, not these
/// numbers.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub(crate) enum OpKind {
    Add = 0,
    Sub = 1,
    Mul = 2,
    Div = 3, // scalar divisor only
    Rem = 4, // scalar divisor only
    BitAnd = 5,
    BitOr = 6,
    BitXor = 7,
    Shl = 8,
    Shr = 9,
    Rotl = 10,
    Rotr = 11,
    Eq = 12,
    Ne = 13,
    Ge = 14,
    Gt = 15,
    Le = 16,
    Lt = 17,
    Min = 18,
    Max = 19,
    Neg = 20,
    Not = 21,
    Cast = 23,           // destination in `target`
    TrivialEncrypt = 24, // type in `target`, clear value as the single scalar operand
    Select = 25,
    Rand = 26,        // type in `target`, the seed as the single scalar operand
    RandBounded = 27, // type in `target`, the seed and the power of two bound as scalars
    Sum = 28,         // output type in `target`
    IsIn = 29,
    MulDiv = 30,
}

impl OpKind {
    /// The host executor opcode, fed to the node's re-randomization context exactly like the
    /// transfer test feeds its own node opcodes.
    fn opcode(self) -> u32 {
        self as u32
    }
}

/// Which simple operations a value type admits through the host executor. The structural
/// operators (cast, selection, sum, membership, MulDiv, trivial encryption) have their own type
/// rules and are checked where they are evaluated.
///
/// This restates the executor rules apart from the generator tables ([`plain_ops_for`]) on
/// purpose: the oracle is what validates the generator, which a table lookup would turn into a
/// tautology. `test_protocol_random_ops_plain_ops_match_oracle` keeps the two in step.
fn int_op_allowed(op: OpKind, ty: FheTypes) -> bool {
    use OpKind::*;
    match ty {
        FheTypes::Uint8
        | FheTypes::Uint16
        | FheTypes::Uint32
        | FheTypes::Uint64
        | FheTypes::Uint128 => {
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
        FheTypes::Uint256 => matches!(
            op,
            BitAnd | BitOr | BitXor | Shl | Shr | Rotl | Rotr | Eq | Ne | Neg | Not
        ),
        FheTypes::Uint160 => matches!(op, Eq | Ne),
        _ => false,
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
            Self::Scalar(s) => Some(ClearInt::from(*s)),
            Self::BigScalar { lo, hi } => Some(ClearInt::from((*lo, *hi))),
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_type_name"
    )]
    pub(crate) target: Option<FheTypes>,
}

/// One encrypted input: its type, its clear value (a boolean as 0 or 1) and the metadata that
/// ties it to its origin. An input is freshly encrypted, unless `persisted` holds the stored
/// bytes of an output of an earlier transaction of the run, see [`PersistedValue`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InputDesc {
    #[serde(with = "type_name")]
    pub(crate) ty: FheTypes,
    pub(crate) value: Operand,
    pub(crate) metadata: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex")]
    pub(crate) persisted: Option<Vec<u8>>,
}

impl InputDesc {
    fn fresh(ty: FheTypes, value: ClearInt, metadata: Vec<u8>) -> Self {
        Self {
            ty,
            value: scalar_operand(value),
            metadata,
            persisted: None,
        }
    }
}

/// The complete clear description of one transaction: enough to re-run it, and small enough to
/// end up verbatim in a failure report. Integer inputs open the integer pool and boolean inputs
/// the boolean pool, each in input order. `output_metadata` is what the outputs the transaction
/// stores are tagged with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TransactionDescription {
    pub(crate) inputs: Vec<InputDesc>,
    pub(crate) nodes: Vec<Node>,
    pub(crate) output_metadata: Vec<u8>,
}

impl TransactionDescription {
    fn num_int_inputs(&self) -> usize {
        self.inputs
            .iter()
            .filter(|input| input.ty != FheTypes::Bool)
            .count()
    }
}

/// An output a transaction stored, compressed alone in its own list like a handle of the
/// protocol, with what a later transaction needs to take it as an input and check it.
#[derive(Clone)]
pub(crate) struct PersistedValue {
    ty: FheTypes,
    value: ClearInt,
    metadata: Vec<u8>,
    bytes: Vec<u8>,
}

impl PersistedValue {
    fn as_input(&self) -> InputDesc {
        InputDesc {
            persisted: Some(self.bytes.clone()),
            ..InputDesc::fresh(self.ty, self.value, self.metadata.clone())
        }
    }
}

/// How many transactions separate an output from the first transaction that may take it as an
/// input. Outputs enter the pool in transaction order and only once this many later transactions
/// have been drawn, so the transaction stream of a seed does not depend on the order concurrent
/// transactions complete in.
const PERSISTED_LAG: usize = 64;
/// How many stored outputs are kept for later transactions, the oldest being dropped first.
const PERSISTED_POOL_SIZE: usize = 16;

/// The stored outputs later transactions draw some of their inputs from: values chain from
/// transaction to transaction through their compressed form, like the handles of the protocol.
#[derive(Default)]
pub(crate) struct PersistedPool {
    values: std::collections::VecDeque<PersistedValue>,
    /// Outputs of completed transactions not old enough to be drawn from yet, by index.
    pending: BTreeMap<usize, Vec<PersistedValue>>,
    /// The next transaction whose outputs enter the pool.
    next: usize,
}

impl PersistedPool {
    pub(crate) fn complete(&mut self, index: usize, outputs: Vec<PersistedValue>) {
        self.pending.insert(index, outputs);
    }

    /// Brings the pool to the state the transaction `index` is drawn from. Returns `false` when
    /// a transaction it depends on has not completed yet.
    pub(crate) fn advance(&mut self, index: usize) -> bool {
        while self.next + PERSISTED_LAG <= index {
            let Some(outputs) = self.pending.remove(&self.next) else {
                return false;
            };
            for value in outputs {
                if self.values.len() == PERSISTED_POOL_SIZE {
                    self.values.pop_front();
                }
                self.values.push_back(value);
            }
            self.next += 1;
        }
        true
    }
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
    /// Prefixes every file the run writes, so the tests of one make target, run one after the
    /// other in the same directory, never overwrite each other's traces and reports.
    pub(crate) test_name: &'a str,
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
        "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128" => {
            Some(TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128)
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
/// one, the maximum value and bit patterns on one half of the draws, uniform values on the other
/// half.
///
/// Two pattern families, aimed at the 2_2 compute parameters the protocol runs on: `0xAA`/`0x55`
/// alternate bits inside every 2 bit block (each block holds the same value, 2 or 1), while
/// `0x33`/`0xCC` alternate at the block level, saturated blocks interleaved with zero blocks,
/// which is what stresses carry and borrow propagation across empty blocks.
fn draw_biased_value(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ty: FheTypes,
) -> ClearInt {
    const ALTERNATING_HIGH: u128 = 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA;
    const ALTERNATING_LOW: u128 = 0x5555_5555_5555_5555_5555_5555_5555_5555;
    const BLOCK_LOW: u128 = 0x3333_3333_3333_3333_3333_3333_3333_3333;
    const BLOCK_HIGH: u128 = 0xCCCC_CCCC_CCCC_CCCC_CCCC_CCCC_CCCC_CCCC;

    let pattern = |p: u128| ClearInt::from((p, p)).masked(ty);

    // 7 corner faces out of 14: a corner case and a uniform draw are equally likely.
    match draw_u64(datagen) % 14 {
        0 => ClearInt::ZERO,
        1 => ClearInt::ONE,
        2 => ty.mask(),
        3 => pattern(ALTERNATING_HIGH),
        4 => pattern(ALTERNATING_LOW),
        5 => pattern(BLOCK_LOW),
        6 => pattern(BLOCK_HIGH),
        _ => ClearInt::from((draw_u128(datagen), draw_u128(datagen))).masked(ty),
    }
}

/// Draws a shift or rotate amount biased toward 0, 1, width−1, width, width+1 and the maximum
/// valid scalar: the executor does not clamp amounts to the width, so the overshift behavior has
/// to stay covered.
fn draw_shift_amount(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ty: FheTypes,
) -> ClearInt {
    let width = ty.bits();
    match draw_u64(datagen) % 8 {
        0 => ClearInt::ZERO,
        1 => ClearInt::ONE,
        2 => ClearInt::from(width - 1),
        3 => ClearInt::from(width),
        4 => ClearInt::from(width + 1),
        5 => ty.mask(),
        _ => draw_biased_value(datagen, ty),
    }
}

fn draw_nonzero_scalar(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ty: FheTypes,
) -> ClearInt {
    loop {
        let value = draw_biased_value(datagen, ty);
        if value != ClearInt::ZERO {
            return value;
        }
    }
}

fn scalar_operand(value: ClearInt) -> Operand {
    match value.to_low_high_u128() {
        (lo, 0) => Operand::Scalar(lo),
        (lo, hi) => Operand::BigScalar { lo, hi },
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

/// The plain operations the generator and the forced pass draw for an integer type.
fn plain_ops_for(ty: FheTypes) -> &'static [OpKind] {
    match ty {
        FheTypes::Uint256 => &U256_OPS,
        FheTypes::Uint160 => &U160_OPS,
        _ => &SMALL_INT_OPS,
    }
}

/// What the executor accepts on encrypted booleans: the bitwise operators, equality and not.
const BOOL_OPS: [OpKind; 6] = [
    OpKind::BitAnd,
    OpKind::BitOr,
    OpKind::BitXor,
    OpKind::Eq,
    OpKind::Ne,
    OpKind::Not,
];

/// Live typed value pools of a transaction being drawn.
struct GenState {
    /// The type of each integer pool slot, inputs first.
    int_types: Vec<FheTypes>,
    bool_count: usize,
}

impl GenState {
    fn slots_of(&self, ty: FheTypes) -> Vec<usize> {
        self.int_types
            .iter()
            .enumerate()
            .filter_map(|(i, t)| (*t == ty).then_some(i))
            .collect()
    }

    fn pick_slot(
        &self,
        datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ) -> (usize, FheTypes) {
        let i = (draw_u64(datagen) as usize) % self.int_types.len();
        (i, self.int_types[i])
    }
}

/// Draws a collection size for sum and membership nodes: the registry asks for 0, 1, 2 and the
/// limits to be covered, but a limit sized node is two orders of magnitude more work than the
/// rest of the transaction, so the limits stay rare.
fn draw_collection_size(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    ty: FheTypes,
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
    let ops = plain_ops_for(ty);
    let op = ops[(draw_u64(datagen) % ops.len() as u64) as usize];

    let operands = match op {
        OpKind::Neg | OpKind::Not => vec![Operand::Ct(lhs)],
        // Division and remainder only exist with a nonzero clear scalar divisor.
        OpKind::Div | OpKind::Rem => vec![
            Operand::Ct(lhs),
            scalar_operand(draw_nonzero_scalar(datagen, ty)),
        ],
        _ => {
            let rhs = if draw_u64(datagen).is_multiple_of(2) {
                let scalar =
                    if matches!(op, OpKind::Shl | OpKind::Shr | OpKind::Rotl | OpKind::Rotr) {
                        draw_shift_amount(datagen, ty)
                    } else {
                        draw_biased_value(datagen, ty)
                    };
                scalar_operand(scalar)
            } else {
                // Aliased operands, the same handle on both sides, are singled out by the fuzzing
                // registry, so they are drawn more often than uniform picking would.
                let same_ty = state.slots_of(ty);
                let rhs_index = if draw_u64(datagen).is_multiple_of(8) {
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

    let operands = if op == OpKind::Not {
        vec![Operand::BoolCt(lhs)]
    } else {
        let rhs = if draw_u64(datagen).is_multiple_of(2) {
            Operand::BoolScalar(draw_u64(datagen).is_multiple_of(2))
        } else {
            Operand::BoolCt((draw_u64(datagen) as usize) % bool_count)
        };
        vec![Operand::BoolCt(lhs), rhs]
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
fn draw_rand_node(datagen: &mut RandomGenerator<DefaultRandomGenerator>) -> (Node, FheTypes) {
    let seed = Operand::Scalar(draw_u128(datagen));
    if draw_u64(datagen).is_multiple_of(2) {
        let target = if draw_u64(datagen).is_multiple_of(7) {
            FheTypes::Bool
        } else {
            N_TYPES[(draw_u64(datagen) % N_TYPES.len() as u64) as usize]
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
        let target = N_TYPES[(draw_u64(datagen) % N_TYPES.len() as u64) as usize];
        let width = target.bits();
        let exponent = match draw_u64(datagen) % 16 {
            0 => 0,
            1 => 1,
            2 => width - 1,
            3 => width + 1,
            _ => 1 + (draw_u64(datagen) as u32) % width,
        }
        .min(255);
        let bound = ClearInt::ONE << exponent;
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

/// A plain node on whatever the pools hold: a transaction whose inputs are all booleans has no
/// integer to operate on until a cast, a trivial encryption or a rand node produces one.
fn draw_plain_node(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    state: &GenState,
) -> Node {
    if state.int_types.is_empty() {
        draw_bool_node(datagen, state.bool_count)
    } else {
        draw_plain_int_node(datagen, state)
    }
}

/// Draws one node. Returns the node and the type of its result, `None` standing for the type a
/// plain node derives from its operands. Categories that need values the pools do not hold yet
/// fall back to a plain node.
fn draw_node(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    state: &GenState,
) -> (Node, Option<FheTypes>) {
    let no_ints = state.int_types.is_empty();
    let category = draw_u64(datagen) % 16;
    match category {
        // Cast: any non-U160 encrypted value to a different type of N.
        0 => {
            let from_bool =
                state.bool_count > 0 && (no_ints || draw_u64(datagen).is_multiple_of(4));
            let (source, source_ty) = if from_bool {
                (
                    Operand::BoolCt((draw_u64(datagen) as usize) % state.bool_count),
                    FheTypes::Bool,
                )
            } else {
                let (slot, ty) = state.pick_slot(datagen);
                if ty == FheTypes::Uint160 {
                    return (draw_plain_int_node(datagen, state), None);
                }
                (Operand::Ct(slot), ty)
            };
            let target = loop {
                let t = N_TYPES[(draw_u64(datagen) % N_TYPES.len() as u64) as usize];
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
            let value = if target == FheTypes::Bool {
                ClearInt::from(draw_u64(datagen) % 2)
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
            if no_ints || draw_u64(datagen).is_multiple_of(5) {
                let a = (draw_u64(datagen) as usize) % state.bool_count;
                let b = (draw_u64(datagen) as usize) % state.bool_count;
                (
                    Node {
                        op: OpKind::Select,
                        operands: vec![condition, Operand::BoolCt(a), Operand::BoolCt(b)],
                        target: None,
                    },
                    Some(FheTypes::Bool),
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
        3 if !no_ints => {
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
        4 if !no_ints => {
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
                Some(FheTypes::Bool),
            )
        }
        // Fused multiply-divide, widths up to 64 bits.
        5 if !no_ints => {
            let (a, ty) = state.pick_slot(datagen);
            if !ty.is_mul_div() {
                return (draw_plain_int_node(datagen, state), None);
            }
            let same_ty = state.slots_of(ty);
            let factor2 = if draw_u64(datagen).is_multiple_of(2) {
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
        // Once the pools hold booleans, some nodes consume them.
        7 | 8 if state.bool_count > 0 => (draw_bool_node(datagen, state.bool_count), None),
        _ => (draw_plain_node(datagen, state), None),
    }
}

/// Draws the inputs of one transaction. Each one is either an output an earlier transaction
/// stored, when there are any, or a fresh encryption of any exposed type. Fresh inputs often
/// repeat the type of the input before them, so operations between two inputs stay common.
fn draw_inputs(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    persisted: &PersistedPool,
) -> Vec<InputDesc> {
    let mut inputs: Vec<InputDesc> = Vec::with_capacity(NUM_INPUTS);
    for _ in 0..NUM_INPUTS {
        let stored = &persisted.values;
        let input = if !stored.is_empty() && draw_u64(datagen).is_multiple_of(3) {
            stored[(draw_u64(datagen) as usize) % stored.len()].as_input()
        } else {
            let ty = match inputs.last() {
                Some(previous) if draw_u64(datagen).is_multiple_of(2) => previous.ty,
                _ => ALL_TYPES[(draw_u64(datagen) % ALL_TYPES.len() as u64) as usize],
            };
            InputDesc::fresh(
                ty,
                draw_biased_value(datagen, ty),
                random_bytes::<METADATA_LEN>(datagen).to_vec(),
            )
        };
        inputs.push(input);
    }
    inputs
}

/// Draws one transaction: its inputs, and a straight-line program whose operands are picked
/// among the values live at that point.
pub(crate) fn draw_transaction(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
    persisted: &PersistedPool,
) -> TransactionDescription {
    let inputs = draw_inputs(datagen, persisted);
    let output_metadata = random_bytes::<METADATA_LEN>(datagen).to_vec();

    let num_nodes = MIN_NODES + (draw_u64(datagen) as usize) % (MAX_NODES - MIN_NODES + 1);
    let mut nodes = Vec::with_capacity(num_nodes);
    let mut state = GenState {
        int_types: inputs
            .iter()
            .map(|input| input.ty)
            .filter(|ty| *ty != FheTypes::Bool)
            .collect(),
        bool_count: 0,
    };
    state.bool_count = inputs.len() - state.int_types.len();

    for _ in 0..num_nodes {
        let (node, explicit_ty) = draw_node(datagen, &state);
        // Bool results go to the boolean pool; everything else to the typed integer pool. Plain
        // nodes return no explicit type: a comparison or a boolean operation produces a boolean,
        // anything else keeps its left operand type.
        let result_ty = explicit_ty.unwrap_or_else(|| match node.operands.first() {
            Some(Operand::BoolCt(_)) => FheTypes::Bool,
            Some(Operand::Ct(i)) => match node.op {
                OpKind::Eq | OpKind::Ne | OpKind::Ge | OpKind::Gt | OpKind::Le | OpKind::Lt => {
                    FheTypes::Bool
                }
                _ => state.int_types[*i],
            },
            _ => unreachable!("drawn nodes always start with an encrypted operand"),
        });
        if result_ty == FheTypes::Bool {
            state.bool_count += 1;
        } else {
            state.int_types.push(result_ty);
        }
        nodes.push(node);
    }

    TransactionDescription {
        inputs,
        nodes,
        output_metadata,
    }
}

//
// Clear oracle
//

enum ClearResult {
    Int(FheTypes, ClearInt),
    Bool(bool),
}

fn node_err(node_index: usize, node: &Node, msg: &str) -> String {
    format!("node {node_index} {node:?}: {msg}")
}

/// A binary operation between two clear values of the same type. The type legality is checked by
/// the caller through [`int_op_allowed`].
fn clear_int_binary(
    op: OpKind,
    a: ClearInt,
    b: ClearInt,
    ty: FheTypes,
) -> Result<ClearResult, String> {
    use ClearResult::{Bool, Int};
    let zero_divisor = || "zero divisor, the executor only accepts nonzero scalars".to_string();
    Ok(match op {
        OpKind::Add => Int(ty, (a + b).masked(ty)),
        OpKind::Sub => Int(ty, (a - b).masked(ty)),
        OpKind::Mul => Int(ty, (a * b).masked(ty)),
        OpKind::Div if b == ClearInt::ZERO => return Err(zero_divisor()),
        OpKind::Rem if b == ClearInt::ZERO => return Err(zero_divisor()),
        OpKind::Div => Int(ty, a / b),
        OpKind::Rem => Int(ty, a % b),
        OpKind::BitAnd => Int(ty, a & b),
        OpKind::BitOr => Int(ty, a | b),
        OpKind::BitXor => Int(ty, a ^ b),
        OpKind::Shl => Int(ty, a.shl(b, ty)),
        OpKind::Shr => Int(ty, a.shr(b, ty)),
        OpKind::Rotl => Int(ty, a.rotl(b, ty)),
        OpKind::Rotr => Int(ty, a.rotr(b, ty)),
        OpKind::Eq => Bool(a == b),
        OpKind::Ne => Bool(a != b),
        OpKind::Ge => Bool(a >= b),
        OpKind::Gt => Bool(a > b),
        OpKind::Le => Bool(a <= b),
        OpKind::Lt => Bool(a < b),
        OpKind::Min => Int(ty, a.min(b)),
        OpKind::Max => Int(ty, a.max(b)),
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

/// The result of evaluating a whole transaction in the clear: the full typed value pools (each
/// one starts with its inputs), the node that produced each value after those, and one coverage
/// signature per node and per input.
pub(crate) struct ClearEvaluation {
    ints: Vec<(FheTypes, ClearInt)>,
    bools: Vec<bool>,
    int_node_map: Vec<usize>,
    bool_node_map: Vec<usize>,
    signatures: Vec<String>,
    input_signatures: Vec<String>,
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
    if desc.output_metadata.len() != METADATA_LEN {
        return Err(format!(
            "the output metadata must be {METADATA_LEN} bytes, got {}",
            desc.output_metadata.len()
        ));
    }

    let mut ints: Vec<(FheTypes, ClearInt)> =
        Vec::with_capacity(desc.inputs.len() + desc.nodes.len());
    let mut bools: Vec<bool> = Vec::new();
    let mut input_signatures: Vec<String> = Vec::with_capacity(desc.inputs.len());
    for (pos, input) in desc.inputs.iter().enumerate() {
        let value = input
            .value
            .as_clear_scalar()
            .filter(|value| value.fits(input.ty))
            .ok_or_else(|| format!("input {pos} value does not fit {}", input.ty.name()))?;
        if input.metadata.len() != METADATA_LEN {
            return Err(format!(
                "input {pos} metadata must be {METADATA_LEN} bytes, got {}",
                input.metadata.len()
            ));
        }
        if input.ty == FheTypes::Bool {
            bools.push(value != ClearInt::ZERO);
        } else {
            ints.push((input.ty, value));
        }
        input_signatures.push(format!(
            "Input/{}/{}",
            input.ty.name(),
            if input.persisted.is_some() {
                "persisted"
            } else {
                "fresh"
            }
        ));
    }
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
        let get_scalar = |operand: &Operand, ty: FheTypes| {
            let s = operand
                .as_clear_scalar()
                .ok_or_else(|| node_err(node_index, node, "expected a clear scalar operand"))?;
            if !s.fits(ty) {
                return Err(node_err(
                    node_index,
                    node,
                    &format!("scalar {} does not fit {}", s.show(), ty.name()),
                ));
            }
            Ok(s)
        };

        let (result, signature) = match node.op {
            OpKind::Cast => {
                let (source_ty, value) = match node.operands.as_slice() {
                    [Operand::Ct(i)] => {
                        let (ty, v) = get_int(*i)?;
                        if ty == FheTypes::Uint160 {
                            return Err(node_err(node_index, node, "U160 cannot be cast"));
                        }
                        (ty, v)
                    }
                    [Operand::BoolCt(i)] => (FheTypes::Bool, ClearInt::from(get_bool(*i)?)),
                    _ => {
                        return Err(node_err(
                            node_index,
                            node,
                            "cast takes one encrypted operand",
                        ))
                    }
                };
                let target = node
                    .target
                    .ok_or_else(|| node_err(node_index, node, "cast needs a target type"))?;
                if !target.is_n() || target == source_ty {
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
                let result = if target == FheTypes::Bool {
                    ClearResult::Bool(value != ClearInt::ZERO)
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
                        if ty != FheTypes::Bool && !ty.is_n() {
                            return Err(node_err(node_index, node, "rand type must be in B ∪ N"));
                        }
                        (ty.bits(), format!("Rand/{}", ty.name()))
                    }
                    (OpKind::RandBounded, [bound]) => {
                        if !ty.is_n() {
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
                        let random_bits = bound.ilog2().min(ty.bits());
                        (
                            random_bits,
                            format!("RandBounded/{}/b{random_bits}", ty.name()),
                        )
                    }
                    _ => return Err(node_err(node_index, node, "malformed operand list")),
                };
                let result = match rand_values.get(&node_index) {
                    None => {
                        // Validation pass: the value is not known yet.
                        if ty == FheTypes::Bool {
                            ClearResult::Bool(false)
                        } else {
                            ClearResult::Int(ty, ClearInt::ZERO)
                        }
                    }
                    Some(RandValue::Bool(b)) if ty == FheTypes::Bool => ClearResult::Bool(*b),
                    Some(RandValue::Int(v)) if ty != FheTypes::Bool => {
                        if !v.fits_bits(random_bits) {
                            return Err(node_err(
                                node_index,
                                node,
                                &format!("rand result {} is not below 2^{random_bits}", v.show()),
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
                    acc = (acc + v).masked(ty);
                }
                (
                    ClearResult::Int(ty, acc),
                    format!("Sum/{}/n{}", ty.name(), node.operands.len()),
                )
            }
            OpKind::IsIn => {
                let [value_operand, set @ ..] = node.operands.as_slice() else {
                    return Err(node_err(
                        node_index,
                        node,
                        "membership needs a value operand",
                    ));
                };
                let Operand::Ct(i) = value_operand else {
                    return Err(node_err(
                        node_index,
                        node,
                        "membership value must be encrypted",
                    ));
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
                        &format!(
                            "membership set holds at most {} elements",
                            ty.collection_limit()
                        ),
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
                if d == ClearInt::ZERO {
                    return Err(node_err(node_index, node, "MulDiv divisor must be nonzero"));
                }
                // The product is not truncated before the division, the result is.
                let result = (a * b / d).masked(ty);
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
                        OpKind::Neg => (ClearInt::ZERO - a).masked(ty),
                        OpKind::Not => (!a).masked(ty),
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
        input_signatures,
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

/// The noise level metadata of every block, read in place: a GPU value stays on the GPU.
fn int_block_noise_levels(ct: &InnerRadixCiphertext) -> Vec<NoiseLevel> {
    match ct {
        InnerRadixCiphertext::Cpu(ct) => ct.blocks.iter().map(|b| b.noise_level()).collect(),
        #[cfg(feature = "gpu")]
        InnerRadixCiphertext::Cuda(ct) => ct
            .ciphertext
            .info
            .blocks
            .iter()
            .map(|b| b.noise_level)
            .collect(),
        #[cfg(feature = "hpu")]
        InnerRadixCiphertext::Hpu(_) => Vec::new(),
    }
}

fn bool_block_noise_levels(ct: &FheBool) -> Vec<NoiseLevel> {
    match &ct.ciphertext {
        InnerBoolean::Cpu(ct) => vec![ct.0.noise_level()],
        #[cfg(feature = "gpu")]
        InnerBoolean::Cuda(ct) => {
            ct.0.ciphertext
                .info
                .blocks
                .iter()
                .map(|b| b.noise_level)
                .collect()
        }
        #[cfg(feature = "hpu")]
        InnerBoolean::Hpu(_) => Vec::new(),
    }
}

/// Every node result has to be compressible as is, which is what the compression asserts: each
/// block at nominal (post PBS) noise, or at zero noise for trivial blocks.
fn check_noise_levels(levels: &[NoiseLevel]) -> Result<(), String> {
    levels
        .iter()
        .position(|&l| l != NoiseLevel::NOMINAL && l != NoiseLevel::ZERO)
        .map_or(Ok(()), |i| {
            Err(format!(
                "block {i} has noise level {:?}, expected nominal (post PBS) or zero; all \
                 blocks: {levels:?}",
                levels[i]
            ))
        })
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
    fn ty(&self) -> FheTypes {
        match self {
            Self::U8(_) => FheTypes::Uint8,
            Self::U16(_) => FheTypes::Uint16,
            Self::U32(_) => FheTypes::Uint32,
            Self::U64(_) => FheTypes::Uint64,
            Self::U128(_) => FheTypes::Uint128,
            Self::U160(_) => FheTypes::Uint160,
            Self::U256(_) => FheTypes::Uint256,
        }
    }

    fn absorb(&self, ctx: &mut ReRandomizationContext) {
        for_int_ct!(self, |ct| ctx.add_ciphertext(ct));
    }

    fn block_noise_levels(&self) -> Vec<NoiseLevel> {
        for_int_ct!(self, |ct| int_block_noise_levels(&ct.ciphertext))
    }

    fn rerand(&mut self, cpk: &CompactPublicKey, seed_gen: &mut ReRandomizationSeedGen) {
        for_int_ct!(self, |ct| re_randomize_operand(ct, cpk, seed_gen));
    }

    fn decrypt_clear(&self, cks: &ClientKey) -> ClearInt {
        match self {
            Self::U8(ct) => {
                let v: u8 = ct.decrypt(cks);
                ClearInt::from(u128::from(v))
            }
            Self::U16(ct) => {
                let v: u16 = ct.decrypt(cks);
                ClearInt::from(u128::from(v))
            }
            Self::U32(ct) => {
                let v: u32 = ct.decrypt(cks);
                ClearInt::from(u128::from(v))
            }
            Self::U64(ct) => {
                let v: u64 = ct.decrypt(cks);
                ClearInt::from(u128::from(v))
            }
            Self::U128(ct) => {
                let v: u128 = ct.decrypt(cks);
                ClearInt::from(v)
            }
            Self::U160(ct) => ct.decrypt(cks),
            Self::U256(ct) => ct.decrypt(cks),
        }
    }

    fn serialize_bytes(&self) -> Vec<u8> {
        for_int_ct!(self, |ct| bincode::serialize(ct).unwrap())
    }

    fn push_into(self, builder: &mut CompressedCiphertextListBuilder) {
        match self {
            Self::U8(ct) => builder.push(ct),
            Self::U16(ct) => builder.push(ct),
            Self::U32(ct) => builder.push(ct),
            Self::U64(ct) => builder.push(ct),
            Self::U128(ct) => builder.push(ct),
            Self::U160(ct) => builder.push(ct),
            Self::U256(ct) => builder.push(ct),
        };
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

fn decrypt_squashed(ns: &SquashedNoiseFheUint, ty: FheTypes, cks: &ClientKey) -> ClearInt {
    match ty {
        FheTypes::Uint8 => {
            let v: u8 = ns.decrypt(cks);
            ClearInt::from(u128::from(v))
        }
        FheTypes::Uint16 => {
            let v: u16 = ns.decrypt(cks);
            ClearInt::from(u128::from(v))
        }
        FheTypes::Uint32 => {
            let v: u32 = ns.decrypt(cks);
            ClearInt::from(u128::from(v))
        }
        FheTypes::Uint64 => {
            let v: u64 = ns.decrypt(cks);
            ClearInt::from(u128::from(v))
        }
        FheTypes::Uint128 => {
            let v: u128 = ns.decrypt(cks);
            ClearInt::from(v)
        }
        _ => ns.decrypt(cks),
    }
}

/// An encrypted value of the graph, an input or the result of a node.
#[derive(Clone)]
enum GraphValue {
    Int(IntCt),
    Bool(FheBool),
}

impl GraphValue {
    fn ty(&self) -> FheTypes {
        match self {
            Self::Int(ct) => ct.ty(),
            Self::Bool(_) => FheTypes::Bool,
        }
    }

    /// What the user does to a transaction input. `value` fits `ty`.
    fn encrypt(ty: FheTypes, value: ClearInt, cks: &ClientKey) -> Self {
        let low = value.low();
        match ty {
            FheTypes::Bool => Self::Bool(FheBool::encrypt(low != 0, cks)),
            FheTypes::Uint8 => Self::Int(IntCt::U8(FheUint8::encrypt(low as u8, cks))),
            FheTypes::Uint16 => Self::Int(IntCt::U16(FheUint16::encrypt(low as u16, cks))),
            FheTypes::Uint32 => Self::Int(IntCt::U32(FheUint32::encrypt(low as u32, cks))),
            FheTypes::Uint64 => Self::Int(IntCt::U64(FheUint64::encrypt(low as u64, cks))),
            FheTypes::Uint128 => Self::Int(IntCt::U128(FheUint128::encrypt(low, cks))),
            FheTypes::Uint160 => Self::Int(IntCt::U160(FheUint160::encrypt(value, cks))),
            FheTypes::Uint256 => Self::Int(IntCt::U256(FheUint256::encrypt(value, cks))),
            other => panic!("{other:?} is not a host executor type"),
        }
    }

    /// The clear value, a boolean as 0 or 1.
    fn decrypt_clear(&self, cks: &ClientKey) -> ClearInt {
        match self {
            Self::Int(ct) => ct.decrypt_clear(cks),
            Self::Bool(ct) => ClearInt::from(ct.decrypt(cks)),
        }
    }

    fn set_metadata(&mut self, data: &[u8]) {
        match self {
            Self::Int(ct) => ct.set_metadata(data),
            Self::Bool(ct) => ct.re_randomization_metadata_mut().set_data(data),
        }
    }

    fn metadata(&self) -> &[u8] {
        match self {
            Self::Int(ct) => ct.metadata(),
            Self::Bool(ct) => ct.re_randomization_metadata().data(),
        }
    }

    fn block_noise_levels(&self) -> Vec<NoiseLevel> {
        match self {
            Self::Int(ct) => ct.block_noise_levels(),
            Self::Bool(ct) => bool_block_noise_levels(ct),
        }
    }

    fn push_into(self, builder: &mut CompressedCiphertextListBuilder) {
        match self {
            Self::Int(ct) => ct.push_into(builder),
            Self::Bool(ct) => {
                builder.push(ct);
            }
        }
    }

    /// Decompresses the value at `pos`, whatever its type: the list knows the kind it stores.
    fn get_from(list: &CompressedCiphertextList, pos: usize) -> Result<Self, String> {
        fn fetch<T: crate::HlExpandable + Tagged>(
            list: &CompressedCiphertextList,
            pos: usize,
        ) -> Result<T, String> {
            list.get::<T>(pos)
                .map_err(|e| format!("failed to decompress value {pos}: {e}"))?
                .ok_or_else(|| format!("value {pos} missing from the compressed list"))
        }
        Ok(match list.get_kind_of(pos) {
            Some(FheTypes::Bool) => Self::Bool(fetch(list, pos)?),
            Some(FheTypes::Uint8) => Self::Int(IntCt::U8(fetch(list, pos)?)),
            Some(FheTypes::Uint16) => Self::Int(IntCt::U16(fetch(list, pos)?)),
            Some(FheTypes::Uint32) => Self::Int(IntCt::U32(fetch(list, pos)?)),
            Some(FheTypes::Uint64) => Self::Int(IntCt::U64(fetch(list, pos)?)),
            Some(FheTypes::Uint128) => Self::Int(IntCt::U128(fetch(list, pos)?)),
            Some(FheTypes::Uint160) => Self::Int(IntCt::U160(fetch(list, pos)?)),
            Some(FheTypes::Uint256) => Self::Int(IntCt::U256(fetch(list, pos)?)),
            kind => {
                return Err(format!(
                    "unexpected kind {kind:?} for the stored value {pos}"
                ))
            }
        })
    }
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
            let s = <$Clear>::try_from(scalar.low())
                .ok()
                .filter(|_| scalar.fits_bits(128))
                .ok_or_else(|| format!("scalar {} does not fit the operand type", scalar.show()))?;
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
define_small_width_eval!(
    bin_u128,
    bin_scalar_u128,
    unary_u128,
    FheUint128,
    u128,
    U128
);

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

fn bin_scalar_u256(op: OpKind, lhs: &FheUint256, s: ClearInt) -> Result<GraphValue, String> {
    use GraphValue as G;
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

fn bin_scalar_u160(op: OpKind, lhs: &FheUint160, s: ClearInt) -> Result<GraphValue, String> {
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
fn cast_int(src: &IntCt, target: FheTypes) -> Result<IntCt, String> {
    macro_rules! cast_from {
        ($v:expr) => {
            match target {
                FheTypes::Uint8 => IntCt::U8(FheUint8::cast_from($v.clone())),
                FheTypes::Uint16 => IntCt::U16(FheUint16::cast_from($v.clone())),
                FheTypes::Uint32 => IntCt::U32(FheUint32::cast_from($v.clone())),
                FheTypes::Uint64 => IntCt::U64(FheUint64::cast_from($v.clone())),
                FheTypes::Uint128 => IntCt::U128(FheUint128::cast_from($v.clone())),
                FheTypes::Uint256 => IntCt::U256(FheUint256::cast_from($v.clone())),
                _ => return Err("invalid cast destination".to_string()),
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

fn cast_bool(src: &FheBool, target: FheTypes) -> Result<IntCt, String> {
    Ok(match target {
        FheTypes::Uint8 => IntCt::U8(FheUint8::cast_from(src.clone())),
        FheTypes::Uint16 => IntCt::U16(FheUint16::cast_from(src.clone())),
        FheTypes::Uint32 => IntCt::U32(FheUint32::cast_from(src.clone())),
        FheTypes::Uint64 => IntCt::U64(FheUint64::cast_from(src.clone())),
        FheTypes::Uint128 => IntCt::U128(FheUint128::cast_from(src.clone())),
        FheTypes::Uint256 => IntCt::U256(FheUint256::cast_from(src.clone())),
        _ => return Err("invalid cast destination".to_string()),
    })
}

/// Trivially encrypts a clear value, mirroring the coprocessor: U160 goes through a trivial U256
/// followed by a cast.
fn trivial_encrypt(value: ClearInt, target: FheTypes) -> GraphValue {
    use GraphValue as G;
    let low = value.low();
    match target {
        FheTypes::Bool => G::Bool(FheBool::encrypt_trivial(low != 0)),
        FheTypes::Uint8 => G::Int(IntCt::U8(FheUint8::encrypt_trivial(low as u8))),
        FheTypes::Uint16 => G::Int(IntCt::U16(FheUint16::encrypt_trivial(low as u16))),
        FheTypes::Uint32 => G::Int(IntCt::U32(FheUint32::encrypt_trivial(low as u32))),
        FheTypes::Uint64 => G::Int(IntCt::U64(FheUint64::encrypt_trivial(low as u64))),
        FheTypes::Uint128 => G::Int(IntCt::U128(FheUint128::encrypt_trivial(low))),
        FheTypes::Uint160 => G::Int(IntCt::U160(FheUint160::cast_from(
            FheUint256::encrypt_trivial(value),
        ))),
        FheTypes::Uint256 => G::Int(IntCt::U256(FheUint256::encrypt_trivial(value))),
        other => panic!("{other:?} is not a host executor type"),
    }
}

/// Randomness, through the same entry points the coprocessor uses: it always calls the bounded
/// generator, with the full width as the bit count when the operation carries no bound.
fn eval_rand_int(ty: FheTypes, seed: Seed, random_bits: u32) -> Result<IntCt, String> {
    let bits = u64::from(random_bits);
    Ok(match ty {
        FheTypes::Uint8 => IntCt::U8(FheUint8::generate_oblivious_pseudo_random_bounded(
            seed, bits,
        )),
        FheTypes::Uint16 => IntCt::U16(FheUint16::generate_oblivious_pseudo_random_bounded(
            seed, bits,
        )),
        FheTypes::Uint32 => IntCt::U32(FheUint32::generate_oblivious_pseudo_random_bounded(
            seed, bits,
        )),
        FheTypes::Uint64 => IntCt::U64(FheUint64::generate_oblivious_pseudo_random_bounded(
            seed, bits,
        )),
        FheTypes::Uint128 => IntCt::U128(FheUint128::generate_oblivious_pseudo_random_bounded(
            seed, bits,
        )),
        FheTypes::Uint256 => IntCt::U256(FheUint256::generate_oblivious_pseudo_random_bounded(
            seed, bits,
        )),
        _ => return Err("integer randomness only exists on N".to_string()),
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
/// operands are homogeneous by the clear validation, but may be empty.
fn eval_sum(operands: &[IntCt], output_ty: FheTypes) -> Result<IntCt, String> {
    // Like the coprocessor (tfhe_ops.rs): an empty sum is a trivial zero of the output type.
    if operands.is_empty() {
        return match trivial_encrypt(ClearInt::ZERO, output_ty) {
            GraphValue::Int(ct) if output_ty.is_arithmetic() => Ok(ct),
            _ => Err("sum output type must be in A".to_string()),
        };
    }
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
    Ok(match &operands[0] {
        IntCt::U8(_) => sum_arm!(U8, FheUint8),
        IntCt::U16(_) => sum_arm!(U16, FheUint16),
        IntCt::U32(_) => sum_arm!(U32, FheUint32),
        IntCt::U64(_) => sum_arm!(U64, FheUint64),
        IntCt::U128(_) => sum_arm!(U128, FheUint128),
        _ => return Err("sum only exists on the arithmetic types".to_string()),
    })
}

/// Membership through the same `contains` entry point the coprocessor uses. The set is
/// homogeneous by the clear validation, but may be empty.
fn eval_is_in(value: &IntCt, set: Vec<IntCt>) -> Result<FheBool, String> {
    // Like the coprocessor (tfhe_ops.rs): an empty set is trivially false, without a PBS.
    if set.is_empty() {
        return Ok(FheBool::encrypt_trivial(false));
    }
    macro_rules! is_in_arm {
        ($V:ident, $Fhe:ty, $value:expr) => {{
            let set: Vec<$Fhe> = set
                .into_iter()
                .map(|v| match v {
                    IntCt::$V(ct) => Ok(ct),
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
fn eval_mul_div(
    a: &IntCt,
    factor2: Option<&IntCt>,
    scalar2: ClearInt,
    divisor: ClearInt,
) -> Result<IntCt, String> {
    macro_rules! mul_div_arm {
        ($V:ident, $Fhe:ty, $Clear:ty, $a:expr) => {{
            let d = <$Clear>::try_from(divisor.low())
                .map_err(|_| "divisor does not fit the operand type".to_string())?;
            match factor2 {
                Some(IntCt::$V(b)) => IntCt::$V($a.fused_mul_scalar_div(b, d)),
                Some(_) => return Err("MulDiv factor type mismatch".to_string()),
                None => {
                    let s = <$Clear>::try_from(scalar2.low())
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
    let num_int_inputs = desc.num_int_inputs();
    let num_bool_inputs = desc.inputs.len() - num_int_inputs;
    for (pos, ct) in ints.iter().enumerate().skip(num_int_inputs) {
        let got = ct.decrypt_clear(cks);
        let (expected_ty, expected) = clear.ints[pos];
        if ct.ty() != expected_ty || got != expected {
            let node_index = clear.int_node_map[pos - num_int_inputs];
            return Err(format!(
                "{}: expected {} {}, got {} {}",
                node_err(node_index, &desc.nodes[node_index], "wrong result"),
                expected_ty.name(),
                expected.show(),
                ct.ty().name(),
                got.show(),
            ));
        }
    }
    for (pos, ct) in bools.iter().enumerate().skip(num_bool_inputs) {
        let got: bool = ct.decrypt(cks);
        let expected = clear.bools[pos];
        if got != expected {
            let node_index = clear.bool_node_map[pos - num_bool_inputs];
            return Err(format!(
                "{}: expected {expected}, got {got}",
                node_err(node_index, &desc.nodes[node_index], "wrong result")
            ));
        }
    }
    Ok(())
}

/// Ends one line of the replay trace, whose node header was printed before the node ran: prints
/// the clear and decrypted values, and fails on the first node where they differ.
fn check_step<T: Copy + PartialEq + std::fmt::Display>(
    node_index: usize,
    node: &Node,
    expected: T,
    got: T,
) -> Result<(), String> {
    let ok = got == expected;
    println!(
        "clear {expected}, decrypted {got} [{}]",
        if ok { "ok" } else { "MISMATCH" }
    );
    if ok {
        Ok(())
    } else {
        Err(node_err(
            node_index,
            node,
            &format!("first diverging step: expected {expected}, got {got}"),
        ))
    }
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
) -> Result<Vec<PersistedValue>, String> {
    // Validation pass, before any FHE work: rand values are not known yet, their nodes evaluate
    // to placeholders. The real clear evaluation runs after the first graph evaluation has
    // decrypted them.
    evaluate_clear(desc, &RandValues::new())?;
    let num_int_inputs = desc.num_int_inputs();
    let num_bool_inputs = desc.inputs.len() - num_int_inputs;
    let input_value = |input: &InputDesc| input.value.as_clear_scalar().unwrap();

    // The user encrypts the fresh inputs, each tied to its origin by metadata, and they are
    // stored compressed.
    let mut builder = CompressedCiphertextListBuilder::new();
    let mut num_fresh = 0;
    for input in desc.inputs.iter().filter(|input| input.persisted.is_none()) {
        let mut ct = GraphValue::encrypt(input.ty, input_value(input), cks);
        ct.set_metadata(&input.metadata);
        ct.push_into(&mut builder);
        num_fresh += 1;
    }
    let compressed_inputs = if num_fresh > 0 {
        Some(
            builder
                .build()
                .map_err(|e| format!("failed to compress the inputs: {e}"))?,
        )
    } else {
        None
    };

    // Every input is loaded back before the transaction is evaluated: the fresh ones from that
    // list, the others from the bytes an earlier transaction stored them as.
    let mut input_ints: Vec<IntCt> = Vec::with_capacity(num_int_inputs);
    let mut input_bools: Vec<FheBool> = Vec::with_capacity(num_bool_inputs);
    let mut fresh_pos = 0;
    for (pos, input) in desc.inputs.iter().enumerate() {
        let ct = match (&input.persisted, &compressed_inputs) {
            (Some(bytes), _) => {
                let list: CompressedCiphertextList = bincode::deserialize(bytes)
                    .map_err(|e| format!("input {pos}: failed to read the stored value: {e}"))?;
                GraphValue::get_from(&list, 0)?
            }
            (None, Some(list)) => {
                fresh_pos += 1;
                GraphValue::get_from(list, fresh_pos - 1)?
            }
            (None, None) => unreachable!("fresh inputs are all in the compressed list"),
        };
        if ct.ty() != input.ty {
            return Err(format!(
                "input {pos} was stored as {}, expected {}",
                ct.ty().name(),
                input.ty.name()
            ));
        }
        if ct.metadata() != input.metadata.as_slice() {
            return Err(format!(
                "input {pos} lost its re-randomization metadata through compression"
            ));
        }
        let decrypted = ct.decrypt_clear(cks);
        if decrypted != input_value(input) {
            return Err(format!(
                "input {pos} changed value through compression/decompression: \
                 expected {}, got {}",
                input_value(input).show(),
                decrypted.show()
            ));
        }
        match ct {
            GraphValue::Int(ct) => input_ints.push(ct),
            GraphValue::Bool(ct) => input_bools.push(ct),
        }
    }

    // The transaction itself: every node re-randomizes its own operands, evaluates, and appends
    // its result to its pool. Operands are cloned per node on purpose, a value feeding several
    // nodes is re-randomized independently in each of them, exactly like a handle read several
    // times by a transaction would be.
    //
    // With `step_by_step`, the replay mode, every node is decrypted and compared to its clear
    // value right after being evaluated, and the whole trace is printed: the first diverging node
    // is named even when later nodes consume its corrupted result. Each line is started before
    // its node runs, so a node that panics or fails is named too. The clear value of a node only
    // depends on earlier nodes, whose rand values are already recorded, so re-evaluating the
    // clear graph after each node gives its exact expected value.
    //
    // Rand nodes are decrypted as they are produced and their values recorded once, keyed by
    // node index: the first evaluation fills the map and seeds the clear oracle with it, the
    // second one finds the entries taken.
    let rand_values: std::cell::RefCell<RandValues> = std::cell::RefCell::new(RandValues::new());
    let run_graph = |step_by_step: bool| -> Result<(Vec<IntCt>, Vec<FheBool>), String> {
        let mut ints: Vec<IntCt> = input_ints.clone();
        let mut bools: Vec<FheBool> = input_bools.clone();

        for (node_index, node) in desc.nodes.iter().enumerate() {
            let op = node.op;
            let opcode = op.opcode();
            let ints_before = ints.len();
            if step_by_step {
                print!("  node {node_index} {node:?}: ");
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }

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
                    trivial_encrypt(value, target)
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
                    let target = node
                        .target
                        .ok_or_else(|| node_err(node_index, node, "randomness needs a type"))?;
                    let [Operand::Scalar(seed), bound @ ..] = node.operands.as_slice() else {
                        return Err(node_err(node_index, node, "malformed operand list"));
                    };
                    let seed = Seed(*seed);
                    // All inputs are clear scalars: nothing to re-randomize, like the executor.
                    match (node.op, bound, target) {
                        (OpKind::Rand, [], FheTypes::Bool) => {
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
                            let random_bits = bound.ilog2().min(ty.bits());
                            GraphValue::Int(
                                eval_rand_int(ty, seed, random_bits)
                                    .map_err(|e| node_err(node_index, node, &e))?,
                            )
                        }
                        _ => return Err(node_err(node_index, node, "malformed operand list")),
                    }
                }
                OpKind::Sum => {
                    let target = node
                        .target
                        .ok_or_else(|| node_err(node_index, node, "sum needs an output type"))?;
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
                        eval_sum(&operands, target).map_err(|e| node_err(node_index, node, &e))?,
                    )
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
                    // The value operand goes through the node context even when the set is empty.
                    let mut handles: Vec<NodeOperand<'_>> =
                        operands.iter_mut().map(NodeOperand::Int).collect();
                    rerand_node(opcode, &mut handles, cpk);
                    let mut operands = operands.into_iter();
                    let value = operands.next().ok_or_else(|| {
                        node_err(node_index, node, "membership needs a value operand")
                    })?;
                    GraphValue::Bool(
                        eval_is_in(&value, operands.collect())
                            .map_err(|e| node_err(node_index, node, &e))?,
                    )
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

            check_noise_levels(&result.block_noise_levels())
                .map_err(|e| node_err(node_index, node, &e))?;

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

            if step_by_step {
                let clear = evaluate_clear(desc, &rand_values.borrow())
                    .map_err(|e| format!("clear evaluation failed: {e}"))?;
                if ints.len() > ints_before {
                    let got = ints.last().unwrap().decrypt_clear(cks);
                    let expected = clear.ints[ints.len() - 1].1;
                    check_step(
                        node_index,
                        node,
                        expected.show().as_str(),
                        got.show().as_str(),
                    )?;
                } else {
                    let got: bool = bools.last().unwrap().decrypt(cks);
                    check_step(node_index, node, clear.bools[bools.len() - 1], got)?;
                }
            }
        }

        Ok((ints, bools))
    };

    // In replay mode this first evaluation is the checked one: whatever goes wrong first, a wrong
    // value, an error or a panic, happens while the trace names the node.
    let (ints, bools) = run_graph(step_by_step)?;

    // The real clear evaluation, seeded with the decrypted rand values; this is also where the
    // range of every rand value is checked against its bound.
    let clear = evaluate_clear(desc, &rand_values.borrow())?;

    // Every produced value is checked right after the graph, so a failure names the node that
    // diverged instead of the transaction as a whole. In replay mode the first evaluation already
    // checked every node as it went.
    if !step_by_step {
        check_produced_values(desc, &clear, &ints, &bools, cks)?;
    }

    // Re-randomization seeds only depend on the node opcode and on the node operands, and the
    // oblivious randomness only on its stored seed, so evaluating the same transaction again has
    // to produce the very same ciphertexts. Both evaluations start from the same input
    // ciphertexts, so only the produced ones are compared.
    let produced_ints = &ints[num_int_inputs..];
    let produced_bools = &bools[num_bool_inputs..];
    {
        let (ints_bis, bools_bis) = run_graph(false)?;
        let produced_ints_bis = &ints_bis[num_int_inputs..];
        let same_ints = produced_ints.len() == produced_ints_bis.len()
            && produced_ints
                .iter()
                .zip(produced_ints_bis.iter())
                .all(|(a, b)| a.serialize_bytes() == b.serialize_bytes());
        let same_bools = bincode::serialize(produced_bools).unwrap()
            == bincode::serialize(&bools_bis[num_bool_inputs..]).unwrap();
        if !same_ints || !same_bools {
            return Err(
                "determinism check failed: the second evaluation produced different \
                        ciphertexts"
                    .to_string(),
            );
        }
    }

    // The produced values with their clear counterparts, integers first.
    let produced: Vec<(GraphValue, ClearInt)> = produced_ints
        .iter()
        .zip(clear.ints[num_int_inputs..].iter())
        .map(|(ct, (_, value))| (GraphValue::Int(ct.clone()), *value))
        .chain(
            produced_bools
                .iter()
                .zip(clear.bools[num_bool_inputs..].iter())
                .map(|(ct, value)| (GraphValue::Bool(ct.clone()), ClearInt::from(*value))),
        )
        .collect();

    // Results are stored back compressed.
    if !produced.is_empty() {
        let mut builder = CompressedCiphertextListBuilder::new();
        for (ct, _) in produced.iter() {
            ct.clone().push_into(&mut builder);
        }
        let compressed_outputs = builder
            .build()
            .map_err(|e| format!("failed to compress the results: {e}"))?;

        for (pos, (original, expected)) in produced.iter().enumerate() {
            let ct = GraphValue::get_from(&compressed_outputs, pos)?;
            if ct.ty() != original.ty() || ct.decrypt_clear(cks) != *expected {
                return Err(format!(
                    "result {pos} changed through compression/decompression"
                ));
            }
        }
    }

    // Before being handed to threshold decryption, results are noise squashed, and the squashed
    // ciphertexts are compressed too. One value per pool is enough to keep the squashing stage
    // covered without doubling the cost of the transaction.
    {
        let mut builder = CompressedSquashedNoiseCiphertextListBuilder::new();

        let expected_int = clear.ints.last().copied();
        if let (Some(last_int), Some((last_ty, expected))) = (ints.last(), expected_int) {
            let ns_int = last_int.squash_noise()?;
            let got = decrypt_squashed(&ns_int, last_ty, cks);
            if got != expected {
                return Err(format!(
                    "last integer value changed through noise squashing: \
                     expected {}, got {}",
                    expected.show(),
                    got.show()
                ));
            }
            builder.push(ns_int);
        }

        let expected_bool = clear.bools.last().copied();
        if let (Some(last_bool), Some(expected)) = (bools.last(), expected_bool) {
            let ns_bool = last_bool
                .squash_noise()
                .map_err(|e| format!("boolean noise squashing failed: {e}"))?;
            let got: bool = ns_bool.decrypt(cks);
            if got != expected {
                return Err("last boolean value changed through noise squashing".to_string());
            }
            builder.push(ns_bool);
        }

        let compressed_ns = builder
            .build()
            .map_err(|e| format!("failed to compress the squashed results: {e}"))?;

        if let Some((last_ty, expected)) = expected_int {
            let ns_int: SquashedNoiseFheUint = compressed_ns
                .get(0)
                .map_err(|e| format!("failed to decompress the squashed integer: {e}"))?
                .ok_or_else(|| "squashed integer missing from the compressed list".to_string())?;
            let got = decrypt_squashed(&ns_int, last_ty, cks);
            if got != expected {
                return Err(format!(
                    "invalid end to end integer result: expected {}, got {}",
                    expected.show(),
                    got.show()
                ));
            }
        }
        if let Some(expected) = expected_bool {
            let ns_bool: SquashedNoiseFheBool = compressed_ns
                .get(usize::from(expected_int.is_some()))
                .map_err(|e| format!("failed to decompress the squashed boolean: {e}"))?
                .ok_or_else(|| "squashed boolean missing from the compressed list".to_string())?;
            let got: bool = ns_bool.decrypt(cks);
            if got != expected {
                return Err(format!(
                    "invalid end to end boolean result: expected {expected}, got {got}"
                ));
            }
        }
    }

    // The last value each pool gained is stored for later transactions to take as an input:
    // tagged with its metadata and compressed alone in its own list, like a handle of the
    // protocol. Whoever takes it checks what it decompresses to.
    let last_int = produced[..produced_ints.len()].last();
    let last_bool = produced[produced_ints.len()..].last();
    let mut stored = Vec::new();
    for (ct, value) in last_int.into_iter().chain(last_bool) {
        let mut ct = ct.clone();
        ct.set_metadata(&desc.output_metadata);
        let ty = ct.ty();
        let mut builder = CompressedCiphertextListBuilder::new();
        ct.push_into(&mut builder);
        let list = builder
            .build()
            .map_err(|e| format!("failed to compress a stored result: {e}"))?;
        stored.push(PersistedValue {
            ty,
            value: *value,
            metadata: desc.output_metadata.clone(),
            bytes: bincode::serialize(&list)
                .map_err(|e| format!("failed to serialize a stored result: {e}"))?,
        });
    }

    Ok(stored)
}

//
// Failure reports and replay
//

/// Where traces and failure reports go: `TFHE_RS_PROTOCOL_FAILURE_DIR`, or the working directory,
/// which under `cargo test` is the crate root (`tfhe/`).
fn failure_dir() -> std::path::PathBuf {
    let dir = std::env::var("TFHE_RS_PROTOCOL_FAILURE_DIR")
        .ok()
        .filter(|dir| !dir.is_empty())
        .map_or_else(
            || std::env::current_dir().expect("failed to read the working directory"),
            std::path::PathBuf::from,
        );
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("failed to create the report directory {dir:?}: {e}"));
    dir
}

/// The start time of this process, in seconds since the Unix epoch, which goes into every trace and
/// report name: a run never overwrites the files of an earlier one, such as the traces of a
/// crashed run that is being rerun.
fn run_stamp() -> &'static str {
    static STAMP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    STAMP.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock is set before 1970")
            .as_secs()
            .to_string()
    })
}

fn failure_report_path(test_name: &str, transaction_index: usize) -> std::path::PathBuf {
    failure_dir().join(format!(
        "{test_name}_{}_failure_tx{transaction_index}.json",
        run_stamp()
    ))
}

/// A rolling trace of the most recent transactions, written next to the failure reports as
/// `<test name>_<run stamp>_recent_slot<n>.json`. Each file is a complete failure report (with
/// a placeholder error), written *before* its transaction runs: when a run dies without
/// reaching the failure path at all, a crash or a device fault, the graphs that were executing
/// are already on disk, each replayable on its own through `TFHE_RS_PROTOCOL_REPLAY`. Slots are
/// reused, so the files rotate by themselves; the index inside each file says which ones are the
/// newest.
pub(crate) struct RecentLog {
    dir: std::path::PathBuf,
    prefix: String,
    capacity: usize,
}

impl RecentLog {
    pub(crate) fn new(capacity: usize, test_name: &str) -> Self {
        let dir = failure_dir();
        let prefix = format!("{test_name}_{}_recent_slot", run_stamp());
        println!("{test_name}: recent transaction traces and failure reports go to {dir:?}");
        println!(
            "{test_name}: trace and report names start with {test_name}_{}",
            run_stamp()
        );
        Self {
            dir,
            prefix,
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
        self.record_in_slot(
            desc,
            transaction_seed,
            index,
            identity,
            index % self.capacity,
        );
    }

    /// Like [`Self::record`], into a slot the caller picked. Drivers that let transactions
    /// complete out of order use it to keep the slot of a transaction still executing from
    /// being reused, which the index modulo the capacity cannot guarantee.
    pub(crate) fn record_in_slot(
        &self,
        desc: &TransactionDescription,
        transaction_seed: Seed,
        index: usize,
        identity: &RunIdentity<'_>,
        slot: usize,
    ) {
        assert!(slot < self.capacity, "trace slot {slot} out of range");
        let report = FailureReport {
            params: identity.params_name.to_string(),
            key_seed: identity.key_seed.0,
            setup_seed: identity.setup_seed.0,
            transaction_seed: transaction_seed.0,
            transaction_index: index,
            error: "recent transaction trace, not a failure".to_string(),
            description: desc.clone(),
        };
        let path = self.dir.join(format!("{}{slot}.json", self.prefix));
        // Best effort: the trace must never take a healthy run down.
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap());
    }
}

/// Seeds the transaction's encryption engine, runs the transaction, and on failure writes the
/// self contained JSON report before panicking with the replay instructions. Returns the outputs
/// the transaction stored.
pub(crate) fn run_transaction_or_dump(
    desc: &TransactionDescription,
    transaction_seed: Seed,
    index: usize,
    keys: &ProtocolKeys,
    identity: &RunIdentity<'_>,
    step_by_step: bool,
) -> Vec<PersistedValue> {
    install_seeded_engine(transaction_seed);

    match run_transaction(desc, &keys.cks, &keys.cpk, step_by_step) {
        Ok(stored) => stored,
        Err(error) => {
            let report = FailureReport {
                params: identity.params_name.to_string(),
                key_seed: identity.key_seed.0,
                setup_seed: identity.setup_seed.0,
                transaction_seed: transaction_seed.0,
                transaction_index: index,
                error: error.clone(),
                description: desc.clone(),
            };
            let path = failure_report_path(identity.test_name, index);
            std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap())
                .unwrap_or_else(|e| panic!("failed to write the failure report to {path:?}: {e}"));

            panic!(
                "transaction {index}: {error}\n\
                 failing graph written to {path:?}\n\
                 replay it alone with TFHE_RS_PROTOCOL_REPLAY={path:?} and the replay test of \
                 the backend the run used",
            );
        }
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
/// a fresh report, if the transaction still fails. That report is named after the replay, never
/// after the original test, so it cannot overwrite the report being replayed and the original
/// error survives.
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
            test_name: "protocol_random_ops_replay",
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

/// The body of the replay tests: replays the failure report `TFHE_RS_PROTOCOL_REPLAY` points
/// at, on the backend `install_server_key` sets up. Does nothing when the variable is unset or
/// empty (`make` exports it empty when `REPLAY` is omitted), so whole-module test filters stay
/// usable.
pub(crate) fn replay_from_env(install_server_key: impl FnOnce(&CompressedServerKey)) {
    let Some(path) = std::env::var("TFHE_RS_PROTOCOL_REPLAY")
        .ok()
        .filter(|path| !path.is_empty())
    else {
        println!("TFHE_RS_PROTOCOL_REPLAY is not set, nothing to replay");
        return;
    };
    replay_from_report(&load_failure_report(&path), install_server_key);
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
        for signature in evaluation
            .input_signatures
            .iter()
            .chain(evaluation.signatures.iter())
        {
            *self.hits.entry(signature.clone()).or_default() += 1;
        }
    }

    pub(crate) fn print(&self) {
        for (signature, count) in self.hits.iter() {
            println!("  {signature}: {count}");
        }
    }
}

/// What every driver starts from: the seeded keys, the identity copied into the reports, and the
/// root seed stream the run keeps drawing from.
pub(crate) struct RunSetup<'a> {
    pub(crate) keys: ProtocolKeys,
    pub(crate) identity: RunIdentity<'a>,
    pub(crate) root: DeterministicSeeder<DefaultRandomGenerator>,
}

/// Resolves the parameter set by the same name the failure reports store, so a run and its
/// replays can never disagree on the parameters, and generates the keys from the root seed of
/// the run.
///
/// The root stream hands out the key seed and the setup seed here; whatever the driver draws next
/// is its own (the random drivers draw their data seed, then one seed per transaction).
pub(crate) fn prepare_run<'a>(params_name: &'a str, test_name: &'a str) -> RunSetup<'a> {
    let meta_params = meta_params_by_name(params_name)
        .unwrap_or_else(|| panic!("unknown parameter set {params_name}"));
    let mut root = DeterministicSeeder::<DefaultRandomGenerator>::new(run_seed(test_name));
    let key_seed = root.seed();
    let setup_seed = root.seed();
    let keys = generate_protocol_keys(Config::from(meta_params), key_seed, setup_seed);
    RunSetup {
        keys,
        identity: RunIdentity {
            test_name,
            params_name,
            key_seed,
            setup_seed,
        },
        root,
    }
}

/// How long a random run goes on: `TFHE_RS_PROTOCOL_DURATION_SECS` of wall clock when set, the
/// transaction count otherwise.
pub(crate) struct RunLength {
    duration: Option<std::time::Duration>,
    count: usize,
}

impl RunLength {
    pub(crate) fn from_env(test_name: &str) -> Self {
        let length = Self {
            duration: run_duration(),
            count: num_transactions(),
        };
        match length.duration {
            Some(budget) => println!(
                "{test_name}: running for {} seconds of wall clock",
                budget.as_secs()
            ),
            None => println!("{test_name}: running {} transactions", length.count),
        }
        length
    }

    /// Whether the transaction `index` still belongs to a run started at `start`.
    pub(crate) fn allows(&self, index: usize, start: Instant) -> bool {
        self.duration
            .map_or(index < self.count, |budget| start.elapsed() < budget)
    }
}

/// The complete run: seeded setup, then transactions drawn and verified until the
/// [`RunLength`] is spent.
///
/// `install_server_key` is the backend specific part: decompressing the server key to the CPU or
/// to a GPU and installing it on whatever threads evaluate transactions.
pub(crate) fn protocol_random_ops_run(
    params_name: &str,
    test_name: &str,
    install_server_key: impl FnOnce(&CompressedServerKey),
) {
    let RunSetup {
        keys,
        identity,
        mut root,
    } = prepare_run(params_name, test_name);
    install_server_key(&keys.compressed_sks);
    let mut datagen = RandomGenerator::<DefaultRandomGenerator>::new(root.seed());
    let length = RunLength::from_env(test_name);

    let start = Instant::now();
    let mut coverage = Coverage::default();
    let recent = RecentLog::new(10, test_name);
    let mut persisted = PersistedPool::default();
    let mut index = 0usize;
    while length.allows(index, start) {
        // Each transaction encrypts under its own seed and carries the bytes of the stored
        // values it takes as inputs, so one failing transaction replays alone from its JSON
        // report, whatever ran before it.
        let transaction_seed = root.seed();
        let advanced = persisted.advance(index);
        debug_assert!(advanced, "every earlier transaction has completed");
        let desc = draw_transaction(&mut datagen, &persisted);
        if let Ok(evaluation) = evaluate_clear(&desc, &RandValues::new()) {
            coverage.record(&evaluation);
        }

        recent.record(&desc, transaction_seed, index, &identity);
        let stored =
            run_transaction_or_dump(&desc, transaction_seed, index, &keys, &identity, false);
        persisted.complete(index, stored);

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

/// Builds one forced transaction: the inputs occupy the first slots of their pool, and every
/// pushed node declares which pool its result extends, returning the slot it lands in.
struct ForcedTransaction {
    inputs: Vec<InputDesc>,
    nodes: Vec<Node>,
    num_ints: usize,
    num_bools: usize,
}

impl ForcedTransaction {
    fn new(inputs: Vec<InputDesc>) -> Self {
        let num_bools = inputs
            .iter()
            .filter(|input| input.ty == FheTypes::Bool)
            .count();
        Self {
            num_ints: inputs.len() - num_bools,
            num_bools,
            inputs,
            nodes: Vec::new(),
        }
    }

    /// Two fresh inputs of the same type.
    fn with_fresh_inputs(ty: FheTypes, a: ClearInt, b: ClearInt) -> Self {
        Self::new(vec![
            InputDesc::fresh(ty, a, vec![0x5A; METADATA_LEN]),
            InputDesc::fresh(ty, b, vec![0xA5; METADATA_LEN]),
        ])
    }

    fn push_int(&mut self, op: OpKind, operands: Vec<Operand>, target: Option<FheTypes>) -> usize {
        self.nodes.push(Node {
            op,
            operands,
            target,
        });
        self.num_ints += 1;
        self.num_ints - 1
    }

    fn push_bool(&mut self, op: OpKind, operands: Vec<Operand>, target: Option<FheTypes>) -> usize {
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
            inputs: self.inputs,
            nodes: self.nodes,
            output_metadata: vec![0x3C; METADATA_LEN],
        }
    }
}

/// The bound exponents the forced pass exercises for one bounded rand type: the degenerate bound
/// of one, two, just under the width, and just over it, where the executor caps the bit count.
/// Bounds cannot exceed 255 bits, the largest power of two an operand can carry.
fn forced_rand_exponents(ty: FheTypes) -> [u32; 4] {
    [0, 1, ty.bits() - 1, (ty.bits() + 1).min(255)]
}

/// The deterministic coverage pass: one handcrafted transaction per value type, on two encrypted
/// inputs of that type, running every admissible operation of that type once per operand mode,
/// plus the cast matrix, the collection sizes 0, 1 and 3, the collection limits on one narrow
/// and one wide type, and the rand bound edges. Every binary operation also runs with a trivial
/// encryption of zero on each side, which is what the protocol turns an uninitialized value
/// into. Where the random generator covers the matrix statistically over a long run, this pass
/// covers it exhaustively in one short one.
///
/// Each integer transaction ends on a trivial encryption of zero, so the value it stores is a
/// trivial one: [`forced_chained_descriptions`] takes it from there.
pub(crate) fn forced_coverage_descriptions() -> Vec<TransactionDescription> {
    // The first operand alternates bits inside every 2 bit block, the second alternates at the
    // block level, zero blocks between saturated ones, so every forced operation sees both
    // pattern families at once.
    const ALTERNATING_HIGH: u128 = 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA;
    const BLOCK_LOW: u128 = 0x3333_3333_3333_3333_3333_3333_3333_3333;

    let mut descriptions = Vec::new();

    for ty in [
        FheTypes::Uint8,
        FheTypes::Uint16,
        FheTypes::Uint32,
        FheTypes::Uint64,
        FheTypes::Uint128,
        FheTypes::Uint160,
        FheTypes::Uint256,
    ] {
        let a_val = ClearInt::from((ALTERNATING_HIGH, ALTERNATING_HIGH)).masked(ty);
        let b_val = ClearInt::from((BLOCK_LOW, BLOCK_LOW)).masked(ty);

        let mut t = ForcedTransaction::with_fresh_inputs(ty, a_val, b_val);
        let (a, b) = (0, 1);
        let zero = t.push_int(OpKind::TrivialEncrypt, vec![Operand::Scalar(0)], Some(ty));
        let flag = t.push_bool(OpKind::Eq, vec![Operand::Ct(a), Operand::Ct(b)], None);
        // `b_val` is at least the width for every type, so shifting by it only checks the
        // overshift path. This odd, in-range amount (5 for u8, 129 for u256) also crosses block
        // and limb boundaries, so the regular shift path gets checked too.
        let shift_val = ClearInt::from(ty.bits() / 2 + 1);
        let shift = t.push_int(
            OpKind::TrivialEncrypt,
            vec![scalar_operand(shift_val)],
            Some(ty),
        );

        for &op in plain_ops_for(ty) {
            match op {
                OpKind::Neg | OpKind::Not => {
                    t.push_int(op, vec![Operand::Ct(a)], None);
                }
                OpKind::Shl | OpKind::Shr => {
                    for amount in [b, shift] {
                        t.push_int(op, vec![Operand::Ct(a), Operand::Ct(amount)], None);
                    }
                    for amount in [b_val, shift_val] {
                        t.push_int(op, vec![Operand::Ct(a), scalar_operand(amount)], None);
                    }
                    t.push_int(op, vec![Operand::Ct(zero), Operand::Ct(a)], None);
                    t.push_int(op, vec![Operand::Ct(a), Operand::Ct(zero)], None);
                }
                // Division and remainder only exist with a clear scalar divisor.
                OpKind::Div | OpKind::Rem => {
                    t.push_int(op, vec![Operand::Ct(a), scalar_operand(b_val)], None);
                    t.push_int(op, vec![Operand::Ct(zero), scalar_operand(b_val)], None);
                }
                OpKind::Eq | OpKind::Ne | OpKind::Ge | OpKind::Gt | OpKind::Le | OpKind::Lt => {
                    t.push_bool(op, vec![Operand::Ct(a), Operand::Ct(b)], None);
                    t.push_bool(op, vec![Operand::Ct(a), scalar_operand(b_val)], None);
                    t.push_bool(op, vec![Operand::Ct(zero), Operand::Ct(a)], None);
                    t.push_bool(op, vec![Operand::Ct(a), Operand::Ct(zero)], None);
                }
                _ => {
                    t.push_int(op, vec![Operand::Ct(a), Operand::Ct(b)], None);
                    t.push_int(op, vec![Operand::Ct(a), scalar_operand(b_val)], None);
                    t.push_int(op, vec![Operand::Ct(zero), Operand::Ct(a)], None);
                    t.push_int(op, vec![Operand::Ct(a), Operand::Ct(zero)], None);
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
            FheTypes::Uint160 => {
                t.push_bool(OpKind::Eq, vec![Operand::Ct(sel), Operand::Ct(a)], None);
            }
            FheTypes::Uint256 => {
                t.push_int(OpKind::BitAnd, vec![Operand::Ct(sel), Operand::Ct(a)], None);
            }
            _ => {
                t.push_int(OpKind::Add, vec![Operand::Ct(sel), Operand::Ct(a)], None);
            }
        }

        if ty != FheTypes::Uint160 {
            for target in N_TYPES {
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

        if ty.is_n() {
            t.push_int(OpKind::Rand, vec![Operand::Scalar(41)], Some(ty));
            for exponent in forced_rand_exponents(ty) {
                t.push_int(
                    OpKind::RandBounded,
                    vec![
                        Operand::Scalar(43 + u128::from(exponent)),
                        scalar_operand(ClearInt::ONE << exponent),
                    ],
                    Some(ty),
                );
            }
        }

        // The collection limits, exercised once on a narrow type and once on a wide one: a limit
        // sized node costs as much as a whole ordinary transaction, covering every type at the
        // limit would dominate the pass without covering anything new.
        if matches!(ty, FheTypes::Uint8 | FheTypes::Uint64) {
            let limit = ty.collection_limit();
            t.push_int(OpKind::Sum, vec![Operand::Ct(a); limit], Some(ty));
            let mut membership = vec![Operand::Ct(a)];
            membership.extend(std::iter::repeat_n(Operand::Ct(b), limit));
            t.push_bool(OpKind::IsIn, membership, None);
        }

        // Last, so this is the integer the transaction stores.
        t.push_int(OpKind::TrivialEncrypt, vec![Operand::Scalar(0)], Some(ty));

        descriptions.push(t.into_description());
    }

    // The boolean transaction: the encrypted boolean operators in both modes, the boolean
    // selection, the boolean cast sources, and the boolean trivial encryption and randomness.
    let mut t = ForcedTransaction::with_fresh_inputs(FheTypes::Bool, ClearInt::ONE, ClearInt::ZERO);
    let (b0, b1) = (0, 1);
    let zero = t.push_bool(
        OpKind::TrivialEncrypt,
        vec![Operand::Scalar(0)],
        Some(FheTypes::Bool),
    );
    for &op in BOOL_OPS.iter() {
        if op == OpKind::Not {
            t.push_bool(op, vec![Operand::BoolCt(b0)], None);
        } else {
            t.push_bool(op, vec![Operand::BoolCt(b0), Operand::BoolCt(b1)], None);
            t.push_bool(
                op,
                vec![Operand::BoolCt(b0), Operand::BoolScalar(true)],
                None,
            );
            t.push_bool(op, vec![Operand::BoolCt(zero), Operand::BoolCt(b0)], None);
            t.push_bool(op, vec![Operand::BoolCt(b0), Operand::BoolCt(zero)], None);
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
    t.push_bool(
        OpKind::TrivialEncrypt,
        vec![Operand::Scalar(1)],
        Some(FheTypes::Bool),
    );
    for target in N_TYPES {
        t.push_int(OpKind::Cast, vec![Operand::BoolCt(b0)], Some(target));
    }
    t.push_bool(
        OpKind::Rand,
        vec![Operand::Scalar(47)],
        Some(FheTypes::Bool),
    );
    descriptions.push(t.into_description());

    descriptions
}

/// The chained part of the coverage pass: one small transaction per stored value, taking it as
/// an input next to a fresh one of the same type, so every stored value is decompressed, checked
/// and computed on. Run on the values the fixed transactions stored, this covers the trivial
/// encryptions they end on; run again on its own outputs, it covers stored operation results.
pub(crate) fn forced_chained_descriptions(
    stored: &[PersistedValue],
) -> Vec<TransactionDescription> {
    const BLOCK_LOW: u128 = 0x3333_3333_3333_3333_3333_3333_3333_3333;

    stored
        .iter()
        .map(|value| {
            let ty = value.ty;
            let fresh = InputDesc::fresh(
                ty,
                ClearInt::from((BLOCK_LOW, BLOCK_LOW)).masked(ty),
                vec![0xA5; METADATA_LEN],
            );
            let mut t = ForcedTransaction::new(vec![value.as_input(), fresh]);
            if ty == FheTypes::Bool {
                let x = t.push_bool(
                    OpKind::BitXor,
                    vec![Operand::BoolCt(0), Operand::BoolCt(1)],
                    None,
                );
                let sel = t.push_bool(
                    OpKind::Select,
                    vec![Operand::BoolCt(x), Operand::BoolCt(0), Operand::BoolCt(1)],
                    None,
                );
                t.push_bool(
                    OpKind::BitOr,
                    vec![Operand::BoolCt(sel), Operand::BoolCt(0)],
                    None,
                );
            } else {
                let flag = t.push_bool(OpKind::Ne, vec![Operand::Ct(0), Operand::Ct(1)], None);
                let sel = t.push_int(
                    OpKind::Select,
                    vec![Operand::BoolCt(flag), Operand::Ct(1), Operand::Ct(0)],
                    None,
                );
                let consume = vec![Operand::Ct(sel), Operand::Ct(0)];
                match ty {
                    FheTypes::Uint160 => t.push_bool(OpKind::Eq, consume, None),
                    FheTypes::Uint256 => t.push_int(OpKind::BitXor, consume, None),
                    _ => t.push_int(OpKind::Add, consume, None),
                };
            }
            t.into_description()
        })
        .collect()
}

/// Runs the forced coverage pass: the fixed transactions of [`forced_coverage_descriptions`],
/// through the same seeded keys, reporting and replay machinery as the random run. Setting
/// `TFHE_RS_PROTOCOL_TRANSACTIONS` truncates the pass to its first transactions.
pub(crate) fn protocol_random_ops_forced_coverage_run(
    params_name: &str,
    test_name: &str,
    install_server_key: impl FnOnce(&CompressedServerKey),
) {
    // The graphs are fixed; the seed only covers the keys and the encryption noise.
    let RunSetup {
        keys,
        identity,
        mut root,
    } = prepare_run(params_name, test_name);
    install_server_key(&keys.compressed_sks);

    let mut descriptions = forced_coverage_descriptions();
    if let Some(cap) = requested_transactions() {
        descriptions.truncate(cap);
    }
    println!(
        "{test_name}: running {} forced coverage transactions, then the chained ones",
        descriptions.len()
    );

    let start = Instant::now();
    let mut coverage = Coverage::default();
    let recent = RecentLog::new(10, test_name);
    let mut index = 0usize;
    // Three rounds: the fixed transactions, the chained ones on what those stored, and the
    // chained ones again on the integers that second round stored, which are operation results.
    for round in 0..3 {
        let mut stored = Vec::new();
        for desc in descriptions.iter() {
            let transaction_seed = root.seed();
            if let Ok(evaluation) = evaluate_clear(desc, &RandValues::new()) {
                coverage.record(&evaluation);
            }

            recent.record(desc, transaction_seed, index, &identity);
            stored.extend(run_transaction_or_dump(
                desc,
                transaction_seed,
                index,
                &keys,
                &identity,
                false,
            ));
            println!(
                "{test_name}: transaction {index} done ({} nodes, {} seconds elapsed)",
                desc.nodes.len(),
                start.elapsed().as_secs()
            );
            index += 1;
        }
        if round == 1 {
            stored.retain(|value| value.ty != FheTypes::Bool);
        }
        descriptions = forced_chained_descriptions(&stored);
    }

    println!("{test_name}: done, {index} transactions, signature coverage:");
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
        "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128",
        "test_cpu_protocol_random_ops_classical",
        cpu_install_server_key,
    );
}

#[test]
#[ignore = "long running protocol test, run explicitly"]
fn test_cpu_protocol_random_ops_forced_coverage() {
    protocol_random_ops_forced_coverage_run(
        "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128",
        "test_cpu_protocol_random_ops_forced_coverage",
        cpu_install_server_key,
    );
}

#[test]
#[ignore = "replay driver, set TFHE_RS_PROTOCOL_REPLAY to a failure report"]
fn test_cpu_protocol_random_ops_replay() {
    replay_from_env(cpu_install_server_key);
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

    /// Two fresh u8 inputs, 200 and 3, in the integer slots 0 and 1.
    fn desc(nodes: Vec<Node>) -> TransactionDescription {
        TransactionDescription {
            inputs: vec![
                InputDesc::fresh(FheTypes::Uint8, ClearInt::from(200u8), metadata()),
                InputDesc::fresh(FheTypes::Uint8, ClearInt::from(3u8), metadata()),
            ],
            nodes,
            output_metadata: metadata(),
        }
    }

    fn node(op: OpKind, operands: Vec<Operand>) -> Node {
        Node {
            op,
            operands,
            target: None,
        }
    }

    fn typed_node(op: OpKind, operands: Vec<Operand>, target: FheTypes) -> Node {
        Node {
            op,
            operands,
            target: Some(target),
        }
    }

    fn last_int(nodes: Vec<Node>) -> (FheTypes, ClearInt) {
        let eval = evaluate_clear(&desc(nodes), &RandValues::new()).unwrap();
        *eval.ints.last().unwrap()
    }

    fn last_bool(nodes: Vec<Node>) -> bool {
        let eval = evaluate_clear(&desc(nodes), &RandValues::new()).unwrap();
        *eval.bools.last().unwrap()
    }

    #[test]
    fn test_protocol_random_ops_clear_oracle() {
        let enc = vec![Operand::Ct(0), Operand::Ct(1)];
        let int_result = |op, operands: Vec<Operand>| last_int(vec![node(op, operands)]).1.low();
        let bool_result = |op, operands: Vec<Operand>| last_bool(vec![node(op, operands)]);

        assert_eq!(
            int_result(OpKind::Add, enc.clone()),
            u128::from(200u8.wrapping_add(3))
        );
        assert_eq!(
            int_result(OpKind::Sub, enc.clone()),
            u128::from(200u8.wrapping_sub(3))
        );
        assert_eq!(
            int_result(OpKind::Mul, enc.clone()),
            u128::from(200u8.wrapping_mul(3))
        );
        assert_eq!(
            int_result(OpKind::Div, vec![Operand::Ct(0), Operand::Scalar(3)]),
            u128::from(200u8 / 3)
        );
        assert_eq!(
            int_result(OpKind::Rem, vec![Operand::Ct(0), Operand::Scalar(3)]),
            u128::from(200u8 % 3)
        );
        assert_eq!(
            int_result(OpKind::BitAnd, enc.clone()),
            u128::from(0xc8_u8 & 0b11)
        );
        assert_eq!(
            int_result(OpKind::BitOr, enc.clone()),
            u128::from(0xc8_u8 | 0b11)
        );
        assert_eq!(
            int_result(OpKind::BitXor, enc.clone()),
            u128::from(0xc8_u8 ^ 0b11)
        );
        assert_eq!(int_result(OpKind::Shl, enc.clone()), u128::from(200u8 << 3));
        assert_eq!(int_result(OpKind::Shr, enc.clone()), u128::from(200u8 >> 3));
        // Overshift yields zero, unlike a rotation of the same amount.
        assert_eq!(
            int_result(OpKind::Shl, vec![Operand::Ct(0), Operand::Scalar(8)]),
            0
        );
        assert_eq!(
            int_result(OpKind::Shr, vec![Operand::Ct(0), Operand::Scalar(255)]),
            0
        );
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
        assert_eq!(
            int_result(OpKind::Not, vec![Operand::Ct(0)]),
            u128::from(!200u8)
        );
        assert!(!bool_result(OpKind::Eq, enc.clone()));
        assert!(bool_result(OpKind::Ne, enc.clone()));
        assert!(bool_result(OpKind::Ge, enc.clone()));
        assert!(bool_result(OpKind::Gt, enc.clone()));
        assert!(!bool_result(OpKind::Le, enc.clone()));
        assert!(!bool_result(OpKind::Lt, enc));

        // The malformed cases a hand-edited replay file could contain are rejected.
        let invalid = |op, operands| {
            evaluate_clear(&desc(vec![node(op, operands)]), &RandValues::new()).is_err()
        };
        assert!(invalid(
            OpKind::Div,
            vec![Operand::Ct(0), Operand::Scalar(0)]
        ));
        assert!(invalid(OpKind::Div, vec![Operand::Ct(0), Operand::Ct(1)]));
        assert!(invalid(
            OpKind::Add,
            vec![Operand::Ct(0), Operand::Scalar(256)]
        ));
        assert!(invalid(OpKind::Add, vec![Operand::Ct(0), Operand::Ct(7)]));
    }

    #[test]
    fn test_protocol_random_ops_clear_oracle_structural() {
        // Cast: widen, then narrow back, then to u256 and onto the u256 operator set.
        let (ty, v) = last_int(vec![typed_node(
            OpKind::Cast,
            vec![Operand::Ct(0)],
            FheTypes::Uint32,
        )]);
        assert_eq!((ty, v.low()), (FheTypes::Uint32, 200));
        let (ty, v) = last_int(vec![
            typed_node(OpKind::Cast, vec![Operand::Ct(0)], FheTypes::Uint32),
            node(OpKind::Add, vec![Operand::Ct(2), Operand::Scalar(100)]),
            typed_node(OpKind::Cast, vec![Operand::Ct(3)], FheTypes::Uint8),
        ]);
        assert_eq!((ty, v.low()), (FheTypes::Uint8, 300 % 256));

        // U256: not of zero is the full mask, rotation across the limb boundary works.
        let u256_not = last_int(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(0)],
                FheTypes::Uint256,
            ),
            node(OpKind::Not, vec![Operand::Ct(2)]),
        ]);
        assert_eq!(u256_not.1, FheTypes::Uint256.mask());
        let rotated = last_int(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(1)],
                FheTypes::Uint256,
            ),
            node(OpKind::Rotl, vec![Operand::Ct(2), Operand::Scalar(200)]),
        ]);
        assert_eq!(rotated.1, ClearInt::from((0, 1u128 << 72)));
        let neg_one = last_int(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(1)],
                FheTypes::Uint256,
            ),
            node(OpKind::Neg, vec![Operand::Ct(2)]),
        ]);
        assert_eq!(neg_one.1, FheTypes::Uint256.mask());

        // U160 equality against a scalar, through a trivial encryption.
        let eq = last_bool(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::BigScalar { lo: 7, hi: 5 }],
                FheTypes::Uint160,
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
        assert_eq!(selected.1.low(), 200);
        let sum = last_int(vec![typed_node(
            OpKind::Sum,
            vec![Operand::Ct(0), Operand::Ct(0), Operand::Ct(1)],
            FheTypes::Uint8,
        )]);
        assert_eq!(
            sum.1.low(),
            u128::from(200u8.wrapping_add(200).wrapping_add(3))
        );
        let empty_sum = last_int(vec![typed_node(OpKind::Sum, vec![], FheTypes::Uint8)]);
        assert_eq!(empty_sum.1.low(), 0);
        assert!(last_bool(vec![node(
            OpKind::IsIn,
            vec![Operand::Ct(0), Operand::Ct(1), Operand::Ct(0)],
        )]));
        assert!(!last_bool(vec![node(OpKind::IsIn, vec![Operand::Ct(0)])]));
        let mul_div = last_int(vec![node(
            OpKind::MulDiv,
            vec![Operand::Ct(0), Operand::Ct(0), Operand::Scalar(100)],
        )]);
        assert_eq!(mul_div.1.low(), (200 * 200 / 100) % 256);

        // Type rules: U256 arithmetic, U160 casts, identity casts and oversized collections are
        // rejected.
        let invalid = |nodes: Vec<Node>| evaluate_clear(&desc(nodes), &RandValues::new()).is_err();
        assert!(invalid(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(1)],
                FheTypes::Uint256
            ),
            node(OpKind::Add, vec![Operand::Ct(2), Operand::Scalar(1)]),
        ]));
        assert!(invalid(vec![
            typed_node(
                OpKind::TrivialEncrypt,
                vec![Operand::Scalar(1)],
                FheTypes::Uint160
            ),
            typed_node(OpKind::Cast, vec![Operand::Ct(2)], FheTypes::Uint64),
        ]));
        assert!(invalid(vec![typed_node(
            OpKind::Cast,
            vec![Operand::Ct(0)],
            FheTypes::Uint8
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::Sum,
            vec![Operand::Ct(0); 101],
            FheTypes::Uint8,
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
            signatures.extend(evaluation.input_signatures);
        }
        let expect = |s: &str| {
            assert!(signatures.contains(s), "missing forced signature {s}");
        };

        let int_types = [
            FheTypes::Uint8,
            FheTypes::Uint16,
            FheTypes::Uint32,
            FheTypes::Uint64,
            FheTypes::Uint128,
            FheTypes::Uint160,
            FheTypes::Uint256,
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
            if ty != FheTypes::Uint160 {
                for target in N_TYPES {
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
            if ty.is_n() {
                expect(&format!("Rand/{}", ty.name()));
                for exponent in forced_rand_exponents(ty) {
                    let random_bits = exponent.min(ty.bits());
                    expect(&format!("RandBounded/{}/b{random_bits}", ty.name()));
                }
            }
        }
        for (ty, limit) in [(FheTypes::Uint8, 100), (FheTypes::Uint64, 60)] {
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
        for target in N_TYPES {
            expect(&format!("Cast/bool->{}", target.name()));
        }
        for ty in ALL_TYPES {
            expect(&format!("Input/{}/fresh", ty.name()));
        }
    }

    #[test]
    fn test_protocol_random_ops_forced_trivial_zero_operands() {
        // In every forced transaction, each binary operation also runs with a trivial encryption
        // of zero on the left and on the right.
        for (index, desc) in forced_coverage_descriptions().iter().enumerate() {
            // The trivial zeros are the first node of each transaction: the first slot after
            // the two inputs, in the pool of the transaction's type.
            let is_bool = desc.inputs[0].ty == FheTypes::Bool;
            let zero = if is_bool {
                Operand::BoolCt(2)
            } else {
                Operand::Ct(2)
            };
            assert_eq!(desc.nodes[0].op, OpKind::TrivialEncrypt);
            assert_eq!(desc.nodes[0].operands, vec![Operand::Scalar(0)]);

            let ops: &[OpKind] = if is_bool {
                &BOOL_OPS
            } else {
                plain_ops_for(desc.inputs[0].ty)
            };
            for &op in ops {
                if matches!(op, OpKind::Neg | OpKind::Not) {
                    continue;
                }
                let has = |side: usize| {
                    desc.nodes
                        .iter()
                        .any(|node| node.op == op && node.operands.get(side) == Some(&zero))
                };
                assert!(
                    has(0),
                    "transaction {index}: no {op:?} with a zero on the left"
                );
                // Division and remainder only take a clear scalar on the right.
                if !matches!(op, OpKind::Div | OpKind::Rem) {
                    assert!(
                        has(1),
                        "transaction {index}: no {op:?} with a zero on the right"
                    );
                }
            }
        }
    }

    fn stored(ty: FheTypes, value: ClearInt) -> PersistedValue {
        PersistedValue {
            ty,
            value,
            metadata: metadata(),
            bytes: vec![0xAB, 0xCD],
        }
    }

    #[test]
    fn test_protocol_random_ops_forced_chained_descriptions() {
        let values: Vec<PersistedValue> = ALL_TYPES
            .into_iter()
            .map(|ty| stored(ty, ClearInt::ZERO))
            .collect();
        let descriptions = forced_chained_descriptions(&values);
        assert_eq!(descriptions.len(), ALL_TYPES.len());
        for (desc, ty) in descriptions.iter().zip(ALL_TYPES) {
            let evaluation = evaluate_clear(desc, &RandValues::new())
                .unwrap_or_else(|e| panic!("chained {} transaction is invalid: {e}", ty.name()));
            assert_eq!(
                evaluation.input_signatures[0],
                format!("Input/{}/persisted", ty.name())
            );
        }
    }

    #[test]
    fn test_protocol_random_ops_persisted_pool() {
        let mut pool = PersistedPool::default();
        // Nothing to wait for until the lag is reached.
        assert!(pool.advance(PERSISTED_LAG - 1));
        // Then the transaction `index - PERSISTED_LAG` has to be complete.
        assert!(!pool.advance(PERSISTED_LAG));
        pool.complete(1, vec![stored(FheTypes::Uint8, ClearInt::ONE)]);
        assert!(!pool.advance(PERSISTED_LAG));
        pool.complete(0, vec![stored(FheTypes::Bool, ClearInt::ZERO)]);
        assert!(pool.advance(PERSISTED_LAG));
        assert_eq!(pool.values.len(), 1);
        // Outputs enter in transaction order, whatever order they completed in.
        assert!(pool.advance(PERSISTED_LAG + 1));
        assert_eq!(pool.values[0].ty, FheTypes::Bool);
        assert_eq!(pool.values[1].ty, FheTypes::Uint8);

        // The pool is bounded, the oldest values leave first.
        let many = vec![stored(FheTypes::Uint64, ClearInt::ONE); PERSISTED_POOL_SIZE];
        pool.complete(2, many);
        assert!(pool.advance(PERSISTED_LAG + 2));
        assert_eq!(pool.values.len(), PERSISTED_POOL_SIZE);
        assert!(pool.values.iter().all(|v| v.ty == FheTypes::Uint64));
    }

    #[test]
    fn test_protocol_random_ops_clear_oracle_rand() {
        // Without a recorded value, the validation pass, a rand node evaluates to a placeholder.
        let (ty, v) = last_int(vec![typed_node(
            OpKind::Rand,
            vec![Operand::Scalar(42)],
            FheTypes::Uint32,
        )]);
        assert_eq!((ty, v), (FheTypes::Uint32, ClearInt::ZERO));
        assert!(!last_bool(vec![typed_node(
            OpKind::Rand,
            vec![Operand::Scalar(42)],
            FheTypes::Bool,
        )]));

        // With a recorded value, the value flows into the pool and its range is checked against
        // the bound: 7 < 2^3 passes and feeds the next node, 8 does not.
        let bounded = desc(vec![
            typed_node(
                OpKind::RandBounded,
                vec![Operand::Scalar(42), Operand::Scalar(8)],
                FheTypes::Uint8,
            ),
            node(OpKind::Add, vec![Operand::Ct(2), Operand::Ct(0)]),
        ]);
        let values = |v: u128| RandValues::from([(0, RandValue::Int(ClearInt::from(v)))]);
        let eval = evaluate_clear(&bounded, &values(7)).unwrap();
        assert_eq!(eval.ints.last().unwrap().1.low(), 207);
        assert_eq!(eval.signatures[0], "RandBounded/u8/b3");
        assert!(evaluate_clear(&bounded, &values(8)).is_err());

        // A bound above the width is capped to it, like the executor caps the bit count.
        let over_width = desc(vec![typed_node(
            OpKind::RandBounded,
            vec![Operand::Scalar(42), Operand::Scalar(65536)],
            FheTypes::Uint8,
        )]);
        let eval = evaluate_clear(&over_width, &values(255)).unwrap();
        assert_eq!(eval.signatures[0], "RandBounded/u8/b8");

        // Rejections: a bound that is not a positive power of two, a bounded boolean, a U160
        // target, and a missing bound.
        let invalid = |nodes: Vec<Node>| evaluate_clear(&desc(nodes), &RandValues::new()).is_err();
        assert!(invalid(vec![typed_node(
            OpKind::RandBounded,
            vec![Operand::Scalar(42), Operand::Scalar(6)],
            FheTypes::Uint8,
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::RandBounded,
            vec![Operand::Scalar(42), Operand::Scalar(0)],
            FheTypes::Uint8,
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::RandBounded,
            vec![Operand::Scalar(42), Operand::Scalar(8)],
            FheTypes::Bool,
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::Rand,
            vec![Operand::Scalar(42)],
            FheTypes::Uint160,
        )]));
        assert!(invalid(vec![typed_node(
            OpKind::RandBounded,
            vec![Operand::Scalar(42)],
            FheTypes::Uint8,
        )]));

        // The range check behind it, across the limb boundary.
        let two_pow_128 = ClearInt::from((0, 1));
        assert!(ClearInt::from(u128::MAX).fits_bits(128));
        assert!(!two_pow_128.fits_bits(128));
        assert!(two_pow_128.fits_bits(129));
        assert!(!ClearInt::ONE.fits_bits(0));
        assert!(ClearInt::MAX.fits_bits(256));
    }

    #[test]
    fn test_protocol_random_ops_plain_ops_match_oracle() {
        let all_plain_ops: Vec<OpKind> = SMALL_INT_OPS
            .iter()
            .chain(U256_OPS.iter())
            .chain(U160_OPS.iter())
            .copied()
            .collect();
        for ty in ALL_TYPES {
            let drawn: &[OpKind] = if ty == FheTypes::Bool {
                &[]
            } else {
                plain_ops_for(ty)
            };
            for &op in &all_plain_ops {
                assert_eq!(
                    int_op_allowed(op, ty),
                    drawn.contains(&op),
                    "{op:?} on {}: the oracle and the generator tables disagree",
                    ty.name()
                );
            }
        }
    }

    #[test]
    fn test_protocol_random_ops_generator_and_report_roundtrip() {
        let mut datagen = RandomGenerator::<DefaultRandomGenerator>::new(Seed(42));
        // Stored values of every type, so the inputs taken from the pool are drawn too.
        let mut persisted = PersistedPool::default();
        let values = ALL_TYPES.into_iter().map(|ty| stored(ty, ClearInt::ONE));
        persisted.complete(0, values.collect());
        assert!(persisted.advance(PERSISTED_LAG));

        let mut signatures = std::collections::BTreeSet::new();
        for index in 0..1000 {
            let desc = draw_transaction(&mut datagen, &persisted);

            // Every drawn transaction is a valid description: the clear oracle accepts it.
            let evaluation = evaluate_clear(&desc, &RandValues::new())
                .unwrap_or_else(|e| panic!("drawn transaction {index} is invalid: {e}"));
            signatures.extend(evaluation.input_signatures);

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

        // Every type is drawn as a fresh input and as a stored one.
        for ty in ALL_TYPES {
            for source in ["fresh", "persisted"] {
                let signature = format!("Input/{}/{source}", ty.name());
                assert!(signatures.contains(&signature), "missing {signature}");
            }
        }
    }
}
