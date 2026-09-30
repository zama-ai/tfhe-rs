//! Types available in the HlApiDialect
use std::collections::HashMap;
use std::num::NonZeroU64;

use super::kinds::FheIntKind;
use crate::core_crypto::commons::math::random::XofSeed;
use crate::ReRandomizationHashAlgo;
use zhc_ir::DialectTypeSystem;

/// The different kinds of values flowing through an HlApiDialect IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValueKind {
    /// Encrypted unsigned integer with n bits
    FheUint(u32),
    /// Encrypted signed integer with n bits
    FheInt(u32),
    /// A boolean
    FheBool,
    /// A clear boolean
    Bool,
    /// A clear unsigned integer with n bits
    Uint(u32),
    /// A clear signed integer with n bits
    Int(u32),
    /// A KVStore is a sort of HashMap, it associates clear keys to encrypted values
    /// and allows to do queries using encrypted keys
    KVStore { key: KvKeyKind, value: FheIntKind },
    /// A clear, variable-length byte string used to seed OPRF ops.
    Seed,
}

/// Concrete clear Rust integer types currently accepted as KVStore keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KvKeyKind {
    U32,
    U64,
}

impl KvKeyKind {
    /// Returns the number of bits necessary
    pub fn bits(self) -> u32 {
        match self {
            Self::U32 => 32,
            Self::U64 => 64,
        }
    }
}

/// Clear key value carried in op payloads for KVStore ops that take a clear
/// key (e.g. `insert`, `remove`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KvKey {
    U32(u32),
    U64(u64),
}

impl KvKey {
    pub fn kind(&self) -> KvKeyKind {
        match self {
            Self::U32(_) => KvKeyKind::U32,
            Self::U64(_) => KvKeyKind::U64,
        }
    }

    /// Widen the variant to a `u128` bit-pattern. All variants are
    /// unsigned, so this is a plain zero-extension.
    pub fn as_u128(&self) -> u128 {
        match self {
            Self::U32(n) => *n as u128,
            Self::U64(n) => *n as u128,
        }
    }
}

impl From<u32> for KvKey {
    fn from(v: u32) -> Self {
        Self::U32(v)
    }
}

impl From<u64> for KvKey {
    fn from(v: u64) -> Self {
        Self::U64(v)
    }
}

/// A `f64` that is guaranteed not to be `NaN`.
///
/// Wraps `f64` so it can be used in `Hash` / `Eq` contexts — standard
/// `f64` can't implement `Eq` because `NaN != NaN` violates reflexivity.
///
/// Construct via [`NonNanF64::new`], which returns `Err` on `NaN`.
/// The constructor also normalises `-0.0` to `0.0` so that the `Hash`/`Eq`
/// contract holds, as `-0.0.eq(0.0) == true` however their byte representation
/// is not the same.
#[derive(Debug, Clone, Copy)]
pub struct NonNanF64(f64);

/// Error returned by [`NonNanF64::new`] when the input is `NaN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotANumberError;

impl std::fmt::Display for NotANumberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "value must not be NaN")
    }
}

impl std::error::Error for NotANumberError {}

impl NonNanF64 {
    /// Wrap a `f64`.
    ///
    /// Returns `Err(NotANumberError)` if the value is `NaN`.
    ///
    /// `-0.0` is normalised to `0.0` so the `Hash`/`Eq` contract holds.
    pub fn new(v: f64) -> Result<Self, NotANumberError> {
        if v.is_nan() {
            Err(NotANumberError)
        } else if v == 0.0 {
            // Collapse `-0.0` and `0.0` to a single canonical bit pattern,
            // so `Eq` (via IEEE `==`) and `Hash` (via `to_bits()`) agree
            // for every value reachable here.
            Ok(Self(0.0))
        } else {
            Ok(Self(v))
        }
    }

    /// Extract the inner `f64`.
    pub fn get(self) -> f64 {
        self.0
    }
}

impl PartialEq for NonNanF64 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// Safe because we reject NaN at construction time
impl Eq for NonNanF64 {}

impl std::hash::Hash for NonNanF64 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

/// Mode parameter for the `FheOprf` op family — selects what distribution
/// the generated random ciphertext is drawn from.
///
/// Validity is enforced by the builder:
/// - `Full`: any of `FheUint`, `FheInt`, `FheBool`.
/// - `Bounded`: `FheUint` or `FheInt`. Rejected on `FheBool`.
/// - `CustomRange`: `FheUint` only. Rejected on `FheInt` and `FheBool`.
///
/// `max_distance` is wrapped in [`NonNanF64`] so the enum can `derive` the
/// usual traits (`Hash`/`Eq`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum OprfMode {
    /// Full-range uniform.
    Full,
    /// Uniform in `[0, 2^bits)`.
    Bounded { bits: u64 },
    /// Almost-uniform in `[0, upper)`. `max_distance` controls the bias
    /// budget; `None` defaults to `2^-128` at execution time (matches HL).
    CustomRange {
        upper: NonZeroU64,
        max_distance: Option<NonNanF64>,
    },
}

impl OprfMode {
    /// Short display name, used in error messages (`InvalidOprfMode`).
    pub fn name(&self) -> &'static str {
        self.into()
    }
}

/// The config used for all re-randomizations of a graph execution
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReRandomizationConfig {
    pub algo: ReRandomizationHashAlgo,
    pub rerand_seeder_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
    pub public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
}

/// Function description fed to a re-randomization context.
///
/// The parts are concatenated in order. A `ReRand` op's full description is
/// 1) its static part (given to the builder)
/// 2) its runtime part (given in the [`ReRandomizationParams`] of an execution).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReRandomizationFnDescription {
    pub fn_description: Vec<Vec<u8>>,
}

impl ReRandomizationFnDescription {
    pub fn new<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Self {
        Self {
            fn_description: parts.into_iter().map(<[u8]>::to_vec).collect(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.fn_description.iter().map(Vec::as_slice)
    }
}

/// Identifies a `ReRand` op of a graph, returned by
/// [`ExecutionGraphBuilder::rerand`](super::ExecutionGraphBuilder::rerand).
///
/// Slots are allocated in order (`0..graph.n_rerand_slots()`), so building
/// the same graph in the same order gives the same slots.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ReRandSlot(pub(super) u32);

impl std::fmt::Display for ReRandSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "re-rand slot {}", self.0)
    }
}

/// Runtime re-randomization params of a graph
///
/// The config shared by all `ReRand` ops and the runtime part of each op's function description.
///
/// By default, every slot of the graph must be given a runtime description
/// (possibly empty), see [`Self::with_missing_slots_as_empty`] to relax this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReRandomizationParams {
    config: ReRandomizationConfig,
    runtime_descriptions: HashMap<ReRandSlot, ReRandomizationFnDescription>,
    missing_slots_as_empty: bool,
}

impl ReRandomizationParams {
    pub fn new(config: ReRandomizationConfig) -> Self {
        Self {
            config,
            runtime_descriptions: HashMap::new(),
            missing_slots_as_empty: false,
        }
    }

    /// Slots without a runtime description use an empty one instead of
    /// making the execution fail.
    pub fn with_missing_slots_as_empty(mut self) -> Self {
        self.missing_slots_as_empty = true;
        self
    }

    pub fn config(&self) -> &ReRandomizationConfig {
        &self.config
    }

    /// Sets the runtime part of the function description of `slot`.
    ///
    /// `runtime_description` is stored as is (it may be empty), the parts
    /// are concatenated in order.
    ///
    /// Returns an error if `slot` already has one.
    pub fn insert<'a>(
        &mut self,
        slot: ReRandSlot,
        runtime_description: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<&mut Self, ReRandParamsError> {
        match self.runtime_descriptions.entry(slot) {
            std::collections::hash_map::Entry::Occupied(_) => {
                Err(ReRandParamsError::DuplicateSlot(slot))
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(ReRandomizationFnDescription::new(runtime_description));
                Ok(self)
            }
        }
    }

    /// The runtime description of `slot`, `None` if it was not given.
    pub fn runtime_description(&self, slot: ReRandSlot) -> Option<&ReRandomizationFnDescription> {
        self.runtime_descriptions.get(&slot)
    }

    /// Checks these params against a graph having `n_slots` slots.
    pub(super) fn check_slots(&self, n_slots: u32) -> Result<(), ReRandParamsError> {
        if let Some(&slot) = self
            .runtime_descriptions
            .keys()
            .filter(|slot| slot.0 >= n_slots)
            .min()
        {
            return Err(ReRandParamsError::UnknownSlot(slot));
        }
        if !self.missing_slots_as_empty {
            if let Some(slot) = (0..n_slots)
                .map(ReRandSlot)
                .find(|slot| !self.runtime_descriptions.contains_key(slot))
            {
                return Err(ReRandParamsError::MissingSlot(slot));
            }
        }
        Ok(())
    }
}

/// Mismatch between a graph's re-randomizations and the
/// [`ReRandomizationParams`] given for an execution.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReRandParamsError {
    /// The graph contains `ReRand` ops but no params were given.
    MissingParams,
    /// The slot has no runtime description, and missing ones are not allowed.
    MissingSlot(ReRandSlot),
    /// A runtime description was given for a slot the graph does not have.
    UnknownSlot(ReRandSlot),
    /// A runtime description was given twice for the same slot.
    DuplicateSlot(ReRandSlot),
}

impl std::fmt::Display for ReRandParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingParams => write!(
                f,
                "the graph contains re-randomizations but no re-randomization params were given"
            ),
            Self::MissingSlot(slot) => write!(f, "no runtime description given for {slot}"),
            Self::UnknownSlot(slot) => {
                write!(
                    f,
                    "runtime description given for {slot}, which the graph does not have"
                )
            }
            Self::DuplicateSlot(slot) => {
                write!(f, "runtime description given twice for {slot}")
            }
        }
    }
}

impl std::error::Error for ReRandParamsError {}

impl std::fmt::Display for ValueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl DialectTypeSystem for ValueKind {}

/// Clear scalar carried in op payloads for `*Scalar*` op variants.
// TODO We will likely need variants with some kind of BigInt to allow more than 128 bits scalar
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScalarValue {
    Bool(bool),
    Unsigned(u128),
    Signed(i128),
}

impl From<bool> for ScalarValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

macro_rules! impl_scalar_from_unsigned {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for ScalarValue {
                fn from(v: $ty) -> Self {
                    Self::Unsigned(u128::from(v))
                }
            }
        )*
    };
}
impl_scalar_from_unsigned!(u8, u16, u32, u64, u128);

macro_rules! impl_scalar_from_signed {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for ScalarValue {
                fn from(v: $ty) -> Self {
                    Self::Signed(i128::from(v))
                }
            }
        )*
    };
}
impl_scalar_from_signed!(i8, i16, i32, i64, i128);

impl ScalarValue {
    /// Normalize the scalar for a target `kind`, returning the (possibly
    /// rewritten) value if it fits.
    ///
    /// By default, unsuffixed literals are signed, things like `build.fhe_add(some_fhe_uint, 42)`
    /// compiles, but would create a runtime error because the ScalarValue of the literal would be
    /// Signed, which is not of the same signedness as some_fhe_uint.
    /// To improve the user experience, we 'normalize' such that we re-assign the variant to match
    /// a given kind if it is possible.
    /// In the `build.fhe_add(some_fhe_uint, 42)`, 42 would be reassigned to Unsigned, making the
    /// code run properly
    pub fn normalize_for(self, kind: ValueKind) -> Option<Self> {
        match (self, kind) {
            // Same-signedness fits — pass through. FHE and clear targets share
            // the same fit rules — only the bit-width matters for normalization.
            (s @ Self::Bool(_), ValueKind::FheBool | ValueKind::Bool) => Some(s),
            (s @ Self::Unsigned(v), ValueKind::FheUint(bits) | ValueKind::Uint(bits))
                if unsigned_fits_bits(v, bits) =>
            {
                Some(s)
            }
            (s @ Self::Signed(v), ValueKind::FheInt(bits) | ValueKind::Int(bits))
                if signed_fits_bits(v, bits) =>
            {
                Some(s)
            }

            // Cross-sign rewrite: non-negative Signed → Unsigned for FheUint(_) / Uint(_).
            (Self::Signed(v), ValueKind::FheUint(bits) | ValueKind::Uint(bits))
                if v >= 0 && unsigned_fits_bits(v as u128, bits) =>
            {
                Some(Self::Unsigned(v as u128))
            }
            // Cross-sign rewrite: Unsigned within i128 range → Signed for FheInt(_) / Int(_).
            (Self::Unsigned(v), ValueKind::FheInt(bits) | ValueKind::Int(bits))
                if v <= i128::MAX as u128 && signed_fits_bits(v as i128, bits) =>
            {
                Some(Self::Signed(v as i128))
            }
            _ => None,
        }
    }
}

/// Does the `value` fit in an unsigned type that has `bits` bits?
fn unsigned_fits_bits(value: u128, bits: u32) -> bool {
    match bits {
        0 => false,
        128.. => true,
        _ => value < (1u128 << bits),
    }
}

/// Does the `value` fit in a signed type that has `bits` bits?
fn signed_fits_bits(value: i128, bits: u32) -> bool {
    match bits {
        0 => false,
        128.. => true,
        _ => {
            let min = -(1i128 << (bits - 1));
            let max = (1i128 << (bits - 1)) - 1;
            (min..=max).contains(&value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_fits_bits_edges() {
        assert!(!signed_fits_bits(0, 0));
        // 1 bit: only -1 and 0 are representable.
        assert!(signed_fits_bits(-1, 1));
        assert!(signed_fits_bits(0, 1));
        assert!(!signed_fits_bits(1, 1));
        assert!(!signed_fits_bits(-2, 1));
        // 8 bits.
        assert!(signed_fits_bits(i128::from(i8::MIN), 8));
        assert!(signed_fits_bits(i128::from(i8::MAX), 8));
        assert!(!signed_fits_bits(i128::from(i8::MAX) + 1, 8));
        assert!(!signed_fits_bits(i128::from(i8::MIN) - 1, 8));
        // >= 128 bits: everything fits.
        assert!(signed_fits_bits(i128::MIN, 128));
        assert!(signed_fits_bits(i128::MAX, 200));
    }

    #[test]
    fn unsigned_fits_bits_edges() {
        assert!(!unsigned_fits_bits(0, 0));
        assert!(unsigned_fits_bits(1, 1));
        assert!(!unsigned_fits_bits(2, 1));
        assert!(unsigned_fits_bits(u128::from(u8::MAX), 8));
        assert!(!unsigned_fits_bits(u128::from(u8::MAX) + 1, 8));
        assert!(unsigned_fits_bits(u128::MAX, 128));
    }
}
