//! Types available in the HlApiDialect
use std::num::NonZeroU64;

use super::kinds::FheIntKind;
use zhc_ir::DialectTypeSystem;

/// The different kinds of values flowing through an HlApiDialect IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValueKind {
    /// Encrypted unsigned integer with n bits
    FheUint(usize),
    /// Encrypted signed integer with n bits
    FheInt(usize),
    /// A boolean
    FheBool,
    /// A clear boolean
    Bool,
    /// A clear unsigned integer with n bits
    Uint(usize),
    /// A clear signed integer with n bits
    Int(usize),
    /// A Compressed ciphertext list
    CompressedList,
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
    pub fn bits(self) -> usize {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        match self {
            Self::Full => "Full",
            Self::Bounded { .. } => "Bounded",
            Self::CustomRange { .. } => "CustomRange",
        }
    }
}

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
fn unsigned_fits_bits(value: u128, bits: usize) -> bool {
    match bits {
        0 => false,
        128.. => true,
        _ => value < (1u128 << bits),
    }
}

/// Does the `value` fit in a signed type that has `bits` bits?
fn signed_fits_bits(value: i128, bits: usize) -> bool {
    match bits {
        0 => false,
        1 => (-1..=0).contains(&value),
        128.. => true,
        _ => {
            let min = -(1i128 << (bits - 1));
            let max = (1i128 << (bits - 1)) - 1;
            (min..=max).contains(&value)
        }
    }
}
