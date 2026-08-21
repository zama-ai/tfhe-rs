//! Runtime value types for the CPU backend: [`RuntimeValue`] and its
//! conversion impls, plus the input/output list wrappers used by callers.

use crate::circuit::{FheIntKind, KvKeyKind, ScalarValue, ValueKind};
use crate::high_level_api::kv_store::KVStore as HlKVStore;
use crate::integer::prelude::*;
use crate::integer::server_key::KVStore;
use crate::integer::{BooleanBlock, RadixCiphertext, SignedRadixCiphertext};
use crate::{
    CompressedCiphertextList, FheBool, FheInt, FheIntId, FheUint, FheUintId,
    ReRandomizationMetadata, Tag,
};

/// Possible runtime values to execute an HLAPI dialect program
#[derive(Clone)]
pub enum RuntimeValue {
    ClearBool(bool),
    /// Clear unsigned integer. Carries a `u128` to fit any `Uint(N)` width
    /// the producing op's `kind` carries the actual `N`.
    ClearUint(u128),
    /// Clear signed integer. Carries an `i128` to fit any `Int(N)` width
    /// the producing op's `kind` carries the actual `N`.
    ClearInt(i128),
    FheBool(BooleanBlock),
    FheUint(RadixCiphertext),
    FheInt(SignedRadixCiphertext),
    FheUintKVStore(KVStore<u128, RadixCiphertext>),
    FheIntKVStore(KVStore<u128, SignedRadixCiphertext>),
    CompressedList(CompressedCiphertextList),
    /// Clear OPRF seed bytes
    Seed(Vec<u8>),
}

impl RuntimeValue {
    /// Recover the clear [`ScalarValue`] payload from a clear `RuntimeValue`
    /// (`ClearBool`/`ClearUint`/`ClearInt`).  
    ///
    /// Panics on any non-clear variant, however this is called in contexts where
    /// the variant has to be a clear value, because dialect signature guarantees a
    /// clear operand in this position at IR-construction time
    pub(super) fn as_clear_scalar(&self) -> ScalarValue {
        match self {
            Self::ClearBool(v) => ScalarValue::Bool(*v),
            Self::ClearUint(v) => ScalarValue::Unsigned(*v),
            Self::ClearInt(v) => ScalarValue::Signed(*v),
            _ => panic!("expected a clear operand as scalar input, got {self:?}"),
        }
    }

    /// Validate this value against a circuit input's declared `expected` kind,
    /// as the `input_index`-th input.
    pub(in crate::high_level_api::circuit::backends) fn check_input(
        &self,
        input_index: usize,
        expected: &ValueKind,
        sks: &crate::integer::ServerKey,
    ) -> Result<(), super::CpuError> {
        let message_modulus = sks.message_modulus();
        let carry_modulus = sks.carry_modulus();
        let bits_per_block = message_modulus.0.ilog2() as usize;

        // 1. Parameter compatibility.
        let check_blocks_params = |blocks: &[crate::shortint::Ciphertext]| {
            blocks
                .iter()
                .find(|b| b.message_modulus != message_modulus || b.carry_modulus != carry_modulus)
                .map_or(Ok(()), |b| {
                    Err(super::CpuError::InputParamsMismatch {
                        input_index,
                        expected_message_modulus: message_modulus,
                        expected_carry_modulus: carry_modulus,
                        got_message_modulus: b.message_modulus,
                        got_carry_modulus: b.carry_modulus,
                    })
                })
        };
        match self {
            Self::FheBool(b) => check_blocks_params(std::slice::from_ref(&b.0))?,
            Self::FheUint(radix) => check_blocks_params(radix.blocks())?,
            Self::FheInt(radix) => check_blocks_params(radix.blocks())?,
            Self::FheUintKVStore(kv) => {
                for (_, v) in kv.iter() {
                    check_blocks_params(v.blocks())?;
                }
            }
            Self::FheIntKVStore(kv) => {
                for (_, v) in kv.iter() {
                    check_blocks_params(v.blocks())?;
                }
            }
            // Clear values and seeds carry no parameters; a CompressedList
            // embeds its own and is validated by the decompression key
            // when unpacked.
            Self::ClearBool(_)
            | Self::ClearUint(_)
            | Self::ClearInt(_)
            | Self::CompressedList(_)
            | Self::Seed(_) => {}
        }

        // 2. Kind compatibility.
        let got = match self {
            Self::ClearBool(_) => ValueKind::Bool,
            // Clear integers carry no declared width: report the minimal
            // width that holds the value.
            Self::ClearUint(v) => ValueKind::Uint((128 - v.leading_zeros()).max(1) as usize),
            Self::ClearInt(v) => {
                let magnitude_bits = if *v < 0 {
                    128 - v.leading_ones()
                } else {
                    128 - v.leading_zeros()
                };
                ValueKind::Int((magnitude_bits + 1) as usize)
            }
            Self::FheBool(_) => ValueKind::FheBool,
            Self::FheUint(radix) => ValueKind::FheUint(radix.blocks().len() * bits_per_block),
            Self::FheInt(radix) => ValueKind::FheInt(radix.blocks().len() * bits_per_block),
            Self::CompressedList(_) => ValueKind::CompressedList,
            Self::Seed(_) => ValueKind::Seed,
            // A store's key kind is not observable from its runtime keys
            // (they are stored widened to u128) and an empty store has no
            // observable value width (0 stands for "empty" below). KVStore
            // is not a tier-1 type yet, so these approximations in error
            // reports are acceptable.
            Self::FheUintKVStore(kv) => ValueKind::KVStore {
                key: KvKeyKind::U32,
                value: FheIntKind::Uint(
                    kv.blocks_per_radix()
                        .map_or(0, |n| (n.get() * bits_per_block) as u32),
                ),
            },
            Self::FheIntKVStore(kv) => ValueKind::KVStore {
                key: KvKeyKind::U32,
                value: FheIntKind::Int(
                    kv.blocks_per_radix()
                        .map_or(0, |n| (n.get() * bits_per_block) as u32),
                ),
            },
        };
        let kind_ok = match (got, *expected) {
            // The minimal observed width fits any at-least-as-wide
            // declaration.
            (ValueKind::Uint(g), ValueKind::Uint(e)) | (ValueKind::Int(g), ValueKind::Int(e)) => {
                g <= e
            }
            // Key kinds are not observable (checked value-wise in stage 3);
            // a value width of 0 means the store is empty and fits any
            // declared width.
            (
                ValueKind::KVStore {
                    value: FheIntKind::Uint(g),
                    ..
                },
                ValueKind::KVStore {
                    value: FheIntKind::Uint(e),
                    ..
                },
            )
            | (
                ValueKind::KVStore {
                    value: FheIntKind::Int(g),
                    ..
                },
                ValueKind::KVStore {
                    value: FheIntKind::Int(e),
                    ..
                },
            ) => g == 0 || g == e,
            _ => got == *expected,
        };
        if !kind_ok {
            return Err(super::CpuError::InputTypeMismatch {
                input_index,
                expected: *expected,
                got,
            });
        }

        // 3. Every store key must fit the declared key kind.
        let check_store_keys = |keys: &mut dyn Iterator<Item = u128>, key_kind: KvKeyKind| {
            let key_bits = key_kind.bits();
            for key in keys {
                if key_bits < 128 && (key >> key_bits) != 0 {
                    return Err(super::CpuError::InputValueOutOfRange {
                        input_index,
                        expected: *expected,
                        value: ScalarValue::Unsigned(key),
                    });
                }
            }
            Ok(())
        };
        match (self, expected) {
            (Self::FheUintKVStore(kv), ValueKind::KVStore { key, .. }) => {
                check_store_keys(&mut kv.iter().map(|(k, _)| *k), *key)?;
            }
            (Self::FheIntKVStore(kv), ValueKind::KVStore { key, .. }) => {
                check_store_keys(&mut kv.iter().map(|(k, _)| *k), *key)?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl std::fmt::Debug for RuntimeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FheBool(v) => match v.decrypt_trivial() {
                Ok(val) => write!(f, "RuntimeValue::FheBool({val})"),
                Err(_) => write!(f, "RuntimeValue::FheBool(<encrypted>)"),
            },
            Self::ClearBool(v) => write!(f, "RuntimeValue::ClearBool({v})"),
            Self::ClearUint(v) => write!(f, "RuntimeValue::ClearUint({v})"),
            Self::ClearInt(v) => write!(f, "RuntimeValue::ClearInt({v})"),
            Self::FheUint(v) => match v.decrypt_trivial::<u128>() {
                Ok(val) => write!(f, "RuntimeValue::FheUint({val})"),
                Err(_) => write!(f, "RuntimeValue::FheUint(<encrypted>)"),
            },
            Self::FheInt(v) => match v.decrypt_trivial::<i128>() {
                Ok(val) => write!(f, "RuntimeValue::FheInt({val})"),
                Err(_) => write!(f, "RuntimeValue::FheInt(<encrypted>)"),
            },
            Self::CompressedList(_) => write!(f, "RuntimeValue::CompressedList(?)"),
            Self::FheUintKVStore(kv) => {
                write!(f, "RuntimeValue::FheUintKVStore(<{} entries>)", kv.len())
            }
            Self::FheIntKVStore(kv) => {
                write!(f, "RuntimeValue::FheIntKVStore(<{} entries>)", kv.len())
            }
            Self::Seed(bytes) => write!(f, "RuntimeValue::Seed(<{}B>)", bytes.len()),
        }
    }
}

impl From<bool> for RuntimeValue {
    fn from(v: bool) -> Self {
        Self::ClearBool(v)
    }
}

macro_rules! impl_exec_value_from_unsigned {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for RuntimeValue {
                fn from(v: $ty) -> Self {
                    Self::ClearUint(u128::from(v))
                }
            }
        )*
    };
}
impl_exec_value_from_unsigned!(u8, u16, u32, u64, u128);

macro_rules! impl_exec_value_from_signed {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for RuntimeValue {
                fn from(v: $ty) -> Self {
                    Self::ClearInt(i128::from(v))
                }
            }
        )*
    };
}
impl_exec_value_from_signed!(i8, i16, i32, i64, i128);

/// Failure of `TryFrom<RuntimeValue>` for one of the output types (`FheUint<Id>`,
/// `FheInt<Id>`, `FheBool`, `CompressedCiphertextList`, and clear scalars).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeValueConversionError {
    /// The `RuntimeValue` variant doesn't match the requested type.
    /// `expected_variant` is a short tag for the destination type
    /// (e.g. `"FheUint"`, `"FheBool"`).
    WrongVariant { expected_variant: &'static str },
    /// Radix block count doesn't match the target `FheUintId` / `FheIntId`
    /// for the active `message_modulus`.
    BlockCountMismatch {
        type_name: &'static str,
        expected_blocks: usize,
        expected_bits: usize,
        actual_blocks: usize,
    },
    /// Radix ciphertext is empty — defensive, shouldn't happen in well-formed
    /// programs
    EmptyRadix,
    /// A retrieved KVStore contains a key that does not fit the requested
    /// clear key type.
    KvKeyOutOfRange { key: u128 },
    /// A clear integer output does not fit the requested Rust integer type.
    ClearIntegerOutOfRange {
        value: ScalarValue,
        type_name: &'static str,
    },
}

impl std::fmt::Display for RuntimeValueConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongVariant { expected_variant } => {
                write!(f, "RuntimeValue is not a {expected_variant}")
            }
            Self::EmptyRadix => write!(f, "RuntimeValue radix has no blocks"),
            Self::BlockCountMismatch {
                type_name,
                expected_blocks,
                expected_bits,
                actual_blocks,
            } => write!(
                f,
                "RuntimeValue block count mismatch for {type_name}: \
                 expected {expected_blocks} blocks ({expected_bits} bits), got {actual_blocks}"
            ),
            Self::KvKeyOutOfRange { key } => write!(
                f,
                "KVStore key {key} does not fit the requested clear key type"
            ),
            Self::ClearIntegerOutOfRange { value, type_name } => {
                write!(f, "clear integer {value:?} does not fit {type_name}")
            }
        }
    }
}

impl std::error::Error for RuntimeValueConversionError {}

impl TryFrom<RuntimeValue> for bool {
    type Error = RuntimeValueConversionError;
    fn try_from(value: RuntimeValue) -> Result<Self, Self::Error> {
        match value {
            RuntimeValue::ClearBool(v) => Ok(v),
            _ => Err(RuntimeValueConversionError::WrongVariant {
                expected_variant: "bool",
            }),
        }
    }
}

macro_rules! impl_clear_unsigned_try_from {
    ($($ty:ty),*) => {
        $(
            impl TryFrom<RuntimeValue> for $ty {
                type Error = RuntimeValueConversionError;

                fn try_from(value: RuntimeValue) -> Result<Self, Self::Error> {
                    match value {
                        RuntimeValue::ClearUint(value) => <$ty>::try_from(value).map_err(|_| {
                            RuntimeValueConversionError::ClearIntegerOutOfRange {
                                value: ScalarValue::Unsigned(value),
                                type_name: std::any::type_name::<$ty>(),
                            }
                        }),
                        _ => Err(RuntimeValueConversionError::WrongVariant {
                            expected_variant: "ClearUint",
                        }),
                    }
                }
            }
        )*
    };
}
impl_clear_unsigned_try_from!(u8, u16, u32, u64, u128);

macro_rules! impl_clear_signed_try_from {
    ($($ty:ty),*) => {
        $(
            impl TryFrom<RuntimeValue> for $ty {
                type Error = RuntimeValueConversionError;

                fn try_from(value: RuntimeValue) -> Result<Self, Self::Error> {
                    match value {
                        RuntimeValue::ClearInt(value) => <$ty>::try_from(value).map_err(|_| {
                            RuntimeValueConversionError::ClearIntegerOutOfRange {
                                value: ScalarValue::Signed(value),
                                type_name: std::any::type_name::<$ty>(),
                            }
                        }),
                        _ => Err(RuntimeValueConversionError::WrongVariant {
                            expected_variant: "ClearInt",
                        }),
                    }
                }
            }
        )*
    };
}
impl_clear_signed_try_from!(i8, i16, i32, i64, i128);

impl<Id: FheUintId> From<FheUint<Id>> for RuntimeValue {
    fn from(value: FheUint<Id>) -> Self {
        Self::FheUint(value.into_raw_parts().0)
    }
}

impl<Id> TryFrom<RuntimeValue> for FheUint<Id>
where
    Id: FheUintId,
{
    type Error = RuntimeValueConversionError;

    fn try_from(value: RuntimeValue) -> Result<Self, Self::Error> {
        match value {
            RuntimeValue::FheUint(radix) => {
                let message_modulus = radix
                    .blocks()
                    .first()
                    .ok_or(RuntimeValueConversionError::EmptyRadix)?
                    .message_modulus;
                let expected_blocks = Id::num_blocks(message_modulus);
                let actual_blocks = radix.blocks().len();
                if actual_blocks != expected_blocks {
                    return Err(RuntimeValueConversionError::BlockCountMismatch {
                        type_name: std::any::type_name::<Id>(),
                        expected_blocks,
                        expected_bits: Id::num_bits(),
                        actual_blocks,
                    });
                }
                Ok(Self::from_raw_parts(
                    radix,
                    Id::default(),
                    Tag::default(),
                    ReRandomizationMetadata::default(),
                ))
            }
            _ => Err(RuntimeValueConversionError::WrongVariant {
                expected_variant: "FheUint",
            }),
        }
    }
}

impl TryFrom<RuntimeValue> for CompressedCiphertextList {
    type Error = RuntimeValueConversionError;

    fn try_from(value: RuntimeValue) -> Result<Self, Self::Error> {
        if let RuntimeValue::CompressedList(list) = value {
            Ok(list)
        } else {
            Err(RuntimeValueConversionError::WrongVariant {
                expected_variant: "CompressedCiphertextList",
            })
        }
    }
}

impl From<FheBool> for RuntimeValue {
    fn from(value: FheBool) -> Self {
        let ct = value.into_raw_parts();
        Self::FheBool(BooleanBlock::new_unchecked(ct))
    }
}

impl TryFrom<RuntimeValue> for FheBool {
    type Error = RuntimeValueConversionError;

    fn try_from(value: RuntimeValue) -> Result<Self, Self::Error> {
        match value {
            RuntimeValue::FheBool(block) => Ok(Self::new(
                block,
                Tag::default(),
                ReRandomizationMetadata::default(),
            )),
            _ => Err(RuntimeValueConversionError::WrongVariant {
                expected_variant: "FheBool",
            }),
        }
    }
}

impl From<RadixCiphertext> for RuntimeValue {
    fn from(value: RadixCiphertext) -> Self {
        Self::FheUint(value)
    }
}

impl From<BooleanBlock> for RuntimeValue {
    fn from(value: BooleanBlock) -> Self {
        Self::FheBool(value)
    }
}

impl From<CompressedCiphertextList> for RuntimeValue {
    fn from(value: CompressedCiphertextList) -> Self {
        Self::CompressedList(value)
    }
}

/// Widen a store's clear keys to the `u128` representation used inside
/// [`RuntimeValue`].
fn kv_store_widen_keys<Key, Ct>(inner: KVStore<Key, Ct>) -> KVStore<u128, Ct>
where
    Key: Into<u128> + Ord,
    Ct: IntegerRadixCiphertext,
{
    let mut converted = KVStore::new();
    for (k, v) in inner {
        converted.insert(k.into(), v);
    }
    converted
}

/// Shared body of the KVStore `TryFrom<RuntimeValue>` impls: validate the
/// stored values' width against the target integer type (all values in a
/// store share one block count, so checking any entry is enough — an empty
/// store fits any width), then narrow the keys to `Key`.
fn kv_store_narrow_keys<Key, Ct>(
    store: KVStore<u128, Ct>,
    type_name: &'static str,
    expected_blocks_of: impl Fn(crate::shortint::MessageModulus) -> usize,
    expected_bits: usize,
) -> Result<KVStore<Key, Ct>, RuntimeValueConversionError>
where
    Key: TryFrom<u128> + Ord,
    Ct: IntegerRadixCiphertext,
{
    if let Some((_, v)) = store.iter().next() {
        let message_modulus = v
            .blocks()
            .first()
            .ok_or(RuntimeValueConversionError::EmptyRadix)?
            .message_modulus;
        let expected_blocks = expected_blocks_of(message_modulus);
        let actual_blocks = v.blocks().len();
        if actual_blocks != expected_blocks {
            return Err(RuntimeValueConversionError::BlockCountMismatch {
                type_name,
                expected_blocks,
                expected_bits,
                actual_blocks,
            });
        }
    }
    let mut out = KVStore::new();
    for (k, v) in store {
        let key = Key::try_from(k)
            .map_err(|_| RuntimeValueConversionError::KvKeyOutOfRange { key: k })?;
        out.insert(key, v);
    }
    Ok(out)
}

/// Lets a [`KVStore`](crate::KVStore) (e.g. one retrieved from a previous
/// execution via [`CpuOutputList::try_get`]) be supplied through
/// [`CpuInputList::push`] for a circuit input declared as
/// `ValueKind::KVStore`.
///
/// A GPU-resident store is copied back to the CPU first, which (like other
/// KVStore operations) requires a cuda server key to be set and panics
/// otherwise.
impl<Key, Id> From<HlKVStore<Key, FheUint<Id>>> for RuntimeValue
where
    Key: Clone + Into<u128> + Ord,
    Id: FheUintId,
{
    fn from(store: HlKVStore<Key, FheUint<Id>>) -> Self {
        Self::FheUintKVStore(kv_store_widen_keys(store.into_cpu_inner()))
    }
}

/// See the `From<KVStore<Key, FheUint<Id>>>` impl.
impl<Key, Id> From<HlKVStore<Key, FheInt<Id>>> for RuntimeValue
where
    Key: Clone + Into<u128> + Ord,
    Id: FheIntId,
{
    fn from(store: HlKVStore<Key, FheInt<Id>>) -> Self {
        Self::FheIntKVStore(kv_store_widen_keys(store.into_cpu_inner()))
    }
}

impl From<SignedRadixCiphertext> for RuntimeValue {
    fn from(value: SignedRadixCiphertext) -> Self {
        Self::FheInt(value)
    }
}

impl<Id: FheIntId> From<FheInt<Id>> for RuntimeValue {
    fn from(value: FheInt<Id>) -> Self {
        Self::FheInt(value.into_raw_parts().0)
    }
}

impl<Id> TryFrom<RuntimeValue> for FheInt<Id>
where
    Id: FheIntId,
{
    type Error = RuntimeValueConversionError;

    fn try_from(value: RuntimeValue) -> Result<Self, Self::Error> {
        match value {
            RuntimeValue::FheInt(radix) => {
                let message_modulus = radix
                    .blocks()
                    .first()
                    .ok_or(RuntimeValueConversionError::EmptyRadix)?
                    .message_modulus;
                let expected_blocks = Id::num_blocks(message_modulus);
                let actual_blocks = radix.blocks().len();
                if actual_blocks != expected_blocks {
                    return Err(RuntimeValueConversionError::BlockCountMismatch {
                        type_name: std::any::type_name::<Id>(),
                        expected_blocks,
                        expected_bits: Id::num_bits(),
                        actual_blocks,
                    });
                }
                Ok(Self::from_raw_parts(
                    radix,
                    Id::default(),
                    Tag::default(),
                    ReRandomizationMetadata::default(),
                ))
            }
            _ => Err(RuntimeValueConversionError::WrongVariant {
                expected_variant: "FheInt",
            }),
        }
    }
}

/// Retrieval counterpart of the `From<KVStore>` input conversion, used via
/// [`CpuOutputList::try_get`] (the store is `Tagged`, so retrieval stamps
/// the executing key's tag on it). The values *inside* the store carry no
/// tag (stores drop value tags, like the classic HLAPI KVStore).
impl<Key, Id> TryFrom<RuntimeValue> for HlKVStore<Key, FheUint<Id>>
where
    Key: TryFrom<u128> + Ord,
    Id: FheUintId,
{
    type Error = RuntimeValueConversionError;

    fn try_from(value: RuntimeValue) -> Result<Self, Self::Error> {
        match value {
            RuntimeValue::FheUintKVStore(store) => {
                let inner = kv_store_narrow_keys(
                    store,
                    std::any::type_name::<Id>(),
                    Id::num_blocks,
                    Id::num_bits(),
                )?;
                Ok(Self::from_cpu_inner(inner))
            }
            _ => Err(RuntimeValueConversionError::WrongVariant {
                expected_variant: "FheUintKVStore",
            }),
        }
    }
}

/// See the `TryFrom<RuntimeValue>` impl for `KVStore<Key, FheUint<Id>>`.
impl<Key, Id> TryFrom<RuntimeValue> for HlKVStore<Key, FheInt<Id>>
where
    Key: TryFrom<u128> + Ord,
    Id: FheIntId,
{
    type Error = RuntimeValueConversionError;

    fn try_from(value: RuntimeValue) -> Result<Self, Self::Error> {
        match value {
            RuntimeValue::FheIntKVStore(store) => {
                let inner = kv_store_narrow_keys(
                    store,
                    std::any::type_name::<Id>(),
                    Id::num_blocks,
                    Id::num_bits(),
                )?;
                Ok(Self::from_cpu_inner(inner))
            }
            _ => Err(RuntimeValueConversionError::WrongVariant {
                expected_variant: "FheIntKVStore",
            }),
        }
    }
}

#[derive(Clone)]
pub struct CpuInputList {
    pub inputs: Vec<RuntimeValue>,
}

impl CpuInputList {
    pub fn new() -> Self {
        Self { inputs: vec![] }
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<RuntimeValue>,
    {
        self.inputs.push(value.into());
        self
    }

    /// Push an OPRF seed input.
    pub fn push_seed(&mut self, seed: impl crate::shortint::OprfSeed) -> &mut Self {
        self.inputs.push(RuntimeValue::Seed(seed.to_vec()));
        self
    }
}

impl Default for CpuInputList {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct CpuOutputList {
    pub(crate) outputs: Vec<RuntimeValue>,
    /// Tag stamped onto every retrieved output (see [`Self::try_get`]).
    /// The executor sets it from the server key's tag, mirroring the
    /// classic HLAPI where every op tags its result from the key.
    pub(crate) tag: Tag,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum CpuOutputError {
    OutOfBounds {
        index: usize,
        len: usize,
    },
    WrongType {
        index: usize,
        source: RuntimeValueConversionError,
    },
}

impl std::fmt::Display for CpuOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfBounds { index, len } => write!(
                f,
                "output index {index} out of bounds, circuit has {len} outputs"
            ),
            Self::WrongType { index, source } => {
                write!(f, "output {index} has wrong type: {source}")
            }
        }
    }
}

impl std::error::Error for CpuOutputError {}

impl CpuOutputList {
    pub fn new() -> Self {
        Self {
            outputs: vec![],
            tag: Tag::default(),
        }
    }

    pub(crate) fn with_tag(tag: Tag) -> Self {
        Self {
            outputs: vec![],
            tag,
        }
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<RuntimeValue>,
    {
        self.outputs.push(value.into());
        self
    }

    /// The tag stamped onto retrieved outputs (taken from the executing
    /// server key's tag).
    pub fn tag(&self) -> &Tag {
        &self.tag
    }

    /// Gets the result at `index`, tagged with [`Self::tag`]
    ///
    /// # Panics
    ///
    /// Panics if the value stored in the slot is not type `T`,
    /// see [Self::try_get] for erroring variant
    pub fn get<T>(&self, index: usize) -> T
    where
        T: TryFrom<RuntimeValue, Error = RuntimeValueConversionError> + crate::prelude::Tagged,
    {
        self.try_get(index).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Gets the result at `index`, tagged with [`Self::tag`]
    pub fn try_get<T>(&self, index: usize) -> Result<T, CpuOutputError>
    where
        T: TryFrom<RuntimeValue, Error = RuntimeValueConversionError> + crate::prelude::Tagged,
    {
        let mut value = self.try_get_clear::<T>(index)?;
        *value.tag_mut() = self.tag.clone();
        Ok(value)
    }

    /// Gets a clear (non-encrypted) result at `index`, e.g. the clear
    /// `bool` produced by a clear-key KVStore lookup. Clear values carry
    /// no tag, so unlike [`Self::try_get`] this has no `Tagged` bound.
    ///
    /// # Panics
    ///
    /// Panics if the value stored in the slot is not type `T`,
    /// see [Self::try_get_clear] for erroring variant
    pub fn get_clear<T>(&self, index: usize) -> T
    where
        T: TryFrom<RuntimeValue, Error = RuntimeValueConversionError>,
    {
        self.try_get_clear(index).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Gets a clear (non-encrypted) result at `index`.
    /// See [`Self::get_clear`].
    pub fn try_get_clear<T>(&self, index: usize) -> Result<T, CpuOutputError>
    where
        T: TryFrom<RuntimeValue, Error = RuntimeValueConversionError>,
    {
        let value = self
            .outputs
            .get(index)
            .ok_or(CpuOutputError::OutOfBounds {
                index,
                len: self.outputs.len(),
            })?
            .clone();
        T::try_from(value).map_err(|source| CpuOutputError::WrongType { index, source })
    }
}

impl Default for CpuOutputList {
    fn default() -> Self {
        Self::new()
    }
}
