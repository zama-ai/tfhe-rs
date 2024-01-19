use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::SignedNumeric;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::{FheUint, FheUintId, IntegerId};
use crate::high_level_api::keys::InternalServerKey;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::client_key::RecomposableSignedInteger;
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::integer::SignedRadixCiphertext;
use crate::named::Named;
use crate::prelude::{CastFrom, OverflowingAdd, OverflowingMul, OverflowingSub};
use crate::{
    ClientKey, CompactFheInt, CompactPublicKey, CompressedFheInt, CompressedPublicKey, FheBool,
    PublicKey,
};
use std::borrow::Borrow;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::high_level_api::traits::{
    DivRem, FheDecrypt, FheEq, FheMax, FheMin, FheOrd, FheTrivialEncrypt, FheTryEncrypt,
    FheTryTrivialEncrypt, RotateLeft, RotateLeftAssign, RotateRight, RotateRightAssign,
};
use crate::integer::{I256, U256};
use crate::shortint::ciphertext::NotTrivialCiphertextError;

pub trait FheIntId: IntegerId {}

/// A Generic FHE signed integer
///
/// This struct is generic over some Id, as its the Id
/// that controls how many bit they represent.
///
/// You will need to use one of this type specialization (e.g., [FheInt8], [FheInt16]).
///
/// Its the type that overloads the operators (`+`, `-`, `*`),
/// since the `FheInt` type is not `Copy` the operators are also overloaded
/// to work with references.
///
/// [FheInt8]: crate::high_level_api::FheUint8
/// [FheInt16]: crate::high_level_api::FheInt16
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct FheInt<Id: FheIntId> {
    pub(in crate::high_level_api) ciphertext: SignedRadixCiphertext,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id> From<CompressedFheInt<Id>> for FheInt<Id>
where
    Id: FheIntId,
{
    fn from(value: CompressedFheInt<Id>) -> Self {
        value.decompress()
    }
}

impl<Id> From<CompactFheInt<Id>> for FheInt<Id>
where
    Id: FheIntId,
{
    fn from(value: CompactFheInt<Id>) -> Self {
        value.expand()
    }
}

impl<Id: FheIntId> ParameterSetConformant for FheInt<Id> {
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.ciphertext.is_conformant(params)
    }
}

impl<Id: FheIntId> Named for FheInt<Id> {
    const NAME: &'static str = "high_level_api::FheInt";
}

impl<Id> FheInt<Id>
where
    Id: FheIntId,
{
    pub(in crate::high_level_api) fn new(ciphertext: SignedRadixCiphertext) -> Self {
        Self {
            ciphertext,
            id: Id::default(),
        }
    }

    pub fn into_raw_parts(self) -> (SignedRadixCiphertext, Id) {
        let Self { ciphertext, id } = self;
        (ciphertext, id)
    }

    pub fn from_raw_parts(ciphertext: SignedRadixCiphertext, id: Id) -> Self {
        Self { ciphertext, id }
    }

    /// Returns the absolute value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-3i16, &client_key);
    /// let result: i16 = a.abs().decrypt(&client_key);
    /// assert_eq!(result, (-3i16).wrapping_abs());
    ///
    /// let a = FheInt16::encrypt(3i16, &client_key);
    /// let result: i16 = a.abs().decrypt(&client_key);
    /// assert_eq!(result, (-3i16).wrapping_abs());
    ///
    /// // The abs of the minimum cannot be represented
    /// // and overflows to itself
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    /// let result: i16 = a.abs().decrypt(&client_key);
    /// assert_eq!(result, i16::MIN.wrapping_abs());
    /// ```
    pub fn abs(&self) -> Self {
        let ciphertext = global_state::with_cpu_internal_keys(|keys| {
            keys.pbs_key().abs_parallelized(&self.ciphertext)
        });

        Self::new(ciphertext)
    }

    /// Tries to decrypt a trivial ciphertext
    ///
    /// Trivial ciphertexts are ciphertexts which are not encrypted
    /// meaning they can be decrypted by any key, or even without a key.
    ///
    /// For debugging it can be useful to use trivial ciphertext to speed up
    /// execution, and use [Self::try_decrypt_trivial] to decrypt temporary values
    /// and debug.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// // This is not a trivial ciphertext as we use a client key to encrypt.
    /// let non_trivial = FheInt16::encrypt(-1i16, &client_key);
    /// // This is a trivial ciphertext
    /// let trivial = FheInt16::encrypt_trivial(-2i16);
    ///
    /// // We can trivial decrypt
    /// let result: Result<i16, _> = trivial.try_decrypt_trivial();
    /// assert_eq!(result, Ok(-2));
    ///
    /// // We cannot trivial decrypt
    /// let result: Result<i16, _> = non_trivial.try_decrypt_trivial();
    /// matches!(result, Err(_));
    /// ```
    pub fn try_decrypt_trivial<Clear>(&self) -> Result<Clear, NotTrivialCiphertextError>
    where
        Clear: RecomposableSignedInteger,
    {
        self.ciphertext.decrypt_trivial()
    }
}

impl<FromId, IntoId> CastFrom<FheInt<FromId>> for FheInt<IntoId>
where
    FromId: FheIntId,
    IntoId: FheIntId,
{
    /// Cast a FheInt to another FheInt
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheInt32};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheInt32::encrypt(i32::MAX, &client_key);
    /// let b = FheInt16::cast_from(a);
    ///
    /// let decrypted: i16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MAX as i16);
    /// ```
    fn cast_from(input: FheInt<FromId>) -> Self {
        global_state::with_cpu_internal_keys(|keys| {
            let target_num_blocks = IntoId::num_blocks(keys.message_modulus());
            let new_ciphertext = keys
                .pbs_key()
                .cast_to_signed(input.ciphertext, target_num_blocks);
            Self::new(new_ciphertext)
        })
    }
}

impl<FromId, IntoId> CastFrom<FheUint<FromId>> for FheInt<IntoId>
where
    FromId: FheUintId,
    IntoId: FheIntId,
{
    /// Cast a FheUint to a FheInt
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheUint32::encrypt(u32::MAX, &client_key);
    /// let b = FheInt16::cast_from(a);
    ///
    /// let decrypted: i16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MAX as i16);
    /// ```
    fn cast_from(input: FheUint<FromId>) -> Self {
        global_state::with_cpu_internal_keys(|keys| {
            let new_ciphertext = keys.key.cast_to_signed(
                input.ciphertext.on_cpu().to_owned(),
                IntoId::num_blocks(keys.message_modulus()),
            );
            Self::new(new_ciphertext)
        })
    }
}

impl<Id> CastFrom<FheBool> for FheInt<Id>
where
    Id: FheIntId,
{
    /// Cast a FheBool to a FheInt
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheInt16::cast_from(a);
    ///
    /// let decrypted: i16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, i16::from(true));
    /// ```
    fn cast_from(input: FheBool) -> Self {
        let ciphertext = global_state::with_cpu_internal_keys(|keys| {
            input
                .ciphertext
                .on_cpu()
                .into_owned()
                .into_radix(Id::num_blocks(keys.message_modulus()), keys.pbs_key())
        });

        Self::new(ciphertext)
    }
}

impl<Id, ClearType> FheDecrypt<ClearType> for FheInt<Id>
where
    Id: FheIntId,
    ClearType: RecomposableSignedInteger,
{
    /// Decrypts a [FheInt] to a signed type.
    ///
    /// The unsigned type has to be explicit.
    ///
    /// # Example
    /// ```rust
    /// # use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheInt16};
    /// # use tfhe::prelude::*;
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheInt16::encrypt(7288i16, &client_key);
    ///
    /// // i16 is explicit
    /// let decrypted: i16 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288i16);
    ///
    /// // i32 is explicit
    /// let decrypted: i32 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288i32);
    /// ```
    fn decrypt(&self, key: &ClientKey) -> ClearType {
        key.key.key.decrypt_signed_radix(&self.ciphertext)
    }
}

impl<Id, T> FheTryEncrypt<T, ClientKey> for FheInt<Id>
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .key
            .encrypt_signed_radix(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(ciphertext))
    }
}

impl<Id, T> FheTryEncrypt<T, PublicKey> for FheInt<Id>
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &PublicKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .encrypt_signed_radix(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(ciphertext))
    }
}

impl<Id, T> FheTryEncrypt<T, CompressedPublicKey> for FheInt<Id>
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .encrypt_signed_radix(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(ciphertext))
    }
}

impl<Id, T> FheTryEncrypt<T, CompactPublicKey> for FheInt<Id>
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let ciphertext = key
            .key
            .key
            .encrypt_signed_radix(value, Id::num_blocks(key.message_modulus()));
        Ok(Self::new(ciphertext))
    }
}

impl<Id> OverflowingAdd<Self> for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Adds two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    /// let b = FheInt16::encrypt(1i16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_add(&b);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .signed_overflowing_add_parallelized(&self.ciphertext, &other.ciphertext);
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id> OverflowingAdd<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Adds two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    /// let b = FheInt16::encrypt(1i16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_add(&b);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingAdd<&Self>>::overflowing_add(&self, other)
    }
}

impl<Id, Clear> OverflowingAdd<Clear> for &FheInt<Id>
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = FheInt<Id>;

    /// Adds a [FheInt] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_add(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Clear) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .signed_overflowing_scalar_add_parallelized(&self.ciphertext, other);
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id, Clear> OverflowingAdd<Clear> for FheInt<Id>
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = Self;

    /// Adds a [FheInt] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_add(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Clear) -> (Self::Output, FheBool) {
        (&self).overflowing_add(other)
    }
}

impl<Id, Clear> OverflowingAdd<&FheInt<Id>> for Clear
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = FheInt<Id>;

    /// Adds a Clear with a [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    ///
    /// // Due to conflicts with u16::overflowing_add method
    /// // we have to use this syntax to help the compiler
    /// let (result, overflowed) = OverflowingAdd::overflowing_add(1i16, &a);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: &FheInt<Id>) -> (Self::Output, FheBool) {
        other.overflowing_add(self)
    }
}

impl<Id> OverflowingSub<Self> for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Subtracts two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    /// let b = FheInt16::encrypt(1i16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_sub(&b);
    /// let (expected_result, expected_overflow) = i16::MIN.overflowing_sub(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflow);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .signed_overflowing_sub_parallelized(&self.ciphertext, &other.ciphertext);
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id> OverflowingSub<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Subtracts two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    /// let b = FheInt16::encrypt(1i16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_sub(&b);
    /// let (expected_result, expected_overflow) = i16::MIN.overflowing_sub(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflow);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingSub<&Self>>::overflowing_sub(&self, other)
    }
}

impl<Id, Clear> OverflowingSub<Clear> for &FheInt<Id>
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = FheInt<Id>;

    /// Subtracts a [FheInt] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_sub(1i16);
    /// let (expected_result, expected_overflow) = i16::MIN.overflowing_sub(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflow);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Clear) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .signed_overflowing_scalar_sub_parallelized(&self.ciphertext, other);
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id, Clear> OverflowingSub<Clear> for FheInt<Id>
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = Self;

    /// Subtracts a [FheInt] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_sub(1i16);
    /// let (expected_result, expected_overflow) = i16::MIN.overflowing_sub(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflow);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Clear) -> (Self::Output, FheBool) {
        <&Self as OverflowingSub<Clear>>::overflowing_sub(&self, other)
    }
}

impl<Id> OverflowingMul<Self> for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Multiplies two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(3434i16, &client_key);
    /// let b = FheInt16::encrypt(54i16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_mul(&b);
    /// let (expected_result, expected_overflowed) = 3434i16.overflowing_mul(54i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflowed);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_mul(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .signed_overflowing_mul_parallelized(&self.ciphertext, &other.ciphertext);
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id> OverflowingMul<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Multiplies two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(3434i16, &client_key);
    /// let b = FheInt16::encrypt(54i16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_mul(&b);
    /// let (expected_result, expected_overflowed) = 3434i16.overflowing_mul(54i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflowed);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_mul(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingMul<&Self>>::overflowing_mul(&self, other)
    }
}

impl<'a, Id> std::iter::Sum<&'a Self> for FheInt<Id>
where
    Id: FheIntId,
{
    /// Sums multiple ciphertexts together.
    ///
    /// This is much more efficient than manually calling the `+` operator, thus
    /// using sum should always be preferred.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    ///
    /// let clears = [-1i16, 2, 3, 4, -5];
    /// let encrypted = clears
    ///     .iter()
    ///     .copied()
    ///     .map(|x| FheInt16::encrypt(x, &client_key))
    ///     .collect::<Vec<_>>();
    ///
    /// // Iter and sum on references
    /// let result = encrypted.iter().sum::<FheInt16>();
    ///
    /// let decrypted: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, clears.into_iter().sum::<i16>());
    /// ```
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key
                    .pbs_key()
                    .sum_ciphertexts_parallelized(iter.map(|elem| &elem.ciphertext))
                    .map_or_else(
                        || {
                            Self::new(cpu_key.key.create_trivial_zero_radix(Id::num_blocks(
                                cpu_key.message_modulus(),
                            )))
                        },
                        Self::new,
                    )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support signed integers");
            }
        })
    }
}

impl<Id, T> FheTryTrivialEncrypt<T> for FheInt<Id>
where
    T: DecomposableInto<u64>,
    Id: FheIntId,
{
    type Error = crate::high_level_api::errors::Error;

    /// Creates a trivial encryption of a signed integer.
    ///
    /// # Warning
    ///
    /// Trivial encryptions are not real encryptions, as a trivially encrypted
    /// ciphertext can be decrypted by any key (in fact, no key is actually needed).
    ///
    /// Trivial encryptions become real encrypted data once used in an operation
    /// that involves a real ciphertext
    fn try_encrypt_trivial(value: T) -> Result<Self, Self::Error> {
        let ciphertext = global_state::with_cpu_internal_keys(|sks| {
            sks.pbs_key()
                .create_trivial_radix(value, Id::num_blocks(sks.message_modulus()))
        });
        Ok(Self::new(ciphertext))
    }
}

impl<Id, T> FheTrivialEncrypt<T> for FheInt<Id>
where
    T: DecomposableInto<u64>,
    Id: FheIntId,
{
    /// Creates a trivial encryption of a signed integer.
    ///
    /// # Warning
    ///
    /// Trivial encryptions are not real encryptions, as a trivially encrypted
    /// ciphertext can be decrypted by any key (in fact, no key is actually needed).
    ///
    /// Trivial encryptions become real encrypted data once used in an operation
    /// that involves a real ciphertext
    #[track_caller]
    fn encrypt_trivial(value: T) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}

impl<Id> FheMax<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Returns the max between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.max(&b);
    ///
    /// let decrypted_max: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_max, (-1i16).max(2i16));
    /// ```
    fn max(&self, rhs: &Self) -> Self::Output {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            sks.pbs_key()
                .max_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result)
    }
}

impl<Id, Clear> FheMax<Clear> for FheInt<Id>
where
    Clear: DecomposableInto<u64>,
    Id: FheIntId,
{
    type Output = Self;

    /// Returns the max between a [FheInt] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.max(2i16);
    ///
    /// let decrypted_max: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_max, (-1i16).max(2i16));
    /// ```
    fn max(&self, rhs: Clear) -> Self::Output {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            sks.pbs_key().scalar_max_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result)
    }
}

impl<Id> FheMin<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Returns the max between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.min(&b);
    ///
    /// let decrypted_min: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_min, (-1i16).min(2i16));
    /// ```
    fn min(&self, rhs: &Self) -> Self::Output {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            sks.pbs_key()
                .min_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result)
    }
}

impl<Id, Clear> FheMin<Clear> for FheInt<Id>
where
    Id: FheIntId,
    Clear: DecomposableInto<u64>,
{
    type Output = Self;

    /// Returns the min between [FheInt] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.min(2i16);
    ///
    /// let decrypted_min: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_min, (-1i16).min(2i16));
    /// ```
    fn min(&self, rhs: Clear) -> Self::Output {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            sks.pbs_key().scalar_min_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result)
    }
}

impl<Id> FheEq<Self> for FheInt<Id>
where
    Id: FheIntId,
{
    fn eq(&self, rhs: Self) -> FheBool {
        self.eq(&rhs)
    }

    fn ne(&self, rhs: Self) -> FheBool {
        self.ne(&rhs)
    }
}

impl<Id> FheEq<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    /// Test for equality between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.eq(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 == 2i16);
    /// ```
    fn eq(&self, rhs: &Self) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.eq_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    /// Test for difference between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.ne(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 != 2i16);
    /// ```
    fn ne(&self, rhs: &Self) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.ne_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }
}

impl<Id, Clear> FheEq<Clear> for FheInt<Id>
where
    Clear: DecomposableInto<u64>,
    Id: FheIntId,
{
    /// Test for equality between a [FheInt] and a clear
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = 2i16;
    ///
    /// let result = a.eq(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 == 2i16);
    /// ```
    fn eq(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_eq_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    /// Test for difference between a [FheInt] and a clear
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.ne(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 != 2i16);
    /// ```
    fn ne(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_ne_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }
}

impl<Id> FheOrd<Self> for FheInt<Id>
where
    Id: FheIntId,
{
    fn lt(&self, rhs: Self) -> FheBool {
        self.lt(&rhs)
    }

    fn le(&self, rhs: Self) -> FheBool {
        self.le(&rhs)
    }

    fn gt(&self, rhs: Self) -> FheBool {
        self.gt(&rhs)
    }

    fn ge(&self, rhs: Self) -> FheBool {
        self.ge(&rhs)
    }
}

impl<Id> FheOrd<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    /// Test for less than between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.lt(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 < 2i16);
    /// ```
    fn lt(&self, rhs: &Self) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.lt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    /// Test for less than or equal between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.le(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 <= 2i16);
    /// ```
    fn le(&self, rhs: &Self) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.le_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    /// Test for greater than between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.gt(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 > 2i16);
    /// ```
    fn gt(&self, rhs: &Self) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.gt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    /// Test for greater than or equal between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.ge(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 >= 2i16);
    /// ```
    fn ge(&self, rhs: &Self) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.ge_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }
}

impl<Id, Clear> FheOrd<Clear> for FheInt<Id>
where
    Id: FheIntId,
    Clear: DecomposableInto<u64>,
{
    /// Test for less than between [FheInt] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.lt(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 < 2i16);
    /// ```
    fn lt(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_lt_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    /// Test for less than or equal between [FheInt] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.le(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 <= 2i16);
    /// ```
    fn le(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_le_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    /// Test for greater than between [FheInt] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.gt(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 > 2i16);
    /// ```
    fn gt(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_gt_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    /// Test for greater than or equal between [FheInt] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.ge(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 >= 2i16);
    /// ```
    fn ge(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_ge_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }
}

impl<Id> DivRem<Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: Self) -> Self::Output {
        <Self as DivRem<&Self>>::div_rem(self, &rhs)
    }
}

impl<Id> DivRem<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: &Self) -> Self::Output {
        <&Self as DivRem<&Self>>::div_rem(&self, rhs)
    }
}

impl<Id> DivRem<Self> for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = (FheInt<Id>, FheInt<Id>);

    /// Computes the quotient and remainder between two [FheInt]
    ///
    /// If you need both the quotient and remainder, then `div_rem` is better
    /// than computing them separately using `/` and `%`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-23i16, &client_key);
    /// let b = FheInt16::encrypt(3i16, &client_key);
    ///
    /// let (quotient, remainder) = (&a).div_rem(&b);
    ///
    /// let quotient: i16 = quotient.decrypt(&client_key);
    /// assert_eq!(quotient, -23i16 / 3i16);
    /// let remainder: i16 = remainder.decrypt(&client_key);
    /// assert_eq!(remainder, -23i16 % 3i16);
    /// ```
    fn div_rem(self, rhs: Self) -> Self::Output {
        let (q, r) = global_state::with_cpu_internal_keys(|integer_key| {
            integer_key
                .pbs_key()
                .div_rem_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        (FheInt::<Id>::new(q), FheInt::<Id>::new(r))
    }
}

// Shifts and rotations are special cases where the right hand side
// is for now, required to be a unsigned integer type.
// And its constraints are a bit relaxed: rhs does not needs to have the same
// amount a bits.
macro_rules! generic_integer_impl_shift_rotate (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {

        // a op b
        impl<Id, Id2> $rust_trait_name<FheUint<Id2>> for FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: FheUint<Id2>) -> Self::Output {
                <&Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(&self, &rhs)
            }

        }

        // a op &b
        impl<Id, Id2> $rust_trait_name<&FheUint<Id2>> for FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: &FheUint<Id2>) -> Self::Output {
                <&Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(&self, rhs)
            }

        }

        // &a op b
        impl<Id, Id2> $rust_trait_name<FheUint<Id2>> for &FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            type Output = FheInt<Id>;

            fn $rust_trait_method(self, rhs: FheUint<Id2>) -> Self::Output {
                <Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(self, &rhs)
            }
        }

        // &a op &b
        impl<Id, Id2> $rust_trait_name<&FheUint<Id2>> for &FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            type Output = FheInt<Id>;

            fn $rust_trait_method(self, rhs: &FheUint<Id2>) -> Self::Output {
                let ciphertext = global_state::with_cpu_internal_keys(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&self.ciphertext, &*rhs.ciphertext.on_cpu())
                });
                FheInt::<Id>::new(ciphertext)
            }
        }
    }
);

macro_rules! generic_integer_impl_shift_rotate_assign(
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {
        // a op= b
        impl<Id, Id2> $rust_trait_name<FheUint<Id2>> for FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            fn $rust_trait_method(&mut self, rhs: FheUint<Id2>) {
                <Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(self, &rhs)
            }
        }

        // a op= &b
        impl<Id, Id2> $rust_trait_name<&FheUint<Id2>> for FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            fn $rust_trait_method(&mut self, rhs: &FheUint<Id2>) {
                global_state::with_cpu_internal_keys(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&mut self.ciphertext, &*rhs.ciphertext.on_cpu())
                })
            }
        }
    }
);

macro_rules! generic_integer_impl_operation (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {

        impl<Id, B> $rust_trait_name<B> for FheInt<Id>
        where
            Id: FheIntId,
            B: Borrow<Self>,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                <&Self as $rust_trait_name<B>>::$rust_trait_method(&self, rhs)
            }

        }

        impl<Id, B> $rust_trait_name<B> for &FheInt<Id>
        where
            Id: FheIntId,
            B: Borrow<FheInt<Id>>,
        {
            type Output = FheInt<Id>;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                let ciphertext = global_state::with_cpu_internal_keys(|integer_key| {
                    let borrowed = rhs.borrow();
                    integer_key
                        .pbs_key()
                        .$key_method(&self.ciphertext, &borrowed.ciphertext)
                });
                FheInt::<Id>::new(ciphertext)
            }
        }
    }
);

macro_rules! generic_integer_impl_operation_assign (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {
        impl<Id, I> $rust_trait_name<I> for FheInt<Id>
        where
            Id: FheIntId,
            I: Borrow<Self>,
        {
            fn $rust_trait_method(&mut self, rhs: I) {
                global_state::with_cpu_internal_keys(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&mut self.ciphertext, &rhs.borrow().ciphertext)
                })
            }
        }
    }
);

// DivRem is a bit special as it returns a tuple of quotient and remainder
macro_rules! generic_integer_impl_scalar_div_rem {
    (
        key_method: $key_method:ident,
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($scalar_type:ty),*)
        ),*
        $(,)?
    ) => {
        $( // First repeating pattern
            $( // Second repeating pattern
                impl DivRem<$scalar_type> for $concrete_type
                {
                    type Output = ($concrete_type, $concrete_type);

                    fn div_rem(self, rhs: $scalar_type) -> Self::Output {
                        <&Self as DivRem<$scalar_type>>::div_rem(&self, rhs)
                    }
                }

                impl DivRem<$scalar_type> for &$concrete_type
                {
                    type Output = ($concrete_type, $concrete_type);

                    fn div_rem(self, rhs: $scalar_type) -> Self::Output {
                        let (q, r) =
                            global_state::with_cpu_internal_keys(|integer_key| {
                                integer_key.pbs_key().$key_method(&self.ciphertext, rhs)
                            });

                        (
                            <$concrete_type>::new(q),
                            <$concrete_type>::new(r)
                        )
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}
generic_integer_impl_scalar_div_rem!(
    key_method: signed_scalar_div_rem_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);

generic_integer_impl_operation!(Add(add) => add_parallelized);
generic_integer_impl_operation!(Sub(sub) => sub_parallelized);
generic_integer_impl_operation!(Mul(mul) => mul_parallelized);
generic_integer_impl_operation!(BitAnd(bitand) => bitand_parallelized);
generic_integer_impl_operation!(BitOr(bitor) => bitor_parallelized);
generic_integer_impl_operation!(BitXor(bitxor) => bitxor_parallelized);
generic_integer_impl_operation!(Div(div) => div_parallelized);
generic_integer_impl_operation!(Rem(rem) => rem_parallelized);
generic_integer_impl_shift_rotate!(Shl(shl) => left_shift_parallelized);
generic_integer_impl_shift_rotate!(Shr(shr) => right_shift_parallelized);
generic_integer_impl_shift_rotate!(RotateLeft(rotate_left) => rotate_left_parallelized);
generic_integer_impl_shift_rotate!(RotateRight(rotate_right) => rotate_right_parallelized);
// assign operations
generic_integer_impl_operation_assign!(AddAssign(add_assign) => add_assign_parallelized);
generic_integer_impl_operation_assign!(SubAssign(sub_assign) => sub_assign_parallelized);
generic_integer_impl_operation_assign!(MulAssign(mul_assign) => mul_assign_parallelized);
generic_integer_impl_operation_assign!(BitAndAssign(bitand_assign) => bitand_assign_parallelized);
generic_integer_impl_operation_assign!(BitOrAssign(bitor_assign) => bitor_assign_parallelized);
generic_integer_impl_operation_assign!(BitXorAssign(bitxor_assign) => bitxor_assign_parallelized);
generic_integer_impl_operation_assign!(DivAssign(div_assign) => div_assign_parallelized);
generic_integer_impl_operation_assign!(RemAssign(rem_assign) => rem_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(ShlAssign(shl_assign) => left_shift_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(ShrAssign(shr_assign) => right_shift_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(RotateLeftAssign(rotate_left_assign) => rotate_left_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(RotateRightAssign(rotate_right_assign) => rotate_right_assign_parallelized);
macro_rules! generic_integer_impl_scalar_operation {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        key_method: $key_method:ident,
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($scalar_type:ty),*)
        ),*
        $(,)?
    ) => {
        $( // First repeating pattern
            $( // Second repeating pattern
                impl $rust_trait_name<$scalar_type> for $concrete_type
                {
                    type Output = $concrete_type;

                    fn $rust_trait_method(self, rhs: $scalar_type) -> Self::Output {
                        <&Self as $rust_trait_name<$scalar_type>>::$rust_trait_method(&self, rhs)
                    }
                }

                impl $rust_trait_name<$scalar_type> for &$concrete_type
                {
                    type Output = $concrete_type;

                    fn $rust_trait_method(self, rhs: $scalar_type) -> Self::Output {
                         global_state::with_cpu_internal_keys(|cpu_key| {
                                let inner_result = cpu_key
                                    .pbs_key()
                                    .$key_method(&self.ciphertext, rhs);
                               <$concrete_type>::new(inner_result)
                        })
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

generic_integer_impl_scalar_operation!(
    rust_trait: Add(add),
    key_method: scalar_add_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Sub(sub),
    key_method: scalar_sub_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Mul(mul),
    key_method: scalar_mul_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: BitAnd(bitand),
    key_method: scalar_bitand_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: BitXor(bitxor),
    key_method: scalar_bitxor_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: BitOr(bitor),
    key_method: scalar_bitor_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Shl(shl),
    key_method: scalar_left_shift_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, u8, u16, u32, u64, u128),
        (super::FheInt4, u8, u16, u32, u64, u128),
        (super::FheInt6, u8, u16, u32, u64, u128),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt10, u8, u16, u32, u64, u128),
        (super::FheInt12, u8, u16, u32, u64, u128),
        (super::FheInt14, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt160, u8, u16, u32, u64, u128, U256),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Shr(shr),
    key_method: scalar_right_shift_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, u8, u16, u32, u64, u128),
        (super::FheInt4, u8, u16, u32, u64, u128),
        (super::FheInt6, u8, u16, u32, u64, u128),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt10, u8, u16, u32, u64, u128),
        (super::FheInt12, u8, u16, u32, u64, u128),
        (super::FheInt14, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt160, u8, u16, u32, u64, u128, U256),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: RotateLeft(rotate_left),
    key_method: scalar_rotate_left_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, u8, u16, u32, u64, u128),
        (super::FheInt4, u8, u16, u32, u64, u128),
        (super::FheInt6, u8, u16, u32, u64, u128),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt10, u8, u16, u32, u64, u128),
        (super::FheInt12, u8, u16, u32, u64, u128),
        (super::FheInt14, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt160, u8, u16, u32, u64, u128, U256),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: RotateRight(rotate_right),
    key_method: scalar_rotate_right_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, u8, u16, u32, u64, u128),
        (super::FheInt4, u8, u16, u32, u64, u128),
        (super::FheInt6, u8, u16, u32, u64, u128),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt10, u8, u16, u32, u64, u128),
        (super::FheInt12, u8, u16, u32, u64, u128),
        (super::FheInt14, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt160, u8, u16, u32, u64, u128, U256),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Div(div),
    key_method: signed_scalar_div_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Rem(rem),
    key_method: signed_scalar_rem_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
macro_rules! generic_integer_impl_scalar_operation_assign {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        key_method: $key_method:ident,
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($scalar_type:ty),*)
        ),*
        $(,)?
    ) => {
        $(
            $(
                impl $rust_trait_name<$scalar_type> for $concrete_type
                {
                    fn $rust_trait_method(&mut self, rhs: $scalar_type) {
                         global_state::with_cpu_internal_keys(|cpu_key| {
                            cpu_key
                                .pbs_key()
                                .$key_method(&mut self.ciphertext, rhs);
                        })
                    }
                }
            )*
        )*
    }
}
generic_integer_impl_scalar_operation_assign!(
    rust_trait: AddAssign(add_assign),
    key_method: scalar_add_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: SubAssign(sub_assign),
    key_method: scalar_sub_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: MulAssign(mul_assign),
    key_method: scalar_mul_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: BitAndAssign(bitand_assign),
    key_method: scalar_bitand_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: BitOrAssign(bitor_assign),
    key_method: scalar_bitor_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: BitXorAssign(bitxor_assign),
    key_method: scalar_bitxor_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: ShlAssign(shl_assign),
    key_method: scalar_left_shift_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, u8, u16, u32, u64, u128),
        (super::FheInt4, u8, u16, u32, u64, u128),
        (super::FheInt6, u8, u16, u32, u64, u128),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt10, u8, u16, u32, u64, u128),
        (super::FheInt12, u8, u16, u32, u64, u128),
        (super::FheInt14, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt160, u8, u16, u32, u64, u128, U256),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: ShrAssign(shr_assign),
    key_method: scalar_right_shift_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, u8, u16, u32, u64, u128),
        (super::FheInt4, u8, u16, u32, u64, u128),
        (super::FheInt6, u8, u16, u32, u64, u128),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt10, u8, u16, u32, u64, u128),
        (super::FheInt12, u8, u16, u32, u64, u128),
        (super::FheInt14, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt160, u8, u16, u32, u64, u128, U256),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RotateLeftAssign(rotate_left_assign),
    key_method: scalar_rotate_left_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, u8, u16, u32, u64, u128),
        (super::FheInt4, u8, u16, u32, u64, u128),
        (super::FheInt6, u8, u16, u32, u64, u128),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt10, u8, u16, u32, u64, u128),
        (super::FheInt12, u8, u16, u32, u64, u128),
        (super::FheInt14, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt160, u8, u16, u32, u64, u128, U256),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RotateRightAssign(rotate_right_assign),
    key_method: scalar_rotate_right_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, u8, u16, u32, u64, u128),
        (super::FheInt4, u8, u16, u32, u64, u128),
        (super::FheInt6, u8, u16, u32, u64, u128),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt10, u8, u16, u32, u64, u128),
        (super::FheInt12, u8, u16, u32, u64, u128),
        (super::FheInt14, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt160, u8, u16, u32, u64, u128, U256),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: DivAssign(div_assign),
    key_method: signed_scalar_div_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RemAssign(rem_assign),
    key_method: signed_scalar_rem_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);

impl<Id> Neg for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Computes the negation of a [FheInt].
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-3i16, &client_key);
    ///
    /// let result = -a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 3i16);
    /// ```
    fn neg(self) -> Self::Output {
        <&Self as Neg>::neg(&self)
    }
}

impl<Id> Neg for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Computes the negation of a [FheInt].
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-3i16, &client_key);
    ///
    /// let result = -&a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 3i16);
    /// ```
    fn neg(self) -> Self::Output {
        let ciphertext = global_state::with_cpu_internal_keys(|integer_key| {
            integer_key.pbs_key().neg_parallelized(&self.ciphertext)
        });
        FheInt::new(ciphertext)
    }
}

impl<Id> Not for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Performs a bitwise 'not'
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-3i16, &client_key);
    ///
    /// let result = !&a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, !-3i16);
    /// ```
    fn not(self) -> Self::Output {
        <&Self as Not>::not(&self)
    }
}

impl<Id> Not for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Performs a bitwise 'not'
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-3i16, &client_key);
    ///
    /// let result = !&a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, !-3i16);
    /// ```
    fn not(self) -> Self::Output {
        let ciphertext = global_state::with_cpu_internal_keys(|integer_key| {
            integer_key.pbs_key().bitnot_parallelized(&self.ciphertext)
        });
        FheInt::<Id>::new(ciphertext)
    }
}
