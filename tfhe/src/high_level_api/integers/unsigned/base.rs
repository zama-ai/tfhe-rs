#![allow(clippy::redundant_closure_call)]
use std::borrow::Borrow;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::conformance::ParameterSetConformant;

use crate::core_crypto::prelude::{CastFrom, UnsignedNumeric};
use crate::high_level_api::details::MaybeCloned;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_stream;
use crate::high_level_api::integers::signed::{FheInt, FheIntId};
use crate::high_level_api::integers::IntegerId;
use crate::high_level_api::keys::{CompressedPublicKey, InternalServerKey};
use crate::high_level_api::traits::{
    DivRem, FheBootstrap, FheDecrypt, FheEq, FheMax, FheMin, FheOrd, FheTrivialEncrypt,
    FheTryEncrypt, FheTryTrivialEncrypt, OverflowingAdd, OverflowingMul, OverflowingSub,
    RotateLeft, RotateLeftAssign, RotateRight, RotateRightAssign,
};
use crate::high_level_api::{global_state, ClientKey, Device, PublicKey};
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::integer::{IntegerCiphertext, U256};
use crate::named::Named;
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::{CompactFheUint, CompactPublicKey, CompressedFheUint, FheBool};
use serde::{Deserializer, Serializer};

pub(crate) enum RadixCiphertext {
    Cpu(crate::integer::RadixCiphertext),
    #[cfg(feature = "gpu")]
    Cuda(crate::integer::gpu::ciphertext::CudaRadixCiphertext),
}

impl From<crate::integer::RadixCiphertext> for RadixCiphertext {
    fn from(value: crate::integer::RadixCiphertext) -> Self {
        Self::Cpu(value)
    }
}

#[cfg(feature = "gpu")]
impl From<crate::integer::gpu::ciphertext::CudaRadixCiphertext> for RadixCiphertext {
    fn from(value: crate::integer::gpu::ciphertext::CudaRadixCiphertext) -> Self {
        Self::Cuda(value)
    }
}

impl Clone for RadixCiphertext {
    fn clone(&self) -> Self {
        match self {
            Self::Cpu(inner) => Self::Cpu(inner.clone()),
            #[cfg(feature = "gpu")]
            Self::Cuda(inner) => {
                with_thread_local_cuda_stream(|stream| Self::Cuda(inner.duplicate(stream)))
            }
        }
    }
}

impl serde::Serialize for RadixCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.on_cpu().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RadixCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut deserialized =
            Self::Cpu(crate::integer::RadixCiphertext::deserialize(deserializer)?);
        deserialized.move_to_device_of_server_key_if_set();
        Ok(deserialized)
    }
}

impl RadixCiphertext {
    pub(crate) fn current_device(&self) -> Device {
        match self {
            Self::Cpu(_) => Device::Cpu,
            #[cfg(feature = "gpu")]
            Self::Cuda(_) => Device::CudaGpu,
        }
    }

    /// Returns the a ref to the inner cpu ciphertext if self is on the CPU, otherwise, returns a
    /// copy that is on the CPU
    pub(crate) fn on_cpu(&self) -> MaybeCloned<'_, crate::integer::RadixCiphertext> {
        match self {
            Self::Cpu(ct) => MaybeCloned::Borrowed(ct),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => with_thread_local_cuda_stream(|stream| {
                let cpu_ct = ct.to_radix_ciphertext(stream);
                MaybeCloned::Cloned(cpu_ct)
            }),
        }
    }

    /// Returns the inner cpu ciphertext if self is on the CPU, otherwise, returns a copy
    /// that is on the CPU
    #[cfg(feature = "gpu")]
    pub(crate) fn on_gpu(
        &self,
    ) -> MaybeCloned<'_, crate::integer::gpu::ciphertext::CudaRadixCiphertext> {
        match self {
            Self::Cpu(ct) => with_thread_local_cuda_stream(|stream| {
                let ct =
                    crate::integer::gpu::ciphertext::CudaRadixCiphertext::from_radix_ciphertext(
                        ct, stream,
                    );
                MaybeCloned::Cloned(ct)
            }),
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => MaybeCloned::Borrowed(ct),
        }
    }

    pub(crate) fn as_cpu_mut(&mut self) -> &mut crate::integer::RadixCiphertext {
        match self {
            Self::Cpu(radix_ct) => radix_ct,
            #[cfg(feature = "gpu")]
            _ => {
                self.move_to_device(Device::Cpu);
                self.as_cpu_mut()
            }
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn as_gpu_mut(
        &mut self,
    ) -> &mut crate::integer::gpu::ciphertext::CudaRadixCiphertext {
        if let Self::Cuda(radix_ct) = self {
            radix_ct
        } else {
            self.move_to_device(Device::CudaGpu);
            self.as_gpu_mut()
        }
    }

    pub(crate) fn into_cpu(self) -> crate::integer::RadixCiphertext {
        match self {
            Self::Cpu(cpu_ct) => cpu_ct,
            #[cfg(feature = "gpu")]
            Self::Cuda(ct) => {
                with_thread_local_cuda_stream(|stream| ct.to_radix_ciphertext(stream))
            }
        }
    }

    pub(crate) fn move_to_device(&mut self, device: Device) {
        match (&self, device) {
            (Self::Cpu(_), Device::Cpu) => {
                // Nothing to do, we already are on the correct device
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(_), Device::CudaGpu) => {
                // Nothing to do, we already are on the correct device
            }
            #[cfg(feature = "gpu")]
            (Self::Cpu(ct), Device::CudaGpu) => {
                let new_inner = with_thread_local_cuda_stream(|stream| {
                    crate::integer::gpu::ciphertext::CudaRadixCiphertext::from_radix_ciphertext(
                        ct, stream,
                    )
                });
                *self = Self::Cuda(new_inner);
            }
            #[cfg(feature = "gpu")]
            (Self::Cuda(ct), Device::Cpu) => {
                let new_inner =
                    with_thread_local_cuda_stream(|stream| ct.to_radix_ciphertext(stream));
                *self = Self::Cpu(new_inner);
            }
        }
    }

    #[inline]
    #[allow(clippy::unused_self)]
    pub(crate) fn move_to_device_of_server_key_if_set(&mut self) {
        #[cfg(feature = "gpu")]
        if let Some(device) = global_state::device_of_internal_keys() {
            self.move_to_device(device);
        }
    }
}

#[derive(Debug)]
pub enum GenericIntegerBlockError {
    NumberOfBlocks(usize, usize),
    CarryModulus(crate::shortint::CarryModulus, crate::shortint::CarryModulus),
    MessageModulus(
        crate::shortint::MessageModulus,
        crate::shortint::MessageModulus,
    ),
}

impl std::fmt::Display for GenericIntegerBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::NumberOfBlocks(correct, incorrect) => write!(
                f,
                "Wrong number of blocks for creating 
                    a GenericInteger: should have been {correct}, but
                    was {incorrect} instead"
            ),
            Self::CarryModulus(correct, incorrect) => write!(
                f,
                "Wrong carry modulus for creating 
                    a GenericInteger: should have been {correct:?}, but
                    was {incorrect:?} instead"
            ),
            Self::MessageModulus(correct, incorrect) => write!(
                f,
                "Wrong message modulus for creating 
                    a GenericInteger: should have been {correct:?}, but
                    was {incorrect:?} instead"
            ),
        }
    }
}

pub trait FheUintId: IntegerId {}

/// A Generic FHE unsigned integer
///
/// This struct is generic over some Id, as its the Id
/// that controls how many bit they represent.
///
/// You will need to use one of this type specialization (e.g., [FheUint8], [FheUint12],
/// [FheUint16]).
///
/// Its the type that overloads the operators (`+`, `-`, `*`),
/// since the `FheUint` type is not `Copy` the operators are also overloaded
/// to work with references.
///
/// [FheUint8]: crate::high_level_api::FheUint8
/// [FheUint12]: crate::high_level_api::FheUint12
/// [FheUint16]: crate::high_level_api::FheUint16
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct FheUint<Id: FheUintId> {
    pub(in crate::high_level_api) ciphertext: RadixCiphertext,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id> From<CompressedFheUint<Id>> for FheUint<Id>
where
    Id: FheUintId,
{
    fn from(value: CompressedFheUint<Id>) -> Self {
        value.decompress()
    }
}

impl<Id> From<CompactFheUint<Id>> for FheUint<Id>
where
    Id: FheUintId,
{
    fn from(value: CompactFheUint<Id>) -> Self {
        value.expand()
    }
}

impl<Id: FheUintId> ParameterSetConformant for FheUint<Id> {
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.ciphertext.on_cpu().is_conformant(params)
    }
}

impl<Id: FheUintId> Named for FheUint<Id> {
    const NAME: &'static str = "high_level_api::FheUint";
}

impl<Id> FheUint<Id>
where
    Id: FheUintId,
{
    pub(in crate::high_level_api) fn new<T>(ciphertext: T) -> Self
    where
        T: Into<RadixCiphertext>,
    {
        Self {
            ciphertext: ciphertext.into(),
            id: Id::default(),
        }
    }

    pub fn into_raw_parts(self) -> (crate::integer::RadixCiphertext, Id) {
        let Self { ciphertext, id } = self;

        let ciphertext = ciphertext.into_cpu();

        (ciphertext, id)
    }

    pub fn from_raw_parts(ciphertext: crate::integer::RadixCiphertext, id: Id) -> Self {
        Self {
            ciphertext: RadixCiphertext::Cpu(ciphertext),
            id,
        }
    }

    pub(in crate::high_level_api) fn move_to_device_of_server_key_if_set(&mut self) {
        self.ciphertext.move_to_device_of_server_key_if_set();
    }

    /// Returns the device where the ciphertext is currently on
    pub fn current_device(&self) -> Device {
        self.ciphertext.current_device()
    }

    /// Moves (in-place) the ciphertext to the desired device.
    ///
    /// Does nothing if the ciphertext is already in the desired device
    pub fn move_to_device(&mut self, device: Device) {
        self.ciphertext.move_to_device(device)
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
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// // This is not a trivial ciphertext as we use a client key to encrypt.
    /// let non_trivial = FheUint16::encrypt(1u16, &client_key);
    /// // This is a trivial ciphertext
    /// let trivial = FheUint16::encrypt_trivial(2u16);
    ///
    /// // We can trivial decrypt
    /// let result: Result<u16, _> = trivial.try_decrypt_trivial();
    /// assert_eq!(result, Ok(2));
    ///
    /// // We cannot trivial decrypt
    /// let result: Result<u16, _> = non_trivial.try_decrypt_trivial();
    /// matches!(result, Err(_));
    /// ```
    pub fn try_decrypt_trivial<Clear>(&self) -> Result<Clear, NotTrivialCiphertextError>
    where
        Clear: UnsignedNumeric + RecomposableFrom<u64>,
    {
        self.ciphertext.on_cpu().decrypt_trivial()
    }

    /// Returns true if the ciphertext is a trivial encryption
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let non_trivial = FheUint16::encrypt(1u16, &client_key);
    /// assert!(!non_trivial.is_trivial());
    ///
    /// let trivial = FheUint16::encrypt_trivial(2u16);
    /// assert!(trivial.is_trivial());
    /// ```
    pub fn is_trivial(&self) -> bool {
        self.ciphertext.on_cpu().is_trivial()
    }

    /// Sums multiple ciphertexts together.
    ///
    /// This is much more efficient than manually calling the `+` operator, thus
    /// using sum should always be prefered.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    /// let c = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = FheUint16::sum([&a, &b, &c]);
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 + 2 + 3);
    ///
    /// // Or
    /// let result = [&a, &b, &c].into_iter().sum::<FheUint16>();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 + 2 + 3);
    /// ```
    pub fn sum<'a, C>(collection: C) -> Self
    where
        C: AsRef<[&'a Self]>,
    {
        collection.as_ref().iter().copied().sum()
    }
}

impl<Id> TryFrom<crate::integer::RadixCiphertext> for FheUint<Id>
where
    Id: FheUintId,
{
    type Error = GenericIntegerBlockError;

    fn try_from(other: crate::integer::RadixCiphertext) -> Result<Self, GenericIntegerBlockError> {
        // Get correct carry modulus and message modulus from ServerKey
        let (correct_carry_mod, correct_message_mod) =
            global_state::with_internal_keys(|sks| match sks {
                InternalServerKey::Cpu(sks) => (
                    sks.pbs_key().key.carry_modulus,
                    sks.pbs_key().key.message_modulus,
                ),
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    (cuda_key.key.carry_modulus, cuda_key.key.message_modulus)
                }
            });

        // Check number of blocks
        let expected_num_blocks = Id::num_blocks(correct_message_mod);
        if other.blocks.len() != expected_num_blocks {
            return Err(GenericIntegerBlockError::NumberOfBlocks(
                expected_num_blocks,
                other.blocks.len(),
            ));
        }

        // For each block, check that carry modulus and message modulus are valid
        for block in &other.blocks {
            let (input_carry_mod, input_message_mod) = (block.carry_modulus, block.message_modulus);

            if input_carry_mod != correct_carry_mod {
                return Err(GenericIntegerBlockError::CarryModulus(
                    correct_carry_mod,
                    input_carry_mod,
                ));
            } else if input_message_mod != correct_message_mod {
                return Err(GenericIntegerBlockError::MessageModulus(
                    correct_message_mod,
                    input_message_mod,
                ));
            }
        }

        let mut ciphertext = Self::new(other);
        ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl<Id, T> TryFrom<Vec<T>> for FheUint<Id>
where
    Id: FheUintId,
    crate::integer::RadixCiphertext: From<Vec<T>>,
{
    type Error = GenericIntegerBlockError;
    fn try_from(blocks: Vec<T>) -> Result<Self, GenericIntegerBlockError> {
        let ciphertext = crate::integer::RadixCiphertext::from(blocks);
        Self::try_from(ciphertext)
    }
}

impl<Id, ClearType> FheDecrypt<ClearType> for FheUint<Id>
where
    Id: FheUintId,
    ClearType: RecomposableFrom<u64> + UnsignedNumeric,
{
    /// Decrypts a [FheUint] to an unsigned type.
    ///
    /// The unsigned type has to be explicit.
    ///
    /// # Example
    /// ```rust
    /// # use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint16};
    /// # use tfhe::prelude::*;
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheUint16::encrypt(7288u16, &client_key);
    ///
    /// // u16 is explicit
    /// let decrypted: u16 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288u16);
    ///
    /// // u32 is explicit
    /// let decrypted: u32 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288u32);
    /// ```
    fn decrypt(&self, key: &ClientKey) -> ClearType {
        key.key.key.decrypt_radix(&self.ciphertext.on_cpu())
    }
}

impl<Id, T> FheTryEncrypt<T, ClientKey> for FheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let cpu_ciphertext = key
            .key
            .key
            .encrypt_radix(value, Id::num_blocks(key.message_modulus()));
        let mut ciphertext = Self::new(cpu_ciphertext);

        ciphertext.move_to_device_of_server_key_if_set();

        Ok(ciphertext)
    }
}

impl<Id, T> FheTryEncrypt<T, PublicKey> for FheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &PublicKey) -> Result<Self, Self::Error> {
        let cpu_ciphertext = key
            .key
            .encrypt_radix(value, Id::num_blocks(key.message_modulus()));
        let mut ciphertext = Self::new(cpu_ciphertext);

        ciphertext.move_to_device_of_server_key_if_set();

        Ok(ciphertext)
    }
}

impl<Id, T> FheTryEncrypt<T, CompressedPublicKey> for FheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let cpu_ciphertext = key
            .key
            .encrypt_radix(value, Id::num_blocks(key.message_modulus()));
        let mut ciphertext = Self::new(cpu_ciphertext);

        ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl<Id, T> FheTryEncrypt<T, CompactPublicKey> for FheUint<Id>
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let cpu_ciphertext = key
            .key
            .key
            .encrypt_radix(value, Id::num_blocks(key.message_modulus()));
        let mut ciphertext = Self::new(cpu_ciphertext);

        ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl<Id, T> FheTryTrivialEncrypt<T> for FheUint<Id>
where
    T: DecomposableInto<u64> + UnsignedNumeric,
    Id: FheUintId,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt_trivial(value: T) -> Result<Self, Self::Error> {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ciphertext: crate::integer::RadixCiphertext = key
                    .pbs_key()
                    .create_trivial_radix(value, Id::num_blocks(key.message_modulus()));
                Ok(Self::new(ciphertext))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner = cuda_key.key.create_trivial_radix(
                    value,
                    Id::num_blocks(cuda_key.key.message_modulus),
                    stream,
                );
                Ok(Self::new(inner))
            }),
        })
    }
}

impl<Id, T> FheTrivialEncrypt<T> for FheUint<Id>
where
    T: DecomposableInto<u64> + UnsignedNumeric,
    Id: FheUintId,
{
    /// Creates a trivially encrypted FheUint
    ///
    /// A trivial encryption is not an encryption, the value can be retrieved
    /// by anyone as if it were a clear value.
    ///
    /// Thus no client or public key is needed to create a trivial encryption,
    /// this can be useful to initialize some values.
    ///
    /// As soon as a trivial encryption is used in an operation that involves
    /// non trivial encryption, the result will be non trivial (secure).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint16};
    /// # use tfhe::prelude::*;
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt_trivial(7288u16);
    ///
    /// let decrypted: u16 = a.decrypt(&client_key);
    /// assert_eq!(decrypted, 7288u16);
    /// ```
    #[track_caller]
    fn encrypt_trivial(value: T) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}

impl<Id> OverflowingAdd<Self> for &FheUint<Id>
where
    Id: FheUintId,
{
    type Output = FheUint<Id>;

    /// Adds two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    /// let b = FheUint16::encrypt(1u16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_add(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key.key.unsigned_overflowing_add_parallelized(
                    &self.ciphertext.on_cpu(),
                    &other.ciphertext.on_cpu(),
                );
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support overflowing_add yet");
            }
        })
    }
}

impl<Id> OverflowingAdd<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Adds two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    /// let b = FheUint16::encrypt(1u16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_add(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingAdd<&Self>>::overflowing_add(&self, other)
    }
}

impl<Id, Clear> OverflowingAdd<Clear> for &FheUint<Id>
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = FheUint<Id>;

    /// Adds a [FheUint] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_add(1u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Clear) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .unsigned_overflowing_scalar_add_parallelized(&self.ciphertext.on_cpu(), other);
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support overflowing_add yet");
            }
        })
    }
}

impl<Id, Clear> OverflowingAdd<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = Self;

    /// Adds a [FheUint] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_add(1u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Clear) -> (Self::Output, FheBool) {
        (&self).overflowing_add(other)
    }
}

impl<Id, Clear> OverflowingAdd<&FheUint<Id>> for Clear
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = FheUint<Id>;

    /// Adds a Clear with a [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    ///
    /// // Due to conflicts with u16::overflowing_add method
    /// // we have to use this syntax to help the compiler
    /// let (result, overflowed) = OverflowingAdd::overflowing_add(1u16, &a);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: &FheUint<Id>) -> (Self::Output, FheBool) {
        other.overflowing_add(self)
    }
}

impl<Id> OverflowingSub<Self> for &FheUint<Id>
where
    Id: FheUintId,
{
    type Output = FheUint<Id>;

    /// Subtracts two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0u16, &client_key);
    /// let b = FheUint16::encrypt(1u16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_sub(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 0u16.wrapping_sub(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     0u16.overflowing_sub(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key.key.unsigned_overflowing_sub_parallelized(
                    &self.ciphertext.on_cpu(),
                    &other.ciphertext.on_cpu(),
                );
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support overflowing_sub yet");
            }
        })
    }
}

impl<Id> OverflowingSub<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Subtracts two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0u16, &client_key);
    /// let b = FheUint16::encrypt(1u16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_sub(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 0u16.wrapping_sub(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     0u16.overflowing_sub(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingSub<&Self>>::overflowing_sub(&self, other)
    }
}

impl<Id, Clear> OverflowingSub<Clear> for &FheUint<Id>
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = FheUint<Id>;

    /// Subtracts a [FheUint] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0u16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_sub(1u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 0u16.wrapping_sub(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     0u16.overflowing_sub(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Clear) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .unsigned_overflowing_scalar_sub_parallelized(&self.ciphertext.on_cpu(), other);
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support overflowing_add yet");
            }
        })
    }
}

impl<Id, Clear> OverflowingSub<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = Self;

    /// Subtracts a [FheUint] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0u16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_sub(1u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 0u16.wrapping_sub(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     0u16.overflowing_sub(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Clear) -> (Self::Output, FheBool) {
        <&Self as OverflowingSub<Clear>>::overflowing_sub(&self, other)
    }
}

impl<Id> OverflowingMul<Self> for &FheUint<Id>
where
    Id: FheUintId,
{
    type Output = FheUint<Id>;

    /// Multiplies two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(3434u16, &client_key);
    /// let b = FheUint16::encrypt(54u16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_mul(&b);
    /// let (expected_result, expected_overflowed) = 3434u16.overflowing_mul(54u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflowed);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_mul(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key.key.unsigned_overflowing_mul_parallelized(
                    &self.ciphertext.on_cpu(),
                    &other.ciphertext.on_cpu(),
                );
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support overflowing_mul");
            }
        })
    }
}

impl<Id> OverflowingMul<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Multiplies two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(3434u16, &client_key);
    /// let b = FheUint16::encrypt(54u16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_mul(&b);
    /// let (expected_result, expected_overflowed) = 3434u16.overflowing_mul(54u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflowed);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_mul(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingMul<&Self>>::overflowing_mul(&self, other)
    }
}

impl<FromId, IntoId> CastFrom<FheInt<FromId>> for FheUint<IntoId>
where
    FromId: FheIntId,
    IntoId: FheUintId,
{
    /// Cast a FheInt to an FheUint
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt32, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheInt32::encrypt(i32::MIN, &client_key);
    /// let b = FheUint16::cast_from(a);
    ///
    /// let decrypted: u16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MIN as u16);
    /// ```
    fn cast_from(input: FheInt<FromId>) -> Self {
        global_state::with_internal_keys(|keys| {
            #[allow(irrefutable_let_patterns)]
            let InternalServerKey::Cpu(integer_key) = keys
            else {
                panic!("Cuda devices do not support signed integers");
            };
            let casted = integer_key.pbs_key().cast_to_unsigned(
                input.ciphertext,
                IntoId::num_blocks(integer_key.message_modulus()),
            );
            Self::new(casted)
        })
    }
}

impl<FromId, IntoId> CastFrom<FheUint<FromId>> for FheUint<IntoId>
where
    FromId: FheUintId,
    IntoId: FheUintId,
{
    /// Cast FheUint to another FheUint
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16, FheUint32};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheUint32::encrypt(u32::MAX, &client_key);
    /// let b = FheUint16::cast_from(a);
    ///
    /// let decrypted: u16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MAX as u16);
    /// ```
    fn cast_from(input: FheUint<FromId>) -> Self {
        global_state::with_internal_keys(|keys| {
            #[allow(irrefutable_let_patterns)]
            let InternalServerKey::Cpu(integer_key) = keys
            else {
                panic!("Cuda devices do not support casting unsigned integers");
            };
            let casted = integer_key.pbs_key().cast_to_unsigned(
                input.ciphertext.on_cpu().into_owned(),
                IntoId::num_blocks(integer_key.message_modulus()),
            );
            Self::new(casted)
        })
    }
}

impl<Id> CastFrom<FheBool> for FheUint<Id>
where
    Id: FheUintId,
{
    /// Cast a boolean ciphertext to an unsigned ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheUint16::cast_from(a);
    ///
    /// let decrypted: u16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, u16::from(true));
    /// ```
    fn cast_from(input: FheBool) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertext: crate::integer::RadixCiphertext = input
                    .ciphertext
                    .on_cpu()
                    .into_owned()
                    .into_radix(Id::num_blocks(cpu_key.message_modulus()), cpu_key.pbs_key());
                Self::new(ciphertext)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support casting yet");
            }
        })
    }
}

impl<Id> std::iter::Sum<Self> for FheUint<Id>
where
    Id: FheUintId,
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
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    ///
    /// let clears = [1, 2, 3, 4, 5];
    /// let encrypted = clears
    ///     .iter()
    ///     .copied()
    ///     .map(|x| FheUint16::encrypt(x, &client_key))
    ///     .collect::<Vec<_>>();
    ///
    /// // Iter and sum consuming (moving out) from the original Vec
    /// let result = encrypted.into_iter().sum::<FheUint16>();
    ///
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, clears.into_iter().sum::<u16>());
    /// ```
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertexts = iter.map(|elem| elem.ciphertext.into_cpu()).collect();
                cpu_key
                    .key
                    .unchecked_sum_ciphertexts_vec_parallelized(ciphertexts)
                    .map_or_else(
                        || {
                            Self::new(RadixCiphertext::Cpu(cpu_key.key.create_trivial_zero_radix(
                                Id::num_blocks(cpu_key.message_modulus()),
                            )))
                        },
                        Self::new,
                    )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let mut iter = iter;
                // TODO have a proper impl on cuda side
                with_thread_local_cuda_stream(|stream| {
                    let mut result = iter.next().unwrap().ciphertext.on_gpu().duplicate(stream);

                    for rhs in iter {
                        cuda_key
                            .key
                            .add_assign(&mut result, &rhs.ciphertext.on_gpu(), stream);
                    }

                    Self::new(result)
                })
            }
        })
    }
}

impl<'a, Id> std::iter::Sum<&'a Self> for FheUint<Id>
where
    Id: FheUintId,
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
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    ///
    /// let clears = [1, 2, 3, 4, 5];
    /// let encrypted = clears
    ///     .iter()
    ///     .copied()
    ///     .map(|x| FheUint16::encrypt(x, &client_key))
    ///     .collect::<Vec<_>>();
    ///
    /// // Iter and sum on references
    /// let result = encrypted.iter().sum::<FheUint16>();
    ///
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, clears.into_iter().sum::<u16>());
    /// ```
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertexts = iter
                    .map(|elem| elem.ciphertext.on_cpu().to_owned())
                    .collect();
                let msg_mod = cpu_key.pbs_key().message_modulus();
                cpu_key
                    .key
                    .unchecked_sum_ciphertexts_vec_parallelized(ciphertexts)
                    .map_or_else(
                        || {
                            Self::new(RadixCiphertext::Cpu(
                                cpu_key
                                    .key
                                    .create_trivial_zero_radix(Id::num_blocks(msg_mod)),
                            ))
                        },
                        Self::new,
                    )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let mut iter = iter;
                // TODO have a proper impl on cuda side
                with_thread_local_cuda_stream(|stream| {
                    let mut result = iter.next().unwrap().ciphertext.on_gpu().duplicate(stream);

                    for rhs in iter {
                        cuda_key
                            .key
                            .add_assign(&mut result, &rhs.ciphertext.on_gpu(), stream);
                    }

                    Self::new(result)
                })
            }
        })
    }
}

impl<Id> FheMax<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Returns the max between two [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.max(&b);
    ///
    /// let decrypted_max: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_max, 1u16.max(2u16));
    /// ```
    fn max(&self, rhs: &Self) -> Self::Output {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .max_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                Self::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result =
                    cuda_key
                        .key
                        .max(&self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                Self::new(inner_result)
            }),
        })
    }
}

impl<Id, Clear> FheMax<Clear> for FheUint<Id>
where
    Clear: DecomposableInto<u64>,
    Id: FheUintId,
{
    type Output = Self;

    /// Returns the max between [FheUint] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.max(b);
    ///
    /// let decrypted_max: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_max, 1u16.max(2u16));
    /// ```
    fn max(&self, rhs: Clear) -> Self::Output {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_max_parallelized(&*self.ciphertext.on_cpu(), rhs);
                Self::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key
                    .key
                    .scalar_max(&self.ciphertext.on_gpu(), rhs, stream);
                Self::new(inner_result)
            }),
        })
    }
}

impl<Id> FheMin<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Returns the min between two [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.min(&b);
    ///
    /// let decrypted_min: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_min, 1u16.min(2u16));
    /// ```
    fn min(&self, rhs: &Self) -> Self::Output {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .min_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                Self::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result =
                    cuda_key
                        .key
                        .min(&self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                Self::new(inner_result)
            }),
        })
    }
}

impl<Id, Clear> FheMin<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: DecomposableInto<u64>,
{
    type Output = Self;

    /// Returns the min between [FheUint] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.min(b);
    ///
    /// let decrypted_min: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_min, 1u16.min(2u16));
    /// ```
    fn min(&self, rhs: Clear) -> Self::Output {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_min_parallelized(&*self.ciphertext.on_cpu(), rhs);
                Self::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key
                    .key
                    .scalar_min(&self.ciphertext.on_gpu(), rhs, stream);
                Self::new(inner_result)
            }),
        })
    }
}

impl<Id> FheEq<Self> for FheUint<Id>
where
    Id: FheUintId,
{
    fn eq(&self, rhs: Self) -> FheBool {
        self.eq(&rhs)
    }

    fn ne(&self, rhs: Self) -> FheBool {
        self.ne(&rhs)
    }
}

impl<Id> FheEq<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    /// Test for equality between two [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.eq(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 == 2u16);
    /// ```
    fn eq(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .eq_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result =
                    cuda_key
                        .key
                        .eq(&self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for difference between two [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.ne(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 != 2u16);
    /// ```
    fn ne(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .ne_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result =
                    cuda_key
                        .key
                        .ne(&self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }
}

impl<Id, Clear> FheEq<Clear> for FheUint<Id>
where
    Clear: DecomposableInto<u64>,
    Id: FheUintId,
{
    /// Test for equality between a [FheUint] and a clear
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.eq(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 == 2u16);
    /// ```
    fn eq(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_eq_parallelized(&*self.ciphertext.on_cpu(), rhs);
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support equality with clear");
            }
        })
    }

    /// Test for difference between a [FheUint] and a clear
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.ne(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 != 2u16);
    /// ```
    fn ne(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_ne_parallelized(&*self.ciphertext.on_cpu(), rhs);
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("cuda devices do not support difference with clear")
            }
        })
    }
}

impl<Id> FheOrd<Self> for FheUint<Id>
where
    Id: FheUintId,
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

impl<Id> FheOrd<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    /// Test for less than between two [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.lt(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 < 2u16);
    /// ```
    fn lt(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .lt_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result =
                    cuda_key
                        .key
                        .lt(&self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for less than or equal between two [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.le(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 <= 2u16);
    /// ```
    fn le(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .le_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result =
                    cuda_key
                        .key
                        .le(&self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for greater than between two [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.gt(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 > 2u16);
    /// ```
    fn gt(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .gt_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result =
                    cuda_key
                        .key
                        .gt(&self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for greater than or equal between two [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.gt(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 > 2u16);
    /// ```
    fn ge(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .ge_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result =
                    cuda_key
                        .key
                        .ge(&self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }
}

impl<Id, Clear> FheOrd<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: DecomposableInto<u64>,
{
    /// Test for less than between a [FheUint] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.lt(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 < 2u16);
    /// ```
    fn lt(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_lt_parallelized(&*self.ciphertext.on_cpu(), rhs);
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key
                    .key
                    .scalar_lt(&self.ciphertext.on_gpu(), rhs, stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for less than or equal between a [FheUint] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.le(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 <= 2u16);
    /// ```
    fn le(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_le_parallelized(&*self.ciphertext.on_cpu(), rhs);
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key
                    .key
                    .scalar_le(&self.ciphertext.on_gpu(), rhs, stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for greater than between a [FheUint] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.gt(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 > 2u16);
    /// ```
    fn gt(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_gt_parallelized(&*self.ciphertext.on_cpu(), rhs);
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key
                    .key
                    .scalar_gt(&self.ciphertext.on_gpu(), rhs, stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for greater than or equal between a [FheUint] and a clear value
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.ge(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 >= 2u16);
    /// ```
    fn ge(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_ge_parallelized(&*self.ciphertext.on_cpu(), rhs);
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key
                    .key
                    .scalar_ge(&self.ciphertext.on_gpu(), rhs, stream);
                FheBool::new(inner_result)
            }),
        })
    }
}

impl<Id> FheBootstrap for FheUint<Id>
where
    Id: FheUintId,
    crate::integer::wopbs::WopbsKey: super::wopbs::WopbsEvaluationKey<
        crate::integer::ServerKey,
        crate::integer::RadixCiphertext,
    >,
{
    fn map<F: Fn(u64) -> u64>(&self, func: F) -> Self {
        use super::wopbs::WopbsEvaluationKey;
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let res = cpu_key
                    .wopbs_key
                    .as_ref()
                    .expect("Function evaluation on integers was not enabled in the config")
                    .apply_wopbs(cpu_key.pbs_key(), &*self.ciphertext.on_cpu(), func);
                Self::new(res)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support function evaluation yet");
            }
        })
    }

    fn apply<F: Fn(u64) -> u64>(&mut self, func: F) {
        let result = self.map(func);
        *self = result;
    }
}

impl<Id> FheUint<Id>
where
    Id: FheUintId,
    crate::integer::wopbs::WopbsKey: super::wopbs::WopbsEvaluationKey<
        crate::integer::ServerKey,
        crate::integer::RadixCiphertext,
    >,
{
    pub fn bivariate_function<F>(&self, other: &Self, func: F) -> Self
    where
        F: Fn(u64, u64) -> u64,
    {
        use super::wopbs::WopbsEvaluationKey;
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let lhs = self.ciphertext.on_cpu();
                let rhs = other.ciphertext.on_cpu();
                let res = cpu_key
                    .wopbs_key
                    .as_ref()
                    .expect("Function evaluation on integers was not enabled in the config")
                    .apply_bivariate_wopbs(cpu_key.pbs_key(), &*lhs, &*rhs, func);
                Self::new(res)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support bivariate functions yet");
            }
        })
    }
}

impl<Id> DivRem<Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: Self) -> Self::Output {
        <Self as DivRem<&Self>>::div_rem(self, &rhs)
    }
}

impl<Id> DivRem<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: &Self) -> Self::Output {
        <&Self as DivRem<&Self>>::div_rem(&self, rhs)
    }
}

impl<Id> DivRem<Self> for &FheUint<Id>
where
    Id: FheUintId,
{
    type Output = (FheUint<Id>, FheUint<Id>);

    /// Computes the quotient and remainder between two [FheUint]
    ///
    /// If you need both the quotient and remainder, then `div_rem` is better
    /// than computing them separately using `/` and `%`.
    ///
    /// # Notes
    ///
    /// When the divisor is 0, the returned quotient will be the max value (i.e. all bits set to 1),
    /// the remainder will be the value of the numerator.
    ///
    /// This behaviour should not be relied on.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(23u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let (quotient, remainder) = (&a).div_rem(&b);
    ///
    /// let quotient: u16 = quotient.decrypt(&client_key);
    /// assert_eq!(quotient, 23u16 / 3u16);
    /// let remainder: u16 = remainder.decrypt(&client_key);
    /// assert_eq!(remainder, 23u16 % 3u16);
    /// ```
    fn div_rem(self, rhs: Self) -> Self::Output {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (q, r) = cpu_key
                    .pbs_key()
                    .div_rem_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                (FheUint::<Id>::new(q), FheUint::<Id>::new(r))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support division yet");
            }
        })
    }
}

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
                            global_state::with_internal_keys(|key| {
                                match key {
                                    InternalServerKey::Cpu(cpu_key) => {
                                        cpu_key.pbs_key().$key_method(&*self.ciphertext.on_cpu(), rhs)
                                    }
                                    #[cfg(feature = "gpu")]
                                    InternalServerKey::Cuda(_) => {
                                        panic!("Cuda devices do not support div_rem yet");
                                    }
                                }
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
    key_method: scalar_div_rem_parallelized,
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);

// Ciphertext/Ciphertext operators
macro_rules! generic_integer_impl_operation (
    (
        $(#[$outer:meta])*
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        implem: {
            $closure:expr
        }
        $(,)?
    ) => {

        impl<Id, B> $rust_trait_name<B> for FheUint<Id>
        where
            Id: FheUintId,
            B: Borrow<Self>,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                <&Self as $rust_trait_name<B>>::$rust_trait_method(&self, rhs)
            }

        }

        impl<Id, B> $rust_trait_name<B> for &FheUint<Id>
        where
            Id: FheUintId,
            B: Borrow<FheUint<Id>>,
        {
            type Output = FheUint<Id>;

            $(#[$outer])*
            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                $closure(self, rhs.borrow())
            }
        }
    }
);
generic_integer_impl_operation!(
   /// Adds two [FheUint]
   ///
   /// The operation is modular, i.e on overflow it wraps around.
   ///
   /// # Example
   ///
   /// ```rust
   /// # use tfhe::prelude::*;
   /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
   /// #
   /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
   /// set_server_key(server_key);
   ///
   /// let a = FheUint16::encrypt(23u16, &client_key);
   /// let b = FheUint16::encrypt(3u16, &client_key);
   ///
   /// let result = &a + &b;
   /// let result: u16 = result.decrypt(&client_key);
   /// assert_eq!(result, 23u16 + 3u16);
   /// ```
   rust_trait: Add(add),
   implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .add_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheUint::new(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        let inner_result = cuda_key.key
                            .add(&lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                        FheUint::new(inner_result)
                    })
                }
            })
        }
   },
);
generic_integer_impl_operation!(
   /// Subtracts two [FheUint]
   ///
   /// The operation is modular, i.e on overflow it wraps around.
   ///
   /// # Example
   ///
   /// ```rust
   /// # use tfhe::prelude::*;
   /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
   /// #
   /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
   /// set_server_key(server_key);
   ///
   /// let a = FheUint16::encrypt(3u16, &client_key);
   /// let b = FheUint16::encrypt(37849u16, &client_key);
   ///
   /// let result = &a - &b;
   /// let result: u16 = result.decrypt(&client_key);
   /// assert_eq!(result, 3u16.wrapping_sub(37849u16));
   /// ```
   rust_trait: Sub(sub),
   implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .sub_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheUint::new(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        let inner_result = cuda_key.key
                            .sub(&lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                        FheUint::new(inner_result)
                    })
                }
            })
        }
   },
);
generic_integer_impl_operation!(
   /// Multiplies two [FheUint]
   ///
   /// The operation is modular, i.e on overflow it wraps around.
   ///
   /// # Example
   ///
   /// ```rust
   /// # use tfhe::prelude::*;
   /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
   /// #
   /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
   /// set_server_key(server_key);
   ///
   /// let a = FheUint16::encrypt(3u16, &client_key);
   /// let b = FheUint16::encrypt(37849u16, &client_key);
   ///
   /// let result = &a * &b;
   /// let result: u16 = result.decrypt(&client_key);
   /// assert_eq!(result, 3u16.wrapping_mul(37849u16));
   /// ```
   rust_trait: Mul(mul),
   implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .mul_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheUint::new(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                     with_thread_local_cuda_stream(|stream| {
                        let inner_result = cuda_key.key
                            .mul(&lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                        FheUint::new(inner_result)
                    })
                }
            })
        }
   },
);
generic_integer_impl_operation!(
   /// Performs a bitwise 'and' between two [FheUint]
   ///
   /// # Example
   ///
   /// ```rust
   /// # use tfhe::prelude::*;
   /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
   /// #
   /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
   /// set_server_key(server_key);
   ///
   /// let a = FheUint16::encrypt(3u16, &client_key);
   /// let b = FheUint16::encrypt(37849u16, &client_key);
   ///
   /// let result = &a & &b;
   /// let result: u16 = result.decrypt(&client_key);
   /// assert_eq!(result,  3u16 & 37849u16);
   /// ```
   rust_trait: BitAnd(bitand),
   implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .bitand_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheUint::new(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                     with_thread_local_cuda_stream(|stream| {
                        let inner_result = cuda_key.key
                            .bitand(&lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                        FheUint::new(inner_result)
                    })
                }
            })
        }
   },
);
generic_integer_impl_operation!(
   /// Performs a bitwise 'or' between two [FheUint]
   ///
   /// # Example
   ///
   /// ```rust
   /// # use tfhe::prelude::*;
   /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
   /// #
   /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
   /// set_server_key(server_key);
   ///
   /// let a = FheUint16::encrypt(3u16, &client_key);
   /// let b = FheUint16::encrypt(37849u16, &client_key);
   ///
   /// let result = &a | &b;
   /// let result: u16 = result.decrypt(&client_key);
   /// assert_eq!(result,  3u16 | 37849u16);
   /// ```
   rust_trait: BitOr(bitor),
   implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .bitor_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheUint::new(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                     with_thread_local_cuda_stream(|stream| {
                        let inner_result = cuda_key.key
                            .bitor(&lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                        FheUint::new(inner_result)
                    })
                }
            })
        }
   },
);
generic_integer_impl_operation!(
   /// Performs a bitwise 'xor' between two [FheUint]
   ///
   /// # Example
   ///
   /// ```rust
   /// # use tfhe::prelude::*;
   /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
   /// #
   /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
   /// set_server_key(server_key);
   ///
   /// let a = FheUint16::encrypt(3u16, &client_key);
   /// let b = FheUint16::encrypt(37849u16, &client_key);
   ///
   /// let result = &a ^ &b;
   /// let result: u16 = result.decrypt(&client_key);
   /// assert_eq!(result,  3u16 ^ 37849u16);
   /// ```
   rust_trait: BitXor(bitxor),
   implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .bitxor_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheUint::new(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                     with_thread_local_cuda_stream(|stream| {
                        let inner_result = cuda_key.key
                            .bitxor(&lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                        FheUint::new(inner_result)
                    })
                }
            })
        }
   },
);
generic_integer_impl_operation!(
   /// Divides two [FheUint] and returns the quotient
   ///
   /// # Note
   ///
   /// If you need both the quotient and remainder, then prefer to use
   /// [FheUint::div_rem], instead of using `/` and `%` separately.
   ///
   /// When the divisor is 0, the returned quotient will be the max value (i.e. all bits set to 1).
   ///
   /// This behaviour should not be relied on.
   ///
   /// # Example
   ///
   /// ```rust
   /// # use tfhe::prelude::*;
   /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
   /// #
   /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
   /// set_server_key(server_key);
   ///
   /// let a = FheUint16::encrypt(37849u16, &client_key);
   /// let b = FheUint16::encrypt(3u16, &client_key);
   ///
   /// let result = &a / &b;
   /// let result: u16 = result.decrypt(&client_key);
   /// assert_eq!(result, 37849u16 / 3u16);
   /// ```
   rust_trait: Div(div),
   implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .div_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheUint::new(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_cuda_key) => {
                    panic!("Division '/' is not yet supported by Cuda devices")
                }
            })
        }
   },
);
generic_integer_impl_operation!(
   /// Divides two [FheUint] and returns the remainder
   ///
   /// # Note
   ///
   /// If you need both the quotient and remainder, then prefer to use
   /// [FheUint::div_rem], instead of using `/` and `%` separately.
   ///
   /// When the divisor is 0, the returned remainder will have the value of the numerator.
   ///
   /// This behaviour should not be relied on.
   ///
   /// # Example
   ///
   /// ```rust
   /// # use tfhe::prelude::*;
   /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
   /// #
   /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
   /// set_server_key(server_key);
   ///
   /// let a = FheUint16::encrypt(37849u16, &client_key);
   /// let b = FheUint16::encrypt(3u16, &client_key);
   ///
   /// let result = &a % &b;
   /// let result: u16 = result.decrypt(&client_key);
   /// assert_eq!(result, 37849u16 % 3u16);
   /// ```
   rust_trait: Rem(rem),
   implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .rem_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheUint::new(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_cuda_key) => {
                   panic!("Remainder/Modulo '%' is not yet supported by Cuda devices")
                }
            })
        }
   },
);
// Shifts and rotations are special cases where the right hand side
// is for now, required to be a unsigned integer type.
// And its constraints are a bit relaxed: rhs does not needs to have the same
// amount a bits.
macro_rules! generic_integer_impl_shift_rotate (
    (
        $(#[$outer:meta])*
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        implem: {
            $closure:expr
        }
        $(,)?
    ) => {

        // a op b
        impl<Id, Id2> $rust_trait_name<FheUint<Id2>> for FheUint<Id>
        where
            Id: FheUintId,
            Id2: FheUintId,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: FheUint<Id2>) -> Self::Output {
                <&Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(&self, &rhs)
            }

        }

        // a op &b
        impl<Id, Id2> $rust_trait_name<&FheUint<Id2>> for FheUint<Id>
        where
            Id: FheUintId,
            Id2: FheUintId,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: &FheUint<Id2>) -> Self::Output {
                <&Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(&self, rhs)
            }

        }

        // &a op b
        impl<Id, Id2> $rust_trait_name<FheUint<Id2>> for &FheUint<Id>
        where
            Id: FheUintId,
            Id2: FheUintId,
        {
            type Output = FheUint<Id>;

            fn $rust_trait_method(self, rhs: FheUint<Id2>) -> Self::Output {
                <Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(self, &rhs)
            }
        }

        // &a op &b
        impl<Id, Id2> $rust_trait_name<&FheUint<Id2>> for &FheUint<Id>
        where
            Id: FheUintId,
            Id2: FheUintId,
        {
            type Output = FheUint<Id>;

            $(#[$outer])*
            fn $rust_trait_method(self, rhs: &FheUint<Id2>) -> Self::Output {
                 $closure(self, rhs.borrow())
            }
        }
    }
);
generic_integer_impl_shift_rotate!(
   /// Performs a bitwise left shift of a [FheUint] by another [FheUint]
   ///
   ///
   /// # Example
   ///
   /// ```rust
   /// # use tfhe::prelude::*;
   /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
   /// #
   /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
   /// set_server_key(server_key);
   ///
   /// let a = FheUint16::encrypt(37849u16, &client_key);
   /// let b = FheUint16::encrypt(3u16, &client_key);
   ///
   /// let result = &a << &b;
   /// let result: u16 = result.decrypt(&client_key);
   /// assert_eq!(result, 37849u16 << 3u16);
   /// ```
    rust_trait: Shl(shl),
    implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| {
                match key {
                    InternalServerKey::Cpu(cpu_key) => {
                        let ciphertext = cpu_key
                            .pbs_key()
                            .left_shift_parallelized(&*lhs.ciphertext.on_cpu(), &rhs.ciphertext.on_cpu());
                        FheUint::new(ciphertext)
                    }
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(_) => {
                        panic!("Shl '<<' is not yet supported by Cuda devices")
                    }
                }
            })
        }
    }
);
generic_integer_impl_shift_rotate!(
    /// Performs a bitwise right shift of a [FheUint] by another [FheUint]
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(37849u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = &a >> &b;
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 37849u16 >> 3u16);
    /// ```
    rust_trait: Shr(shr),
    implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| {
                match key {
                    InternalServerKey::Cpu(cpu_key) => {
                        let ciphertext = cpu_key
                            .pbs_key()
                            .right_shift_parallelized(&*lhs.ciphertext.on_cpu(), &rhs.ciphertext.on_cpu());
                        FheUint::new(ciphertext)
                    }
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(_) => {
                        panic!("Shr '>>' is not yet supported by Cuda devices")
                    }
                }
            })
        }
    }
);
generic_integer_impl_shift_rotate!(
    /// Performs a bitwise left rotation of a [FheUint] by another [FheUint]
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(37849u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = (&a).rotate_left(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 37849u16.rotate_left(3));
    /// ```
    rust_trait: RotateLeft(rotate_left),
    implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| {
                match key {
                    InternalServerKey::Cpu(cpu_key) => {
                        let ciphertext = cpu_key
                            .pbs_key()
                            .rotate_left_parallelized(&*lhs.ciphertext.on_cpu(), &rhs.ciphertext.on_cpu());
                        FheUint::new(ciphertext)
                    }
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(_) => {
                       panic!("RotateLeft is not yet supported by Cuda devices")
                    }
                }
            })
        }
    }
);
generic_integer_impl_shift_rotate!(
    /// Performs a bitwise right rotation of a [FheUint] by another [FheUint]
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(37849u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = (&a).rotate_right(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 37849u16.rotate_right(3));
    /// ```
    rust_trait: RotateRight(rotate_right),
    implem: {
        |lhs: &FheUint<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| {
                match key {
                    InternalServerKey::Cpu(cpu_key) => {
                        let ciphertext = cpu_key
                            .pbs_key()
                            .rotate_right_parallelized(&*lhs.ciphertext.on_cpu(), &rhs.ciphertext.on_cpu());
                        FheUint::new(ciphertext)
                    }
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(_) => {
                        panic!("RotateRight is not yet supported by Cuda devices")
                    }
                }
            })
        }
    }
);

// Ciphertext/Ciphertext assign operations
// For these, macros would not reduce code by a lot so we don't use one
impl<Id, I> AddAssign<I> for FheUint<Id>
where
    Id: FheUintId,
    I: Borrow<Self>,
{
    /// Performs the `+=` operation on [FheUint]
    ///
    /// The operation is modular, i.e on overflow it wraps around.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(3u16, &client_key);
    /// let b = FheUint16::encrypt(37849u16, &client_key);
    ///
    /// a += &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3u16.wrapping_add(37849u16));
    /// ```
    fn add_assign(&mut self, rhs: I) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().add_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &*rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.add_assign(
                    self.ciphertext.as_gpu_mut(),
                    &rhs.ciphertext.on_gpu(),
                    stream,
                );
            }),
        })
    }
}
impl<Id, I> SubAssign<I> for FheUint<Id>
where
    Id: FheUintId,
    I: Borrow<Self>,
{
    /// Performs the `-=` operation on [FheUint]
    ///
    /// The operation is modular, i.e on overflow it wraps around.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(3u16, &client_key);
    /// let b = FheUint16::encrypt(37849u16, &client_key);
    ///
    /// a -= &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3u16.wrapping_sub(37849u16));
    /// ```
    fn sub_assign(&mut self, rhs: I) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().sub_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &*rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.sub_assign(
                    self.ciphertext.as_gpu_mut(),
                    &rhs.ciphertext.on_gpu(),
                    stream,
                );
            }),
        })
    }
}
impl<Id, I> MulAssign<I> for FheUint<Id>
where
    Id: FheUintId,
    I: Borrow<Self>,
{
    /// Performs the `*=` operation on [FheUint]
    ///
    /// The operation is modular, i.e on overflow it wraps around.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(3u16, &client_key);
    /// let b = FheUint16::encrypt(37849u16, &client_key);
    ///
    /// a *= &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3u16.wrapping_mul(37849u16));
    /// ```
    fn mul_assign(&mut self, rhs: I) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().mul_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &*rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.mul_assign(
                    self.ciphertext.as_gpu_mut(),
                    &rhs.ciphertext.on_gpu(),
                    stream,
                );
            }),
        })
    }
}
impl<Id, I> BitAndAssign<I> for FheUint<Id>
where
    Id: FheUintId,
    I: Borrow<Self>,
{
    /// Performs the `&=` operation on [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(3u16, &client_key);
    /// let b = FheUint16::encrypt(37849u16, &client_key);
    ///
    /// a &= &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3u16 & 37849u16);
    /// ```
    fn bitand_assign(&mut self, rhs: I) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().bitand_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &*rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.bitand_assign(
                    self.ciphertext.as_gpu_mut(),
                    &rhs.ciphertext.on_gpu(),
                    stream,
                );
            }),
        })
    }
}
impl<Id, I> BitOrAssign<I> for FheUint<Id>
where
    Id: FheUintId,
    I: Borrow<Self>,
{
    /// Performs the `&=` operation on [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(3u16, &client_key);
    /// let b = FheUint16::encrypt(37849u16, &client_key);
    ///
    /// a |= &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3u16 | 37849u16);
    /// ```
    fn bitor_assign(&mut self, rhs: I) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().bitor_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &*rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.bitor_assign(
                    self.ciphertext.as_gpu_mut(),
                    &rhs.ciphertext.on_gpu(),
                    stream,
                );
            }),
        })
    }
}
impl<Id, I> BitXorAssign<I> for FheUint<Id>
where
    Id: FheUintId,
    I: Borrow<Self>,
{
    /// Performs the `^=` operation on [FheUint]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(3u16, &client_key);
    /// let b = FheUint16::encrypt(37849u16, &client_key);
    ///
    /// a ^= &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3u16 ^ 37849u16);
    /// ```
    fn bitxor_assign(&mut self, rhs: I) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().bitxor_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &*rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.bitxor_assign(
                    self.ciphertext.as_gpu_mut(),
                    &rhs.ciphertext.on_gpu(),
                    stream,
                );
            }),
        })
    }
}
impl<Id, I> DivAssign<I> for FheUint<Id>
where
    Id: FheUintId,
    I: Borrow<Self>,
{
    /// Performs the `/=` operation on [FheUint]
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheUint::div_rem], instead of using `/` and `%` separately.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(37849u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a /= &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 37849u16 / 3u16);
    /// ```
    fn div_assign(&mut self, rhs: I) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().div_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &*rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support division");
            }
        })
    }
}
impl<Id, I> RemAssign<I> for FheUint<Id>
where
    Id: FheUintId,
    I: Borrow<Self>,
{
    /// Performs the `%=` operation on [FheUint]
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheUint::div_rem], instead of using `/` and `%` separately.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(37849u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a %= &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 37849u16 % 3u16);
    /// ```
    fn rem_assign(&mut self, rhs: I) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().rem_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &*rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support division");
            }
        })
    }
}

impl<Id, Id2> ShlAssign<FheUint<Id2>> for FheUint<Id>
where
    Id: FheUintId,
    Id2: FheUintId,
{
    fn shl_assign(&mut self, rhs: FheUint<Id2>) {
        <Self as ShlAssign<&FheUint<Id2>>>::shl_assign(self, &rhs)
    }
}

impl<Id, Id2> ShlAssign<&FheUint<Id2>> for FheUint<Id>
where
    Id: FheUintId,
    Id2: FheUintId,
{
    /// Performs the `<<=` operation on [FheUint]
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheUint::div_rem], instead of using `/` and `%` separately.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(37849u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a <<= &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 37849u16 << 3u16);
    /// ```
    fn shl_assign(&mut self, rhs: &FheUint<Id2>) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().left_shift_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support left shift with encrypted value");
            }
        })
    }
}
impl<Id, Id2> ShrAssign<FheUint<Id2>> for FheUint<Id>
where
    Id: FheUintId,
    Id2: FheUintId,
{
    fn shr_assign(&mut self, rhs: FheUint<Id2>) {
        <Self as ShrAssign<&FheUint<Id2>>>::shr_assign(self, &rhs)
    }
}

impl<Id, Id2> ShrAssign<&FheUint<Id2>> for FheUint<Id>
where
    Id: FheUintId,
    Id2: FheUintId,
{
    /// Performs the `>>=` operation on [FheUint]
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheUint::div_rem], instead of using `/` and `%` separately.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(37849u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a >>= &b;
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 37849u16 >> 3u16);
    /// ```
    fn shr_assign(&mut self, rhs: &FheUint<Id2>) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().right_shift_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support right shift with encrypted value");
            }
        })
    }
}

impl<Id, Id2> RotateLeftAssign<FheUint<Id2>> for FheUint<Id>
where
    Id: FheUintId,
    Id2: FheUintId,
{
    fn rotate_left_assign(&mut self, rhs: FheUint<Id2>) {
        <Self as RotateLeftAssign<&FheUint<Id2>>>::rotate_left_assign(self, &rhs)
    }
}

impl<Id, Id2> RotateLeftAssign<&FheUint<Id2>> for FheUint<Id>
where
    Id: FheUintId,
    Id2: FheUintId,
{
    /// Performs a left bit rotation and assign operation on [FheUint]
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheUint::div_rem], instead of using `/` and `%` separately.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(37849u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a.rotate_left_assign(&b);
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 37849u16.rotate_left(3));
    /// ```
    fn rotate_left_assign(&mut self, rhs: &FheUint<Id2>) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().rotate_left_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support rotate left with encrypted value");
            }
        })
    }
}

impl<Id, Id2> RotateRightAssign<FheUint<Id2>> for FheUint<Id>
where
    Id: FheUintId,
    Id2: FheUintId,
{
    fn rotate_right_assign(&mut self, rhs: FheUint<Id2>) {
        <Self as RotateRightAssign<&FheUint<Id2>>>::rotate_right_assign(self, &rhs)
    }
}

impl<Id, Id2> RotateRightAssign<&FheUint<Id2>> for FheUint<Id>
where
    Id: FheUintId,
    Id2: FheUintId,
{
    /// Performs a right bit rotation and assign operation on [FheUint]
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheUint::div_rem], instead of using `/` and `%` separately.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheUint16::encrypt(37849u16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a.rotate_right_assign(&b);
    /// let result: u16 = a.decrypt(&client_key);
    /// assert_eq!(result, 37849u16.rotate_right(3));
    /// ```
    fn rotate_right_assign(&mut self, rhs: &FheUint<Id2>) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                cpu_key.pbs_key().rotate_right_assign_parallelized(
                    self.ciphertext.as_cpu_mut(),
                    &rhs.ciphertext.on_cpu(),
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support rotate right with encrypted value");
            }
        })
    }
}

// Ciphertext/Scalar ops
macro_rules! generic_integer_impl_scalar_operation {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        implem: {
            // A closure that must return a RadixCiphertext
            $closure:expr
        },
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
                        let inner_result = $closure(self, rhs);
                        <$concrete_type>::new(inner_result)
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

generic_integer_impl_scalar_operation!(
    rust_trait: Add(add),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_add_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_add(
                            &lhs.ciphertext.on_gpu(), rhs, stream
                        )
                    });
                    RadixCiphertext::Cuda(inner_result)
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Sub(sub),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_sub_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                 InternalServerKey::Cuda(cuda_key) => {
                    let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_sub(
                            &lhs.ciphertext.on_gpu(), rhs, stream
                        )
                    });
                    RadixCiphertext::Cuda(inner_result)
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Mul(mul),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_mul_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_) => {
                    panic!("Mul '*' with clear value is not yet supported by Cuda devices")
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: BitAnd(bitand),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_bitand_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_bitand(
                            &lhs.ciphertext.on_gpu(), rhs, stream
                        )
                    });
                    RadixCiphertext::Cuda(inner_result)
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: BitOr(bitor),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_bitor_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_bitor(
                            &lhs.ciphertext.on_gpu(), rhs, stream
                        )
                    });
                    RadixCiphertext::Cuda(inner_result)
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: BitXor(bitxor),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_bitxor_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },

                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_bitxor(
                            &lhs.ciphertext.on_gpu(), rhs, stream
                        )
                    });
                    RadixCiphertext::Cuda(inner_result)
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Shl(shl),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_left_shift_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_left_shift(
                            &lhs.ciphertext.on_gpu(), u64::cast_from(rhs), stream
                        )
                    });
                    RadixCiphertext::Cuda(inner_result)
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8, u16, u32, u64, u128),
        (super::FheUint4, u8, u16, u32, u64, u128),
        (super::FheUint6, u8, u16, u32, u64, u128),
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint160, u8, u16, u32, u64, u128, U256),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Shr(shr),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_right_shift_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                   let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_right_shift(
                            &lhs.ciphertext.on_gpu(), u64::cast_from(rhs), stream
                        )
                    });
                    RadixCiphertext::Cuda(inner_result)
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8, u16, u32, u64, u128),
        (super::FheUint4, u8, u16, u32, u64, u128),
        (super::FheUint6, u8, u16, u32, u64, u128),
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint160, u8, u16, u32, u64, u128, U256),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: RotateLeft(rotate_left),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_rotate_left_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_rotate_left(
                            &lhs.ciphertext.on_gpu(), u64::cast_from(rhs), stream
                        )
                    });
                    RadixCiphertext::Cuda(inner_result)
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8, u16, u32, u64, u128),
        (super::FheUint4, u8, u16, u32, u64, u128),
        (super::FheUint6, u8, u16, u32, u64, u128),
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint160, u8, u16, u32, u64, u128, U256),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: RotateRight(rotate_right),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_rotate_right_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_rotate_right(
                            &lhs.ciphertext.on_gpu(), u64::cast_from(rhs), stream
                        )
                    });
                    RadixCiphertext::Cuda(inner_result)
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8, u16, u32, u64, u128),
        (super::FheUint4, u8, u16, u32, u64, u128),
        (super::FheUint6, u8, u16, u32, u64, u128),
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint160, u8, u16, u32, u64, u128, U256),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Div(div),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_div_parallelized(&lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_) => {
                    panic!("Div '/' with clear value is not yet supported by Cuda devices")
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Rem(rem),
    implem: {
        |lhs: &FheUint<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .scalar_rem_parallelized(&lhs.ciphertext.on_cpu(), rhs);
                   RadixCiphertext::Cpu(inner_result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_) => {
                    panic!("Rem '%' with clear value is not yet supported by Cuda devices")
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);

// Scalar / Ciphertext ops
macro_rules! generic_integer_impl_scalar_left_operation {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        implem: {
            // A closure that must return a RadixCiphertext
            $closure:expr
        },
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($(#[$doc:meta])* $scalar_type:ty),*)
        ),*
        $(,)?
    ) => {
        $( // First repeating pattern
            $( // Second repeating pattern

                // clear $op ciphertext
                impl $rust_trait_name<$concrete_type> for $scalar_type
                {
                    type Output = $concrete_type;

                    fn $rust_trait_method(self, rhs: $concrete_type) -> Self::Output {
                        <&Self as $rust_trait_name<&$concrete_type>>::$rust_trait_method(&self, &rhs)
                    }
                }

                // clear $op &ciphertext
                impl $rust_trait_name<&$concrete_type> for $scalar_type
                {
                    type Output = $concrete_type;

                    fn $rust_trait_method(self, rhs: &$concrete_type) -> Self::Output {
                        <&Self as $rust_trait_name<&$concrete_type>>::$rust_trait_method(&self, rhs)
                    }
                }

                // &clear $op ciphertext
                impl $rust_trait_name<$concrete_type> for &$scalar_type
                {
                    type Output = $concrete_type;

                    fn $rust_trait_method(self, rhs: $concrete_type) -> Self::Output {
                        <Self as $rust_trait_name<&$concrete_type>>::$rust_trait_method(self, &rhs)
                    }
                }

                // &clear $op &ciphertext
                impl $rust_trait_name<&$concrete_type> for &$scalar_type
                {
                    type Output = $concrete_type;

                    $(#[$doc])*
                    fn $rust_trait_method(self, rhs: &$concrete_type) -> Self::Output {
                        let inner_result = $closure(*self, rhs);
                        <$concrete_type>::new(inner_result)
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

generic_integer_impl_scalar_left_operation!(
    rust_trait: Add(add),
    implem: {
        |lhs, rhs: &FheUint<_>| {
            // `+` is commutative
            let result: FheUint<_> = rhs + lhs;
            result.ciphertext
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16,
            /// Adds a [super::FheUint16] to a clear
            ///
            /// The operation is modular, i.e on overflow it wraps around.
            ///
            /// # Example
            ///
            /// ```rust
            /// # use tfhe::prelude::*;
            /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            /// #
            /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
            /// set_server_key(server_key);
            ///
            /// let a = 23u16;
            /// let b = FheUint16::encrypt(3u16, &client_key);
            ///
            /// let result = a + &b;
            /// let result: u16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23u16 + 3u16);
            /// ```
            u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_left_operation!(
    rust_trait: Sub(sub),
    implem: {
        |lhs, rhs: &FheUint<_>| {
            // `-` is not commutative, so we resort to converting to trivial
            // which should give same perf
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let mut result = cpu_key
                        .pbs_key()
                        .create_trivial_radix(lhs, rhs.ciphertext.on_cpu().blocks().len());
                    cpu_key
                        .pbs_key()
                        .sub_assign_parallelized(&mut result, &*rhs.ciphertext.on_cpu());
                    RadixCiphertext::Cpu(result)
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        let mut result = cuda_key.key.create_trivial_radix(lhs, rhs.ciphertext.on_gpu().info.blocks.len(), stream);
                        cuda_key.key.sub_assign(&mut result, &rhs.ciphertext.on_gpu(), stream);
                        RadixCiphertext::Cuda(result)
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16,
            /// Subtract a [super::FheUint16] to a clear
            ///
            /// The operation is modular, i.e on overflow it wraps around.
            ///
            /// # Example
            ///
            /// ```rust
            /// # use tfhe::prelude::*;
            /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            /// #
            /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
            /// set_server_key(server_key);
            ///
            /// let a = 23u16;
            /// let b = FheUint16::encrypt(3u16, &client_key);
            ///
            /// let result = a - &b;
            /// let result: u16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23u16 - 3u16);
            /// ```
            u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_left_operation!(
    rust_trait: Mul(mul),
    implem: {
        |lhs, rhs: &FheUint<_>| {
            // `*` is commutative
            let result: FheUint<_> = rhs * lhs;
            result.ciphertext
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16,
            /// Multiplies a [super::FheUint16] to a clear
            ///
            /// The operation is modular, i.e on overflow it wraps around.
            ///
            /// # Example
            ///
            /// ```rust
            /// # use tfhe::prelude::*;
            /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            /// #
            /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
            /// set_server_key(server_key);
            ///
            /// let a = 23u16;
            /// let b = FheUint16::encrypt(3u16, &client_key);
            ///
            /// let result = a * &b;
            /// let result: u16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23u16 * 3u16);
            /// ```
            u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_left_operation!(
    rust_trait: BitAnd(bitand),
    implem: {
        |lhs, rhs: &FheUint<_>| {
            // `&` is commutative
            let result: FheUint<_> = rhs & lhs;
            result.ciphertext
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16,
            /// Performs a bitwise 'and' between a clear and [super::FheUint16]
            ///
            /// # Example
            ///
            /// ```rust
            /// # use tfhe::prelude::*;
            /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            /// #
            /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
            /// set_server_key(server_key);
            ///
            /// let a = 23u16;
            /// let b = FheUint16::encrypt(3u16, &client_key);
            ///
            /// let result = a & &b;
            /// let result: u16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23u16 & 3u16);
            /// ```
            u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_left_operation!(
    rust_trait: BitOr(bitor),
    implem: {
        |lhs, rhs: &FheUint<_>| {
            // `|` is commutative
            let result: FheUint<_> = rhs | lhs;
            result.ciphertext
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8,u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16,
            /// Performs a bitwise 'or' between a clear and [super::FheUint16]
            ///
            /// # Example
            ///
            /// ```rust
            /// # use tfhe::prelude::*;
            /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            /// #
            /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
            /// set_server_key(server_key);
            ///
            /// let a = 23u16;
            /// let b = FheUint16::encrypt(3u16, &client_key);
            ///
            /// let result = a | &b;
            /// let result: u16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23u16 | 3u16);
            /// ```
            u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_left_operation!(
    rust_trait: BitXor(bitxor),
    implem: {
        |lhs, rhs: &FheUint<_>| {
            // `^` is commutative
            let result: FheUint<_> = rhs ^ lhs;
            result.ciphertext
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16,
            /// Performs a bitwise 'xor' between a clear and [super::FheUint16]
            ///
            /// # Example
            ///
            /// ```rust
            /// # use tfhe::prelude::*;
            /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            /// #
            /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
            /// set_server_key(server_key);
            ///
            /// let a = 23u16;
            /// let b = FheUint16::encrypt(3u16, &client_key);
            ///
            /// let result = a ^ &b;
            /// let result: u16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23u16 ^ 3u16);
            /// ```
            u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);

// Scalar assign ops
macro_rules! generic_integer_impl_scalar_operation_assign {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        implem: {
            $closure:expr
        },
         // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($(#[$doc:meta])* $scalar_type:ty),*)
        ),*
        $(,)?
    ) => {
        $(
            $(
                impl $rust_trait_name<$scalar_type> for $concrete_type
                {
                    $(#[$doc])*
                    fn $rust_trait_method(&mut self, rhs: $scalar_type) {
                        $closure(self, rhs);
                    }
                }
            )*
        )*
    }
}

generic_integer_impl_scalar_operation_assign!(
    rust_trait: AddAssign(add_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_add_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                 InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_add_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16,
        /// Adds a clear to a [super::FheUint16]
        ///
        /// The operation is modular, i.e on overflow it wraps around.
        ///
        /// # Example
        ///
        /// ```rust
        /// # use tfhe::prelude::*;
        /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
        /// #
        /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
        /// set_server_key(server_key);
        ///
        /// let mut a = FheUint16::encrypt(3u16, &client_key);
        /// let b = 23u16;
        ///
        /// a += b;
        ///
        /// let result: u16 = a.decrypt(&client_key);
        /// assert_eq!(result, 23u16 + 3u16);
        /// ```
        u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: SubAssign(sub_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_sub_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_sub_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: MulAssign(mul_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_mul_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_) => {
                    panic!("MulAssign '*=' with clear value is not yet supported by Cuda devices")
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: BitAndAssign(bitand_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_bitand_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_bitand_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: BitOrAssign(bitor_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_bitor_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_bitor_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: BitXorAssign(bitxor_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_bitxor_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_bitxor_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: ShlAssign(shl_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_left_shift_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_left_shift_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8, u16, u32, u64, u128),
        (super::FheUint4, u8, u16, u32, u64, u128),
        (super::FheUint6, u8, u16, u32, u64, u128),
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint160, u8, u16, u32, u64, u128, U256),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: ShrAssign(shr_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_right_shift_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_right_shift_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8, u16, u32, u64, u128),
        (super::FheUint4, u8, u16, u32, u64, u128),
        (super::FheUint6, u8, u16, u32, u64, u128),
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint160, u8, u16, u32, u64, u128, U256),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RotateLeftAssign(rotate_left_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_rotate_left_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_rotate_left_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8, u16, u32, u64, u128),
        (super::FheUint4, u8, u16, u32, u64, u128),
        (super::FheUint6, u8, u16, u32, u64, u128),
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint160, u8, u16, u32, u64, u128, U256),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RotateRightAssign(rotate_right_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_rotate_right_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_rotate_right_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8, u16, u32, u64, u128),
        (super::FheUint4, u8, u16, u32, u64, u128),
        (super::FheUint6, u8, u16, u32, u64, u128),
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint160, u8, u16, u32, u64, u128, U256),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: DivAssign(div_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_div_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_) => {
                    panic!("DivAssign '/=' with clear value is not yet supported by Cuda devices")
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RemAssign(rem_assign),
    implem: {
         |lhs: &mut FheUint<_>, rhs| {
             global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .scalar_rem_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_) => {
                    panic!("RemAssign '%=' with clear value is not yet supported by Cuda devices")
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheUint2, u8),
        (super::FheUint4, u8),
        (super::FheUint6, u8),
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint160, U256),
        (super::FheUint256, U256),
);

impl<Id> Neg for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Computes the negation of a [FheUint].
    ///
    /// Since FheUint are usigned integers meaning the value they can
    /// represent is always positive, negating a FheUint will yield a
    /// positive number.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = -a;
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 3u16.wrapping_neg());
    /// ```
    fn neg(self) -> Self::Output {
        <&Self as Neg>::neg(&self)
    }
}

impl<Id> Neg for &FheUint<Id>
where
    Id: FheUintId,
{
    type Output = FheUint<Id>;

    /// Computes the negation of a [FheUint].
    ///
    /// Since FheUint are usigned integers meaning the value they can
    /// represent is always positive, negating a FheUint will yield a
    /// positive number.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = -&a;
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 3u16.wrapping_neg());
    /// ```
    fn neg(self) -> Self::Output {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertext = cpu_key
                    .pbs_key()
                    .neg_parallelized(&*self.ciphertext.on_cpu());
                FheUint::new(ciphertext)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key.key.neg(&self.ciphertext.on_gpu(), stream);
                FheUint::new(inner_result)
            }),
        })
    }
}

impl<Id> Not for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Performs a bitwise 'not'
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = !a;
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, !3u16);
    /// ```
    fn not(self) -> Self::Output {
        <&Self as Not>::not(&self)
    }
}

impl<Id> Not for &FheUint<Id>
where
    Id: FheUintId,
{
    type Output = FheUint<Id>;

    /// Performs a bitwise 'not'
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = !&a;
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, !3u16);
    /// ```
    fn not(self) -> Self::Output {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertext = cpu_key
                    .pbs_key()
                    .bitnot_parallelized(&*self.ciphertext.on_cpu());
                FheUint::new(ciphertext)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Not '!' is not yet supported by Cuda devices")
            }
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::conformance::ParameterSetConformant;
    use crate::core_crypto::prelude::UnsignedInteger;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use crate::shortint::{CiphertextModulus, PBSOrder};
    use crate::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
    use rand::{thread_rng, Rng};

    type IndexedParameterAccessor<Ct, T> = dyn Fn(usize, &mut Ct) -> &mut T;

    type IndexedParameterModifier<'a, Ct> = dyn Fn(usize, &mut Ct) + 'a;

    fn change_parameters<Ct, T: UnsignedInteger>(
        func: &IndexedParameterAccessor<Ct, T>,
    ) -> [Box<IndexedParameterModifier<'_, Ct>>; 3] {
        [
            Box::new(|i, ct| *func(i, ct) = T::ZERO),
            Box::new(|i, ct| *func(i, ct) = func(i, ct).wrapping_add(T::ONE)),
            Box::new(|i, ct| *func(i, ct) = func(i, ct).wrapping_sub(T::ONE)),
        ]
    }

    #[test]
    fn test_invalid_generic_integer() {
        type Ct = FheUint8;

        let config = ConfigBuilder::default().build();

        let (client_key, _server_key) = generate_keys(config);

        let ct = FheUint8::try_encrypt(0_u64, &client_key).unwrap();

        assert!(
            ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                4
            ))
        );

        let breaker_lists = [
            change_parameters(&|i, ct: &mut Ct| {
                &mut ct.ciphertext.as_cpu_mut().blocks[i].message_modulus.0
            }),
            change_parameters(&|i, ct: &mut Ct| {
                &mut ct.ciphertext.as_cpu_mut().blocks[i].carry_modulus.0
            }),
            change_parameters(&|i, ct: &mut Ct| {
                ct.ciphertext.as_cpu_mut().blocks[i].degree.as_mut()
            }),
        ];

        for breaker_list in breaker_lists {
            for breaker in breaker_list {
                for i in 0..ct.ciphertext.on_cpu().blocks.len() {
                    let mut ct_clone = ct.clone();

                    breaker(i, &mut ct_clone);

                    assert!(!ct_clone.is_conformant(
                        &RadixCiphertextConformanceParams::from_pbs_parameters(
                            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                            4
                        )
                    ));
                }
            }
        }
        let breakers2: Vec<&IndexedParameterModifier<'_, Ct>> = vec![
            &|i, ct: &mut Ct| {
                *ct.ciphertext.as_cpu_mut().blocks[i]
                    .ct
                    .get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new_power_of_2(1).unwrap();
            },
            &|i, ct: &mut Ct| {
                *ct.ciphertext.as_cpu_mut().blocks[i]
                    .ct
                    .get_mut_ciphertext_modulus() = CiphertextModulus::try_new(3).unwrap();
            },
            &|_i, ct: &mut Ct| {
                ct.ciphertext.as_cpu_mut().blocks.pop();
            },
            &|i, ct: &mut Ct| {
                let cloned_block = ct.ciphertext.on_cpu().blocks[i].clone();
                ct.ciphertext.as_cpu_mut().blocks.push(cloned_block);
            },
            &|i, ct: &mut Ct| {
                ct.ciphertext.as_cpu_mut().blocks[i].pbs_order = PBSOrder::BootstrapKeyswitch;
            },
        ];

        for breaker in breakers2 {
            for i in 0..ct.ciphertext.on_cpu().blocks.len() {
                let mut ct_clone = ct.clone();

                breaker(i, &mut ct_clone);

                assert!(!ct_clone.is_conformant(
                    &RadixCiphertextConformanceParams::from_pbs_parameters(
                        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                        4
                    )
                ));
            }
        }
    }

    #[test]
    fn test_valid_generic_integer() {
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config);

        set_server_key(server_key);

        let ct = FheUint8::try_encrypt(0_u64, &client_key).unwrap();

        assert!(
            ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                4
            ))
        );

        let mut rng = thread_rng();

        let num_blocks = ct.ciphertext.on_cpu().blocks.len();

        for _ in 0..10 {
            let mut ct_clone = ct.clone();

            for i in 0..num_blocks {
                ct_clone.ciphertext.as_cpu_mut().blocks[i]
                    .ct
                    .as_mut()
                    .fill_with(|| rng.gen::<u64>());
            }

            assert!(ct_clone.is_conformant(
                &RadixCiphertextConformanceParams::from_pbs_parameters(
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    4
                )
            ));

            ct_clone += &ct_clone.clone();
        }
    }
}
