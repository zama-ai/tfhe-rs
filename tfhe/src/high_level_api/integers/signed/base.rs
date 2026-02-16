use tfhe_versionable::Versionize;

use super::inner::SignedRadixCiphertext;
use crate::backward_compatibility::integers::FheIntVersions;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::SignedNumeric;
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::{FheIntegerType, FheUint, FheUintId, IntegerId};
use crate::high_level_api::keys::{CompactPublicKey, InternalServerKey};
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::traits::{FheWait, ReRandomize, Tagged};
use crate::integer::block_decomposition::{DecomposableInto, RecomposableSignedInteger};
use crate::integer::ciphertext::ReRandomizationSeed;
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::named::Named;
use crate::prelude::CastFrom;
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::shortint::AtomicPatternParameters;
use crate::{Device, FheBool, ServerKey, Tag};
use std::marker::PhantomData;

#[cfg(not(feature = "gpu"))]
type ExpectedInnerGpu = ();
#[cfg(feature = "gpu")]
type ExpectedInnerGpu = crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
pub trait FheIntId:
    IntegerId<InnerCpu = crate::integer::SignedRadixCiphertext, InnerGpu = ExpectedInnerGpu>
{
}

/// A Generic FHE signed integer
///
/// This struct is generic over some ID, as it's the ID
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
#[derive(Clone, serde::Deserialize, serde::Serialize, Versionize)]
#[versionize(FheIntVersions)]
pub struct FheInt<Id: FheIntId> {
    pub(in crate::high_level_api) ciphertext: SignedRadixCiphertext,
    pub(in crate::high_level_api) id: Id,
    pub(crate) tag: Tag,
    pub(crate) re_randomization_metadata: ReRandomizationMetadata,
}

#[derive(Copy, Clone)]
pub struct FheIntConformanceParams<Id: FheIntId> {
    pub(crate) params: RadixCiphertextConformanceParams,
    pub(crate) id: PhantomData<Id>,
}

impl<Id: FheIntId, P: Into<AtomicPatternParameters>> From<P> for FheIntConformanceParams<Id> {
    fn from(params: P) -> Self {
        let params = params.into();
        Self {
            params: RadixCiphertextConformanceParams {
                shortint_params: params.to_shortint_conformance_param(),
                num_blocks_per_integer: Id::num_blocks(params.message_modulus()),
            },
            id: PhantomData,
        }
    }
}

impl<Id: FheIntId> From<&ServerKey> for FheIntConformanceParams<Id> {
    fn from(sk: &ServerKey) -> Self {
        Self {
            params: RadixCiphertextConformanceParams {
                shortint_params: sk.key.pbs_key().key.conformance_params(),
                num_blocks_per_integer: Id::num_blocks(sk.key.pbs_key().message_modulus()),
            },
            id: PhantomData,
        }
    }
}

impl<Id: FheIntId> ParameterSetConformant for FheInt<Id> {
    type ParameterSet = FheIntConformanceParams<Id>;

    fn is_conformant(&self, params: &FheIntConformanceParams<Id>) -> bool {
        let Self {
            ciphertext,
            id: _,
            tag: _,
            re_randomization_metadata: _,
        } = self;

        ciphertext.on_cpu().is_conformant(&params.params)
    }
}

impl<Id: FheIntId> Named for FheInt<Id> {
    const NAME: &'static str = "high_level_api::FheInt";
}

impl<Id> Tagged for FheInt<Id>
where
    Id: FheIntId,
{
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl<Id> FheIntegerType for FheInt<Id>
where
    Id: FheIntId,
{
    type Id = Id;

    fn on_cpu(&self) -> MaybeCloned<'_, <Self::Id as IntegerId>::InnerCpu> {
        self.ciphertext.on_cpu()
    }

    fn into_cpu(self) -> <Self::Id as IntegerId>::InnerCpu {
        self.ciphertext.into_cpu()
    }

    fn from_cpu(
        inner: <Self::Id as IntegerId>::InnerCpu,
        tag: Tag,
        re_randomization_metadata: ReRandomizationMetadata,
    ) -> Self {
        Self::new(inner, tag, re_randomization_metadata)
    }
}

impl<Id> FheInt<Id>
where
    Id: FheIntId,
{
    pub(in crate::high_level_api) fn new(
        ciphertext: impl Into<SignedRadixCiphertext>,
        tag: Tag,
        re_randomization_metadata: ReRandomizationMetadata,
    ) -> Self {
        Self {
            ciphertext: ciphertext.into(),
            id: Id::default(),
            tag,
            re_randomization_metadata,
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::SignedRadixCiphertext,
        Id,
        Tag,
        ReRandomizationMetadata,
    ) {
        let Self {
            ciphertext,
            id,
            tag,
            re_randomization_metadata,
        } = self;
        (ciphertext.into_cpu(), id, tag, re_randomization_metadata)
    }

    pub fn from_raw_parts(
        ciphertext: crate::integer::SignedRadixCiphertext,
        id: Id,
        tag: Tag,
        re_randomization_metadata: ReRandomizationMetadata,
    ) -> Self {
        Self {
            ciphertext: ciphertext.into(),
            id,
            tag,
            re_randomization_metadata,
        }
    }

    pub fn num_bits() -> usize {
        Id::num_bits()
    }

    /// Moves (in-place) the ciphertext to the desired device.
    ///
    /// Does nothing if the ciphertext is already in the desired device
    pub fn move_to_device(&mut self, device: Device) {
        self.ciphertext.move_to_device(device)
    }

    /// Moves (in-place) the ciphertext to the current device.
    ///
    /// Does nothing if the ciphertext is already in the current device
    pub fn move_to_current_device(&mut self) {
        self.ciphertext.move_to_device_of_server_key_if_set()
    }

    /// Returns the device where the ciphertext is currently on
    pub fn current_device(&self) -> Device {
        self.ciphertext.current_device()
    }

    /// Returns the absolute value
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertext = cpu_key
                    .pbs_key()
                    .abs_parallelized(&*self.ciphertext.on_cpu());
                Self::new(
                    ciphertext,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let result = cuda_key
                    .key
                    .key
                    .abs(&*self.ciphertext.on_gpu(streams), streams);
                Self::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns a FheBool that encrypts `true` if the value is even
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(46i16, &client_key);
    ///
    /// let result = a.is_even();
    /// let decrypted = result.decrypt(&client_key);
    /// assert!(decrypted);
    /// ```
    pub fn is_even(&self) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .is_even_parallelized(&*self.ciphertext.on_cpu());
                FheBool::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let result = cuda_key
                    .key
                    .key
                    .is_even(&*self.ciphertext.on_gpu(streams), streams);
                FheBool::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns a FheBool that encrypts `true` if the value is odd
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(1i16, &client_key);
    ///
    /// let result = a.is_odd();
    /// let decrypted = result.decrypt(&client_key);
    /// assert!(decrypted);
    /// ```
    pub fn is_odd(&self) -> FheBool {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .is_odd_parallelized(&*self.ciphertext.on_cpu());
                FheBool::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let result = cuda_key
                    .key
                    .key
                    .is_odd(&*self.ciphertext.on_gpu(streams), streams);
                FheBool::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the number of leading zeros in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.leading_zeros();
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 0);
    /// ```
    pub fn leading_zeros(&self) -> crate::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .leading_zeros_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                crate::FheUint32::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let result = cuda_key
                    .key
                    .key
                    .leading_zeros(&*self.ciphertext.on_gpu(streams), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the number of leading ones in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.leading_ones();
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 16);
    /// ```
    pub fn leading_ones(&self) -> crate::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .leading_ones_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                crate::FheUint32::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let result = cuda_key
                    .key
                    .key
                    .leading_ones(&*self.ciphertext.on_gpu(streams), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the number of trailing zeros in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-4i16, &client_key);
    ///
    /// let result = a.trailing_zeros();
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 2);
    /// ```
    pub fn trailing_zeros(&self) -> crate::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .trailing_zeros_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                crate::FheUint32::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let result = cuda_key
                    .key
                    .key
                    .trailing_zeros(&*self.ciphertext.on_gpu(streams), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the number of trailing ones in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(3i16, &client_key);
    ///
    /// let result = a.trailing_ones();
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 2);
    /// ```
    pub fn trailing_ones(&self) -> crate::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .trailing_ones_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                crate::FheUint32::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let result = cuda_key
                    .key
                    .key
                    .trailing_ones(&*self.ciphertext.on_gpu(streams), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the number of ones in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let clear_a = 0b0000000_0110111i16;
    /// let a = FheInt16::encrypt(clear_a, &client_key);
    ///
    /// let result = a.count_ones();
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, clear_a.count_ones());
    /// ```
    pub fn count_ones(&self) -> crate::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .count_ones_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                crate::FheUint32::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support count_ones yet");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the number of zeros in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let clear_a = 0b0000000_0110111i16;
    /// let a = FheInt16::encrypt(clear_a, &client_key);
    ///
    /// let result = a.count_zeros();
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, clear_a.count_zeros());
    /// ```
    pub fn count_zeros(&self) -> crate::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .count_zeros_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                crate::FheUint32::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support count_zeros yet");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// Result has no meaning if self encrypts a value <= 0. See [Self::checked_ilog2]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.ilog2();
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1);
    /// ```
    pub fn ilog2(&self) -> crate::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .ilog2_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                crate::FheUint32::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let result = cuda_key
                    .key
                    .key
                    .ilog2(&*self.ciphertext.on_gpu(streams), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// Also returns a boolean flag that is true if the result is valid (i.e self was > 0)
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let (result, is_ok) = a.checked_ilog2();
    ///
    /// let is_ok = is_ok.decrypt(&client_key);
    /// assert!(!is_ok);
    ///
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 15); // result is meaningless
    /// ```
    pub fn checked_ilog2(&self) -> (crate::FheUint32, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, is_ok) = cpu_key
                    .pbs_key()
                    .checked_ilog2_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                (
                    crate::FheUint32::new(
                        result,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                    FheBool::new(
                        is_ok,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let (result, is_ok) = cuda_key
                    .key
                    .key
                    .checked_ilog2(&*self.ciphertext.on_gpu(streams), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                (
                    crate::FheUint32::new(
                        result,
                        cuda_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                    FheBool::new(
                        is_ok,
                        cuda_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// assert!(result.is_err());
    /// ```
    pub fn try_decrypt_trivial<Clear>(&self) -> Result<Clear, NotTrivialCiphertextError>
    where
        Clear: RecomposableSignedInteger,
    {
        self.ciphertext.on_cpu().decrypt_trivial()
    }

    /// Reverse the bit of the signed integer
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let msg = 0b0110100_i8;
    ///
    /// let a = FheInt8::encrypt(msg, &client_key);
    ///
    /// let result: FheInt8 = a.reverse_bits();
    ///
    /// let decrypted: i8 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, msg.reverse_bits());
    /// ```
    pub fn reverse_bits(&self) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let sk = &cpu_key.pbs_key();

                let ct = self.ciphertext.on_cpu();

                Self::new(
                    sk.reverse_bits_parallelized(&*ct),
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support reverse yet");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Creates a FheInt that encrypts either of two values depending
    /// on an encrypted condition
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let cond = FheBool::encrypt(true, &client_key);
    ///
    /// let result = FheInt32::if_then_else(&cond, i32::MAX, i32::MIN);
    /// let decrypted: i32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MAX);
    ///
    /// let result = FheInt32::if_then_else(&!cond, i32::MAX, i32::MIN);
    /// let decrypted: i32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MIN);
    /// ```
    pub fn if_then_else<Clear>(condition: &FheBool, true_value: Clear, false_value: Clear) -> Self
    where
        Clear: SignedNumeric + DecomposableInto<u64>,
    {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let sk = cpu_key.pbs_key();

                let result: crate::integer::SignedRadixCiphertext = sk
                    .scalar_if_then_else_parallelized(
                        &condition.ciphertext.on_cpu(),
                        true_value,
                        false_value,
                        Id::num_blocks(sk.message_modulus()),
                    );

                Self::new(
                    result,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support if_then_else yet");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support this operation yet.");
            }
        })
    }

    /// Same as [Self::if_then_else] but with a different name
    pub fn select<Clear>(condition: &FheBool, true_value: Clear, false_value: Clear) -> Self
    where
        Clear: SignedNumeric + DecomposableInto<u64>,
    {
        Self::if_then_else(condition, true_value, false_value)
    }

    /// Same as [Self::if_then_else] but with a different name
    pub fn cmux<Clear>(condition: &FheBool, true_value: Clear, false_value: Clear) -> Self
    where
        Clear: SignedNumeric + DecomposableInto<u64>,
    {
        Self::if_then_else(condition, true_value, false_value)
    }

    pub fn re_randomization_metadata(&self) -> &ReRandomizationMetadata {
        &self.re_randomization_metadata
    }

    pub fn re_randomization_metadata_mut(&mut self) -> &mut ReRandomizationMetadata {
        &mut self.re_randomization_metadata
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheInt32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt32::encrypt(i32::MAX, &client_key);
    /// let b = FheInt16::cast_from(a);
    ///
    /// let decrypted: i16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MAX as i16);
    /// ```
    fn cast_from(input: FheInt<FromId>) -> Self {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let target_num_blocks = IntoId::num_blocks(cpu_key.message_modulus());
                let new_ciphertext = cpu_key
                    .pbs_key()
                    .cast_to_signed(input.ciphertext.into_cpu(), target_num_blocks);
                Self::new(
                    new_ciphertext,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let target_num_blocks = IntoId::num_blocks(cuda_key.message_modulus());
                let new_ciphertext = cuda_key.key.key.cast_to_signed(
                    input.ciphertext.into_gpu(streams),
                    target_num_blocks,
                    streams,
                );
                Self::new(
                    new_ciphertext,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint32::encrypt(u32::MAX, &client_key);
    /// let b = FheInt16::cast_from(a);
    ///
    /// let decrypted: i16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MAX as i16);
    /// ```
    fn cast_from(input: FheUint<FromId>) -> Self {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let new_ciphertext = cpu_key.pbs_key().cast_to_signed(
                    input.ciphertext.on_cpu().to_owned(),
                    IntoId::num_blocks(cpu_key.message_modulus()),
                );
                Self::new(
                    new_ciphertext,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let new_ciphertext = cuda_key.key.key.cast_to_signed(
                    input.ciphertext.into_gpu(streams),
                    IntoId::num_blocks(cuda_key.message_modulus()),
                    streams,
                );
                Self::new(
                    new_ciphertext,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheInt16::cast_from(a);
    ///
    /// let decrypted: i16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, i16::from(true));
    /// ```
    fn cast_from(input: FheBool) -> Self {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertext = input
                    .ciphertext
                    .on_cpu()
                    .into_owned()
                    .into_radix::<crate::integer::SignedRadixCiphertext>(
                    Id::num_blocks(cpu_key.message_modulus()),
                    cpu_key.pbs_key(),
                );
                Self::new(
                    ciphertext,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.cast_to_signed(
                    input.ciphertext.into_gpu(streams).0,
                    Id::num_blocks(cuda_key.message_modulus()),
                    streams,
                );
                Self::new(
                    inner,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id> FheWait for FheInt<Id>
where
    Id: FheIntId,
{
    fn wait(&self) {
        self.ciphertext.wait()
    }
}

impl<Id> ReRandomize for FheInt<Id>
where
    Id: FheIntId,
{
    fn add_to_re_randomization_context(
        &self,
        context: &mut crate::high_level_api::re_randomization::ReRandomizationContext,
    ) {
        let on_cpu = self.ciphertext.on_cpu();
        context.inner.add_ciphertext(&*on_cpu);
        context
            .inner
            .add_bytes(self.re_randomization_metadata.data());
    }

    fn re_randomize(
        &mut self,
        compact_public_key: &CompactPublicKey,
        seed: ReRandomizationSeed,
    ) -> crate::Result<()> {
        global_state::with_internal_keys(|key| {
            match key {
                InternalServerKey::Cpu(key) => {
                    let re_randomization_key = key.legacy_re_randomization_cpk_casting_key()?;

                    self.ciphertext.as_cpu_mut().re_randomize(
                        &compact_public_key.key.key,
                        re_randomization_key.as_ref(),
                        seed,
                    )?;
                }
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    let Some(re_randomization_key) = cuda_key.re_randomization_cpk_casting_key()
                    else {
                        return Err(crate::high_level_api::errors::UninitializedReRandKey.into());
                    };

                    let streams = &cuda_key.streams;
                    self.ciphertext.as_gpu_mut(streams).re_randomize(
                        &compact_public_key.key.key,
                        re_randomization_key,
                        seed,
                        streams,
                    )?;
                }
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("HPU does not support re_randomize.")
                }
            }

            self.re_randomization_metadata_mut().clear();

            Ok(())
        })
    }

    fn re_randomize_without_keyswitch(&mut self, seed: ReRandomizationSeed) -> crate::Result<()> {
        global_state::with_internal_keys(|key| {
            match key {
                InternalServerKey::Cpu(key) => {
                    let re_randomization_key = key.cpk_for_re_randomization_without_keyswitch()?;

                    self.ciphertext
                        .as_cpu_mut()
                        .re_randomize(re_randomization_key, None, seed)?;
                }
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_cuda_key) => {
                    panic!("GPU does not support re_randomize_without_keyswitch.")
                }
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("HPU does not support re_randomize_without_keyswitch.")
                }
            }

            self.re_randomization_metadata_mut().clear();

            Ok(())
        })
    }
}
