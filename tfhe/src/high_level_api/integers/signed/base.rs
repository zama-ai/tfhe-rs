use tfhe_versionable::Versionize;

use super::inner::RadixCiphertext;
use crate::backward_compatibility::integers::FheIntVersions;
use crate::conformance::ParameterSetConformant;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::{FheUint, FheUintId, IntegerId};
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::Tagged;
use crate::integer::client_key::RecomposableSignedInteger;
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::named::Named;
use crate::prelude::CastFrom;
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::shortint::PBSParameters;
use crate::{Device, FheBool, ServerKey, Tag};
use std::marker::PhantomData;

#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_streams;
pub trait FheIntId: IntegerId {}

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
    pub(in crate::high_level_api) ciphertext: RadixCiphertext,
    pub(in crate::high_level_api) id: Id,
    pub(crate) tag: Tag,
}

#[derive(Copy, Clone)]
pub struct FheIntConformanceParams<Id: FheIntId> {
    pub(crate) params: RadixCiphertextConformanceParams,
    pub(crate) id: PhantomData<Id>,
}

impl<Id: FheIntId, P: Into<PBSParameters>> From<P> for FheIntConformanceParams<Id> {
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

impl<Id> FheInt<Id>
where
    Id: FheIntId,
{
    pub(in crate::high_level_api) fn new(ciphertext: impl Into<RadixCiphertext>, tag: Tag) -> Self {
        Self {
            ciphertext: ciphertext.into(),
            id: Id::default(),
            tag,
        }
    }

    pub fn into_raw_parts(self) -> (crate::integer::SignedRadixCiphertext, Id, Tag) {
        let Self {
            ciphertext,
            id,
            tag,
        } = self;
        (ciphertext.into_cpu(), id, tag)
    }

    pub fn from_raw_parts(
        ciphertext: crate::integer::SignedRadixCiphertext,
        id: Id,
        tag: Tag,
    ) -> Self {
        Self {
            ciphertext: ciphertext.into(),
            id,
            tag,
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
                Self::new(ciphertext, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices does not support abs yet")
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
                FheBool::new(result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let result = cuda_key
                    .key
                    .key
                    .is_even(&*self.ciphertext.on_gpu(), streams);
                FheBool::new(result, cuda_key.tag.clone())
            }),
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
                FheBool::new(result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let result = cuda_key.key.key.is_odd(&*self.ciphertext.on_gpu(), streams);
                FheBool::new(result, cuda_key.tag.clone())
            }),
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
                crate::FheUint32::new(result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let result = cuda_key
                    .key
                    .key
                    .leading_zeros(&*self.ciphertext.on_gpu(), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(result, cuda_key.tag.clone())
            }),
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
                crate::FheUint32::new(result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let result = cuda_key
                    .key
                    .key
                    .leading_ones(&*self.ciphertext.on_gpu(), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(result, cuda_key.tag.clone())
            }),
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
                crate::FheUint32::new(result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let result = cuda_key
                    .key
                    .key
                    .trailing_zeros(&*self.ciphertext.on_gpu(), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(result, cuda_key.tag.clone())
            }),
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
                crate::FheUint32::new(result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let result = cuda_key
                    .key
                    .key
                    .trailing_ones(&*self.ciphertext.on_gpu(), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(result, cuda_key.tag.clone())
            }),
        })
    }

    /// Returns the number of ones in the binary representation of self.
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
                crate::FheUint32::new(result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support count_ones yet");
            }
        })
    }

    /// Returns the number of zeros in the binary representation of self.
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
                crate::FheUint32::new(result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support count_zeros yet");
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
                crate::FheUint32::new(result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let result = cuda_key.key.key.ilog2(&*self.ciphertext.on_gpu(), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                crate::FheUint32::new(result, cuda_key.tag.clone())
            }),
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
                    crate::FheUint32::new(result, cpu_key.tag.clone()),
                    FheBool::new(is_ok, cpu_key.tag.clone()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let (result, is_ok) = cuda_key
                    .key
                    .key
                    .checked_ilog2(&*self.ciphertext.on_gpu(), streams);
                let result = cuda_key.key.key.cast_to_unsigned(
                    result,
                    crate::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                (
                    crate::FheUint32::new(result, cuda_key.tag.clone()),
                    FheBool::new(is_ok, cuda_key.tag.clone()),
                )
            }),
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

                Self::new(sk.reverse_bits_parallelized(&*ct), cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support reverse yet");
            }
        })
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
                Self::new(new_ciphertext, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let target_num_blocks = IntoId::num_blocks(cuda_key.message_modulus());
                let new_ciphertext = cuda_key.key.key.cast_to_signed(
                    input.ciphertext.into_gpu(),
                    target_num_blocks,
                    streams,
                );
                Self::new(new_ciphertext, cuda_key.tag.clone())
            }),
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
                Self::new(new_ciphertext, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let new_ciphertext = cuda_key.key.key.cast_to_signed(
                    input.ciphertext.into_gpu(),
                    IntoId::num_blocks(cuda_key.message_modulus()),
                    streams,
                );
                Self::new(new_ciphertext, cuda_key.tag.clone())
            }),
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
                Self::new(ciphertext, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let inner = cuda_key.key.key.cast_to_signed(
                    input.ciphertext.into_gpu().0,
                    Id::num_blocks(cuda_key.message_modulus()),
                    streams,
                );
                Self::new(inner, cuda_key.tag.clone())
            }),
        })
    }
}
