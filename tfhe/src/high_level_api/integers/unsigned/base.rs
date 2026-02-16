use tfhe_versionable::Versionize;

use super::inner::RadixCiphertext;
use crate::backward_compatibility::integers::FheUintVersions;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{CastFrom, UnsignedInteger, UnsignedNumeric};
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::integers::signed::{FheInt, FheIntId};
use crate::high_level_api::integers::{FheIntegerType, IntegerId};
use crate::high_level_api::keys::{CompactPublicKey, InternalServerKey};
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::traits::{FheWait, ReRandomize, Tagged};
use crate::high_level_api::{global_state, Device};
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::ciphertext::ReRandomizationSeed;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
#[cfg(feature = "hpu")]
use crate::integer::hpu::ciphertext::HpuRadixCiphertext;
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::integer::server_key::MatchValues;
use crate::named::Named;
use crate::prelude::CastInto;
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::shortint::AtomicPatternParameters;
#[cfg(feature = "gpu")]
use crate::GpuIndex;
use crate::{FheBool, ServerKey, Tag};
use std::marker::PhantomData;

#[cfg(feature = "hpu")]
use crate::high_level_api::traits::{FheHpu, HpuHandle};
#[cfg(feature = "hpu")]
use tfhe_hpu_backend::prelude::*;

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

#[cfg(not(feature = "gpu"))]
type ExpectedInnerGpu = ();
#[cfg(feature = "gpu")]
type ExpectedInnerGpu = crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
pub trait FheUintId:
    IntegerId<InnerCpu = crate::integer::RadixCiphertext, InnerGpu = ExpectedInnerGpu>
{
}

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
#[derive(Clone, serde::Deserialize, serde::Serialize, Versionize)]
#[versionize(FheUintVersions)]
pub struct FheUint<Id: FheUintId> {
    pub(in crate::high_level_api) ciphertext: RadixCiphertext,
    pub(in crate::high_level_api) id: Id,
    pub(crate) tag: Tag,
    pub(crate) re_randomization_metadata: ReRandomizationMetadata,
}

#[derive(Copy, Clone)]
pub struct FheUintConformanceParams<Id: FheUintId> {
    pub(crate) params: RadixCiphertextConformanceParams,
    pub(crate) id: PhantomData<Id>,
}

impl<Id: FheUintId, P: Into<AtomicPatternParameters>> From<P> for FheUintConformanceParams<Id> {
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

impl<Id: FheUintId> From<&ServerKey> for FheUintConformanceParams<Id> {
    fn from(sks: &ServerKey) -> Self {
        Self {
            params: RadixCiphertextConformanceParams {
                shortint_params: sks.key.pbs_key().key.conformance_params(),
                num_blocks_per_integer: Id::num_blocks(sks.key.pbs_key().message_modulus()),
            },
            id: PhantomData,
        }
    }
}

impl<Id: FheUintId> ParameterSetConformant for FheUint<Id> {
    type ParameterSet = FheUintConformanceParams<Id>;

    fn is_conformant(&self, params: &FheUintConformanceParams<Id>) -> bool {
        let Self {
            ciphertext,
            id: _,
            tag: _,
            re_randomization_metadata: _,
        } = self;

        ciphertext.on_cpu().is_conformant(&params.params)
    }
}

impl<Id: FheUintId> Named for FheUint<Id> {
    const NAME: &'static str = "high_level_api::FheUint";
}

impl<Id> FheIntegerType for FheUint<Id>
where
    Id: FheUintId,
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

impl<Id> Tagged for FheUint<Id>
where
    Id: FheUintId,
{
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl<Id> FheWait for FheUint<Id>
where
    Id: FheUintId,
{
    fn wait(&self) {
        self.ciphertext.wait()
    }
}

#[cfg(feature = "hpu")]
impl<Id> FheHpu for FheUint<Id>
where
    Id: FheUintId,
{
    fn iop_exec(iop: &hpu_asm::AsmIOpcode, src: HpuHandle<&Self>) -> HpuHandle<Self> {
        use crate::integer::hpu::ciphertext::HpuRadixCiphertext;
        global_state::with_thread_local_hpu_device(|device| {
            let mut srcs = Vec::new();
            for n in src.native.iter() {
                srcs.push(n.ciphertext.on_hpu(device).clone());
            }
            for b in src.boolean.iter() {
                srcs.push(b.ciphertext.on_hpu(device).clone());
            }

            let (opcode, proto) = {
                (
                    iop.opcode(),
                    &iop.format().expect("Unspecified IOP format").proto,
                )
            };
            // These clones are cheap as they are just Arc
            let hpu_res = HpuRadixCiphertext::exec(proto, opcode, &srcs, &src.imm);
            HpuHandle {
                native: hpu_res
                    .iter()
                    .filter(|x| !x.0.is_boolean())
                    .map(|x| {
                        Self::new(
                            x.clone(),
                            device.tag.clone(),
                            ReRandomizationMetadata::default(),
                        )
                    })
                    .collect::<Vec<_>>(),
                boolean: hpu_res
                    .iter()
                    .filter(|x| x.0.is_boolean())
                    .map(|x| {
                        FheBool::new(
                            x.clone(),
                            device.tag.clone(),
                            ReRandomizationMetadata::default(),
                        )
                    })
                    .collect::<Vec<_>>(),
                imm: Vec::new(),
            }
        })
    }
}

impl<Id> FheUint<Id>
where
    Id: FheUintId,
{
    pub(in crate::high_level_api) fn new<T>(
        ciphertext: T,
        tag: Tag,
        re_randomization_metadata: ReRandomizationMetadata,
    ) -> Self
    where
        T: Into<RadixCiphertext>,
    {
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
        crate::integer::RadixCiphertext,
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

        let ciphertext = ciphertext.into_cpu();

        (ciphertext, id, tag, re_randomization_metadata)
    }

    pub fn from_raw_parts(
        ciphertext: crate::integer::RadixCiphertext,
        id: Id,
        tag: Tag,
        re_randomization_metadata: ReRandomizationMetadata,
    ) -> Self {
        Self {
            ciphertext: RadixCiphertext::Cpu(ciphertext),
            id,
            tag,
            re_randomization_metadata,
        }
    }

    pub fn num_bits() -> usize {
        Id::num_bits()
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

    /// Moves (in-place) the ciphertext to the device of the current
    /// thread-local server key
    ///
    /// Does nothing if the ciphertext is already in the desired device
    /// or if no server key is set
    pub fn move_to_current_device(&mut self) {
        self.ciphertext.move_to_device_of_server_key_if_set();
    }

    /// Returns the indexes of the GPUs where the ciphertext lives
    ///
    /// If the ciphertext is on another deive (e.g CPU) then the returned
    /// slice is empty
    #[cfg(feature = "gpu")]
    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        if let RadixCiphertext::Cuda(cuda_ct) = &self.ciphertext {
            cuda_ct.gpu_indexes()
        } else {
            &[]
        }
    }
    /// Returns a FheBool that encrypts `true` if the value is even
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(32u16, &client_key);
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
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(4393u16, &client_key);
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
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// assert!(result.is_err());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// using sum should always be preferred.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
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

    /// Returns the number of leading zeros in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0b00111111_11111111u16, &client_key);
    ///
    /// let result = a.leading_zeros();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 2);
    /// ```
    pub fn leading_zeros(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .leading_zeros_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(
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
                    super::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                super::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(device) => {
                let hpu_self = self.ciphertext.on_hpu(device);

                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_LEAD0;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                let hpu_result =
                    HpuRadixCiphertext::exec(proto, opcode, std::slice::from_ref(&hpu_self), &[])
                        .pop()
                        .expect("IOP_LEAD0 must return 1 value");
                super::FheUint32::new(
                    hpu_result,
                    device.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
        })
    }

    /// Returns the number of leading ones in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0b11000000_00000000u16, &client_key);
    ///
    /// let result = a.leading_ones();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 2);
    /// ```
    pub fn leading_ones(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .leading_ones_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(
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
                    super::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                super::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(device) => {
                let hpu_self = self.ciphertext.on_hpu(device);

                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_LEAD1;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                let hpu_result =
                    HpuRadixCiphertext::exec(proto, opcode, std::slice::from_ref(&hpu_self), &[])
                        .pop()
                        .expect("IOP_LEAD1 must return 1 value");
                super::FheUint32::new(
                    hpu_result,
                    device.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
        })
    }

    /// Returns the number of trailing zeros in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0b0000000_0101000u16, &client_key);
    ///
    /// let result = a.trailing_zeros();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 3);
    /// ```
    pub fn trailing_zeros(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .trailing_zeros_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(
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
                    super::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                super::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(device) => {
                let hpu_self = self.ciphertext.on_hpu(device);

                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_TRAIL0;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                let hpu_result =
                    HpuRadixCiphertext::exec(proto, opcode, std::slice::from_ref(&hpu_self), &[])
                        .pop()
                        .expect("IOP_TRAIL0 must return 1 value");
                super::FheUint32::new(
                    hpu_result,
                    device.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
        })
    }

    /// Returns the number of trailing ones in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0b0000000_0110111u16, &client_key);
    ///
    /// let result = a.trailing_ones();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 3);
    /// ```
    pub fn trailing_ones(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .trailing_ones_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(
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
                    super::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                super::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(device) => {
                let hpu_self = self.ciphertext.on_hpu(device);

                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_TRAIL1;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                let hpu_result =
                    HpuRadixCiphertext::exec(proto, opcode, std::slice::from_ref(&hpu_self), &[])
                        .pop()
                        .expect("IOP_TRAIL1 must return 1 value");
                super::FheUint32::new(
                    hpu_result,
                    device.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
        })
    }

    /// Returns the number of ones in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let clear_a = 0b0000000_0110111u16;
    /// let a = FheUint16::encrypt(clear_a, &client_key);
    ///
    /// let result = a.count_ones();
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, clear_a.count_ones());
    /// ```
    pub fn count_ones(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .count_ones_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(
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
            InternalServerKey::Hpu(device) => {
                let hpu_self = self.ciphertext.on_hpu(device);

                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_COUNT0;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                let hpu_result =
                    HpuRadixCiphertext::exec(proto, opcode, std::slice::from_ref(&hpu_self), &[])
                        .pop()
                        .expect("IOP_COUNT0 must return 1 value");
                super::FheUint32::new(
                    hpu_result,
                    device.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
        })
    }

    /// Returns the number of zeros in the binary representation of self.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let clear_a = 0b0000000_0110111u16;
    /// let a = FheUint16::encrypt(clear_a, &client_key);
    ///
    /// let result = a.count_zeros();
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, clear_a.count_zeros());
    /// ```
    pub fn count_zeros(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .count_zeros_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(
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
            InternalServerKey::Hpu(device) => {
                let hpu_self = self.ciphertext.on_hpu(device);

                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_COUNT1;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                let hpu_result =
                    HpuRadixCiphertext::exec(proto, opcode, std::slice::from_ref(&hpu_self), &[])
                        .pop()
                        .expect("IOP_COUNT1 must return 1 value");
                super::FheUint32::new(
                    hpu_result,
                    device.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
        })
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// Result has no meaning if self encrypts 0. See [Self::checked_ilog2]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.ilog2();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1);
    /// ```
    pub fn ilog2(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .ilog2_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(
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
                    super::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                super::FheUint32::new(
                    result,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(device) => {
                let hpu_self = self.ciphertext.on_hpu(device);

                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_ILOG2;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                let hpu_result =
                    HpuRadixCiphertext::exec(proto, opcode, std::slice::from_ref(&hpu_self), &[])
                        .pop()
                        .expect("IOP_ILOG2 must return 1 value");
                super::FheUint32::new(
                    hpu_result,
                    device.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
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
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0u16, &client_key);
    ///
    /// let (result, is_ok) = a.checked_ilog2();
    ///
    /// let is_ok = is_ok.decrypt(&client_key);
    /// assert!(!is_ok);
    ///
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 63); // result is meaningless
    /// ```
    pub fn checked_ilog2(&self) -> (super::FheUint32, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, is_ok) = cpu_key
                    .pbs_key()
                    .checked_ilog2_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                (
                    super::FheUint32::new(
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
                    super::FheUint32Id::num_blocks(cuda_key.key.key.message_modulus),
                    streams,
                );
                (
                    super::FheUint32::new(
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

    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `self` could hold. And the
    ///   output type can be different.
    ///
    /// Returns a FheBool that encrypts `true` if the input `self`
    /// matched one of the possible inputs
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{
    ///     generate_keys, set_server_key, ConfigBuilder, FheUint16, FheUint8, MatchValues,
    /// };
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(17u16, &client_key);
    ///
    /// let match_values = MatchValues::new(vec![
    ///     (0u16, 3u16),
    ///     (1u16, 3u16),
    ///     (2u16, 3u16),
    ///     (17u16, 25u16),
    /// ])
    /// .unwrap();
    /// let (result, matched): (FheUint8, _) = a.match_value(&match_values)
    ///     .unwrap(); // All possible output values fit in a u8
    ///
    /// let matched = matched.decrypt(&client_key);
    /// assert!(matched);
    ///
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 25u16)
    /// ```
    pub fn match_value<Clear, OutId>(
        &self,
        matches: &MatchValues<Clear>,
    ) -> crate::Result<(FheUint<OutId>, FheBool)>
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
        OutId: FheUintId,
    {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, matched) = cpu_key
                    .pbs_key()
                    .match_value_parallelized(&self.ciphertext.on_cpu(), matches);
                let target_num_blocks = OutId::num_blocks(cpu_key.message_modulus());
                if target_num_blocks >= result.blocks.len() {
                    let result = cpu_key
                        .pbs_key()
                        .cast_to_unsigned(result, target_num_blocks);
                    Ok((
                        FheUint::new(
                            result,
                            cpu_key.tag.clone(),
                            ReRandomizationMetadata::default(),
                        ),
                        FheBool::new(
                            matched,
                            cpu_key.tag.clone(),
                            ReRandomizationMetadata::default(),
                        ),
                    ))
                } else {
                    Err(crate::Error::new("Output type does not have enough bits to represent all possible output values".to_string()))
                }
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let (result, matched) = cuda_key.key.key.match_value(
                    &self.ciphertext.on_gpu(streams),
                    matches,
                    streams,
                );
                let target_num_blocks = OutId::num_blocks(cuda_key.key.key.message_modulus);
                if target_num_blocks >= result.ciphertext.d_blocks.lwe_ciphertext_count().0 {
                    Ok((
                        FheUint::new(
                            result,
                            cuda_key.tag.clone(),
                            ReRandomizationMetadata::default(),
                        ),
                        FheBool::new(
                            matched,
                            cuda_key.tag.clone(),
                            ReRandomizationMetadata::default(),
                        ),
                    ))
                } else {
                    Err(crate::Error::new("Output type does not have enough bits to represent all possible output values".to_string()))
                }
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the estimated memory usage (in bytes) required on the GPU to perform
    /// the `match_value` operation.
    ///
    /// This is useful to check if the operation fits in the GPU memory before attempting execution.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16, MatchValues};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(17u16, &client_key);
    ///
    /// let match_values = MatchValues::new(vec![(0u16, 3u16), (17u16, 25u16)]).unwrap();
    ///
    /// #[cfg(feature = "gpu")]
    /// {
    ///     let size_bytes = a.get_match_value_size_on_gpu(&match_values).unwrap();
    ///     println!("Memory required on GPU: {} bytes", size_bytes);
    ///     assert!(size_bytes > 0);
    /// }
    /// ```
    #[cfg(feature = "gpu")]
    pub fn get_match_value_size_on_gpu<Clear>(
        &self,
        matches: &MatchValues<Clear>,
    ) -> crate::Result<u64>
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(_) => Err(crate::Error::new(
                "This function is only available when using the CUDA backend".to_string(),
            )),
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let ct_on_gpu = self.ciphertext.on_gpu(streams);

                let size = cuda_key
                    .key
                    .key
                    .get_unchecked_match_value_size_on_gpu(&ct_on_gpu, matches, streams);
                Ok(size)
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation.")
            }
        })
    }

    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `self` could hold. And the
    ///   output type can be different.
    ///
    /// If none of the input matched the `self` then, `self` will encrypt the
    /// value given to `or_value`
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{
    ///     generate_keys, set_server_key, ConfigBuilder, FheUint16, FheUint8, MatchValues,
    /// };
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(17u16, &client_key);
    ///
    /// let match_values = MatchValues::new(vec![
    ///     (0u16, 3u16), // map 0 to 3
    ///     (1u16, 234u16),
    ///     (2u16, 123u16),
    /// ])
    /// .unwrap();
    /// let result: FheUint8 = a.match_value_or(&match_values, 25u16)
    ///     .unwrap(); // All possible output values fit on a u8
    ///
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 25u16)
    /// ```
    pub fn match_value_or<Clear, OutId>(
        &self,
        matches: &MatchValues<Clear>,
        or_value: Clear,
    ) -> crate::Result<FheUint<OutId>>
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
        OutId: FheUintId,
    {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key.pbs_key().match_value_or_parallelized(
                    &self.ciphertext.on_cpu(),
                    matches,
                    or_value,
                );
                let target_num_blocks = OutId::num_blocks(cpu_key.message_modulus());
                if target_num_blocks >= result.blocks.len() {
                    let result = cpu_key
                        .pbs_key()
                        .cast_to_unsigned(result, target_num_blocks);
                    Ok(FheUint::new(
                        result,
                        cpu_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ))
                } else {
                    Err(crate::Error::new("Output type does not have enough bits to represent all possible output values".to_string()))
                }
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let result = cuda_key.key.key.match_value_or(
                    &self.ciphertext.on_gpu(streams),
                    matches,
                    or_value,
                    streams,
                );
                let target_num_blocks = OutId::num_blocks(cuda_key.key.key.message_modulus);
                if target_num_blocks >= result.ciphertext.d_blocks.lwe_ciphertext_count().0 {
                    Ok(FheUint::new(
                        result,
                        cuda_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    ))
                } else {
                    Err(crate::Error::new("Output type does not have enough bits to represent all possible output values".to_string()))
                }
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Returns the estimated memory usage (in bytes) required on the GPU to perform
    /// the `match_value_or` operation.
    ///
    /// This is useful to check if the operation fits in the GPU memory before attempting execution.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16, MatchValues};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(17u16, &client_key);
    ///
    /// let match_values = MatchValues::new(vec![(0u16, 3u16), (17u16, 25u16)]).unwrap();
    ///
    /// #[cfg(feature = "gpu")]
    /// {
    ///     let size_bytes = a
    ///         .get_match_value_or_size_on_gpu(&match_values, 55u16)
    ///         .unwrap();
    ///     println!("Memory required on GPU: {} bytes", size_bytes);
    ///     assert!(size_bytes > 0);
    /// }
    /// ```
    #[cfg(feature = "gpu")]
    pub fn get_match_value_or_size_on_gpu<Clear>(
        &self,
        matches: &MatchValues<Clear>,
        or_value: Clear,
    ) -> crate::Result<u64>
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(_) => Err(crate::Error::new(
                "This function is only available when using the CUDA backend".to_string(),
            )),
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let ct_on_gpu = self.ciphertext.on_gpu(streams);

                let size = cuda_key.key.key.get_unchecked_match_value_or_size_on_gpu(
                    &ct_on_gpu, matches, or_value, streams,
                );
                Ok(size)
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation.")
            }
        })
    }

    /// Reverse the bit of the unsigned integer
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let msg = 0b10110100_u8;
    ///
    /// let a = FheUint8::encrypt(msg, &client_key);
    ///
    /// let result: FheUint8 = a.reverse_bits();
    ///
    /// let decrypted: u8 = result.decrypt(&client_key);
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

    /// Creates a FheUint that encrypts either of two values depending
    /// on an encrypted condition
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let cond = FheBool::encrypt(true, &client_key);
    ///
    /// let result = FheUint32::if_then_else(&cond, u32::MAX, u32::MIN);
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MAX);
    ///
    /// let result = FheUint32::if_then_else(&!cond, u32::MAX, u32::MIN);
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MIN);
    /// ```
    pub fn if_then_else<Clear>(condition: &FheBool, true_value: Clear, false_value: Clear) -> Self
    where
        Clear: UnsignedNumeric + DecomposableInto<u64>,
    {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let sk = cpu_key.pbs_key();

                let result: crate::integer::RadixCiphertext = sk.scalar_if_then_else_parallelized(
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
        Clear: UnsignedNumeric + DecomposableInto<u64>,
    {
        Self::if_then_else(condition, true_value, false_value)
    }

    /// Same as [Self::if_then_else] but with a different name
    pub fn cmux<Clear>(condition: &FheBool, true_value: Clear, false_value: Clear) -> Self
    where
        Clear: UnsignedNumeric + DecomposableInto<u64>,
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
                InternalServerKey::Cuda(cuda_key) => (
                    cuda_key.key.key.carry_modulus,
                    cuda_key.key.key.message_modulus,
                ),
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
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

        let mut ciphertext = Self::new(other, Tag::default(), ReRandomizationMetadata::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt32, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt32::encrypt(i32::MIN, &client_key);
    /// let b = FheUint16::cast_from(a);
    ///
    /// let decrypted: u16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MIN as u16);
    /// ```
    fn cast_from(input: FheInt<FromId>) -> Self {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let casted = cpu_key.pbs_key().cast_to_unsigned(
                    input.ciphertext.into_cpu(),
                    IntoId::num_blocks(cpu_key.message_modulus()),
                );
                Self::new(
                    casted,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let casted = cuda_key.key.key.cast_to_unsigned(
                    input.ciphertext.into_gpu(streams),
                    IntoId::num_blocks(cuda_key.message_modulus()),
                    streams,
                );
                Self::new(
                    casted,
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16, FheUint32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint32::encrypt(u32::MAX, &client_key);
    /// let b = FheUint16::cast_from(a);
    ///
    /// let decrypted: u16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MAX as u16);
    /// ```
    fn cast_from(input: FheUint<FromId>) -> Self {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let casted = cpu_key.pbs_key().cast_to_unsigned(
                    input.ciphertext.on_cpu().to_owned(),
                    IntoId::num_blocks(cpu_key.message_modulus()),
                );
                Self::new(
                    casted,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let casted = cuda_key.key.key.cast_to_unsigned(
                    input.ciphertext.into_gpu(streams),
                    IntoId::num_blocks(cuda_key.message_modulus()),
                    streams,
                );
                Self::new(
                    casted,
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

impl<Id> CastFrom<FheBool> for FheUint<Id>
where
    Id: FheUintId,
{
    /// Cast a boolean ciphertext to an unsigned ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
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
                Self::new(
                    ciphertext,
                    cpu_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.cast_to_unsigned(
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

impl<Id> ReRandomize for FheUint<Id>
where
    Id: FheUintId,
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
                    panic!("HPU does not support CPKReRandomize.")
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::prelude::UnsignedInteger;
    use crate::prelude::*;
    use crate::shortint::parameters::{AtomicPatternKind, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
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

        assert!(ct.is_conformant(&FheUintConformanceParams::from(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        )));

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

                    assert!(!ct_clone.is_conformant(&FheUintConformanceParams::from(
                        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    )));
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
                ct.ciphertext.as_cpu_mut().blocks[i].atomic_pattern =
                    AtomicPatternKind::Standard(PBSOrder::BootstrapKeyswitch);
            },
        ];

        for breaker in breakers2 {
            for i in 0..ct.ciphertext.on_cpu().blocks.len() {
                let mut ct_clone = ct.clone();

                breaker(i, &mut ct_clone);

                assert!(!ct_clone.is_conformant(&FheUintConformanceParams::from(
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                )));
            }
        }
    }

    #[test]
    fn test_valid_generic_integer() {
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config);

        set_server_key(server_key);

        let ct = FheUint8::try_encrypt(0_u64, &client_key).unwrap();

        assert!(ct.is_conformant(&FheUintConformanceParams::from(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        )));

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

            assert!(ct.is_conformant(&FheUintConformanceParams::from(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            )));

            ct_clone += &ct_clone.clone();
        }
    }
}
