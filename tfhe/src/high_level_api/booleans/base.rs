use super::inner::InnerBoolean;
use crate::backward_compatibility::booleans::FheBoolVersions;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::high_level_api::integers::{FheInt, FheIntId, FheUint, FheUintId};
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::traits::{
    FheEq, Flip, IfThenElse, IfThenZero, ReRandomize, ScalarIfThenElse, Tagged,
};
use crate::high_level_api::{global_state, CompactPublicKey};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::ReRandomizationSeed;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::prelude::*;
use crate::integer::BooleanBlock;
use crate::named::Named;
use crate::prelude::FheWait;
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::shortint::parameters::CiphertextConformanceParams;
use crate::shortint::AtomicPatternParameters;
use crate::{Device, ServerKey, Tag};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};
use tfhe_versionable::Versionize;

#[cfg(feature = "hpu")]
use crate::integer::hpu::ciphertext::HpuRadixCiphertext;
#[cfg(feature = "gpu")]
use crate::prelude::{
    BitAndSizeOnGpu, BitNotSizeOnGpu, BitOrSizeOnGpu, BitXorSizeOnGpu, FheEqSizeOnGpu,
    IfThenElseSizeOnGpu,
};
#[cfg(feature = "hpu")]
use tfhe_hpu_backend::prelude::*;

/// The FHE boolean data type.
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
///
/// let config = ConfigBuilder::default().build();
///
/// let (client_key, server_key) = generate_keys(config);
///
/// let ttrue = FheBool::encrypt(true, &client_key);
/// let ffalse = FheBool::encrypt(false, &client_key);
///
/// // Do not forget to set the server key before doing any computation
/// set_server_key(server_key);
///
/// let fhe_result = ttrue & ffalse;
///
/// let clear_result = fhe_result.decrypt(&client_key);
/// assert!(!clear_result);
/// ```
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(FheBoolVersions)]
pub struct FheBool {
    pub(in crate::high_level_api) ciphertext: InnerBoolean,
    pub(crate) tag: Tag,
    pub(crate) re_randomization_metadata: ReRandomizationMetadata,
}

impl Named for FheBool {
    const NAME: &'static str = "high_level_api::FheBool";
}

impl FheWait for FheBool {
    fn wait(&self) {
        self.ciphertext.wait()
    }
}

#[derive(Copy, Clone)]
pub struct FheBoolConformanceParams(pub(crate) CiphertextConformanceParams);

impl<P> From<P> for FheBoolConformanceParams
where
    P: Into<AtomicPatternParameters>,
{
    fn from(params: P) -> Self {
        let mut params = params.into().to_shortint_conformance_param();
        params.degree = crate::shortint::ciphertext::Degree::new(1);
        Self(params)
    }
}

impl From<&ServerKey> for FheBoolConformanceParams {
    fn from(sk: &ServerKey) -> Self {
        let mut parameter_set = Self(sk.key.pbs_key().key.conformance_params());
        parameter_set.0.degree = crate::shortint::ciphertext::Degree::new(1);
        parameter_set
    }
}

impl ParameterSetConformant for FheBool {
    type ParameterSet = FheBoolConformanceParams;

    fn is_conformant(&self, params: &FheBoolConformanceParams) -> bool {
        let Self {
            ciphertext,
            tag: _,
            re_randomization_metadata: _,
        } = self;

        let BooleanBlock(block) = &*ciphertext.on_cpu();

        block.is_conformant(&params.0)
    }
}

impl FheBool {
    pub(in crate::high_level_api) fn new<T: Into<InnerBoolean>>(
        ciphertext: T,
        tag: Tag,
        re_randomization_metadata: ReRandomizationMetadata,
    ) -> Self {
        Self {
            ciphertext: ciphertext.into(),
            tag,
            re_randomization_metadata,
        }
    }

    pub fn current_device(&self) -> Device {
        self.ciphertext.current_device()
    }

    pub fn num_bits() -> usize {
        1
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

    pub fn into_raw_parts(mut self) -> crate::shortint::Ciphertext {
        self.ciphertext.move_to_device(Device::Cpu);
        match self.ciphertext {
            InnerBoolean::Cpu(ct) => ct.into_raw_parts(),
            #[cfg(feature = "gpu")]
            InnerBoolean::Cuda(_) => unreachable!(),
            #[cfg(feature = "hpu")]
            InnerBoolean::Hpu(_) => unreachable!(),
        }
    }

    /// Tries to decrypt a trivial ciphertext
    ///
    /// Trivial ciphertexts are ciphertexts which are not encrypted
    /// meaning they can be decrypted by any key, or even without a key.
    ///
    /// For debugging, it can be useful to use trivial ciphertext to speed up
    /// execution, and use [Self::try_decrypt_trivial] to decrypt temporary values
    /// and debug.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// // This is not a trivial ciphertext as we use a client key to encrypt.
    /// let non_trivial = FheBool::encrypt(false, &client_key);
    /// // This is a trivial ciphertext
    /// let trivial = FheBool::encrypt_trivial(true);
    ///
    /// // We can trivial decrypt
    /// let result: Result<bool, _> = trivial.try_decrypt_trivial();
    /// assert_eq!(result, Ok(true));
    ///
    /// // We cannot trivial decrypt
    /// let result: Result<bool, _> = non_trivial.try_decrypt_trivial();
    /// assert!(result.is_err());
    /// ```
    pub fn try_decrypt_trivial(&self) -> Result<bool, NotTrivialCiphertextError> {
        self.ciphertext.on_cpu().decrypt_trivial()
    }

    /// Returns true if the ciphertext is a trivial encryption
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let non_trivial = FheBool::encrypt(false, &client_key);
    /// assert!(!non_trivial.is_trivial());
    ///
    /// let trivial = FheBool::encrypt_trivial(true);
    /// assert!(trivial.is_trivial());
    /// ```
    pub fn is_trivial(&self) -> bool {
        self.ciphertext.on_cpu().is_trivial()
    }

    pub fn re_randomization_metadata(&self) -> &ReRandomizationMetadata {
        &self.re_randomization_metadata
    }

    pub fn re_randomization_metadata_mut(&mut self) -> &mut ReRandomizationMetadata {
        &mut self.re_randomization_metadata
    }
}

impl<Id, Scalar> ScalarIfThenElse<&FheUint<Id>, Scalar> for FheBool
where
    Id: FheUintId,
    Scalar: DecomposableInto<u64> + UnsignedNumeric,
{
    type Output = FheUint<Id>;

    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint32::encrypt(u32::MAX, &client_key);
    /// let b = 1u32;
    /// let cond = FheBool::encrypt(true, &client_key);
    ///
    /// let result = cond.scalar_if_then_else(&a, b);
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MAX);
    ///
    /// let result = (!cond).scalar_if_then_else(&a, b);
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1);
    /// ```
    fn scalar_if_then_else(&self, then_value: &FheUint<Id>, else_value: Scalar) -> Self::Output {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let inner = cpu_sks.pbs_key().if_then_else_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*then_value.ciphertext.on_cpu(),
                    else_value,
                );
                FheUint::new(
                    inner,
                    cpu_sks.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda does not support if_then_else with clear input")
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_) => {
                panic!("Hpu does not support if_then_else with clear input")
            }
        })
    }
}

impl<Id, Scalar> ScalarIfThenElse<Scalar, &FheUint<Id>> for FheBool
where
    Id: FheUintId,
    Scalar: DecomposableInto<u64> + UnsignedNumeric,
{
    type Output = FheUint<Id>;

    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = u32::MIN;
    /// let b = FheUint32::encrypt(u32::MAX, &client_key);
    /// let cond = FheBool::encrypt(true, &client_key);
    ///
    /// let result = cond.scalar_if_then_else(a, &b);
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MIN);
    ///
    /// let result = (!cond).scalar_if_then_else(a, &b);
    /// let decrypted: u32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MAX);
    /// ```
    fn scalar_if_then_else(&self, then_value: Scalar, else_value: &FheUint<Id>) -> Self::Output {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let inner = cpu_sks.pbs_key().if_then_else_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    then_value,
                    &*else_value.ciphertext.on_cpu(),
                );
                FheUint::new(
                    inner,
                    cpu_sks.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda does not support if_then_else with clear input")
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support if_then_else with clear input")
            }
        })
    }
}

impl<Id, Scalar> ScalarIfThenElse<&FheInt<Id>, Scalar> for FheBool
where
    Id: FheIntId,
    Scalar: DecomposableInto<u64> + SignedNumeric,
{
    type Output = FheInt<Id>;

    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt32::encrypt(i32::MAX, &client_key);
    /// let b = i32::MIN;
    /// let cond = FheBool::encrypt(true, &client_key);
    ///
    /// let result = cond.scalar_if_then_else(&a, b);
    /// let decrypted: i32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MAX);
    ///
    /// let result = (!cond).scalar_if_then_else(&a, b);
    /// let decrypted: i32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MIN);
    /// ```
    fn scalar_if_then_else(&self, then_value: &FheInt<Id>, else_value: Scalar) -> Self::Output {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let inner = cpu_sks.pbs_key().if_then_else_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*then_value.ciphertext.on_cpu(),
                    else_value,
                );
                FheInt::new(
                    inner,
                    cpu_sks.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda does not support if_then_else with clear input")
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support if_then_else with clear input")
            }
        })
    }
}

impl<Id, Scalar> ScalarIfThenElse<Scalar, &FheInt<Id>> for FheBool
where
    Id: FheIntId,
    Scalar: DecomposableInto<u64> + SignedNumeric,
{
    type Output = FheInt<Id>;

    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = i32::MIN;
    /// let b = FheInt32::encrypt(i32::MAX, &client_key);
    /// let cond = FheBool::encrypt(true, &client_key);
    ///
    /// let result = cond.scalar_if_then_else(a, &b);
    /// let decrypted: i32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MIN);
    ///
    /// let result = (!cond).scalar_if_then_else(a, &b);
    /// let decrypted: i32 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MAX);
    /// ```
    fn scalar_if_then_else(&self, then_value: Scalar, else_value: &FheInt<Id>) -> Self::Output {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let inner = cpu_sks.pbs_key().if_then_else_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    then_value,
                    &*else_value.ciphertext.on_cpu(),
                );
                FheInt::new(
                    inner,
                    cpu_sks.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda does not support if_then_else with clear input")
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support if_then_else with clear input")
            }
        })
    }
}

impl ScalarIfThenElse<&Self, &Self> for FheBool {
    type Output = Self;

    fn scalar_if_then_else(&self, ct_then: &Self, ct_else: &Self) -> Self::Output {
        let ct_condition = self;
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let new_ct = key.pbs_key().if_then_else_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*ct_then.ciphertext.on_cpu(),
                    &*ct_else.ciphertext.on_cpu(),
                );
                (InnerBoolean::Cpu(new_ct), key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.if_then_else(
                    &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                    &*ct_then.ciphertext.on_gpu(streams),
                    &*ct_else.ciphertext.on_gpu(streams),
                    streams,
                );
                let boolean_inner = CudaBooleanBlock(inner);
                (InnerBoolean::Cuda(boolean_inner), cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support if_then_else with clear input")
            }
        });
        Self::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

impl<Id> IfThenElse<FheUint<Id>> for FheBool
where
    Id: FheUintId,
{
    /// Conditional selection.
    ///
    /// The output value returned depends on the value of `self`.
    ///
    /// - if `self` is true, the output will have the value of `ct_then`
    /// - if `self` is false, the output will have the value of `ct_else`
    fn if_then_else(&self, ct_then: &FheUint<Id>, ct_else: &FheUint<Id>) -> FheUint<Id> {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let inner = cpu_sks.pbs_key().if_then_else_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*ct_then.ciphertext.on_cpu(),
                    &*ct_else.ciphertext.on_cpu(),
                );
                FheUint::new(
                    inner,
                    cpu_sks.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.if_then_else(
                    &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                    &*ct_then.ciphertext.on_gpu(streams),
                    &*ct_else.ciphertext.on_gpu(streams),
                    streams,
                );

                FheUint::new(
                    inner,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(device) => {
                let hpu_then = ct_then.ciphertext.on_hpu(device);
                let hpu_else = ct_else.ciphertext.on_hpu(device);
                let hpu_cond = self.ciphertext.on_hpu(device);

                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_IF_THEN_ELSE;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                // These clones are cheap are they are just Arc
                let hpu_result = HpuRadixCiphertext::exec(
                    proto,
                    opcode,
                    &[hpu_then.clone(), hpu_else.clone(), hpu_cond.clone()],
                    &[],
                )
                .pop()
                .unwrap();
                FheUint::new(
                    hpu_result,
                    device.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
        })
    }
}

impl<Id> IfThenZero<FheUint<Id>> for FheBool
where
    Id: FheUintId,
{
    /// Conditional selection.
    ///
    /// The output value returned depends on the value of `self`.
    ///
    /// - if `self` is true, the output will have the value of `ct_then`
    /// - if `self` is false, the output will be an encryption of 0
    fn if_then_zero(&self, ct_then: &FheUint<Id>) -> FheUint<Id> {
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let ct_condition = self;
                let mut ct_out = ct_then.ciphertext.on_cpu().clone();
                cpu_sks.pbs_key().zero_out_if_condition_is_false(
                    &mut ct_out,
                    &ct_condition.ciphertext.on_cpu().0,
                );
                FheUint::new(
                    ct_out,
                    cpu_sks.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda does not support if_then_zero")
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(device) => {
                let hpu_then = ct_then.ciphertext.on_hpu(device);
                let hpu_cond = self.ciphertext.on_hpu(device);

                let (opcode, proto) = {
                    let asm_iop = &hpu_asm::iop::IOP_IF_THEN_ZERO;
                    (
                        asm_iop.opcode(),
                        &asm_iop.format().expect("Unspecified IOP format").proto,
                    )
                };
                // These clones are cheap are they are just Arc
                let hpu_result = HpuRadixCiphertext::exec(
                    proto,
                    opcode,
                    &[hpu_then.clone(), hpu_cond.clone()],
                    &[],
                )
                .pop()
                .unwrap();
                FheUint::new(
                    hpu_result,
                    device.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
        })
    }
}

impl<Id: FheIntId> IfThenElse<FheInt<Id>> for FheBool {
    /// Conditional selection.
    ///
    /// The output value returned depends on the value of `self`.
    ///
    /// - if `self` is true, the output will have the value of `ct_then`
    /// - if `self` is false, the output will have the value of `ct_else`
    fn if_then_else(&self, ct_then: &FheInt<Id>, ct_else: &FheInt<Id>) -> FheInt<Id> {
        let ct_condition = self;
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let new_ct = key.pbs_key().if_then_else_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*ct_then.ciphertext.on_cpu(),
                    &*ct_else.ciphertext.on_cpu(),
                );
                FheInt::new(new_ct, key.tag.clone(), ReRandomizationMetadata::default())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.if_then_else(
                    &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                    &*ct_then.ciphertext.on_gpu(streams),
                    &*ct_else.ciphertext.on_gpu(streams),
                    streams,
                );

                FheInt::new(
                    inner,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support signed integers")
            }
        })
    }
}

impl IfThenElse<Self> for FheBool {
    fn if_then_else(&self, ct_then: &Self, ct_else: &Self) -> Self {
        let ct_condition = self;
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let new_ct = key.pbs_key().if_then_else_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*ct_then.ciphertext.on_cpu(),
                    &*ct_else.ciphertext.on_cpu(),
                );
                (InnerBoolean::Cpu(new_ct), key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.if_then_else(
                    &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                    &*ct_then.ciphertext.on_gpu(streams),
                    &*ct_else.ciphertext.on_gpu(streams),
                    streams,
                );
                let boolean_inner = CudaBooleanBlock(inner);
                (InnerBoolean::Cuda(boolean_inner), cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bool if then else")
            }
        });
        Self::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

impl<Id> Flip<&FheInt<Id>, &FheInt<Id>> for FheBool
where
    Id: FheIntId + std::marker::Send + std::marker::Sync,
{
    type Output = FheInt<Id>;

    /// Flips the two inputs based on the value of `self`.
    ///
    /// * flip(true, a, b) returns (b, a)
    /// * flip(false, a, b) returns (a, b)
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
    /// let a = i32::MIN;
    /// let b = FheInt32::encrypt(i32::MAX, &client_key);
    /// let cond = FheBool::encrypt(true, &client_key);
    ///
    /// let (ra, rb) = cond.flip(a, &b);
    /// let da: i32 = ra.decrypt(&client_key);
    /// let db: i32 = rb.decrypt(&client_key);
    /// assert_eq!((da, db), (i32::MAX, i32::MIN));
    /// ```
    fn flip(&self, lhs: &FheInt<Id>, rhs: &FheInt<Id>) -> (Self::Output, Self::Output) {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let (a, b) = cpu_sks.pbs_key().flip_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*lhs.ciphertext.on_cpu(),
                    &*rhs.ciphertext.on_cpu(),
                );
                (
                    FheInt::new(a, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                    FheInt::new(b, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => rayon::join(
                || {
                    let streams = &cuda_key.streams;
                    let inner = cuda_key.key.key.if_then_else(
                        &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                        &*rhs.ciphertext.on_gpu(streams),
                        &*lhs.ciphertext.on_gpu(streams),
                        streams,
                    );

                    FheInt::new(
                        inner,
                        cuda_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    )
                },
                || {
                    let streams = &cuda_key.streams;
                    let inner = cuda_key.key.key.if_then_else(
                        &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                        &*lhs.ciphertext.on_gpu(streams),
                        &*rhs.ciphertext.on_gpu(streams),
                        streams,
                    );

                    FheInt::new(
                        inner,
                        cuda_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    )
                },
            ),
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                let a = self.if_then_else(rhs, lhs);
                let b = self.if_then_else(lhs, rhs);
                (a, b)
            }
        })
    }
}

impl<Id> Flip<&FheUint<Id>, &FheUint<Id>> for FheBool
where
    Id: FheUintId + std::marker::Send + std::marker::Sync,
{
    type Output = FheUint<Id>;

    /// Flips the two inputs based on the value of `self`.
    ///
    /// * flip(true, a, b) returns (b, a)
    /// * flip(false, a, b) returns (a, b)
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
    /// let a = u32::MIN;
    /// let b = FheUint32::encrypt(u32::MAX, &client_key);
    /// let cond = FheBool::encrypt(true, &client_key);
    ///
    /// let (ra, rb) = cond.flip(a, &b);
    /// let da: u32 = ra.decrypt(&client_key);
    /// let db: u32 = rb.decrypt(&client_key);
    /// assert_eq!((da, db), (u32::MAX, u32::MIN));
    /// ```
    fn flip(&self, lhs: &FheUint<Id>, rhs: &FheUint<Id>) -> (Self::Output, Self::Output) {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let (a, b) = cpu_sks.pbs_key().flip_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*lhs.ciphertext.on_cpu(),
                    &*rhs.ciphertext.on_cpu(),
                );
                (
                    FheUint::new(a, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                    FheUint::new(b, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => rayon::join(
                || {
                    let streams = &cuda_key.streams;
                    let inner = cuda_key.key.key.if_then_else(
                        &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                        &*rhs.ciphertext.on_gpu(streams),
                        &*lhs.ciphertext.on_gpu(streams),
                        streams,
                    );

                    FheUint::new(
                        inner,
                        cuda_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    )
                },
                || {
                    let streams = &cuda_key.streams;
                    let inner = cuda_key.key.key.if_then_else(
                        &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                        &*lhs.ciphertext.on_gpu(streams),
                        &*rhs.ciphertext.on_gpu(streams),
                        streams,
                    );

                    FheUint::new(
                        inner,
                        cuda_key.tag.clone(),
                        ReRandomizationMetadata::default(),
                    )
                },
            ),
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                let a = self.if_then_else(rhs, lhs);
                let b = self.if_then_else(lhs, rhs);
                (a, b)
            }
        })
    }
}

impl<Id, T> Flip<&FheUint<Id>, T> for FheBool
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Output = FheUint<Id>;

    fn flip(&self, lhs: &FheUint<Id>, rhs: T) -> (Self::Output, Self::Output) {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let (a, b) = cpu_sks.pbs_key().flip_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*lhs.ciphertext.on_cpu(),
                    rhs,
                );
                (
                    FheUint::new(a, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                    FheUint::new(b, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Gpu does not support FheBool::flip with clear input")
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support FheBool::flip with clear input")
            }
        })
    }
}

impl<Id, T> Flip<&FheInt<Id>, T> for FheBool
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Output = FheInt<Id>;

    fn flip(&self, lhs: &FheInt<Id>, rhs: T) -> (Self::Output, Self::Output) {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let (a, b) = cpu_sks.pbs_key().flip_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*lhs.ciphertext.on_cpu(),
                    rhs,
                );
                (
                    FheInt::new(a, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                    FheInt::new(b, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Gpu does not support FheBool::flip with clear input")
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support FheBool::flip with clear input")
            }
        })
    }
}

impl<Id, T> Flip<T, &FheInt<Id>> for FheBool
where
    Id: FheIntId,
    T: DecomposableInto<u64> + SignedNumeric,
{
    type Output = FheInt<Id>;

    fn flip(&self, lhs: T, rhs: &FheInt<Id>) -> (Self::Output, Self::Output) {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let (a, b) = cpu_sks.pbs_key().flip_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    lhs,
                    &*rhs.ciphertext.on_cpu(),
                );
                (
                    FheInt::new(a, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                    FheInt::new(b, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Gpu does not support FheBool::flip with clear input")
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support FheBool::flip with clear input")
            }
        })
    }
}

impl<Id, T> Flip<T, &FheUint<Id>> for FheBool
where
    Id: FheUintId,
    T: DecomposableInto<u64> + UnsignedNumeric,
{
    type Output = FheUint<Id>;

    fn flip(&self, lhs: T, rhs: &FheUint<Id>) -> (Self::Output, Self::Output) {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let (a, b) = cpu_sks.pbs_key().flip_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    lhs,
                    &*rhs.ciphertext.on_cpu(),
                );
                (
                    FheUint::new(a, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                    FheUint::new(b, cpu_sks.tag.clone(), ReRandomizationMetadata::default()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Gpu does not support FheBool::flip with clear input")
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support FheBool::flip with clear input")
            }
        })
    }
}

impl Tagged for FheBool {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl<B> FheEq<B> for FheBool
where
    B: Borrow<Self>,
{
    /// Test for equality between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(false, &client_key);
    ///
    /// let result = a.eq(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert!(!decrypted);
    /// ```
    fn eq(&self, other: B) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key.pbs_key().key.equal(
                    self.ciphertext.on_cpu().as_ref(),
                    other.borrow().ciphertext.on_cpu().as_ref(),
                );
                let ciphertext = InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner));
                Self::new(
                    ciphertext,
                    key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.eq(
                    &*self.ciphertext.on_gpu(streams),
                    &other.borrow().ciphertext.on_gpu(streams),
                    streams,
                );
                let ciphertext = InnerBoolean::Cuda(inner);
                Self::new(
                    ciphertext,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support FheBool::eq")
            }
        })
    }

    /// Test for difference between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(false, &client_key);
    ///
    /// let result = a.ne(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true != false);
    /// ```
    fn ne(&self, other: B) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key.pbs_key().key.not_equal(
                    self.ciphertext.on_cpu().as_ref(),
                    other.borrow().ciphertext.on_cpu().as_ref(),
                );
                let ciphertext = InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner));
                Self::new(
                    ciphertext,
                    key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.ne(
                    &*self.ciphertext.on_gpu(streams),
                    &other.borrow().ciphertext.on_gpu(streams),
                    streams,
                );
                let ciphertext = InnerBoolean::Cuda(inner);
                Self::new(
                    ciphertext,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support FheBool::ne")
            }
        })
    }
}

impl FheEq<bool> for FheBool {
    /// Test for equality between a [FheBool] and a [bool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a.eq(false);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert!(!decrypted);
    /// ```
    fn eq(&self, other: bool) -> FheBool {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key
                    .pbs_key()
                    .key
                    .scalar_equal(self.ciphertext.on_cpu().as_ref(), u8::from(other));
                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.scalar_eq(
                    &*self.ciphertext.on_gpu(streams),
                    u8::from(other),
                    streams,
                );
                (InnerBoolean::Cuda(inner), cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support FheBool::eq with a bool")
            }
        });
        Self::new(ciphertext, tag, ReRandomizationMetadata::default())
    }

    /// Test for equality between a [FheBool] and a [bool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a.ne(false);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true != false);
    /// ```
    fn ne(&self, other: bool) -> FheBool {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key
                    .pbs_key()
                    .key
                    .scalar_not_equal(self.ciphertext.on_cpu().as_ref(), u8::from(other));
                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner = cuda_key.key.key.scalar_ne(
                    &*self.ciphertext.on_gpu(streams),
                    u8::from(other),
                    streams,
                );
                (InnerBoolean::Cuda(inner), cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support FheBool::ne with a bool")
            }
        });
        Self::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

#[cfg(feature = "gpu")]
impl<B> FheEqSizeOnGpu<B> for FheBool
where
    B: Borrow<Self>,
{
    fn get_eq_size_on_gpu(&self, rhs: B) -> u64 {
        let rhs = rhs.borrow();

        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_eq_size_on_gpu(
                    &*self.ciphertext.on_gpu(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                )
            } else {
                0
            }
        })
    }
    fn get_ne_size_on_gpu(&self, rhs: B) -> u64 {
        let rhs = rhs.borrow();

        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_ne_size_on_gpu(
                    &*self.ciphertext.on_gpu(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                )
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl FheEqSizeOnGpu<bool> for FheBool {
    fn get_eq_size_on_gpu(&self, _rhs: bool) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_eq_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
    fn get_ne_size_on_gpu(&self, _rhs: bool) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_ne_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
}

impl<B> BitAnd<B> for FheBool
where
    B: Borrow<Self>,
{
    type Output = Self;

    /// Performs a bitwise 'and' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a & &b;
    /// let result = result.decrypt(&client_key);
    /// assert!(result);
    /// ```
    fn bitand(self, rhs: B) -> Self::Output {
        BitAnd::bitand(&self, rhs)
    }
}

impl<B> BitAnd<B> for &FheBool
where
    B: Borrow<FheBool>,
{
    type Output = FheBool;
    /// Performs a bitwise 'and' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// let result = &a & &b;
    /// let result = result.decrypt(&client_key);
    /// assert!(result);
    /// ```
    fn bitand(self, rhs: B) -> Self::Output {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key
                    .pbs_key()
                    .boolean_bitand(&self.ciphertext.on_cpu(), &rhs.borrow().ciphertext.on_cpu());
                (InnerBoolean::Cpu(inner_ct), key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_left_block = self.ciphertext.on_gpu(streams).as_ref().duplicate(streams);
                let inner_right_block = rhs
                    .borrow()
                    .ciphertext
                    .on_gpu(streams)
                    .as_ref()
                    .duplicate(streams);
                let boolean_block_left =
                    CudaBooleanBlock::from_cuda_radix_ciphertext(inner_left_block);
                let boolean_block_right =
                    CudaBooleanBlock::from_cuda_radix_ciphertext(inner_right_block);

                let inner_ct = cuda_key.key.key.boolean_bitand(
                    &boolean_block_left,
                    &boolean_block_right,
                    streams,
                );

                (InnerBoolean::Cuda(inner_ct), cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitand (&)")
            }
        });
        FheBool::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

#[cfg(feature = "gpu")]
impl<B> BitAndSizeOnGpu<B> for FheBool
where
    B: Borrow<Self>,
{
    fn get_bitand_size_on_gpu(&self, rhs: B) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                let inner_left_block = self.ciphertext.on_gpu(streams).as_ref().duplicate(streams);
                let inner_right_block = rhs
                    .borrow()
                    .ciphertext
                    .on_gpu(streams)
                    .as_ref()
                    .duplicate(streams);
                let boolean_block_left =
                    CudaBooleanBlock::from_cuda_radix_ciphertext(inner_left_block);
                let boolean_block_right =
                    CudaBooleanBlock::from_cuda_radix_ciphertext(inner_right_block);

                cuda_key.key.key.get_boolean_bitand_size_on_gpu(
                    &boolean_block_left,
                    &boolean_block_right,
                    streams,
                )
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl BitAndSizeOnGpu<bool> for FheBool {
    fn get_bitand_size_on_gpu(&self, _rhs: bool) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_bitand_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
}

impl<B> BitOr<B> for FheBool
where
    B: Borrow<Self>,
{
    type Output = Self;

    /// Performs a bitwise 'or' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(false, &client_key);
    ///
    /// let result = a | &b;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, true | false);
    /// ```
    fn bitor(self, rhs: B) -> Self::Output {
        BitOr::bitor(&self, rhs)
    }
}

impl<B> BitOr<B> for &FheBool
where
    B: Borrow<FheBool>,
{
    type Output = FheBool;

    /// Performs a bitwise 'or' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(false, &client_key);
    ///
    /// let result = &a | &b;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, true | false);
    /// ```
    fn bitor(self, rhs: B) -> Self::Output {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key.pbs_key().key.bitor(
                    self.ciphertext.on_cpu().as_ref(),
                    rhs.borrow().ciphertext.on_cpu().as_ref(),
                );
                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_ct = cuda_key.key.key.bitor(
                    &*self.ciphertext.on_gpu(streams),
                    &rhs.borrow().ciphertext.on_gpu(streams),
                    streams,
                );
                (
                    InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                        inner_ct.ciphertext,
                    )),
                    cuda_key.tag.clone(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitor (|)")
            }
        });
        FheBool::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

#[cfg(feature = "gpu")]
impl<B> BitOrSizeOnGpu<B> for FheBool
where
    B: Borrow<Self>,
{
    fn get_bitor_size_on_gpu(&self, rhs: B) -> u64 {
        let rhs = rhs.borrow();

        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_bitor_size_on_gpu(
                    &*self.ciphertext.on_gpu(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                )
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl BitOrSizeOnGpu<bool> for FheBool {
    fn get_bitor_size_on_gpu(&self, _rhs: bool) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_bitor_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
}

impl<B> BitXor<B> for FheBool
where
    B: Borrow<Self>,
{
    type Output = Self;

    /// Performs a bitwise 'xor' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a ^ &b;
    /// let result = result.decrypt(&client_key);
    /// assert!(!result);
    /// ```
    fn bitxor(self, rhs: B) -> Self::Output {
        BitXor::bitxor(&self, rhs)
    }
}

impl<B> BitXor<B> for &FheBool
where
    B: Borrow<FheBool>,
{
    type Output = FheBool;

    /// Performs a bitwise 'xor' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// let result = &a ^ &b;
    /// let result = result.decrypt(&client_key);
    /// assert!(!result);
    /// ```
    fn bitxor(self, rhs: B) -> Self::Output {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key.pbs_key().key.bitxor(
                    self.ciphertext.on_cpu().as_ref(),
                    rhs.borrow().ciphertext.on_cpu().as_ref(),
                );
                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_ct = cuda_key.key.key.bitxor(
                    &*self.ciphertext.on_gpu(streams),
                    &rhs.borrow().ciphertext.on_gpu(streams),
                    streams,
                );
                (
                    InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                        inner_ct.ciphertext,
                    )),
                    cuda_key.tag.clone(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitxor (^)")
            }
        });
        FheBool::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

#[cfg(feature = "gpu")]
impl<B> BitXorSizeOnGpu<B> for FheBool
where
    B: Borrow<Self>,
{
    fn get_bitxor_size_on_gpu(&self, rhs: B) -> u64 {
        let rhs = rhs.borrow();

        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_bitxor_size_on_gpu(
                    &*self.ciphertext.on_gpu(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                )
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl BitXorSizeOnGpu<bool> for FheBool {
    fn get_bitxor_size_on_gpu(&self, _rhs: bool) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_bitxor_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
}

impl BitAnd<bool> for FheBool {
    type Output = Self;

    /// Performs a bitwise 'and' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a & false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true & false);
    /// ```
    fn bitand(self, rhs: bool) -> Self::Output {
        <&Self as BitAnd<bool>>::bitand(&self, rhs)
    }
}

impl BitAnd<bool> for &FheBool {
    type Output = FheBool;

    /// Performs a bitwise 'and' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = &a & false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true & false);
    /// ```
    fn bitand(self, rhs: bool) -> Self::Output {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key
                    .pbs_key()
                    .key
                    .scalar_bitand(self.ciphertext.on_cpu().as_ref(), u8::from(rhs));
                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_ct = cuda_key.key.key.scalar_bitand(
                    &*self.ciphertext.on_gpu(streams),
                    u8::from(rhs),
                    streams,
                );
                (
                    InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                        inner_ct.ciphertext,
                    )),
                    cuda_key.tag.clone(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("hpu does not bitand (&) with a bool")
            }
        });
        FheBool::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

impl BitOr<bool> for FheBool {
    type Output = Self;

    /// Performs a bitwise 'or' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a | false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true | false);
    /// ```
    fn bitor(self, rhs: bool) -> Self::Output {
        <&Self as BitOr<bool>>::bitor(&self, rhs)
    }
}

impl BitOr<bool> for &FheBool {
    type Output = FheBool;

    /// Performs a bitwise 'or' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a | false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true | false);
    /// ```
    fn bitor(self, rhs: bool) -> Self::Output {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key
                    .pbs_key()
                    .key
                    .scalar_bitor(self.ciphertext.on_cpu().as_ref(), u8::from(rhs));
                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_ct = cuda_key.key.key.scalar_bitor(
                    &*self.ciphertext.on_gpu(streams),
                    u8::from(rhs),
                    streams,
                );
                (
                    InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                        inner_ct.ciphertext,
                    )),
                    cuda_key.tag.clone(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("hpu does not bitor (|) with a bool")
            }
        });
        FheBool::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

impl BitXor<bool> for FheBool {
    type Output = Self;

    /// Performs a bitwise 'xor' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a ^ false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true ^ false);
    /// ```
    fn bitxor(self, rhs: bool) -> Self::Output {
        <&Self as BitXor<bool>>::bitxor(&self, rhs)
    }
}

impl BitXor<bool> for &FheBool {
    type Output = FheBool;

    /// Performs a bitwise 'xor' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a ^ false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true ^ false);
    /// ```
    fn bitxor(self, rhs: bool) -> Self::Output {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key
                    .pbs_key()
                    .key
                    .scalar_bitxor(self.ciphertext.on_cpu().as_ref(), u8::from(rhs));
                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_ct = cuda_key.key.key.scalar_bitxor(
                    &*self.ciphertext.on_gpu(streams),
                    u8::from(rhs),
                    streams,
                );
                (
                    InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                        inner_ct.ciphertext,
                    )),
                    cuda_key.tag.clone(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("hpu does not bitxor (^) with a bool")
            }
        });
        FheBool::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

impl BitAnd<FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'and' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false & a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false & true);
    /// ```
    fn bitand(self, rhs: FheBool) -> Self::Output {
        rhs & self
    }
}

impl BitAnd<&FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'and' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false & &a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false & true);
    /// ```
    fn bitand(self, rhs: &FheBool) -> Self::Output {
        // and is commutative
        rhs & self
    }
}

impl BitOr<FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'or' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false | a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false | true);
    /// ```
    fn bitor(self, rhs: FheBool) -> Self::Output {
        rhs | self
    }
}

impl BitOr<&FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'or' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false | &a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false | true);
    /// ```
    fn bitor(self, rhs: &FheBool) -> Self::Output {
        // or is commutative
        rhs | self
    }
}

impl BitXor<FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'xor' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false ^ a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false ^ true);
    /// ```
    fn bitxor(self, rhs: FheBool) -> Self::Output {
        // xor is commutative
        rhs ^ self
    }
}

impl BitXor<&FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'xor' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false ^ &a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false ^ true);
    /// ```
    fn bitxor(self, rhs: &FheBool) -> Self::Output {
        // xor is commutative
        rhs ^ self
    }
}

impl<B> BitAndAssign<B> for FheBool
where
    B: Borrow<Self>,
{
    /// Performs a bitwise 'and' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    /// let b = true;
    ///
    /// a &= b;
    /// let result = a.decrypt(&client_key);
    /// assert!(result);
    /// ```
    fn bitand_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key().key.bitand_assign(
                    &mut self.ciphertext.as_cpu_mut().0,
                    &rhs.ciphertext.on_cpu().0,
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.bitand_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitand assign (&=)")
            }
        });
    }
}

impl<B> BitOrAssign<B> for FheBool
where
    B: Borrow<Self>,
{
    /// Performs a bitwise 'or' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// a |= &b;
    /// let result = a.decrypt(&client_key);
    /// assert!(result);
    /// ```
    fn bitor_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key().key.bitor_assign(
                    &mut self.ciphertext.as_cpu_mut().0,
                    &rhs.ciphertext.on_cpu().0,
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.bitor_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitor assign (|=)")
            }
        });
    }
}

impl<B> BitXorAssign<B> for FheBool
where
    B: Borrow<Self>,
{
    /// Performs a bitwise 'xor' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// a ^= &b;
    /// let result = a.decrypt(&client_key);
    /// assert!(!result);
    /// ```
    fn bitxor_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key().key.bitxor_assign(
                    &mut self.ciphertext.as_cpu_mut().0,
                    &rhs.ciphertext.on_cpu().0,
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.bitxor_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitxor assign (^=)")
            }
        });
    }
}

impl BitAndAssign<bool> for FheBool {
    /// Performs a bitwise 'and' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    ///
    /// a &= false;
    /// let result = a.decrypt(&client_key);
    /// assert_eq!(result, true & false);
    /// ```
    fn bitand_assign(&mut self, rhs: bool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key()
                    .key
                    .scalar_bitand_assign(&mut self.ciphertext.as_cpu_mut().0, u8::from(rhs));
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.scalar_bitand_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    u8::from(rhs),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitand assign (&=) with a bool")
            }
        });
    }
}

impl BitOrAssign<bool> for FheBool {
    /// Performs a bitwise 'or' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    ///
    /// a |= false;
    /// let result = a.decrypt(&client_key);
    /// assert_eq!(result, true | false);
    /// ```
    fn bitor_assign(&mut self, rhs: bool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key()
                    .key
                    .scalar_bitor_assign(&mut self.ciphertext.as_cpu_mut().0, u8::from(rhs));
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.scalar_bitor_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    u8::from(rhs),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitor assign (|=) with a bool")
            }
        });
    }
}

impl BitXorAssign<bool> for FheBool {
    /// Performs a bitwise 'xor' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    ///
    /// a ^= false;
    /// let result = a.decrypt(&client_key);
    /// assert_eq!(result, true ^ false);
    /// ```
    fn bitxor_assign(&mut self, rhs: bool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key()
                    .key
                    .scalar_bitxor_assign(&mut self.ciphertext.as_cpu_mut().0, u8::from(rhs));
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.scalar_bitxor_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    u8::from(rhs),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitor assign (^=) with a bool")
            }
        });
    }
}

impl std::ops::Not for FheBool {
    type Output = Self;

    /// Performs a bitwise 'not'
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = !a;
    /// let result = result.decrypt(&client_key);
    /// assert!(!result);
    /// ```
    fn not(self) -> Self::Output {
        (&self).not()
    }
}

impl std::ops::Not for &FheBool {
    type Output = FheBool;

    /// Performs a bitwise 'not'
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = !&a;
    /// let result = result.decrypt(&client_key);
    /// assert!(!result);
    /// ```
    fn not(self) -> Self::Output {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key.pbs_key().boolean_bitnot(&self.ciphertext.on_cpu());
                (InnerBoolean::Cpu(inner), key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_block = self.ciphertext.on_gpu(streams).as_ref().duplicate(streams);
                let boolean_block = CudaBooleanBlock::from_cuda_radix_ciphertext(inner_block);
                let inner = cuda_key.key.key.boolean_bitnot(&boolean_block, streams);
                (InnerBoolean::Cuda(inner), cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support bitnot (!)")
            }
        });
        FheBool::new(ciphertext, tag, ReRandomizationMetadata::default())
    }
}

impl ReRandomize for FheBool {
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

#[cfg(feature = "gpu")]
impl<Id> IfThenElseSizeOnGpu<FheUint<Id>> for FheBool
where
    Id: FheUintId,
{
    fn get_if_then_else_size_on_gpu(&self, ct_then: &FheUint<Id>, ct_else: &FheUint<Id>) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_if_then_else_size_on_gpu(
                    &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                    &*ct_then.ciphertext.on_gpu(streams),
                    &*ct_else.ciphertext.on_gpu(streams),
                    streams,
                )
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl<Id> IfThenElseSizeOnGpu<FheInt<Id>> for FheBool
where
    Id: FheIntId,
{
    fn get_if_then_else_size_on_gpu(&self, ct_then: &FheInt<Id>, ct_else: &FheInt<Id>) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_if_then_else_size_on_gpu(
                    &CudaBooleanBlock(self.ciphertext.on_gpu(streams).duplicate(streams)),
                    &*ct_then.ciphertext.on_gpu(streams),
                    &*ct_else.ciphertext.on_gpu(streams),
                    streams,
                )
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl BitNotSizeOnGpu for FheBool {
    fn get_bitnot_size_on_gpu(&self) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                let inner_block = self.ciphertext.on_gpu(streams).as_ref().duplicate(streams);
                let boolean_block = CudaBooleanBlock::from_cuda_radix_ciphertext(inner_block);

                cuda_key
                    .key
                    .key
                    .get_boolean_bitnot_size_on_gpu(&boolean_block, streams)
            } else {
                0
            }
        })
    }
}
