use crate::core_crypto::prelude::{Numeric, OverflowingAdd, SignedNumeric, UnsignedNumeric};
use crate::high_level_api::global_state;
use crate::high_level_api::integers::{FheIntId, FheIntegerType, FheUintId};
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
use crate::high_level_api::traits::FheSliceDotProduct;
use crate::integer::block_decomposition::DecomposableInto;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::RadixCiphertext;
use crate::prelude::{CastFrom, CastInto};
use crate::{FheBool, FheInt, FheUint, Tag};
use std::ops::{AddAssign, Mul};

#[cfg(feature = "high-level-c-api")]
pub(crate) fn fhe_uint_array_eq<Id: FheUintId>(
    lhs: &[FheUint<Id>],
    rhs: &[FheUint<Id>],
) -> FheBool {
    global_state::with_internal_keys(|sks| match sks {
        InternalServerKey::Cpu(cpu_key) => {
            let tmp_lhs = lhs
                .iter()
                .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
                .collect::<Vec<_>>();
            let tmp_rhs = rhs
                .iter()
                .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
                .collect::<Vec<_>>();

            let result = cpu_key
                .pbs_key()
                .all_eq_slices_parallelized(&tmp_lhs, &tmp_rhs);
            FheBool::new(
                result,
                cpu_key.tag.clone(),
                ReRandomizationMetadata::default(),
            )
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(gpu_key) => {
            let streams = &gpu_key.streams;
            let tmp_lhs = lhs
                .iter()
                .map(|fhe_uint| fhe_uint.clone().ciphertext.into_gpu(streams))
                .collect::<Vec<_>>();
            let tmp_rhs = rhs
                .iter()
                .map(|fhe_uint| fhe_uint.clone().ciphertext.into_gpu(streams))
                .collect::<Vec<_>>();

            let result = gpu_key.key.key.all_eq_slices(&tmp_lhs, &tmp_rhs, streams);
            FheBool::new(
                result,
                gpu_key.tag.clone(),
                ReRandomizationMetadata::default(),
            )
        }
        #[cfg(feature = "hpu")]
        InternalServerKey::Hpu(_device) => {
            panic!("Hpu does not support Array yet.")
        }
    })
}

#[cfg(feature = "high-level-c-api")]
pub(crate) fn fhe_uint_array_contains_sub_slice<Id: FheUintId>(
    lhs: &[FheUint<Id>],
    pattern: &[FheUint<Id>],
) -> FheBool {
    global_state::with_internal_keys(|sks| match sks {
        InternalServerKey::Cpu(cpu_key) => {
            let tmp_lhs = lhs
                .iter()
                .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
                .collect::<Vec<_>>();
            let tmp_pattern = pattern
                .iter()
                .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
                .collect::<Vec<_>>();

            let result = cpu_key
                .pbs_key()
                .contains_sub_slice_parallelized(&tmp_lhs, &tmp_pattern);
            FheBool::new(
                result,
                cpu_key.tag.clone(),
                ReRandomizationMetadata::default(),
            )
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(gpu_key) => {
            let streams = &gpu_key.streams;
            let tmp_lhs = lhs
                .iter()
                .map(|fhe_uint| fhe_uint.clone().ciphertext.into_gpu(streams))
                .collect::<Vec<_>>();
            let tmp_pattern = pattern
                .iter()
                .map(|fhe_uint| fhe_uint.clone().ciphertext.into_gpu(streams))
                .collect::<Vec<_>>();

            let result = gpu_key
                .key
                .key
                .contains_sub_slice(&tmp_lhs, &tmp_pattern, streams);
            FheBool::new(
                result,
                gpu_key.tag.clone(),
                ReRandomizationMetadata::default(),
            )
        }
        #[cfg(feature = "hpu")]
        InternalServerKey::Hpu(_device) => {
            panic!("Hpu does not support Array yet.")
        }
    })
}

pub fn fhe_array_contains<T>(data: &[T], value: &T) -> FheBool
where
    T: FheIntegerType,
{
    global_state::with_internal_keys(|sks| match sks {
        InternalServerKey::Cpu(cpu_key) => {
            let tmp_data = data
                .iter()
                .map(|element| element.on_cpu().into_owned())
                .collect::<Vec<_>>();
            let tmp_value = value.on_cpu();

            let result = cpu_key
                .pbs_key()
                .contains_parallelized(&tmp_data, &*tmp_value);
            FheBool::new(
                result,
                cpu_key.tag.clone(),
                ReRandomizationMetadata::default(),
            )
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(gpu_key) => {
            use crate::high_level_api::details::MaybeCloned;

            let streams = &gpu_key.streams;
            let tmp_data = data
                .iter()
                .map(|element| match element.on_gpu(streams) {
                    MaybeCloned::Borrowed(ct) => ct.duplicate(streams),
                    MaybeCloned::Cloned(ct) => ct,
                })
                .collect::<Vec<_>>();
            let tmp_value = value.on_gpu(streams);

            let result = gpu_key.pbs_key().contains(&tmp_data, &*tmp_value, streams);
            FheBool::new(
                result,
                gpu_key.tag.clone(),
                ReRandomizationMetadata::default(),
            )
        }
        #[cfg(feature = "hpu")]
        InternalServerKey::Hpu(_) => {
            panic!("HPU does not support contains() on FheIntegerType yet")
        }
    })
}

/// Small helper to reduce code
///
/// * num_bits: num bits of the FheType
/// * create_fhe_value: function that create a value of FheType given some blocks and tag
fn fhe_bool_dot_product<Clear>(
    bools: &[FheBool],
    clears: &[Clear],
    num_bits: u32,
) -> (Vec<crate::shortint::Ciphertext>, Tag)
where
    Clear: Numeric
        + DecomposableInto<u64>
        + CastInto<usize>
        + CastFrom<u128>
        + Mul<Clear, Output = Clear>
        + AddAssign<Clear>
        + OverflowingAdd<Clear, Output = Clear>,
{
    global_state::with_internal_keys(|keys| match keys {
        InternalServerKey::Cpu(cpu_key) => {
            let boolean_blocks = bools
                .iter()
                .map(|b| b.ciphertext.on_cpu().to_owned())
                .collect::<Vec<_>>();
            let radix: RadixCiphertext = cpu_key.pbs_key().boolean_scalar_dot_prod_parallelized(
                &boolean_blocks,
                clears,
                num_bits / cpu_key.message_modulus().0.ilog2(),
            );

            (radix.blocks, cpu_key.tag.clone())
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(_) => {
            panic!("Cuda does not support FheBool dot product")
        }
        #[cfg(feature = "hpu")]
        InternalServerKey::Hpu(_) => {
            panic!("Hpu does not support FheBool dot product")
        }
    })
}

impl<Id, Clear> FheSliceDotProduct<FheBool, Clear> for FheUint<Id>
where
    Clear: UnsignedNumeric
        + DecomposableInto<u64>
        + CastInto<usize>
        + CastFrom<u128>
        + Mul<Clear, Output = Clear>
        + AddAssign<Clear>
        + OverflowingAdd<Clear, Output = Clear>,
    Id: FheUintId,
{
    /// Performs a dot product between a slice of encrypted booleans and a slice of
    /// clear unsigned integers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint8};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = [true, false, true]
    ///     .into_iter()
    ///     .map(|b| FheBool::encrypt(b, &client_key))
    ///     .collect::<Vec<_>>();
    ///
    /// let b = [2u8, 3u8, 4u8];
    ///
    /// let result = FheUint8::dot_product(&a, &b);
    /// let decrypted: u8 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 6u8);
    /// ```
    fn dot_product(bools: &[FheBool], clears: &[Clear]) -> Self {
        let (blocks, tag) = fhe_bool_dot_product(bools, clears, Id::num_bits() as u32);
        Self::new(
            crate::integer::RadixCiphertext::from(blocks),
            tag,
            ReRandomizationMetadata::default(),
        )
    }
}

impl<Id, Clear> FheSliceDotProduct<FheBool, Clear> for FheInt<Id>
where
    Clear: SignedNumeric
        + DecomposableInto<u64>
        + CastInto<usize>
        + CastFrom<u128>
        + Mul<Clear, Output = Clear>
        + AddAssign<Clear>
        + OverflowingAdd<Clear, Output = Clear>,
    Id: FheIntId,
{
    /// Performs a dot product between a slice of encrypted booleans and a slice of
    /// clear signed integers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt8};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = [true, false, true]
    ///     .into_iter()
    ///     .map(|b| FheBool::encrypt(b, &client_key))
    ///     .collect::<Vec<_>>();
    ///
    /// let b = [-2i8, -3i8, -4i8];
    ///
    /// let result = FheInt8::dot_product(&a, &b);
    /// let decrypted: i8 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -6i8);
    /// ```
    fn dot_product(bools: &[FheBool], clears: &[Clear]) -> Self {
        let (blocks, tag) = fhe_bool_dot_product(bools, clears, Id::num_bits() as u32);
        Self::new(
            crate::integer::SignedRadixCiphertext::from(blocks),
            tag,
            ReRandomizationMetadata::default(),
        )
    }
}
