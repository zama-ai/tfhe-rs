// Ask clippy not to worry about this
// this is the pattern we use for the macros
#![allow(clippy::redundant_closure_call)]

use super::base::FheUint;
use super::inner::RadixCiphertext;
use crate::error::InvalidRangeError;
use crate::high_level_api::errors::UnwrapResultExt;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheUintId;
use crate::high_level_api::keys::InternalServerKey;
#[cfg(feature = "gpu")]
use crate::high_level_api::traits::{
    AddSizeOnGpu, BitAndSizeOnGpu, BitOrSizeOnGpu, BitXorSizeOnGpu, FheMaxSizeOnGpu,
    FheMinSizeOnGpu, FheOrdSizeOnGpu, RotateLeftSizeOnGpu, RotateRightSizeOnGpu, ShlSizeOnGpu,
    ShrSizeOnGpu, SubSizeOnGpu,
};
use crate::high_level_api::traits::{
    BitSlice, DivRem, FheEq, FheMax, FheMin, FheOrd, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
use crate::integer::bigint::{U1024, U2048, U512};
use crate::integer::block_decomposition::DecomposableInto;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::U256;
use crate::prelude::{CastFrom, CastInto};
use crate::FheBool;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, RangeBounds, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result =
                    cuda_key
                        .key
                        .key
                        .scalar_eq(&*self.ciphertext.on_gpu(streams), rhs, streams);
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Test for difference between a [FheUint] and a clear
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
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result =
                    cuda_key
                        .key
                        .key
                        .scalar_ne(&*self.ciphertext.on_gpu(streams), rhs, streams);
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result =
                    cuda_key
                        .key
                        .key
                        .scalar_lt(&*self.ciphertext.on_gpu(streams), rhs, streams);
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Test for less than or equal between a [FheUint] and a clear value
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
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result =
                    cuda_key
                        .key
                        .key
                        .scalar_le(&*self.ciphertext.on_gpu(streams), rhs, streams);
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Test for greater than between a [FheUint] and a clear value
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
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result =
                    cuda_key
                        .key
                        .key
                        .scalar_gt(&*self.ciphertext.on_gpu(streams), rhs, streams);
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Test for greater than or equal between a [FheUint] and a clear value
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
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result =
                    cuda_key
                        .key
                        .key
                        .scalar_ge(&*self.ciphertext.on_gpu(streams), rhs, streams);
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl<Id, Clear> FheOrdSizeOnGpu<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: DecomposableInto<u64>,
{
    fn get_gt_size_on_gpu(&self, _rhs: Clear) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_gt_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
    fn get_ge_size_on_gpu(&self, _rhs: Clear) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_ge_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
    fn get_lt_size_on_gpu(&self, _rhs: Clear) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_lt_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
    fn get_le_size_on_gpu(&self, _rhs: Clear) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_le_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl<Id, Clear> FheMinSizeOnGpu<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: DecomposableInto<u64>,
{
    fn get_min_size_on_gpu(&self, _rhs: Clear) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_min_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
}
#[cfg(feature = "gpu")]
impl<Id, Clear> FheMaxSizeOnGpu<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: DecomposableInto<u64>,
{
    fn get_max_size_on_gpu(&self, _rhs: Clear) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_scalar_max_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.max(b);
    ///
    /// let decrypted_max: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_max, 2u16);
    /// ```
    fn max(&self, rhs: Clear) -> Self::Output {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_max_parallelized(&*self.ciphertext.on_cpu(), rhs);
                Self::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result =
                    cuda_key
                        .key
                        .key
                        .scalar_max(&*self.ciphertext.on_gpu(streams), rhs, streams);
                Self::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = 2u16;
    ///
    /// let result = a.min(b);
    ///
    /// let decrypted_min: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_min, 1u16);
    /// ```
    fn min(&self, rhs: Clear) -> Self::Output {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_min_parallelized(&*self.ciphertext.on_cpu(), rhs);
                Self::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result =
                    cuda_key
                        .key
                        .key
                        .scalar_min(&*self.ciphertext.on_gpu(streams), rhs, streams);
                Self::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id, Clear> BitSlice<Clear> for &FheUint<Id>
where
    Id: FheUintId,
    Clear: CastFrom<usize> + CastInto<usize> + Copy,
{
    type Output = FheUint<Id>;

    /// Extract a slice of bits from a [FheUint].
    ///
    /// This function is more efficient if the range starts on a block boundary.
    ///
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
    /// let msg: u16 = 225;
    /// let a = FheUint16::encrypt(msg, &client_key);
    /// let start_bit = 3;
    /// let end_bit = 6;
    ///
    /// let result = (&a).bitslice(start_bit..end_bit).unwrap();
    ///
    /// let decrypted_slice: u16 = result.decrypt(&client_key);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, decrypted_slice);
    /// ```
    fn bitslice<R>(self, range: R) -> Result<Self::Output, InvalidRangeError>
    where
        R: RangeBounds<Clear>,
    {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .scalar_bitslice_parallelized(&self.ciphertext.on_cpu(), range)?;
                Ok(FheUint::new(result, cpu_key.tag.clone()))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support bitslice yet");
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id, Clear> BitSlice<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: CastFrom<usize> + CastInto<usize> + Copy,
{
    type Output = Self;

    /// Extract a slice of bits from a [FheUint].
    ///
    /// This function is more efficient if the range starts on a block boundary.
    ///
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
    /// let msg: u16 = 225;
    /// let a = FheUint16::encrypt(msg, &client_key);
    /// let start_bit = 3;
    /// let end_bit = 6;
    ///
    /// let result = a.bitslice(start_bit..end_bit).unwrap();
    ///
    /// let decrypted_slice: u16 = result.decrypt(&client_key);
    /// assert_eq!((msg % (1 << end_bit)) >> start_bit, decrypted_slice);
    /// ```
    fn bitslice<R>(self, range: R) -> Result<Self::Output, InvalidRangeError>
    where
        R: RangeBounds<Clear>,
    {
        <&Self as BitSlice<Clear>>::bitslice(&self, range)
    }
}

// DivRem is a bit special as it returns a tuple of quotient and remainder
macro_rules! generic_integer_impl_scalar_div_rem {
    (
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
                        global_state::with_internal_keys(|key| {
                            match key {
                                InternalServerKey::Cpu(cpu_key) => {
                                    let (q, r) = cpu_key.pbs_key().scalar_div_rem_parallelized(&*self.ciphertext.on_cpu(), rhs);
                                    (
                                        <$concrete_type>::new(q, cpu_key.tag.clone()),
                                        <$concrete_type>::new(r, cpu_key.tag.clone())
                                    )
                                }
                                #[cfg(feature = "gpu")]
                                InternalServerKey::Cuda(cuda_key) => {
                                    let (inner_q, inner_r) = {
                                        let streams = &cuda_key.streams;
                                        cuda_key.key.key.scalar_div_rem(
                                            &*self.ciphertext.on_gpu(streams), rhs, streams
                                            )
                                    };
                                    let (q, r) = (RadixCiphertext::Cuda(inner_q), RadixCiphertext::Cuda(inner_r));
                                    (
                                        <$concrete_type>::new(q, cuda_key.tag.clone()),
                                        <$concrete_type>::new(r, cuda_key.tag.clone())
                                    )
                                }
                                #[cfg(feature = "hpu")]
                                InternalServerKey::Hpu(_device) => {
                                    panic!("Hpu does not support this operation yet.")
                                }
                            }
                        })
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
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
            ($concrete_type:ty, $($scalar_type:ty),* $(,)?)
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
                        let tag = global_state::tag_of_internal_server_key().unwrap_display();
                        <$concrete_type>::new(inner_result, tag)
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

pub(in crate::high_level_api::integers) use generic_integer_impl_scalar_operation;

#[cfg(feature = "gpu")]
macro_rules! generic_integer_impl_get_scalar_operation_size_on_gpu {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        implem: {
            // A closure that must return a u64
            $closure:expr
        },
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($scalar_type:ty),* $(,)?)
        ),*
        $(,)?
    ) => {
        $( // First repeating pattern
            $( // Second repeating pattern
                impl $rust_trait_name<$scalar_type> for $concrete_type
                {
                    fn $rust_trait_method(&self, rhs: $scalar_type) -> u64 {
                        $closure(&self, rhs)
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

#[cfg(feature = "gpu")]
pub(in crate::high_level_api::integers) use generic_integer_impl_get_scalar_operation_size_on_gpu;

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
                        let tag = global_state::tag_of_internal_server_key().unwrap_display();
                        <$concrete_type>::new(inner_result, tag)
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

pub(in crate::high_level_api::integers) use generic_integer_impl_scalar_left_operation;

#[cfg(feature = "gpu")]
macro_rules! generic_integer_impl_get_scalar_left_operation_size_on_gpu {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        implem: {
            // A closure that must return a u64
            $closure:expr
        },
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($scalar_type:ty),* $(,)?)
        ),*
        $(,)?
    ) => {
        $( // First repeating pattern
            $( // Second repeating pattern
                impl $rust_trait_name<&$concrete_type> for $scalar_type
                {
                    fn $rust_trait_method(&self, rhs: &$concrete_type) -> u64 {
                        $closure(&self, rhs)
                    }
                }
                impl $rust_trait_name<$concrete_type> for $scalar_type
                {
                    fn $rust_trait_method(&self, rhs: $concrete_type) -> u64 {
                        $closure(&self, &rhs)
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

#[cfg(feature = "gpu")]
pub(in crate::high_level_api::integers) use generic_integer_impl_get_scalar_left_operation_size_on_gpu;

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
            ($concrete_type:ty, $($(#[$doc:meta])* $scalar_type:ty),* $(,)?)
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

pub(in crate::high_level_api::integers) use generic_integer_impl_scalar_operation_assign;

macro_rules! define_scalar_rotate_shifts {
    (
        $(
            ($concrete_type:ty, $($scalar_type:ty),* $(,)?)
        ),*
        $(,)?
    ) => {

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
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_left_shift(
                                    &*lhs.ciphertext.on_gpu(streams), u64::cast_from(rhs), streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_operation_size_on_gpu!(
            rust_trait: ShlSizeOnGpu(get_left_shift_size_on_gpu),
            implem: {
                |lhs: &FheUint<_>, _rhs| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_left_shift_size_on_gpu(
                                    &*lhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
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
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_right_shift(
                                    &*lhs.ciphertext.on_gpu(streams), u64::cast_from(rhs), streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_operation_size_on_gpu!(
            rust_trait: ShrSizeOnGpu(get_right_shift_size_on_gpu),
            implem: {
                |lhs: &FheUint<_>, _rhs| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_right_shift_size_on_gpu(
                                    &*lhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
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
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_rotate_left(
                                    &*lhs.ciphertext.on_gpu(streams), u64::cast_from(rhs), streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_operation_size_on_gpu!(
            rust_trait: RotateLeftSizeOnGpu(get_rotate_left_size_on_gpu),
            implem: {
                |lhs: &FheUint<_>, _rhs| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_rotate_left_size_on_gpu(
                                    &*lhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
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
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_rotate_right(
                                    &*lhs.ciphertext.on_gpu(streams), u64::cast_from(rhs), streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_operation_size_on_gpu!(
            rust_trait: RotateRightSizeOnGpu(get_rotate_right_size_on_gpu),
            implem: {
                |lhs: &FheUint<_>, _rhs| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_rotate_right_size_on_gpu(
                                    &*lhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
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
                            {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_left_shift_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                            }
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
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
                            {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_right_shift_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                            }
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
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
                            let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_rotate_left_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
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
                            let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_rotate_right_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type,)*),
                )*
        );
    };
}

#[cfg(feature = "extended-types")]
define_scalar_rotate_shifts!(
    (super::FheUint24, u8, u16, u32, u64, u128),
    (super::FheUint40, u8, u16, u32, u64, u128),
    (super::FheUint48, u8, u16, u32, u64, u128),
    (super::FheUint56, u8, u16, u32, u64, u128),
    (super::FheUint72, u8, u16, u32, u64, u128),
    (super::FheUint80, u8, u16, u32, u64, u128),
    (super::FheUint88, u8, u16, u32, u64, u128),
    (super::FheUint96, u8, u16, u32, u64, u128),
    (super::FheUint104, u8, u16, u32, u64, u128),
    (super::FheUint112, u8, u16, u32, u64, u128),
    (super::FheUint120, u8, u16, u32, u64, u128),
    (super::FheUint136, u8, u16, u32, u64, u128, U256),
    (super::FheUint144, u8, u16, u32, u64, u128, U256),
    (super::FheUint152, u8, u16, u32, u64, u128, U256),
    (super::FheUint168, u8, u16, u32, u64, u128, U256),
    (super::FheUint176, u8, u16, u32, u64, u128, U256),
    (super::FheUint184, u8, u16, u32, u64, u128, U256),
    (super::FheUint192, u8, u16, u32, u64, u128, U256),
    (super::FheUint200, u8, u16, u32, u64, u128, U256),
    (super::FheUint208, u8, u16, u32, u64, u128, U256),
    (super::FheUint216, u8, u16, u32, u64, u128, U256),
    (super::FheUint224, u8, u16, u32, u64, u128, U256),
    (super::FheUint232, u8, u16, u32, u64, u128, U256),
    (super::FheUint240, u8, u16, u32, u64, u128, U256),
    (super::FheUint248, u8, u16, u32, u64, u128, U256),
);

define_scalar_rotate_shifts!(
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
    (super::FheUint512, u8, u16, u32, u64, u128, U256, U512),
    (
        super::FheUint1024,
        u8,
        u16,
        u32,
        u64,
        u128,
        U256,
        U512,
        U1024
    ),
    (
        super::FheUint2048,
        u8,
        u16,
        u32,
        u64,
        u128,
        U256,
        U512,
        U1024,
        U2048
    ),
);

macro_rules! define_scalar_ops {
    (
        $(
            ($concrete_type:ty, $($(#[$doc:meta])* $scalar_type:ty),*)
        ),*
        $(,)?
    ) => {

        generic_integer_impl_scalar_div_rem!(
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );


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
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_add(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(device) => {
                            let lhs = lhs.ciphertext.on_hpu(device);
                            let rhs = u128::try_from(rhs).unwrap();

                            RadixCiphertext::Hpu(&*lhs + rhs)
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_operation_size_on_gpu!(
            rust_trait: AddSizeOnGpu(get_add_size_on_gpu),
            implem: {
                |lhs: &FheUint<_>, _rhs| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_add_size_on_gpu(
                                    &*lhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_sub(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(device) => {
                            let lhs = lhs.ciphertext.on_hpu(device);
                            let rhs = u128::try_from(rhs).unwrap();

                            RadixCiphertext::Hpu(&*lhs - rhs)
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_operation_size_on_gpu!(
            rust_trait: SubSizeOnGpu(get_sub_size_on_gpu),
            implem: {
                |lhs: &FheUint<_>, _rhs| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_sub_size_on_gpu(
                                    &*lhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_mul(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(device) => {
                             let lhs = lhs.ciphertext.on_hpu(device);
                            let rhs = u128::try_from(rhs).unwrap();

                            RadixCiphertext::Hpu(&*lhs * rhs)
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_bitand(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_operation_size_on_gpu!(
            rust_trait: BitAndSizeOnGpu(get_bitand_size_on_gpu),
            implem: {
                |lhs: &FheUint<_>, _rhs| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_bitand_size_on_gpu(
                                    &*lhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_bitor(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_operation_size_on_gpu!(
            rust_trait: BitOrSizeOnGpu(get_bitor_size_on_gpu),
            implem: {
                |lhs: &FheUint<_>, _rhs| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_bitor_size_on_gpu(
                                    &*lhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_bitxor(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_operation_size_on_gpu!(
            rust_trait: BitXorSizeOnGpu(get_bitxor_size_on_gpu),
            implem: {
                |lhs: &FheUint<_>, _rhs| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_bitxor_size_on_gpu(
                                    &*lhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_div(
                                    &lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {
                                let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_rem(
                                    &lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            RadixCiphertext::Cuda(inner_result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );


        // Scalar Ops With Scalar As Lhs
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
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: AddSizeOnGpu(get_add_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheUint<_>| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_add_size_on_gpu(
                                    &*rhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );


        generic_integer_impl_scalar_left_operation!(
            rust_trait: Sub(sub),
            implem: {
                |lhs, rhs: &FheUint<_>| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let result = cpu_key.pbs_key().left_scalar_sub_parallelized(lhs, &*rhs.ciphertext.on_cpu());
                            RadixCiphertext::Cpu(result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let streams = &cuda_key.streams;
                                let mut result: CudaUnsignedRadixCiphertext = cuda_key.pbs_key().create_trivial_radix(
                                    lhs, rhs.ciphertext.on_gpu(streams).ciphertext.info.blocks.len(), streams);
                                cuda_key.pbs_key().sub_assign(&mut result, &rhs.ciphertext.on_gpu(streams), streams);
                                RadixCiphertext::Cuda(result)
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: SubSizeOnGpu(get_sub_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheUint<_>| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_sub_size_on_gpu(
                                    &*rhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );


        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: BitAndSizeOnGpu(get_bitand_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheUint<_>| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_bitand_size_on_gpu(
                                    &*rhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: BitOrSizeOnGpu(get_bitor_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheUint<_>| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_bitor_size_on_gpu(
                                    &*rhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature = "gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: BitXorSizeOnGpu(get_bitxor_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheUint<_>| {
                    global_state::with_internal_keys(|key|
                        if let InternalServerKey::Cuda(cuda_key) = key {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key.get_scalar_bitxor_size_on_gpu(
                                    &*rhs.ciphertext.on_gpu(streams),
                                    streams,
                                )
                        } else {
                            0
                        })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        // Scalar Assign Ops

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
                            let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_add_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(device) => {
                            let lhs = lhs.ciphertext.as_hpu_mut(device);
                            let rhs = u128::try_from(rhs).unwrap();

                           *lhs += rhs;
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type,
                        $(
                            #[doc = "Performs an addition assignment operation of a clear to a [FheUint]."]
                            $scalar_type
                        )*),
                )*
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
                            let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_sub_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(device) => {
                            let lhs = lhs.ciphertext.as_hpu_mut(device);
                            let rhs = u128::try_from(rhs).unwrap();

                            *lhs -= rhs;
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                        InternalServerKey::Cuda(cuda_key) => {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_mul_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(device) => {
                            let lhs = lhs.ciphertext.as_hpu_mut(device);
                            let rhs = u128::try_from(rhs).unwrap();

                            *lhs *= rhs;
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                            let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_bitand_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                            let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_bitor_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                            let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_bitxor_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
                        }
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                        InternalServerKey::Cuda(cuda_key) => {
                            let streams = &cuda_key.streams;
                            let cuda_lhs = lhs.ciphertext.as_gpu_mut(streams);
                            let cuda_result = cuda_key.pbs_key().scalar_div(&cuda_lhs, rhs, streams);
                            *cuda_lhs = cuda_result;
                        },
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
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
                        InternalServerKey::Cuda(cuda_key) => {
                            let streams = &cuda_key.streams;
                            let cuda_lhs = lhs.ciphertext.as_gpu_mut(streams);
                            let cuda_result = cuda_key.pbs_key().scalar_rem(&cuda_lhs, rhs, streams);
                            *cuda_lhs = cuda_result;
                        },
                        #[cfg(feature = "hpu")]
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );
    };
}

define_scalar_ops!(
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
    (super::FheUint512, U512),
    (super::FheUint1024, U1024),
    (super::FheUint2048, U2048),
);

#[cfg(feature = "extended-types")]
define_scalar_ops!(
    (super::FheUint24, u32),
    (super::FheUint40, u64),
    (super::FheUint48, u64),
    (super::FheUint56, u64),
    (super::FheUint72, u128),
    (super::FheUint80, u128),
    (super::FheUint88, u128),
    (super::FheUint96, u128),
    (super::FheUint104, u128),
    (super::FheUint112, u128),
    (super::FheUint120, u128),
    (super::FheUint136, U256),
    (super::FheUint144, U256),
    (super::FheUint152, U256),
    (super::FheUint168, U256),
    (super::FheUint176, U256),
    (super::FheUint184, U256),
    (super::FheUint192, U256),
    (super::FheUint200, U256),
    (super::FheUint208, U256),
    (super::FheUint216, U256),
    (super::FheUint224, U256),
    (super::FheUint232, U256),
    (super::FheUint240, U256),
    (super::FheUint248, U256),
);
