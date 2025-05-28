#[cfg(feature = "gpu")]
use crate::core_crypto::commons::numeric::CastFrom;
use crate::high_level_api::errors::UnwrapResultExt;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::signed::inner::SignedRadixCiphertext;
use crate::high_level_api::integers::FheIntId;
use crate::high_level_api::keys::InternalServerKey;
#[cfg(feature = "gpu")]
use crate::high_level_api::traits::{
    AddSizeOnGpu, BitAndSizeOnGpu, BitOrSizeOnGpu, BitXorSizeOnGpu, FheMaxSizeOnGpu,
    FheMinSizeOnGpu, FheOrdSizeOnGpu, RotateLeftSizeOnGpu, RotateRightSizeOnGpu, ShlSizeOnGpu,
    ShrSizeOnGpu, SubSizeOnGpu,
};
use crate::high_level_api::traits::{
    DivRem, FheEq, FheMax, FheMin, FheOrd, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
use crate::integer::bigint::{I1024, I2048, U1024, U2048};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::{I256, I512, U256, U512};
use crate::{FheBool, FheInt};
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.max(2i16);
    ///
    /// let decrypted_max: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_max, 2i16);
    /// ```
    fn max(&self, rhs: Clear) -> Self::Output {
        global_state::with_internal_keys(|keys| match keys {
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    ///
    /// let result = a.min(2i16);
    ///
    /// let decrypted_min: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_min, -1i16);
    /// ```
    fn min(&self, rhs: Clear) -> Self::Output {
        global_state::with_internal_keys(|keys| match keys {
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        global_state::with_internal_keys(|keys| match keys {
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

    /// Test for difference between a [FheInt] and a clear
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
    /// let b = 2u16;
    ///
    /// let result = a.ne(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 != 2i16);
    /// ```
    fn ne(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        global_state::with_internal_keys(|keys| match keys {
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

    /// Test for less than or equal between [FheInt] and a clear value
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
    /// let result = a.le(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 <= 2i16);
    /// ```
    fn le(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
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

    /// Test for greater than between [FheInt] and a clear value
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
    /// let result = a.gt(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 > 2i16);
    /// ```
    fn gt(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
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

    /// Test for greater than or equal between [FheInt] and a clear value
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
    /// let result = a.ge(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 >= 2i16);
    /// ```
    fn ge(&self, rhs: Clear) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
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
impl<Id, Clear> FheOrdSizeOnGpu<Clear> for FheInt<Id>
where
    Id: FheIntId,
    Clear: DecomposableInto<u64>,
{
    fn get_gt_size_on_gpu(&self, _rhs: Clear) -> u64 {
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
    fn get_ge_size_on_gpu(&self, _rhs: Clear) -> u64 {
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
    fn get_lt_size_on_gpu(&self, _rhs: Clear) -> u64 {
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
impl<Id, Clear> FheMinSizeOnGpu<Clear> for FheInt<Id>
where
    Id: FheIntId,
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
impl<Id, Clear> FheMaxSizeOnGpu<Clear> for FheInt<Id>
where
    Id: FheIntId,
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
// DivRem is a bit special as it returns a tuple of quotient and remainder
macro_rules! generic_integer_impl_scalar_div_rem {
    (
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheInt8 and the rest is scalar types (i8, i16, etc)
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
                        global_state::with_internal_keys(|keys| match keys {
                            InternalServerKey::Cpu(cpu_key) => {
                                let (q, r) = cpu_key
                                    .pbs_key()
                                    .signed_scalar_div_rem_parallelized(&*self.ciphertext.on_cpu(), rhs);
                                (
                                    <$concrete_type>::new(q, cpu_key.tag.clone()),
                                    <$concrete_type>::new(r, cpu_key.tag.clone())
                                )
                            }
                            #[cfg(feature = "gpu")]
                            InternalServerKey::Cuda(cuda_key) => {
                                let (inner_q, inner_r) = {let streams = &cuda_key.streams;
                                    cuda_key.key.key.signed_scalar_div_rem(
                                        &*self.ciphertext.on_gpu(streams), rhs, streams
                                    )
                                };
                                let (q, r) = (
                                    SignedRadixCiphertext::Cuda(inner_q),
                                    SignedRadixCiphertext::Cuda(inner_r),
                                );
                                (
                                    <$concrete_type>::new(q, cuda_key.tag.clone()),
                                    <$concrete_type>::new(r, cuda_key.tag.clone()),
                                )
                            }
                            #[cfg(feature = "hpu")]
                            InternalServerKey::Hpu(_device) => {
                                panic!("Hpu does not support this operation yet.")
                            }
                        })
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

#[cfg(feature = "gpu")]
use crate::high_level_api::integers::unsigned::scalar_ops::{
    generic_integer_impl_get_scalar_left_operation_size_on_gpu,
    generic_integer_impl_get_scalar_operation_size_on_gpu,
};
use crate::high_level_api::integers::unsigned::scalar_ops::{
    generic_integer_impl_scalar_left_operation, generic_integer_impl_scalar_operation,
    generic_integer_impl_scalar_operation_assign,
};

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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_left_shift_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_left_shift(
                                    &*lhs.ciphertext.on_gpu(streams), u64::cast_from(rhs), streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
                |lhs: &FheInt<_>, _rhs| {
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_right_shift_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_right_shift(
                                    &*lhs.ciphertext.on_gpu(streams), u64::cast_from(rhs), streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
                |lhs: &FheInt<_>, _rhs| {
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_rotate_left_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_rotate_left(
                                    &*lhs.ciphertext.on_gpu(streams), u64::cast_from(rhs), streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
                |lhs: &FheInt<_>, _rhs| {
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_rotate_right_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_rotate_right(
                                    &*lhs.ciphertext.on_gpu(streams), u64::cast_from(rhs), streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
                |lhs: &FheInt<_>, _rhs| {
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
                |lhs: &mut FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            cpu_key
                                .pbs_key()
                                .scalar_left_shift_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) =>
                            {let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_left_shift_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
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
                |lhs: &mut FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            cpu_key
                                .pbs_key()
                                .scalar_right_shift_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_right_shift_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
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
                |lhs: &mut FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            cpu_key
                                .pbs_key()
                                .scalar_rotate_left_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) =>
                            {let streams = &cuda_key.streams;
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
                |lhs: &mut FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            cpu_key
                                .pbs_key()
                                .scalar_rotate_right_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            {let streams = &cuda_key.streams;
                                cuda_key.key.key
                                    .scalar_rotate_right_assign(lhs.ciphertext.as_gpu_mut(streams), rhs, streams);
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
    };
}

define_scalar_rotate_shifts!(
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
    (super::FheInt512, u8, u16, u32, u64, u128, U256, U512),
    (
        super::FheInt1024,
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
        super::FheInt2048,
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

#[cfg(feature = "extended-types")]
define_scalar_rotate_shifts!(
    (super::FheInt24, u8, u16, u32, u64, u128),
    (super::FheInt40, u8, u16, u32, u64, u128),
    (super::FheInt48, u8, u16, u32, u64, u128),
    (super::FheInt56, u8, u16, u32, u64, u128),
    (super::FheInt72, u8, u16, u32, u64, u128),
    (super::FheInt80, u8, u16, u32, u64, u128),
    (super::FheInt88, u8, u16, u32, u64, u128),
    (super::FheInt96, u8, u16, u32, u64, u128),
    (super::FheInt104, u8, u16, u32, u64, u128),
    (super::FheInt112, u8, u16, u32, u64, u128),
    (super::FheInt120, u8, u16, u32, u64, u128),
    (super::FheInt136, u8, u16, u32, u64, u128, U256),
    (super::FheInt144, u8, u16, u32, u64, u128, U256),
    (super::FheInt152, u8, u16, u32, u64, u128, U256),
    (super::FheInt168, u8, u16, u32, u64, u128, U256),
    (super::FheInt176, u8, u16, u32, u64, u128, U256),
    (super::FheInt184, u8, u16, u32, u64, u128, U256),
    (super::FheInt192, u8, u16, u32, u64, u128, U256),
    (super::FheInt200, u8, u16, u32, u64, u128, U256),
    (super::FheInt208, u8, u16, u32, u64, u128, U256),
    (super::FheInt216, u8, u16, u32, u64, u128, U256),
    (super::FheInt224, u8, u16, u32, u64, u128, U256),
    (super::FheInt232, u8, u16, u32, u64, u128, U256),
    (super::FheInt240, u8, u16, u32, u64, u128, U256),
    (super::FheInt248, u8, u16, u32, u64, u128, U256),
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_add_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_add(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
            rust_trait: AddSizeOnGpu(get_add_size_on_gpu),
            implem: {
                |lhs: &FheInt<_>, _rhs| {
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_sub_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_sub(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
            rust_trait: SubSizeOnGpu(get_sub_size_on_gpu),
            implem: {
                |lhs: &FheInt<_>, _rhs| {
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_mul_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_mul(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
            rust_trait: BitAnd(bitand),
            implem: {
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_bitand_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_bitand(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
                |lhs: &FheInt<_>, _rhs| {
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_bitor_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_bitor(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
                |lhs: &FheInt<_>, _rhs| {
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .scalar_bitxor_parallelized(&*lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },

                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.scalar_bitxor(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
                |lhs: &FheInt<_>, _rhs| {
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .signed_scalar_div_parallelized(&lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.signed_scalar_div(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
                |lhs: &FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let inner_result = cpu_key
                                .pbs_key()
                                .signed_scalar_rem_parallelized(&lhs.ciphertext.on_cpu(), rhs);
                            SignedRadixCiphertext::Cpu(inner_result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let inner_result = {let streams = &cuda_key.streams;
                                cuda_key.key.key.signed_scalar_rem(
                                    &*lhs.ciphertext.on_gpu(streams), rhs, streams
                                )
                            };
                            SignedRadixCiphertext::Cuda(inner_result)
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
                |lhs, rhs: &FheInt<_>| {
                    // `+` is commutative
                    let result: FheInt<_> = rhs + lhs;
                    result.ciphertext
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature="gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: AddSizeOnGpu(get_add_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheInt<_>| {
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
                |lhs, rhs: &FheInt<_>| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            let result = cpu_key.pbs_key().left_scalar_sub_parallelized(lhs, &*rhs.ciphertext.on_cpu());
                            SignedRadixCiphertext::Cpu(result)
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            use crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
                            let streams = &cuda_key.streams;
                                let mut result: CudaSignedRadixCiphertext = cuda_key.pbs_key().create_trivial_radix(
                                    lhs, rhs.ciphertext.on_gpu(streams).ciphertext.info.blocks.len(), streams);
                                cuda_key.pbs_key().sub_assign(&mut result, &*rhs.ciphertext.on_gpu(streams), streams);
                                SignedRadixCiphertext::Cuda(result)
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

        #[cfg(feature="gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: SubSizeOnGpu(get_sub_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheInt<_>| {
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
                |lhs, rhs: &FheInt<_>| {
                    // `*` is commutative
                    let result: FheInt<_> = rhs * lhs;
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
                |lhs, rhs: &FheInt<_>| {
                    // `&` is commutative
                    let result: FheInt<_> = rhs & lhs;
                    result.ciphertext
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature="gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: BitAndSizeOnGpu(get_bitand_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheInt<_>| {
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
                |lhs, rhs: &FheInt<_>| {
                    // `|` is commutative
                    let result: FheInt<_> = rhs | lhs;
                    result.ciphertext
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature="gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: BitOrSizeOnGpu(get_bitor_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheInt<_>| {
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
                |lhs, rhs: &FheInt<_>| {
                    // `^` is commutative
                    let result: FheInt<_> = rhs ^ lhs;
                    result.ciphertext
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type, $($scalar_type)*),
                )*
        );

        #[cfg(feature="gpu")]
        generic_integer_impl_get_scalar_left_operation_size_on_gpu!(
            rust_trait: BitXorSizeOnGpu(get_bitxor_size_on_gpu),
            implem: {
                |_lhs, rhs: &FheInt<_>| {
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
                |lhs: &mut FheInt<_>, rhs| {
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
                        InternalServerKey::Hpu(_device) => {
                            panic!("Hpu does not support this operation yet.")
                        }
                    })
                }
            },
            fhe_and_scalar_type:
                $(
                    ($concrete_type,
                        $(
                            #[doc = "Performs an addition assignment operation of a clear to a [FheInt]."]
                            $scalar_type
                        )*),
                )*
        );


        generic_integer_impl_scalar_operation_assign!(
            rust_trait: SubAssign(sub_assign),
            implem: {
                |lhs: &mut FheInt<_>, rhs| {
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
            rust_trait: MulAssign(mul_assign),
            implem: {
                |lhs: &mut FheInt<_>, rhs| {
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
            rust_trait: BitAndAssign(bitand_assign),
            implem: {
                |lhs: &mut FheInt<_>, rhs| {
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
                |lhs: &mut FheInt<_>, rhs| {
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
                |lhs: &mut FheInt<_>, rhs| {
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
                |lhs: &mut FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            cpu_key
                                .pbs_key()
                                .signed_scalar_div_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {
                            let streams = &cuda_key.streams;
                            let cuda_lhs = lhs.ciphertext.as_gpu_mut(streams);
                            let cuda_result = cuda_key.pbs_key().signed_scalar_div(&cuda_lhs, rhs, streams);
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
                |lhs: &mut FheInt<_>, rhs| {
                    global_state::with_internal_keys(|key| match key {
                        InternalServerKey::Cpu(cpu_key) => {
                            cpu_key
                                .pbs_key()
                                .signed_scalar_rem_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                        },
                        #[cfg(feature = "gpu")]
                        InternalServerKey::Cuda(cuda_key) => {let streams = &cuda_key.streams;
                            let cuda_lhs = lhs.ciphertext.as_gpu_mut(streams);
                            let cuda_result = cuda_key.pbs_key().signed_scalar_rem(&cuda_lhs, rhs, streams);
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
    (super::FheInt512, I512),
    (super::FheInt1024, I1024),
    (super::FheInt2048, I2048),
);

#[cfg(feature = "extended-types")]
define_scalar_ops!(
    (super::FheInt24, i32),
    (super::FheInt40, i64),
    (super::FheInt48, i64),
    (super::FheInt56, i64),
    (super::FheInt72, i128),
    (super::FheInt80, i128),
    (super::FheInt88, i128),
    (super::FheInt96, i128),
    (super::FheInt104, i128),
    (super::FheInt112, i128),
    (super::FheInt120, i128),
    (super::FheInt136, I256),
    (super::FheInt144, I256),
    (super::FheInt152, I256),
    (super::FheInt168, I256),
    (super::FheInt176, I256),
    (super::FheInt184, I256),
    (super::FheInt192, I256),
    (super::FheInt200, I256),
    (super::FheInt208, I256),
    (super::FheInt216, I256),
    (super::FheInt224, I256),
    (super::FheInt232, I256),
    (super::FheInt240, I256),
    (super::FheInt248, I256),
);
