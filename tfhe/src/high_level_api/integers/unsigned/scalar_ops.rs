// Ask clippy not to worry about this
// this is the pattern we use for the macros
#![allow(clippy::redundant_closure_call)]

use super::base::FheUint;
use super::inner::RadixCiphertext;
#[cfg(feature = "gpu")]
use crate::core_crypto::commons::numeric::CastFrom;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_stream;
use crate::high_level_api::integers::FheUintId;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::{
    DivRem, FheEq, FheMax, FheMin, FheOrd, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
use crate::integer::bigint::U2048;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::IntegerCiphertext;
use crate::integer::U256;
use crate::FheBool;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
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
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key
                    .key
                    .scalar_eq(&self.ciphertext.on_gpu(), rhs, stream);
                FheBool::new(inner_result)
            }),
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
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key
                    .key
                    .scalar_ne(&self.ciphertext.on_gpu(), rhs, stream);
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
        (super::FheUint2048, U2048),
);

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

pub(in crate::high_level_api::integers) use generic_integer_impl_scalar_operation;

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
                            &*lhs.ciphertext.on_gpu(), rhs, stream
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
        (super::FheUint2048, U2048),
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
                            &*lhs.ciphertext.on_gpu(), rhs, stream
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
        (super::FheUint2048, U2048),
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
                    let inner_result = with_thread_local_cuda_stream(|stream| {
                        cuda_key.key.scalar_mul(
                            &*lhs.ciphertext.on_gpu(), rhs, stream
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
        (super::FheUint2048, U2048),
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
                            &*lhs.ciphertext.on_gpu(), rhs, stream
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
        (super::FheUint2048, U2048),
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
                            &*lhs.ciphertext.on_gpu(), rhs, stream
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
        (super::FheUint2048, U2048),
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
                            &*lhs.ciphertext.on_gpu(), rhs, stream
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
        (super::FheUint2048, U2048),
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
                            &*lhs.ciphertext.on_gpu(), u64::cast_from(rhs), stream
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
        (super::FheUint2048, u8, u16, u32, u64, u128, U256, U2048),
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
                            &*lhs.ciphertext.on_gpu(), u64::cast_from(rhs), stream
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
        (super::FheUint2048, u8, u16, u32, u64, u128, U256, U2048),
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
                            &*lhs.ciphertext.on_gpu(), u64::cast_from(rhs), stream
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
        (super::FheUint2048, u8, u16, u32, u64, u128, U256, U2048),
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
                            &*lhs.ciphertext.on_gpu(), u64::cast_from(rhs), stream
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
        (super::FheUint2048, u8, u16, u32, u64, u128, U256, U2048),
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
        (super::FheUint2048, U2048),
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
        (super::FheUint2048, U2048),
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

pub(in crate::high_level_api::integers) use generic_integer_impl_scalar_left_operation;

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
            /// use tfhe::prelude::*;
            /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            ///
            /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        (super::FheUint2048, U2048),
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
                        let mut result = cuda_key.key.create_trivial_radix(lhs, rhs.ciphertext.on_gpu().ciphertext.info.blocks.len(), stream);
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
            /// use tfhe::prelude::*;
            /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            ///
            /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        (super::FheUint2048, U2048),
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
            /// use tfhe::prelude::*;
            /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            ///
            /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        (super::FheUint2048, U2048),
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
            /// use tfhe::prelude::*;
            /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            ///
            /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        (super::FheUint2048, U2048),
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
            /// use tfhe::prelude::*;
            /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            ///
            /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        (super::FheUint2048, U2048),
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
            /// use tfhe::prelude::*;
            /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
            ///
            /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        (super::FheUint2048, U2048),
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

pub(in crate::high_level_api::integers) use generic_integer_impl_scalar_operation_assign;

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
        /// The operation is modular, i.e. on overflow it wraps around.
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
        (super::FheUint2048, U2048),
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
        (super::FheUint2048, U2048),
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
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_mul_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
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
        (super::FheUint2048, U2048),
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
        (super::FheUint2048, U2048),
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
        (super::FheUint2048, U2048),
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
        (super::FheUint2048, U2048),
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
        (super::FheUint2048, u8, u16, u32, u64, u128, U256, U2048),
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
        (super::FheUint2048, u8, u16, u32, u64, u128, U256, U2048),
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
        (super::FheUint2048, u8, u16, u32, u64, u128, U256, U2048),
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
        (super::FheUint2048, u8, u16, u32, u64, u128, U256, U2048),
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
        (super::FheUint2048, U2048),
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
        (super::FheUint2048, U2048),
);
