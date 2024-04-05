#[cfg(feature = "gpu")]
use crate::core_crypto::commons::numeric::CastFrom;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_stream;
use crate::high_level_api::integers::signed::inner::RadixCiphertext;
use crate::high_level_api::integers::FheIntId;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::{
    DivRem, FheEq, FheMax, FheMin, FheOrd, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::IntegerCiphertext;
use crate::integer::{I256, U256};
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
    /// assert_eq!(decrypted_max, (-1i16).max(2i16));
    /// ```
    fn max(&self, rhs: Clear) -> Self::Output {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_max_parallelized(&*self.ciphertext.on_cpu(), rhs);
                Self::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices does not support max yet")
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
    /// assert_eq!(decrypted_min, (-1i16).min(2i16));
    /// ```
    fn min(&self, rhs: Clear) -> Self::Output {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .scalar_min_parallelized(&*self.ciphertext.on_cpu(), rhs);
                Self::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices does not support min yet")
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
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices does not support casting yet")
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
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices does not support casting yet")
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
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices does not support casting yet")
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
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices does not support casting yet")
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
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices does not support casting yet")
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
                FheBool::new(inner_result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices does not support casting yet")
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
                        global_state::with_internal_keys(|keys| match keys {
                            InternalServerKey::Cpu(cpu_key) => {
                                let (q, r) = cpu_key
                                    .pbs_key()
                                    .$key_method(&*self.ciphertext.on_cpu(), rhs);
                                (
                                    <$concrete_type>::new(q),
                                    <$concrete_type>::new(r)
                                )
                            }
                            #[cfg(feature = "gpu")]
                            InternalServerKey::Cuda(_) => {
                                panic!("Cuda devices does not support casting yet")
                            }
                        })
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

use crate::high_level_api::integers::unsigned::scalar_ops::{
    generic_integer_impl_scalar_left_operation, generic_integer_impl_scalar_operation,
    generic_integer_impl_scalar_operation_assign,
};

generic_integer_impl_scalar_operation!(
    rust_trait: Add(add),
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .signed_scalar_div_parallelized(&lhs.ciphertext.on_cpu(), rhs);
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
    implem: {
        |lhs: &FheInt<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .signed_scalar_rem_parallelized(&lhs.ciphertext.on_cpu(), rhs);
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
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16,
            /// Adds a [super::FheInt16] to a clear
            ///
            /// The operation is modular, i.e. on overflow it wraps around.
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
            /// let a = 23i16;
            /// let b = FheInt16::encrypt(3i16, &client_key);
            ///
            /// let result = a + &b;
            /// let result: i16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23i16 + 3i16);
            /// ```
            i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_left_operation!(
    rust_trait: Sub(sub),
    implem: {
        |lhs, rhs: &FheInt<_>| {
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
                InternalServerKey::Cuda(_cuda_key) => {
                    with_thread_local_cuda_stream(|_stream| {
                        panic!("Cuda devices do not support subtracting a chiphertext to a clear")
//                        let mut result = cuda_key.key.create_signed_trivial_radix(lhs, rhs.ciphertext.on_gpu().ciphertext.info.blocks.len(), stream);
//                        cuda_key.key.sub_assign(&mut result, &rhs.ciphertext.on_gpu(), stream);
//                        RadixCiphertext::Cuda(result)
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16,
            /// Subtract a [super::FheInt16] to a clear
            ///
            /// The operation is modular, i.e. on overflow it wraps around.
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
            /// let a = 23i16;
            /// let b = FheInt16::encrypt(3i16, &client_key);
            ///
            /// let result = a - &b;
            /// let result: i16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23i16 - 3i16);
            /// ```
            i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
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
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16,
            /// Multiplies a [super::FheInt16] to a clear
            ///
            /// The operation is modular, i.e. on overflow it wraps around.
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
            /// let a = 23i16;
            /// let b = FheInt16::encrypt(3i16, &client_key);
            ///
            /// let result = a * &b;
            /// let result: i16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23i16 * 3i16);
            /// ```
            i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
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
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16,
            /// Performs a bitwise 'and' between a clear and [super::FheInt16]
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
            /// let a = 23i16;
            /// let b = FheInt16::encrypt(3i16, &client_key);
            ///
            /// let result = a & &b;
            /// let result: i16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23i16 & 3i16);
            /// ```
            i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
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
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16,
            /// Performs a bitwise 'or' between a clear and [super::FheInt16]
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
            /// let a = 23i16;
            /// let b = FheInt16::encrypt(3i16, &client_key);
            ///
            /// let result = a | &b;
            /// let result: i16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23i16 | 3i16);
            /// ```
            i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
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
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16,
            /// Performs a bitwise 'xor' between a clear and [super::FheInt16]
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
            /// let a = 23i16;
            /// let b = FheInt16::encrypt(3i16, &client_key);
            ///
            /// let result = a ^ &b;
            /// let result: i16 = result.decrypt(&client_key);
            /// assert_eq!(result, 23i16 ^ 3i16);
            /// ```
            i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
);

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
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_add_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
    fhe_and_scalar_type:
        (super::FheInt2, i8),
        (super::FheInt4, i8),
        (super::FheInt6, i8),
        (super::FheInt8, i8),
        (super::FheInt10, i16),
        (super::FheInt12, i16),
        (super::FheInt14, i16),
        (super::FheInt16,
        /// Adds a clear to a [super::FheInt16]
        ///
        /// The operation is modular, i.e. on overflow it wraps around.
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
        /// let mut a = FheInt16::encrypt(3i16, &client_key);
        /// let b = 23i16;
        ///
        /// a += b;
        ///
        /// let result: i16 = a.decrypt(&client_key);
        /// assert_eq!(result, 23i16 + 3i16);
        /// ```
        i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt160, I256),
        (super::FheInt256, I256),
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
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_sub_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
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
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_mul_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
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
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_bitand_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
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
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_bitor_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
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
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_bitxor_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
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
    implem: {
        |lhs: &mut FheInt<_>, rhs| {
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
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_right_shift_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
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
    implem: {
        |lhs: &mut FheInt<_>, rhs| {
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
                    with_thread_local_cuda_stream(|stream| {
                        cuda_key.key
                            .scalar_rotate_right_assign(lhs.ciphertext.as_gpu_mut(), rhs, stream);
                    })
                }
            })
        }
    },
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
    implem: {
        |lhs: &mut FheInt<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .signed_scalar_div_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_) => {
                    panic!("DivAssign '/=' with clear value is not yet supported by Cuda devices")
                }
            })
        }
    },
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
    implem: {
        |lhs: &mut FheInt<_>, rhs| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    cpu_key
                        .pbs_key()
                        .signed_scalar_rem_assign_parallelized(lhs.ciphertext.as_cpu_mut(), rhs);
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(_) => {
                    panic!("RemAssign '%=' with clear value is not yet supported by Cuda devices")
                }
            })
        }
    },
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
