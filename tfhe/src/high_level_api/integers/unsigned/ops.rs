// Ask clippy not to worry about this
// this is the pattern we use for the macros
#![allow(clippy::redundant_closure_call)]
use super::inner::RadixCiphertext;
#[cfg(feature = "gpu")]
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_stream;
use crate::high_level_api::integers::FheUintId;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::{
    DivRem, FheBootstrap, FheEq, FheMax, FheMin, FheOrd, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::{FheBool, FheUint};
use std::borrow::Borrow;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
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
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let cts = iter
                    .map(|fhe_uint| fhe_uint.ciphertext.into_gpu())
                    .collect::<Vec<_>>();

                let inner = cuda_key
                    .key
                    .sum_ciphertexts(cts, stream)
                    .unwrap_or_else(|| {
                        cuda_key.key.create_trivial_radix(
                            0,
                            Id::num_blocks(cuda_key.message_modulus()),
                            stream,
                        )
                    });
                Self::new(inner)
            }),
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
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
                with_thread_local_cuda_stream(|stream| {
                    let cts = iter
                        .map(|fhe_uint| {
                            match fhe_uint.ciphertext.on_gpu() {
                                MaybeCloned::Borrowed(gpu_ct) => {
                                    unsafe {
                                        // SAFETY
                                        // The gpu_ct is a ref, meaning it belongs to the thing
                                        // that is being iterated on, so it will stay alive for the
                                        // whole function
                                        gpu_ct.duplicate_async(stream)
                                    }
                                }
                                MaybeCloned::Cloned(gpu_ct) => gpu_ct,
                            }
                        })
                        .collect::<Vec<_>>();

                    let inner = cuda_key
                        .key
                        .sum_ciphertexts(cts, stream)
                        .unwrap_or_else(|| {
                            cuda_key.key.create_trivial_radix(
                                0,
                                Id::num_blocks(cuda_key.message_modulus()),
                                stream,
                            )
                        });
                    Self::new(inner)
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                let inner_result = cuda_key.key.max(
                    &*self.ciphertext.on_gpu(),
                    &*rhs.ciphertext.on_gpu(),
                    stream,
                );
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                let inner_result = cuda_key.key.min(
                    &*self.ciphertext.on_gpu(),
                    &*rhs.ciphertext.on_gpu(),
                    stream,
                );
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                        .eq(&*self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for difference between two [FheUint]
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
                        .ne(&*self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                        .lt(&*self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for less than or equal between two [FheUint]
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
                        .le(&*self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for greater than between two [FheUint]
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
                        .gt(&*self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                FheBool::new(inner_result)
            }),
        })
    }

    /// Test for greater than or equal between two [FheUint]
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
                        .ge(&*self.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                            .add(&*lhs.ciphertext.on_gpu(), &*rhs.ciphertext.on_gpu(), stream);
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                            .sub(&*lhs.ciphertext.on_gpu(), &*rhs.ciphertext.on_gpu(), stream);
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                            .mul(&*lhs.ciphertext.on_gpu(), &*rhs.ciphertext.on_gpu(), stream);
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                            .bitand(&*lhs.ciphertext.on_gpu(), &*rhs.ciphertext.on_gpu(), stream);
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                            .bitor(&*lhs.ciphertext.on_gpu(), &*rhs.ciphertext.on_gpu(), stream);
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                            .bitxor(&*lhs.ciphertext.on_gpu(), &*rhs.ciphertext.on_gpu(), stream);
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                    InternalServerKey::Cuda(cuda_key) => {
                         with_thread_local_cuda_stream(|stream| {
                            let inner_result = cuda_key.key
                                .left_shift(&*lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                            FheUint::new(inner_result)
                        })
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                    InternalServerKey::Cuda(cuda_key) => {
                         with_thread_local_cuda_stream(|stream| {
                            let inner_result = cuda_key.key
                                .right_shift(&*lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                            FheUint::new(inner_result)
                        })
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                    InternalServerKey::Cuda(cuda_key) => {
                         with_thread_local_cuda_stream(|stream| {
                            let inner_result = cuda_key.key
                                .rotate_left(&*lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                            FheUint::new(inner_result)
                        })
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                    InternalServerKey::Cuda(cuda_key) => {
                         with_thread_local_cuda_stream(|stream| {
                            let inner_result = cuda_key.key
                                .rotate_right(&*lhs.ciphertext.on_gpu(), &rhs.ciphertext.on_gpu(), stream);
                            FheUint::new(inner_result)
                        })
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
            InternalServerKey::Cuda(cuda_key) => {
                with_thread_local_cuda_stream(|stream| {
                    cuda_key.key.left_shift_assign(
                        self.ciphertext.as_gpu_mut(),
                        &rhs.ciphertext.on_gpu(),
                        stream,
                    );
                });
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
            InternalServerKey::Cuda(cuda_key) => {
                with_thread_local_cuda_stream(|stream| {
                    cuda_key.key.right_shift_assign(
                        self.ciphertext.as_gpu_mut(),
                        &rhs.ciphertext.on_gpu(),
                        stream,
                    );
                });
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
            InternalServerKey::Cuda(cuda_key) => {
                with_thread_local_cuda_stream(|stream| {
                    cuda_key.key.rotate_left_assign(
                        self.ciphertext.as_gpu_mut(),
                        &rhs.ciphertext.on_gpu(),
                        stream,
                    );
                });
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
            InternalServerKey::Cuda(cuda_key) => {
                with_thread_local_cuda_stream(|stream| {
                    cuda_key.key.rotate_right_assign(
                        self.ciphertext.as_gpu_mut(),
                        &rhs.ciphertext.on_gpu(),
                        stream,
                    );
                });
            }
        })
    }
}

impl<Id> Neg for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Computes the negation of a [FheUint].
    ///
    /// Since FheUint are unsigned integers meaning the value they can
    /// represent is always positive, negating a FheUint will yield a
    /// positive number.
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
    /// Since FheUint are unsigned integers meaning the value they can
    /// represent is always positive, negating a FheUint will yield a
    /// positive number.
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
                let inner_result = cuda_key.key.neg(&*self.ciphertext.on_gpu(), stream);
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
                let ciphertext = cpu_key.pbs_key().bitnot(&*self.ciphertext.on_cpu());
                FheUint::new(ciphertext)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_result = cuda_key.key.bitnot(&*self.ciphertext.on_gpu(), stream);
                FheUint::new(inner_result)
            }),
        })
    }
}
