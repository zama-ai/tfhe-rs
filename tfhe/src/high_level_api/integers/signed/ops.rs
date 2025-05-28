#[cfg(feature = "gpu")]
use crate::high_level_api::details::MaybeCloned;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::high_level_api::keys::InternalServerKey;
#[cfg(feature = "gpu")]
use crate::high_level_api::traits::{
    AddSizeOnGpu, BitAndSizeOnGpu, BitNotSizeOnGpu, BitOrSizeOnGpu, BitXorSizeOnGpu,
    FheMaxSizeOnGpu, FheMinSizeOnGpu, FheOrdSizeOnGpu, RotateLeftSizeOnGpu, RotateRightSizeOnGpu,
    ShlSizeOnGpu, ShrSizeOnGpu, SizeOnGpu, SubSizeOnGpu,
};
use crate::high_level_api::traits::{
    DivRem, FheEq, FheMax, FheMin, FheOrd, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::{FheBool, FheInt, FheUint};
use std::borrow::Borrow;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

impl<'a, Id> std::iter::Sum<&'a Self> for FheInt<Id>
where
    Id: FheIntId,
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
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let clears = [-1i16, 2, 3, 4, -5];
    /// let encrypted = clears
    ///     .iter()
    ///     .copied()
    ///     .map(|x| FheInt16::encrypt(x, &client_key))
    ///     .collect::<Vec<_>>();
    ///
    /// // Iter and sum on references
    /// let result = encrypted.iter().sum::<FheInt16>();
    ///
    /// let decrypted: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, clears.into_iter().sum::<i16>());
    /// ```
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertexts = iter
                    .map(|elem| elem.ciphertext.on_cpu().to_owned())
                    .collect::<Vec<_>>();
                cpu_key
                    .pbs_key()
                    .sum_ciphertexts_parallelized(ciphertexts.iter())
                    .map_or_else(
                        || {
                            let radix: crate::integer::SignedRadixCiphertext =
                                cpu_key.pbs_key().create_trivial_zero_radix(Id::num_blocks(
                                    cpu_key.message_modulus(),
                                ));
                            Self::new(radix, cpu_key.tag.clone())
                        },
                        |ct| Self::new(ct, cpu_key.tag.clone()),
                    )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                {
                    let streams = &cuda_key.streams;
                    let cts = iter
                        .map(|fhe_uint| {
                            match fhe_uint.ciphertext.on_gpu(streams) {
                                MaybeCloned::Borrowed(gpu_ct) => {
                                    unsafe {
                                        // SAFETY
                                        // The gpu_ct is a ref, meaning it belongs to the thing
                                        // that is being iterated on, so it will stay alive for the
                                        // whole function
                                        gpu_ct.duplicate_async(streams)
                                    }
                                }
                                MaybeCloned::Cloned(gpu_ct) => gpu_ct,
                            }
                        })
                        .collect::<Vec<_>>();

                    let inner = cuda_key
                        .key
                        .key
                        .sum_ciphertexts(cts, streams)
                        .unwrap_or_else(|| {
                            cuda_key.key.key.create_trivial_radix(
                                0,
                                Id::num_blocks(cuda_key.message_modulus()),
                                streams,
                            )
                        });
                    Self::new(inner, cuda_key.tag.clone())
                }
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id> FheMax<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Returns the max between two [FheInt]
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
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.max(&b);
    ///
    /// let decrypted_max: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_max, 2i16);
    /// ```
    fn max(&self, rhs: &Self) -> Self::Output {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .max_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                Self::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key.key.key.max(
                    &*self.ciphertext.on_gpu(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
                Self::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id> FheMin<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Returns the max between two [FheInt]
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
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.min(&b);
    ///
    /// let decrypted_min: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_min, -1i16);
    /// ```
    fn min(&self, rhs: &Self) -> Self::Output {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .min_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                Self::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key.key.key.min(
                    &*self.ciphertext.on_gpu(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
                Self::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id> FheEq<Self> for FheInt<Id>
where
    Id: FheIntId,
{
    fn eq(&self, rhs: Self) -> FheBool {
        self.eq(&rhs)
    }

    fn ne(&self, rhs: Self) -> FheBool {
        self.ne(&rhs)
    }
}

impl<Id> FheEq<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    /// Test for equality between two [FheInt]
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
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.eq(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 == 2i16);
    /// ```
    fn eq(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .eq_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key.key.key.eq(
                    &*self.ciphertext.on_gpu(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Test for difference between two [FheInt]
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
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.ne(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 != 2i16);
    /// ```
    fn ne(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .ne_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key.key.key.ne(
                    &*self.ciphertext.on_gpu(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id> FheOrd<Self> for FheInt<Id>
where
    Id: FheIntId,
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

impl<Id> FheOrd<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    /// Test for less than between two [FheInt]
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
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.lt(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 < 2i16);
    /// ```
    fn lt(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .lt_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key.key.key.lt(
                    &*self.ciphertext.on_gpu(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Test for less than or equal between two [FheInt]
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
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.le(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 <= 2i16);
    /// ```
    fn le(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .le_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key.key.key.le(
                    &*self.ciphertext.on_gpu(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Test for greater than between two [FheInt]
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
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.gt(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 > 2i16);
    /// ```
    fn gt(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .gt_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key.key.key.gt(
                    &*self.ciphertext.on_gpu(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Test for greater than or equal between two [FheInt]
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
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.ge(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 >= 2i16);
    /// ```
    fn ge(&self, rhs: &Self) -> FheBool {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let inner_result = cpu_key
                    .pbs_key()
                    .ge_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                FheBool::new(inner_result, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key.key.key.ge(
                    &*self.ciphertext.on_gpu(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
                FheBool::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id> DivRem<Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: Self) -> Self::Output {
        <Self as DivRem<&Self>>::div_rem(self, &rhs)
    }
}

impl<Id> DivRem<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: &Self) -> Self::Output {
        <&Self as DivRem<&Self>>::div_rem(&self, rhs)
    }
}

impl<Id> DivRem<Self> for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = (FheInt<Id>, FheInt<Id>);

    /// Computes the quotient and remainder between two [FheInt]
    ///
    /// If you need both the quotient and remainder, then `div_rem` is better
    /// than computing them separately using `/` and `%`.
    ///
    /// When the divisor is 0, remainder will have the same value as the numerator, and,
    /// if the numerator is < 0, quotient will be -1 else 1
    ///
    /// This behaviour should not be relied on.
    ///
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
    /// let a = FheInt16::encrypt(-23i16, &client_key);
    /// let b = FheInt16::encrypt(3i16, &client_key);
    ///
    /// let (quotient, remainder) = (&a).div_rem(&b);
    ///
    /// let quotient: i16 = quotient.decrypt(&client_key);
    /// assert_eq!(quotient, -23i16 / 3i16);
    /// let remainder: i16 = remainder.decrypt(&client_key);
    /// assert_eq!(remainder, -23i16 % 3i16);
    /// ```
    fn div_rem(self, rhs: Self) -> Self::Output {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let (q, r) = cpu_key
                    .pbs_key()
                    .div_rem_parallelized(&*self.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                (
                    FheInt::<Id>::new(q, cpu_key.tag.clone()),
                    FheInt::<Id>::new(r, cpu_key.tag.clone()),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let (q, r) = cuda_key.key.key.div_rem(
                    &*self.ciphertext.on_gpu(streams),
                    &*rhs.ciphertext.on_gpu(streams),
                    streams,
                );
                (
                    FheInt::<Id>::new(q, cuda_key.tag.clone()),
                    FheInt::<Id>::new(r, cuda_key.tag.clone()),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

macro_rules! generic_integer_impl_operation (
    (
        $(#[$outer:meta])*
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        implem: {
            $closure:expr
        }
        $(,)?
    ) => {
        impl<Id, B> $rust_trait_name<B> for FheInt<Id>
        where
            Id: FheIntId,
            B: Borrow<Self>,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                <&Self as $rust_trait_name<B>>::$rust_trait_method(&self, rhs)
            }
        }

        impl<Id, B> $rust_trait_name<B> for &FheInt<Id>
        where
            Id: FheIntId,
            B: Borrow<FheInt<Id>>,
        {
            type Output = FheInt<Id>;

            $(#[$outer])*
            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                $closure(self, rhs.borrow())
            }
        }
    }
);

generic_integer_impl_operation!(
    /// Adds two [FheInt]
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
    /// let a = FheInt16::encrypt(23i16, &client_key);
    /// let b = FheInt16::encrypt(3i16, &client_key);
    ///
    /// let result = &a + &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 23i16 + 3i16);
    /// ```
    rust_trait: Add(add),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheInt<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .add_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheInt::new(inner_result, cpu_key.tag.clone())
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    {let streams = &cuda_key.streams;
                        let inner_result = cuda_key.key.key
                            .add(&*lhs.ciphertext.on_gpu(streams), &*rhs.ciphertext.on_gpu(streams), streams);
                        FheInt::new(inner_result, cuda_key.tag.clone())
                    }
                }
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
                }
            })
        }
    },
);
generic_integer_impl_operation!(
    /// Subtracts two [FheInt]
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
    /// let a = FheInt16::encrypt(3i16, &client_key);
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// let result = &a - &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 3i16.wrapping_sub(7849i16));
    /// ```
    rust_trait: Sub(sub),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheInt<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .sub_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheInt::new(inner_result, cpu_key.tag.clone())
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    {let streams = &cuda_key.streams;
                        let inner_result = cuda_key.key.key
                            .sub(&*lhs.ciphertext.on_gpu(streams), &*rhs.ciphertext.on_gpu(streams), streams);
                        FheInt::new(inner_result, cuda_key.tag.clone())
                    }
                }
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
                }
            })
        }
    },
);
generic_integer_impl_operation!(
    /// Multiplies two [FheInt]
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
    /// let a = FheInt16::encrypt(3i16, &client_key);
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// let result = &a * &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 3i16.wrapping_mul(7849i16));
    /// ```
    rust_trait: Mul(mul),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheInt<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .mul_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheInt::new(inner_result, cpu_key.tag.clone())
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                     {let streams = &cuda_key.streams;
                        let inner_result = cuda_key.key.key
                            .mul(&*lhs.ciphertext.on_gpu(streams), &*rhs.ciphertext.on_gpu(streams), streams);
                        FheInt::new(inner_result, cuda_key.tag.clone())
                    }
                }
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
                }
            })
        }
    },
);
generic_integer_impl_operation!(
    /// Performs a bitwise 'and' between two [FheInt]
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
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// let result = &a & &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result,  3i16 & 7849i16);
    /// ```
    rust_trait: BitAnd(bitand),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheInt<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .bitand_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheInt::new(inner_result, cpu_key.tag.clone())
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                     {let streams = &cuda_key.streams;
                        let inner_result = cuda_key.key.key
                            .bitand(&*lhs.ciphertext.on_gpu(streams), &*rhs.ciphertext.on_gpu(streams), streams);
                        FheInt::new(inner_result, cuda_key.tag.clone())
                    }
                }
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
                }
            })
        }
    },
);
generic_integer_impl_operation!(
    /// Performs a bitwise 'or' between two [FheInt]
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
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// let result = &a | &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result,  3i16 | 7849i16);
    /// ```
    rust_trait: BitOr(bitor),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheInt<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .bitor_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheInt::new(inner_result, cpu_key.tag.clone())
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                     {let streams = &cuda_key.streams;
                        let inner_result = cuda_key.key.key
                            .bitor(&*lhs.ciphertext.on_gpu(streams), &*rhs.ciphertext.on_gpu(streams), streams);
                        FheInt::new(inner_result, cuda_key.tag.clone())
                    }
                }
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
                }
            })
        }
    },
);
generic_integer_impl_operation!(
    /// Performs a bitwise 'xor' between two [FheInt]
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
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// let result = &a ^ &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result,  3i16 ^ 7849i16);
    /// ```
    rust_trait: BitXor(bitxor),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheInt<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .bitxor_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheInt::new(inner_result, cpu_key.tag.clone())
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                     {let streams = &cuda_key.streams;
                        let inner_result = cuda_key.key.key
                            .bitxor(&*lhs.ciphertext.on_gpu(streams), &*rhs.ciphertext.on_gpu(streams), streams);
                        FheInt::new(inner_result, cuda_key.tag.clone())
                    }
                }
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
                }
            })
        }
    },
);
generic_integer_impl_operation!(
    /// Divides two [FheInt] and returns the quotient
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheInt::div_rem], instead of using `/` and `%` separately.
    ///
    /// When the divisor is 0, the returned quotient will be the max value (i.e. all bits set to 1).
    ///
    /// This behaviour should not be relied on.
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheInt16::encrypt(3i16, &client_key);
    ///
    /// let result = &a / &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 7849i16 / 3i16);
    /// ```
    rust_trait: Div(div),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheInt<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .div_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheInt::new(inner_result, cpu_key.tag.clone())
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {let streams = &cuda_key.streams;
                    let inner_result =
                        cuda_key
                            .key
                            .key
                            .div(&*lhs.ciphertext.on_gpu(streams), &*rhs.ciphertext.on_gpu(streams), streams);
                    FheInt::new(inner_result, cuda_key.tag.clone())
                },
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
                }
            })
        }
    },
);
generic_integer_impl_operation!(
    /// Divides two [FheInt] and returns the remainder
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheInt::div_rem], instead of using `/` and `%` separately.
    ///
    /// When the divisor is 0, the returned remainder will have the value of the numerator.
    ///
    /// This behaviour should not be relied on.
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
    /// let a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheInt16::encrypt(3i16, &client_key);
    ///
    /// let result = &a % &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 7849i16 % 3i16);
    /// ```
    rust_trait: Rem(rem),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheInt<_>| {
            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(cpu_key) => {
                    let inner_result = cpu_key
                        .pbs_key()
                        .rem_parallelized(&*lhs.ciphertext.on_cpu(), &*rhs.ciphertext.on_cpu());
                    FheInt::new(inner_result, cpu_key.tag.clone())
                },
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {let streams = &cuda_key.streams;
                    let inner_result =
                        cuda_key
                            .key
                            .key
                            .rem(&*lhs.ciphertext.on_gpu(streams), &*rhs.ciphertext.on_gpu(streams), streams);
                    FheInt::new(inner_result, cuda_key.tag.clone())
                },
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
                }
            })
        }
    },
);

// Shifts and rotations are special cases where the right hand side
// is for now, required to be an unsigned integer type.
// And its constraints are a bit relaxed: rhs does not need to have the same
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
        impl<Id, Id2> $rust_trait_name<FheUint<Id2>> for FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: FheUint<Id2>) -> Self::Output {
                <&Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(&self, &rhs)
            }

        }

        // a op &b
        impl<Id, Id2> $rust_trait_name<&FheUint<Id2>> for FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: &FheUint<Id2>) -> Self::Output {
                <&Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(&self, rhs)
            }

        }

        // &a op b
        impl<Id, Id2> $rust_trait_name<FheUint<Id2>> for &FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            type Output = FheInt<Id>;

            fn $rust_trait_method(self, rhs: FheUint<Id2>) -> Self::Output {
                <Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(self, &rhs)
            }
        }

        // &a op &b
        impl<Id, Id2> $rust_trait_name<&FheUint<Id2>> for &FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            type Output = FheInt<Id>;

            $(#[$outer])*
            fn $rust_trait_method(self, rhs: &FheUint<Id2>) -> Self::Output {
                $closure(self, rhs.borrow())
            }
        }
    }
);
generic_integer_impl_shift_rotate!(
    /// Performs a bitwise left shift of a [FheInt] by a [FheUint]
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = &a << &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 7849i16 << 3u16);
    /// ```
    rust_trait: Shl(shl),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| {
                match key {
                    InternalServerKey::Cpu(cpu_key) => {
                        let ciphertext = cpu_key
                            .pbs_key()
                            .left_shift_parallelized(&*lhs.ciphertext.on_cpu(), &rhs.ciphertext.on_cpu());
                        FheInt::new(ciphertext, cpu_key.tag.clone())
                    }
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(cuda_key) => {
                         {let streams = &cuda_key.streams;
                            let inner_result = cuda_key.key.key
                                .left_shift(&*lhs.ciphertext.on_gpu(streams), &rhs.ciphertext.on_gpu(streams), streams);
                            FheInt::new(inner_result, cuda_key.tag.clone())
                        }
                    }
                    #[cfg(feature = "hpu")]
                    InternalServerKey::Hpu(_device) => {
                        panic!("Hpu does not support this operation yet.")
                    }
                }
            })
        }
    }
);
generic_integer_impl_shift_rotate!(
    /// Performs a bitwise right shift of a [FheInt] by a [FheUint]
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = &a >> &b;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 7849i16 >> 3u16);
    /// ```
    rust_trait: Shr(shr),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| {
                match key {
                    InternalServerKey::Cpu(cpu_key) => {
                        let ciphertext = cpu_key
                            .pbs_key()
                            .right_shift_parallelized(&*lhs.ciphertext.on_cpu(), &rhs.ciphertext.on_cpu());
                        FheInt::new(ciphertext, cpu_key.tag.clone())
                    }
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(cuda_key) => {
                         {let streams = &cuda_key.streams;
                            let inner_result = cuda_key.key.key
                                .right_shift(&*lhs.ciphertext.on_gpu(streams), &rhs.ciphertext.on_gpu(streams), streams);
                            FheInt::new(inner_result, cuda_key.tag.clone())
                        }
                    }
                    #[cfg(feature = "hpu")]
                    InternalServerKey::Hpu(_device) => {
                        panic!("Hpu does not support this operation yet.")
                    }
                }
            })
        }
    }
);
generic_integer_impl_shift_rotate!(
    /// Performs a bitwise left rotation of a [FheInt] by a [FheUint]
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = (&a).rotate_left(&b);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 7849i16.rotate_left(3));
    /// ```
    rust_trait: RotateLeft(rotate_left),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| {
                match key {
                    InternalServerKey::Cpu(cpu_key) => {
                        let ciphertext = cpu_key
                            .pbs_key()
                            .rotate_left_parallelized(&*lhs.ciphertext.on_cpu(), &rhs.ciphertext.on_cpu());
                        FheInt::new(ciphertext, cpu_key.tag.clone())
                    }
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(cuda_key) => {
                         {let streams = &cuda_key.streams;
                            let inner_result = cuda_key.key.key
                                .rotate_left(&*lhs.ciphertext.on_gpu(streams), &rhs.ciphertext.on_gpu(streams), streams);
                            FheInt::new(inner_result, cuda_key.tag.clone())
                        }
                    }
                    #[cfg(feature = "hpu")]
                    InternalServerKey::Hpu(_device) => {
                        panic!("Hpu does not support this operation yet.")
                    }
                }
            })
        }
    }
);
generic_integer_impl_shift_rotate!(
    /// Performs a bitwise right rotation of a [FheInt] by a [FheUint]
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = (&a).rotate_right(&b);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 7849i16.rotate_right(3));
    /// ```
    rust_trait: RotateRight(rotate_right),
    implem: {
        |lhs: &FheInt<_>, rhs: &FheUint<_>| {
            global_state::with_internal_keys(|key| {
                match key {
                    InternalServerKey::Cpu(cpu_key) => {
                        let ciphertext = cpu_key
                            .pbs_key()
                            .rotate_right_parallelized(&*lhs.ciphertext.on_cpu(), &rhs.ciphertext.on_cpu());
                        FheInt::new(ciphertext, cpu_key.tag.clone())
                    }
                    #[cfg(feature = "gpu")]
                    InternalServerKey::Cuda(cuda_key) => {
                         {let streams = &cuda_key.streams;
                            let inner_result = cuda_key.key.key
                                .rotate_right(&*lhs.ciphertext.on_gpu(streams), &rhs.ciphertext.on_gpu(streams), streams);
                            FheInt::new(inner_result, cuda_key.tag.clone())
                        }
                    }
                    #[cfg(feature = "hpu")]
                    InternalServerKey::Hpu(_device) => {
                        panic!("Hpu does not support this operation yet.")
                    }
                }
            })
        }
    }
);

// Ciphertext/Ciphertext assign operations
// For these, macros would not reduce code by a lot, so we don't use one
impl<Id, I> AddAssign<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    /// Performs the `+=` operation on [FheInt]
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
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// a += &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3i16.wrapping_add(7849i16));
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
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.add_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}
impl<Id, I> SubAssign<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    /// Performs the `-=` operation on [FheInt]
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
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// a -= &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3i16.wrapping_sub(7849i16));
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
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.sub_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}
impl<Id, I> MulAssign<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    /// Performs the `*=` operation on [FheInt]
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
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// a *= &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3i16.wrapping_mul(7849i16));
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
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.mul_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}
impl<Id, I> BitAndAssign<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    /// Performs the `&=` operation on [FheInt]
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
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// a &= &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3i16 & 7849i16);
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
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                cuda_key.key.key.bitand_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}
impl<Id, I> BitOrAssign<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    /// Performs the `&=` operation on [FheInt]
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
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// a |= &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3i16 | 7849i16);
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
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}
impl<Id, I> BitXorAssign<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    /// Performs the `^=` operation on [FheInt]
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
    /// let b = FheInt16::encrypt(7849i16, &client_key);
    ///
    /// a ^= &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 3i16 ^ 7849i16);
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
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}
impl<Id, I> DivAssign<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    /// Performs the `/=` operation on [FheInt]
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheInt::div_rem], instead of using `/` and `%` separately.
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
    /// let mut a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheInt16::encrypt(3i16, &client_key);
    ///
    /// a /= &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 7849i16 / 3i16);
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
            InternalServerKey::Cuda(cuda_key) => {
                {
                    let streams = &cuda_key.streams;
                    let cuda_lhs = self.ciphertext.as_gpu_mut(streams);
                    let cuda_result = cuda_key.pbs_key().div(
                        &*cuda_lhs,
                        &rhs.ciphertext.on_gpu(streams),
                        streams,
                    );
                    *cuda_lhs = cuda_result;
                };
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}
impl<Id, I> RemAssign<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    /// Performs the `%=` operation on [FheInt]
    ///
    /// # Note
    ///
    /// If you need both the quotient and remainder, then prefer to use
    /// [FheInt::div_rem], instead of using `/` and `%` separately.
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
    /// let mut a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheInt16::encrypt(3i16, &client_key);
    ///
    /// a %= &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 7849i16 % 3i16);
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
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let cuda_lhs = self.ciphertext.as_gpu_mut(streams);
                let cuda_result =
                    cuda_key
                        .pbs_key()
                        .rem(&*cuda_lhs, &rhs.ciphertext.on_gpu(streams), streams);
                *cuda_lhs = cuda_result;
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id, Id2> ShlAssign<FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    fn shl_assign(&mut self, rhs: FheUint<Id2>) {
        <Self as ShlAssign<&FheUint<Id2>>>::shl_assign(self, &rhs)
    }
}

impl<Id, Id2> ShlAssign<&FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    /// Performs the `<<=` operation on [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a <<= &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 7849i16 << 3u16);
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
                let streams = &cuda_key.streams;
                cuda_key.key.key.left_shift_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}
impl<Id, Id2> ShrAssign<FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    fn shr_assign(&mut self, rhs: FheUint<Id2>) {
        <Self as ShrAssign<&FheUint<Id2>>>::shr_assign(self, &rhs)
    }
}

impl<Id, Id2> ShrAssign<&FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    /// Performs the `>>=` operation on [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a >>= &b;
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 7849i16 >> 3u16);
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
                let streams = &cuda_key.streams;
                cuda_key.key.key.right_shift_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id, Id2> RotateLeftAssign<FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    fn rotate_left_assign(&mut self, rhs: FheUint<Id2>) {
        <Self as RotateLeftAssign<&FheUint<Id2>>>::rotate_left_assign(self, &rhs)
    }
}

impl<Id, Id2> RotateLeftAssign<&FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    /// Performs a left bit rotation and assign operation on [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a.rotate_left_assign(&b);
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 7849i16.rotate_left(3));
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
                let streams = &cuda_key.streams;
                cuda_key.key.key.rotate_left_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id, Id2> RotateRightAssign<FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    fn rotate_right_assign(&mut self, rhs: FheUint<Id2>) {
        <Self as RotateRightAssign<&FheUint<Id2>>>::rotate_right_assign(self, &rhs)
    }
}

impl<Id, Id2> RotateRightAssign<&FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    /// Performs a right bit rotation and assign operation on [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheInt16::encrypt(7849i16, &client_key);
    /// let b = FheUint16::encrypt(3u16, &client_key);
    ///
    /// a.rotate_right_assign(&b);
    /// let result: i16 = a.decrypt(&client_key);
    /// assert_eq!(result, 7849i16.rotate_right(3));
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
                let streams = &cuda_key.streams;
                cuda_key.key.key.rotate_right_assign(
                    self.ciphertext.as_gpu_mut(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                );
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id> Neg for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Computes the negation of a [FheInt].
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
    ///
    /// let result = -a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 3i16);
    /// ```
    fn neg(self) -> Self::Output {
        <&Self as Neg>::neg(&self)
    }
}

impl<Id> Neg for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Computes the negation of a [FheInt].
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
    ///
    /// let result = -&a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 3i16);
    /// ```
    fn neg(self) -> Self::Output {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertext = cpu_key
                    .pbs_key()
                    .neg_parallelized(&*self.ciphertext.on_cpu());
                FheInt::new(ciphertext, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key
                    .key
                    .key
                    .neg(&*self.ciphertext.on_gpu(streams), streams);
                FheInt::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

impl<Id> Not for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Performs a bitwise 'not'
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
    ///
    /// let result = !&a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, !-3i16);
    /// ```
    fn not(self) -> Self::Output {
        <&Self as Not>::not(&self)
    }
}

impl<Id> Not for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Performs a bitwise 'not'
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
    ///
    /// let result = !&a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, !-3i16);
    /// ```
    fn not(self) -> Self::Output {
        global_state::with_internal_keys(|keys| match keys {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertext = cpu_key.pbs_key().bitnot(&*self.ciphertext.on_cpu());
                FheInt::new(ciphertext, cpu_key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let inner_result = cuda_key
                    .key
                    .key
                    .bitnot(&*self.ciphertext.on_gpu(streams), streams);
                FheInt::new(inner_result, cuda_key.tag.clone())
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl<Id, I> AddSizeOnGpu<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    fn get_add_size_on_gpu(&self, rhs: I) -> u64 {
        let rhs = rhs.borrow();

        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_add_size_on_gpu(
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
impl<Id, I> SubSizeOnGpu<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    fn get_sub_size_on_gpu(&self, rhs: I) -> u64 {
        let rhs = rhs.borrow();

        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_sub_size_on_gpu(
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
impl<Id> SizeOnGpu for FheInt<Id>
where
    Id: FheIntId,
{
    fn get_size_on_gpu(&self) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_ciphertext_size_on_gpu(&*self.ciphertext.on_gpu(streams))
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl<Id, I> BitAndSizeOnGpu<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    fn get_bitand_size_on_gpu(&self, rhs: I) -> u64 {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_bitand_size_on_gpu(
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
impl<Id, I> BitOrSizeOnGpu<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    fn get_bitor_size_on_gpu(&self, rhs: I) -> u64 {
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
impl<Id, I> BitXorSizeOnGpu<I> for FheInt<Id>
where
    Id: FheIntId,
    I: Borrow<Self>,
{
    fn get_bitxor_size_on_gpu(&self, rhs: I) -> u64 {
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
impl<Id> BitNotSizeOnGpu for FheInt<Id>
where
    Id: FheIntId,
{
    fn get_bitnot_size_on_gpu(&self) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_bitnot_size_on_gpu(&*self.ciphertext.on_gpu(streams), streams)
            } else {
                0
            }
        })
    }
}

#[cfg(feature = "gpu")]
impl<Id> FheOrdSizeOnGpu<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    fn get_gt_size_on_gpu(&self, rhs: &Self) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_gt_size_on_gpu(
                    &*self.ciphertext.on_gpu(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                )
            } else {
                0
            }
        })
    }
    fn get_ge_size_on_gpu(&self, rhs: &Self) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_ge_size_on_gpu(
                    &*self.ciphertext.on_gpu(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                )
            } else {
                0
            }
        })
    }
    fn get_lt_size_on_gpu(&self, rhs: &Self) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_lt_size_on_gpu(
                    &*self.ciphertext.on_gpu(streams),
                    &rhs.ciphertext.on_gpu(streams),
                    streams,
                )
            } else {
                0
            }
        })
    }
    fn get_le_size_on_gpu(&self, rhs: &Self) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_le_size_on_gpu(
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
impl<Id> FheMinSizeOnGpu<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    fn get_min_size_on_gpu(&self, rhs: &Self) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_min_size_on_gpu(
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
impl<Id> FheMaxSizeOnGpu<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    fn get_max_size_on_gpu(&self, rhs: &Self) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_max_size_on_gpu(
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
impl<Id, Id2> ShlSizeOnGpu<&FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    fn get_left_shift_size_on_gpu(&self, rhs: &FheUint<Id2>) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_left_shift_size_on_gpu(
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
impl<Id, Id2> ShrSizeOnGpu<&FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    fn get_right_shift_size_on_gpu(&self, rhs: &FheUint<Id2>) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_right_shift_size_on_gpu(
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
impl<Id, Id2> RotateLeftSizeOnGpu<&FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    fn get_rotate_left_size_on_gpu(&self, rhs: &FheUint<Id2>) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_rotate_left_size_on_gpu(
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
impl<Id, Id2> RotateRightSizeOnGpu<&FheUint<Id2>> for FheInt<Id>
where
    Id: FheIntId,
    Id2: FheUintId,
{
    fn get_rotate_right_size_on_gpu(&self, rhs: &FheUint<Id2>) -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key.key.key.get_rotate_right_size_on_gpu(
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
