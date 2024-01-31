use crate::high_level_api::global_state;
use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::high_level_api::keys::InternalServerKey;
use crate::{FheBool, FheInt, FheUint};
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::high_level_api::traits::{
    DivRem, FheEq, FheMax, FheMin, FheOrd, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
use std::borrow::Borrow;

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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
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
                cpu_key
                    .pbs_key()
                    .sum_ciphertexts_parallelized(iter.map(|elem| &elem.ciphertext))
                    .map_or_else(
                        || {
                            Self::new(cpu_key.key.create_trivial_zero_radix(Id::num_blocks(
                                cpu_key.message_modulus(),
                            )))
                        },
                        Self::new,
                    )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support signed integers");
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.max(&b);
    ///
    /// let decrypted_max: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_max, (-1i16).max(2i16));
    /// ```
    fn max(&self, rhs: &Self) -> Self::Output {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            sks.pbs_key()
                .max_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result)
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-1i16, &client_key);
    /// let b = FheInt16::encrypt(2i16, &client_key);
    ///
    /// let result = a.min(&b);
    ///
    /// let decrypted_min: i16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted_min, (-1i16).min(2i16));
    /// ```
    fn min(&self, rhs: &Self) -> Self::Output {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            sks.pbs_key()
                .min_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result)
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.eq_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    /// Test for difference between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.ne_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.lt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    /// Test for less than or equal between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.le_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    /// Test for greater than between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.gt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    /// Test for greater than or equal between two [FheInt]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.ge_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let (q, r) = global_state::with_cpu_internal_keys(|integer_key| {
            integer_key
                .pbs_key()
                .div_rem_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        (FheInt::<Id>::new(q), FheInt::<Id>::new(r))
    }
}

// Shifts and rotations are special cases where the right hand side
// is for now, required to be a unsigned integer type.
// And its constraints are a bit relaxed: rhs does not needs to have the same
// amount a bits.
macro_rules! generic_integer_impl_shift_rotate (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {

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

            fn $rust_trait_method(self, rhs: &FheUint<Id2>) -> Self::Output {
                let ciphertext = global_state::with_cpu_internal_keys(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&self.ciphertext, &*rhs.ciphertext.on_cpu())
                });
                FheInt::<Id>::new(ciphertext)
            }
        }
    }
);

macro_rules! generic_integer_impl_shift_rotate_assign(
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {
        // a op= b
        impl<Id, Id2> $rust_trait_name<FheUint<Id2>> for FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            fn $rust_trait_method(&mut self, rhs: FheUint<Id2>) {
                <Self as $rust_trait_name<&FheUint<Id2>>>::$rust_trait_method(self, &rhs)
            }
        }

        // a op= &b
        impl<Id, Id2> $rust_trait_name<&FheUint<Id2>> for FheInt<Id>
        where
            Id: FheIntId,
            Id2: FheUintId,
        {
            fn $rust_trait_method(&mut self, rhs: &FheUint<Id2>) {
                global_state::with_cpu_internal_keys(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&mut self.ciphertext, &*rhs.ciphertext.on_cpu())
                })
            }
        }
    }
);

macro_rules! generic_integer_impl_operation (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {

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

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                let ciphertext = global_state::with_cpu_internal_keys(|integer_key| {
                    let borrowed = rhs.borrow();
                    integer_key
                        .pbs_key()
                        .$key_method(&self.ciphertext, &borrowed.ciphertext)
                });
                FheInt::<Id>::new(ciphertext)
            }
        }
    }
);

macro_rules! generic_integer_impl_operation_assign (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {
        impl<Id, I> $rust_trait_name<I> for FheInt<Id>
        where
            Id: FheIntId,
            I: Borrow<Self>,
        {
            fn $rust_trait_method(&mut self, rhs: I) {
                global_state::with_cpu_internal_keys(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&mut self.ciphertext, &rhs.borrow().ciphertext)
                })
            }
        }
    }
);

generic_integer_impl_operation!(Add(add) => add_parallelized);
generic_integer_impl_operation!(Sub(sub) => sub_parallelized);
generic_integer_impl_operation!(Mul(mul) => mul_parallelized);
generic_integer_impl_operation!(BitAnd(bitand) => bitand_parallelized);
generic_integer_impl_operation!(BitOr(bitor) => bitor_parallelized);
generic_integer_impl_operation!(BitXor(bitxor) => bitxor_parallelized);
generic_integer_impl_operation!(Div(div) => div_parallelized);
generic_integer_impl_operation!(Rem(rem) => rem_parallelized);
generic_integer_impl_shift_rotate!(Shl(shl) => left_shift_parallelized);
generic_integer_impl_shift_rotate!(Shr(shr) => right_shift_parallelized);
generic_integer_impl_shift_rotate!(RotateLeft(rotate_left) => rotate_left_parallelized);
generic_integer_impl_shift_rotate!(RotateRight(rotate_right) => rotate_right_parallelized);
// assign operations
generic_integer_impl_operation_assign!(AddAssign(add_assign) => add_assign_parallelized);
generic_integer_impl_operation_assign!(SubAssign(sub_assign) => sub_assign_parallelized);
generic_integer_impl_operation_assign!(MulAssign(mul_assign) => mul_assign_parallelized);
generic_integer_impl_operation_assign!(BitAndAssign(bitand_assign) => bitand_assign_parallelized);
generic_integer_impl_operation_assign!(BitOrAssign(bitor_assign) => bitor_assign_parallelized);
generic_integer_impl_operation_assign!(BitXorAssign(bitxor_assign) => bitxor_assign_parallelized);
generic_integer_impl_operation_assign!(DivAssign(div_assign) => div_assign_parallelized);
generic_integer_impl_operation_assign!(RemAssign(rem_assign) => rem_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(ShlAssign(shl_assign) => left_shift_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(ShrAssign(shr_assign) => right_shift_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(RotateLeftAssign(rotate_left_assign) => rotate_left_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(RotateRightAssign(rotate_right_assign) => rotate_right_assign_parallelized);

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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-3i16, &client_key);
    ///
    /// let result = -&a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, 3i16);
    /// ```
    fn neg(self) -> Self::Output {
        let ciphertext = global_state::with_cpu_internal_keys(|integer_key| {
            integer_key.pbs_key().neg_parallelized(&self.ciphertext)
        });
        FheInt::new(ciphertext)
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt16::encrypt(-3i16, &client_key);
    ///
    /// let result = !&a;
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, !-3i16);
    /// ```
    fn not(self) -> Self::Output {
        let ciphertext = global_state::with_cpu_internal_keys(|integer_key| {
            integer_key.pbs_key().bitnot_parallelized(&self.ciphertext)
        });
        FheInt::<Id>::new(ciphertext)
    }
}
