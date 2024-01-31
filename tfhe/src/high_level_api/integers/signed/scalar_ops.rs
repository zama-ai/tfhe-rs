use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheIntId;
use crate::high_level_api::traits::{
    DivRem, FheEq, FheMax, FheMin, FheOrd, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
use crate::integer::block_decomposition::DecomposableInto;
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            sks.pbs_key().scalar_max_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result)
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            sks.pbs_key().scalar_min_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result)
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_eq_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    /// Test for difference between a [FheInt] and a clear
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
    /// let b = 2u16;
    ///
    /// let result = a.ne(b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 != 2i16);
    /// ```
    fn ne(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_ne_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
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
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_lt_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    /// Test for less than or equal between [FheInt] and a clear value
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
    ///
    /// let result = a.le(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 <= 2i16);
    /// ```
    fn le(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_le_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    /// Test for greater than between [FheInt] and a clear value
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
    ///
    /// let result = a.gt(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 > 2i16);
    /// ```
    fn gt(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_gt_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    /// Test for greater than or equal between [FheInt] and a clear value
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
    ///
    /// let result = a.ge(2i16);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, -1i16 >= 2i16);
    /// ```
    fn ge(&self, rhs: Clear) -> FheBool {
        let inner_result = global_state::with_cpu_internal_keys(|sks| {
            let pbs_key = sks.pbs_key();
            pbs_key.scalar_ge_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
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
                            global_state::with_cpu_internal_keys(|integer_key| {
                                integer_key.pbs_key().$key_method(&self.ciphertext, rhs)
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

macro_rules! generic_integer_impl_scalar_operation {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
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
                         global_state::with_cpu_internal_keys(|cpu_key| {
                                let inner_result = cpu_key
                                    .pbs_key()
                                    .$key_method(&self.ciphertext, rhs);
                               <$concrete_type>::new(inner_result)
                        })
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

generic_integer_impl_scalar_operation!(
    rust_trait: Add(add),
    key_method: scalar_add_parallelized,
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
    key_method: scalar_sub_parallelized,
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
    key_method: scalar_mul_parallelized,
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
    key_method: scalar_bitand_parallelized,
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
    key_method: scalar_bitxor_parallelized,
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
    key_method: scalar_bitor_parallelized,
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
    key_method: scalar_left_shift_parallelized,
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
    key_method: scalar_right_shift_parallelized,
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
    key_method: scalar_rotate_left_parallelized,
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
    key_method: scalar_rotate_right_parallelized,
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
    key_method: signed_scalar_div_parallelized,
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
    key_method: signed_scalar_rem_parallelized,
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
macro_rules! generic_integer_impl_scalar_operation_assign {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        key_method: $key_method:ident,
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($scalar_type:ty),*)
        ),*
        $(,)?
    ) => {
        $(
            $(
                impl $rust_trait_name<$scalar_type> for $concrete_type
                {
                    fn $rust_trait_method(&mut self, rhs: $scalar_type) {
                         global_state::with_cpu_internal_keys(|cpu_key| {
                            cpu_key
                                .pbs_key()
                                .$key_method(&mut self.ciphertext, rhs);
                        })
                    }
                }
            )*
        )*
    }
}
generic_integer_impl_scalar_operation_assign!(
    rust_trait: AddAssign(add_assign),
    key_method: scalar_add_assign_parallelized,
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
    rust_trait: SubAssign(sub_assign),
    key_method: scalar_sub_assign_parallelized,
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
    key_method: scalar_mul_assign_parallelized,
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
    key_method: scalar_bitand_assign_parallelized,
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
    key_method: scalar_bitor_assign_parallelized,
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
    key_method: scalar_bitxor_assign_parallelized,
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
    key_method: scalar_left_shift_assign_parallelized,
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
    key_method: scalar_right_shift_assign_parallelized,
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
    key_method: scalar_rotate_left_assign_parallelized,
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
    key_method: scalar_rotate_right_assign_parallelized,
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
    key_method: signed_scalar_div_assign_parallelized,
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
    key_method: signed_scalar_rem_assign_parallelized,
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
