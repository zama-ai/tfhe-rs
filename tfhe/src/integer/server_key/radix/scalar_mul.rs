use crate::core_crypto::prelude::{Numeric, SignedInteger};
use crate::integer::ciphertext::{IntegerRadixCiphertext, RadixCiphertext};
use crate::integer::server_key::CheckError;
use crate::integer::ServerKey;

pub trait ScalarMultiplier: Numeric {
    fn is_power_of_two(self) -> bool;

    fn ilog2(self) -> u32;
}

macro_rules! impl_scalar_multiplier_for_unsigned {
    ($($type:ty),*) => {
        $(
            impl ScalarMultiplier for $type {
                fn is_power_of_two(self) -> bool {
                    <$type>::is_power_of_two(self)
                }

                fn ilog2(self) -> u32 {
                    self.ilog2()
                }
            }
        )*
    }
}

macro_rules! impl_scalar_multiplier_for_signed {
    ($($type:ty),*) => {
        $(
            impl ScalarMultiplier for $type {
                // i8, i18, etc do not have their is_power_of_two
                fn is_power_of_two(self) -> bool {
                    self > 0 && <Self as SignedInteger>::into_unsigned(self).is_power_of_two()
                }

                // Panics is self is <= 0
                fn ilog2(self) -> u32 {
                    self.ilog2()
                }
            }
        )*
    }
}

impl_scalar_multiplier_for_unsigned!(u8, u16, u32, u64, u128);
impl_scalar_multiplier_for_signed!(i8, i16, i32, i64, i128);

impl<const N: usize> ScalarMultiplier
    for crate::integer::bigint::static_signed::StaticSignedBigInt<N>
{
    fn is_power_of_two(self) -> bool {
        self.is_power_of_two()
    }

    fn ilog2(self) -> u32 {
        self.ilog2()
    }
}
impl<const N: usize> ScalarMultiplier
    for crate::integer::bigint::static_unsigned::StaticUnsignedBigInt<N>
{
    fn is_power_of_two(self) -> bool {
        self.is_power_of_two()
    }

    fn ilog2(self) -> u32 {
        self.ilog2()
    }
}

impl ServerKey {
    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.unchecked_small_scalar_mul(&ct, scalar);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(scalar * msg, clear);
    /// ```
    pub fn unchecked_small_scalar_mul(
        &self,
        ctxt: &RadixCiphertext,
        scalar: u64,
    ) -> RadixCiphertext {
        let mut ct_result = ctxt.clone();
        self.unchecked_small_scalar_mul_assign(&mut ct_result, scalar);

        ct_result
    }

    pub fn unchecked_small_scalar_mul_assign(&self, ctxt: &mut RadixCiphertext, scalar: u64) {
        for ct_i in ctxt.blocks.iter_mut() {
            self.key.unchecked_scalar_mul_assign(ct_i, scalar as u8);
        }
    }

    ///Verifies if ct1 can be multiplied by scalar.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg = 25u64;
    /// let scalar1 = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Verification if the scalar multiplication can be computed:
    /// sks.is_small_scalar_mul_possible(&ct, scalar1).unwrap();
    ///
    /// let scalar2 = 7;
    /// // Verification if the scalar multiplication can be computed:
    /// let res = sks.is_small_scalar_mul_possible(&ct, scalar2);
    /// assert!(res.is_err());
    /// ```
    pub fn is_small_scalar_mul_possible(
        &self,
        ctxt: &RadixCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        for ct_i in ctxt.blocks.iter() {
            self.key
                .is_scalar_mul_possible(ct_i.noise_degree(), scalar as u8)?;
        }
        Ok(())
    }

    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg = 1u64;
    /// let power = 2;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.blockshift(&ct, power);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(16, clear);
    /// ```
    pub fn blockshift<T>(&self, ctxt: &T, shift: usize) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ctxt.clone();
        result.blocks_mut().rotate_right(shift);
        for block in &mut result.blocks_mut()[..shift] {
            self.key.create_trivial_assign(block, 0);
        }
        result
    }
}
