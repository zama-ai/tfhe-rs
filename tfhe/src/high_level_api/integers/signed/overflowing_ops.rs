use crate::core_crypto::prelude::SignedNumeric;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheIntId;
use crate::high_level_api::keys::InternalServerKey;
use crate::integer::block_decomposition::DecomposableInto;
use crate::prelude::{OverflowingAdd, OverflowingMul, OverflowingSub};
use crate::{FheBool, FheInt};

impl<Id> OverflowingAdd<Self> for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Adds two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    /// let b = FheInt16::encrypt(1i16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_add(&b);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key.key.signed_overflowing_add_parallelized(
                    &self.ciphertext.on_cpu(),
                    &other.ciphertext.on_cpu(),
                );
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id> OverflowingAdd<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Adds two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    /// let b = FheInt16::encrypt(1i16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_add(&b);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingAdd<&Self>>::overflowing_add(&self, other)
    }
}

impl<Id, Clear> OverflowingAdd<Clear> for &FheInt<Id>
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = FheInt<Id>;

    /// Adds a [FheInt] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_add(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Clear) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .signed_overflowing_scalar_add_parallelized(&self.ciphertext.on_cpu(), other);
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id, Clear> OverflowingAdd<Clear> for FheInt<Id>
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = Self;

    /// Adds a [FheInt] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_add(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Clear) -> (Self::Output, FheBool) {
        (&self).overflowing_add(other)
    }
}

impl<Id, Clear> OverflowingAdd<&FheInt<Id>> for Clear
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = FheInt<Id>;

    /// Adds a Clear with a [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(i16::MAX, &client_key);
    ///
    /// // Due to conflicts with u16::overflowing_add method
    /// // we have to use this syntax to help the compiler
    /// let (result, overflowed) = OverflowingAdd::overflowing_add(1i16, &a);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, i16::MAX.wrapping_add(1i16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     i16::MAX.overflowing_add(1i16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: &FheInt<Id>) -> (Self::Output, FheBool) {
        other.overflowing_add(self)
    }
}

impl<Id> OverflowingSub<Self> for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Subtracts two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    /// let b = FheInt16::encrypt(1i16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_sub(&b);
    /// let (expected_result, expected_overflow) = i16::MIN.overflowing_sub(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflow);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key.key.signed_overflowing_sub_parallelized(
                    &self.ciphertext.on_cpu(),
                    &other.ciphertext.on_cpu(),
                );
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id> OverflowingSub<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Subtracts two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    /// let b = FheInt16::encrypt(1i16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_sub(&b);
    /// let (expected_result, expected_overflow) = i16::MIN.overflowing_sub(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflow);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingSub<&Self>>::overflowing_sub(&self, other)
    }
}

impl<Id, Clear> OverflowingSub<Clear> for &FheInt<Id>
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = FheInt<Id>;

    /// Subtracts a [FheInt] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_sub(1i16);
    /// let (expected_result, expected_overflow) = i16::MIN.overflowing_sub(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflow);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Clear) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .signed_overflowing_scalar_sub_parallelized(&self.ciphertext.on_cpu(), other);
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id, Clear> OverflowingSub<Clear> for FheInt<Id>
where
    Id: FheIntId,
    Clear: SignedNumeric + DecomposableInto<u64>,
{
    type Output = Self;

    /// Subtracts a [FheInt] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_sub(1i16);
    /// let (expected_result, expected_overflow) = i16::MIN.overflowing_sub(1i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflow);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Clear) -> (Self::Output, FheBool) {
        <&Self as OverflowingSub<Clear>>::overflowing_sub(&self, other)
    }
}

impl<Id> OverflowingMul<Self> for &FheInt<Id>
where
    Id: FheIntId,
{
    type Output = FheInt<Id>;

    /// Multiplies two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(3434i16, &client_key);
    /// let b = FheInt16::encrypt(54i16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_mul(&b);
    /// let (expected_result, expected_overflowed) = 3434i16.overflowing_mul(54i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflowed);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_mul(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key.key.signed_overflowing_mul_parallelized(
                    &self.ciphertext.on_cpu(),
                    &other.ciphertext.on_cpu(),
                );
                (FheInt::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support signed integer");
            }
        })
    }
}

impl<Id> OverflowingMul<&Self> for FheInt<Id>
where
    Id: FheIntId,
{
    type Output = Self;

    /// Multiplies two [FheInt] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e. on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
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
    /// let a = FheInt16::encrypt(3434i16, &client_key);
    /// let b = FheInt16::encrypt(54i16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_mul(&b);
    /// let (expected_result, expected_overflowed) = 3434i16.overflowing_mul(54i16);
    /// let result: i16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflowed);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_mul(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingMul<&Self>>::overflowing_mul(&self, other)
    }
}
