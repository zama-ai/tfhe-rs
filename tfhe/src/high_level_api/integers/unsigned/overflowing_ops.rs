use crate::core_crypto::prelude::UnsignedNumeric;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheUintId;
use crate::high_level_api::keys::InternalServerKey;
use crate::integer::block_decomposition::DecomposableInto;
use crate::prelude::{OverflowingAdd, OverflowingMul, OverflowingSub};
use crate::{FheBool, FheUint};

impl<Id> OverflowingAdd<Self> for &FheUint<Id>
where
    Id: FheUintId,
{
    type Output = FheUint<Id>;

    /// Adds two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    /// let b = FheUint16::encrypt(1u16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_add(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key.key.unsigned_overflowing_add_parallelized(
                    &self.ciphertext.on_cpu(),
                    &other.ciphertext.on_cpu(),
                );
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support overflowing_add yet");
            }
        })
    }
}

impl<Id> OverflowingAdd<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Adds two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    /// let b = FheUint16::encrypt(1u16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_add(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingAdd<&Self>>::overflowing_add(&self, other)
    }
}

impl<Id, Clear> OverflowingAdd<Clear> for &FheUint<Id>
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = FheUint<Id>;

    /// Adds a [FheUint] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_add(1u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Clear) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .unsigned_overflowing_scalar_add_parallelized(&self.ciphertext.on_cpu(), other);
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support overflowing_add yet");
            }
        })
    }
}

impl<Id, Clear> OverflowingAdd<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = Self;

    /// Adds a [FheUint] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_add(1u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: Clear) -> (Self::Output, FheBool) {
        (&self).overflowing_add(other)
    }
}

impl<Id, Clear> OverflowingAdd<&FheUint<Id>> for Clear
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = FheUint<Id>;

    /// Adds a Clear with a [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(u16::MAX, &client_key);
    ///
    /// // Due to conflicts with u16::overflowing_add method
    /// // we have to use this syntax to help the compiler
    /// let (result, overflowed) = OverflowingAdd::overflowing_add(1u16, &a);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, u16::MAX.wrapping_add(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     u16::MAX.overflowing_add(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_add(self, other: &FheUint<Id>) -> (Self::Output, FheBool) {
        other.overflowing_add(self)
    }
}

impl<Id> OverflowingSub<Self> for &FheUint<Id>
where
    Id: FheUintId,
{
    type Output = FheUint<Id>;

    /// Subtracts two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0u16, &client_key);
    /// let b = FheUint16::encrypt(1u16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_sub(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 0u16.wrapping_sub(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     0u16.overflowing_sub(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key.key.unsigned_overflowing_sub_parallelized(
                    &self.ciphertext.on_cpu(),
                    &other.ciphertext.on_cpu(),
                );
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support overflowing_sub yet");
            }
        })
    }
}

impl<Id> OverflowingSub<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Subtracts two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0u16, &client_key);
    /// let b = FheUint16::encrypt(1u16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_sub(&b);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 0u16.wrapping_sub(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     0u16.overflowing_sub(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingSub<&Self>>::overflowing_sub(&self, other)
    }
}

impl<Id, Clear> OverflowingSub<Clear> for &FheUint<Id>
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = FheUint<Id>;

    /// Subtracts a [FheUint] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0u16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_sub(1u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 0u16.wrapping_sub(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     0u16.overflowing_sub(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Clear) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key
                    .key
                    .unsigned_overflowing_scalar_sub_parallelized(&self.ciphertext.on_cpu(), other);
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support overflowing_add yet");
            }
        })
    }
}

impl<Id, Clear> OverflowingSub<Clear> for FheUint<Id>
where
    Id: FheUintId,
    Clear: UnsignedNumeric + DecomposableInto<u8>,
{
    type Output = Self;

    /// Subtracts a [FheUint] with a Clear and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(0u16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_sub(1u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, 0u16.wrapping_sub(1u16));
    /// assert_eq!(
    ///     overflowed.decrypt(&client_key),
    ///     0u16.overflowing_sub(1u16).1
    /// );
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_sub(self, other: Clear) -> (Self::Output, FheBool) {
        <&Self as OverflowingSub<Clear>>::overflowing_sub(&self, other)
    }
}

impl<Id> OverflowingMul<Self> for &FheUint<Id>
where
    Id: FheUintId,
{
    type Output = FheUint<Id>;

    /// Multiplies two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(3434u16, &client_key);
    /// let b = FheUint16::encrypt(54u16, &client_key);
    ///
    /// let (result, overflowed) = (&a).overflowing_mul(&b);
    /// let (expected_result, expected_overflowed) = 3434u16.overflowing_mul(54u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflowed);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_mul(self, other: Self) -> (Self::Output, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, overflow) = cpu_key.key.unsigned_overflowing_mul_parallelized(
                    &self.ciphertext.on_cpu(),
                    &other.ciphertext.on_cpu(),
                );
                (FheUint::new(result), FheBool::new(overflow))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not support overflowing_mul");
            }
        })
    }
}

impl<Id> OverflowingMul<&Self> for FheUint<Id>
where
    Id: FheUintId,
{
    type Output = Self;

    /// Multiplies two [FheUint] and returns a boolean indicating overflow.
    ///
    /// * The operation is modular, i.e on overflow the result wraps around.
    /// * On overflow the [FheBool] is true, otherwise false
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint16::encrypt(3434u16, &client_key);
    /// let b = FheUint16::encrypt(54u16, &client_key);
    ///
    /// let (result, overflowed) = a.overflowing_mul(&b);
    /// let (expected_result, expected_overflowed) = 3434u16.overflowing_mul(54u16);
    /// let result: u16 = result.decrypt(&client_key);
    /// assert_eq!(result, expected_result);
    /// assert_eq!(overflowed.decrypt(&client_key), expected_overflowed);
    /// assert_eq!(overflowed.decrypt(&client_key), true);
    /// ```
    fn overflowing_mul(self, other: &Self) -> (Self::Output, FheBool) {
        <&Self as OverflowingMul<&Self>>::overflowing_mul(&self, other)
    }
}
