use super::inner::RadixCiphertext;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{CastFrom, UnsignedNumeric};
use crate::high_level_api::integers::signed::{FheInt, FheIntId};
use crate::high_level_api::integers::IntegerId;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::{global_state, Device};
use crate::integer::block_decomposition::RecomposableFrom;
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::named::Named;
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::shortint::PBSParameters;
use crate::{FheBool, ServerKey};
use std::marker::PhantomData;

#[derive(Debug)]
pub enum GenericIntegerBlockError {
    NumberOfBlocks(usize, usize),
    CarryModulus(crate::shortint::CarryModulus, crate::shortint::CarryModulus),
    MessageModulus(
        crate::shortint::MessageModulus,
        crate::shortint::MessageModulus,
    ),
}

impl std::fmt::Display for GenericIntegerBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::NumberOfBlocks(correct, incorrect) => write!(
                f,
                "Wrong number of blocks for creating 
                    a GenericInteger: should have been {correct}, but
                    was {incorrect} instead"
            ),
            Self::CarryModulus(correct, incorrect) => write!(
                f,
                "Wrong carry modulus for creating 
                    a GenericInteger: should have been {correct:?}, but
                    was {incorrect:?} instead"
            ),
            Self::MessageModulus(correct, incorrect) => write!(
                f,
                "Wrong message modulus for creating 
                    a GenericInteger: should have been {correct:?}, but
                    was {incorrect:?} instead"
            ),
        }
    }
}

pub trait FheUintId: IntegerId {}

/// A Generic FHE unsigned integer
///
/// This struct is generic over some Id, as its the Id
/// that controls how many bit they represent.
///
/// You will need to use one of this type specialization (e.g., [FheUint8], [FheUint12],
/// [FheUint16]).
///
/// Its the type that overloads the operators (`+`, `-`, `*`),
/// since the `FheUint` type is not `Copy` the operators are also overloaded
/// to work with references.
///
/// [FheUint8]: crate::high_level_api::FheUint8
/// [FheUint12]: crate::high_level_api::FheUint12
/// [FheUint16]: crate::high_level_api::FheUint16
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct FheUint<Id: FheUintId> {
    pub(in crate::high_level_api) ciphertext: RadixCiphertext,
    pub(in crate::high_level_api::integers) id: Id,
}

pub struct FheUintConformanceParams<Id: FheUintId> {
    pub(crate) params: RadixCiphertextConformanceParams,
    pub(crate) id: PhantomData<Id>,
}

impl<Id: FheUintId, P: Into<PBSParameters>> From<P> for FheUintConformanceParams<Id> {
    fn from(params: P) -> Self {
        let params = params.into();
        Self {
            params: RadixCiphertextConformanceParams {
                shortint_params: params.to_shortint_conformance_param(),
                num_blocks_per_integer: Id::num_blocks(params.message_modulus()),
            },
            id: PhantomData,
        }
    }
}

impl<Id: FheUintId> From<&ServerKey> for FheUintConformanceParams<Id> {
    fn from(sks: &ServerKey) -> Self {
        Self {
            params: RadixCiphertextConformanceParams {
                shortint_params: sks.key.pbs_key().key.conformance_params(),
                num_blocks_per_integer: Id::num_blocks(sks.key.pbs_key().message_modulus()),
            },
            id: PhantomData,
        }
    }
}

impl<Id: FheUintId> ParameterSetConformant for FheUint<Id> {
    type ParameterSet = FheUintConformanceParams<Id>;

    fn is_conformant(&self, params: &FheUintConformanceParams<Id>) -> bool {
        self.ciphertext.on_cpu().is_conformant(&params.params)
    }
}

impl<Id: FheUintId> Named for FheUint<Id> {
    const NAME: &'static str = "high_level_api::FheUint";
}

impl<Id> FheUint<Id>
where
    Id: FheUintId,
{
    pub(in crate::high_level_api) fn new<T>(ciphertext: T) -> Self
    where
        T: Into<RadixCiphertext>,
    {
        Self {
            ciphertext: ciphertext.into(),
            id: Id::default(),
        }
    }

    pub fn into_raw_parts(self) -> (crate::integer::RadixCiphertext, Id) {
        let Self { ciphertext, id } = self;

        let ciphertext = ciphertext.into_cpu();

        (ciphertext, id)
    }

    pub fn from_raw_parts(ciphertext: crate::integer::RadixCiphertext, id: Id) -> Self {
        Self {
            ciphertext: RadixCiphertext::Cpu(ciphertext),
            id,
        }
    }

    pub(in crate::high_level_api) fn move_to_device_of_server_key_if_set(&mut self) {
        self.ciphertext.move_to_device_of_server_key_if_set();
    }

    /// Returns the device where the ciphertext is currently on
    pub fn current_device(&self) -> Device {
        self.ciphertext.current_device()
    }

    /// Moves (in-place) the ciphertext to the desired device.
    ///
    /// Does nothing if the ciphertext is already in the desired device
    pub fn move_to_device(&mut self, device: Device) {
        self.ciphertext.move_to_device(device)
    }

    /// Tries to decrypt a trivial ciphertext
    ///
    /// Trivial ciphertexts are ciphertexts which are not encrypted
    /// meaning they can be decrypted by any key, or even without a key.
    ///
    /// For debugging it can be useful to use trivial ciphertext to speed up
    /// execution, and use [Self::try_decrypt_trivial] to decrypt temporary values
    /// and debug.
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
    /// // This is not a trivial ciphertext as we use a client key to encrypt.
    /// let non_trivial = FheUint16::encrypt(1u16, &client_key);
    /// // This is a trivial ciphertext
    /// let trivial = FheUint16::encrypt_trivial(2u16);
    ///
    /// // We can trivial decrypt
    /// let result: Result<u16, _> = trivial.try_decrypt_trivial();
    /// assert_eq!(result, Ok(2));
    ///
    /// // We cannot trivial decrypt
    /// let result: Result<u16, _> = non_trivial.try_decrypt_trivial();
    /// matches!(result, Err(_));
    /// ```
    pub fn try_decrypt_trivial<Clear>(&self) -> Result<Clear, NotTrivialCiphertextError>
    where
        Clear: UnsignedNumeric + RecomposableFrom<u64>,
    {
        self.ciphertext.on_cpu().decrypt_trivial()
    }

    /// Returns true if the ciphertext is a trivial encryption
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
    /// let non_trivial = FheUint16::encrypt(1u16, &client_key);
    /// assert!(!non_trivial.is_trivial());
    ///
    /// let trivial = FheUint16::encrypt_trivial(2u16);
    /// assert!(trivial.is_trivial());
    /// ```
    pub fn is_trivial(&self) -> bool {
        self.ciphertext.on_cpu().is_trivial()
    }

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
    /// let a = FheUint16::encrypt(1u16, &client_key);
    /// let b = FheUint16::encrypt(2u16, &client_key);
    /// let c = FheUint16::encrypt(3u16, &client_key);
    ///
    /// let result = FheUint16::sum([&a, &b, &c]);
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 + 2 + 3);
    ///
    /// // Or
    /// let result = [&a, &b, &c].into_iter().sum::<FheUint16>();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1u16 + 2 + 3);
    /// ```
    pub fn sum<'a, C>(collection: C) -> Self
    where
        C: AsRef<[&'a Self]>,
    {
        collection.as_ref().iter().copied().sum()
    }

    /// Returns the number of leading zeros in the binary representation of self.
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
    /// let a = FheUint16::encrypt(0b00111111_11111111u16, &client_key);
    ///
    /// let result = a.leading_zeros();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 2);
    /// ```
    pub fn leading_zeros(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .leading_zeros_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support leading_zeros yet");
            }
        })
    }

    /// Returns the number of leading ones in the binary representation of self.
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
    /// let a = FheUint16::encrypt(0b11000000_00000000u16, &client_key);
    ///
    /// let result = a.leading_ones();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 2);
    /// ```
    pub fn leading_ones(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .leading_ones_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support leading_ones yet");
            }
        })
    }

    /// Returns the number of trailing zeros in the binary representation of self.
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
    /// let a = FheUint16::encrypt(0b0000000_0101000u16, &client_key);
    ///
    /// let result = a.trailing_zeros();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 3);
    /// ```
    pub fn trailing_zeros(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .trailing_zeros_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support trailing_zeros yet");
            }
        })
    }

    /// Returns the number of trailing ones in the binary representation of self.
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
    /// let a = FheUint16::encrypt(0b0000000_0110111u16, &client_key);
    ///
    /// let result = a.trailing_ones();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 3);
    /// ```
    pub fn trailing_ones(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .trailing_ones_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support trailing_ones yet");
            }
        })
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// Result has no meaning if self encrypts 0. See [Self::checked_ilog2]
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
    /// let a = FheUint16::encrypt(2u16, &client_key);
    ///
    /// let result = a.ilog2();
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 1);
    /// ```
    pub fn ilog2(&self) -> super::FheUint32 {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let result = cpu_key
                    .pbs_key()
                    .ilog2_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                super::FheUint32::new(result)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support ilog2 yet");
            }
        })
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// Also returns a boolean flag that is true if the result is valid (i.e self was > 0)
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
    /// let a = FheUint16::encrypt(0u16, &client_key);
    ///
    /// let (result, is_ok) = a.checked_ilog2();
    ///
    /// let is_ok = is_ok.decrypt(&client_key);
    /// assert_eq!(is_ok, false);
    ///
    /// let decrypted: u16 = result.decrypt(&client_key);
    /// assert_eq!(decrypted, 63); // result is meaningless
    /// ```
    pub fn checked_ilog2(&self) -> (super::FheUint32, FheBool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let (result, is_ok) = cpu_key
                    .pbs_key()
                    .checked_ilog2_parallelized(&*self.ciphertext.on_cpu());
                let result = cpu_key.pbs_key().cast_to_unsigned(
                    result,
                    super::FheUint32Id::num_blocks(cpu_key.pbs_key().message_modulus()),
                );
                (super::FheUint32::new(result), FheBool::new(is_ok))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support checked_ilog2 yet");
            }
        })
    }
}

impl<Id> TryFrom<crate::integer::RadixCiphertext> for FheUint<Id>
where
    Id: FheUintId,
{
    type Error = GenericIntegerBlockError;

    fn try_from(other: crate::integer::RadixCiphertext) -> Result<Self, GenericIntegerBlockError> {
        // Get correct carry modulus and message modulus from ServerKey
        let (correct_carry_mod, correct_message_mod) =
            global_state::with_internal_keys(|sks| match sks {
                InternalServerKey::Cpu(sks) => (
                    sks.pbs_key().key.carry_modulus,
                    sks.pbs_key().key.message_modulus,
                ),
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    (cuda_key.key.carry_modulus, cuda_key.key.message_modulus)
                }
            });

        // Check number of blocks
        let expected_num_blocks = Id::num_blocks(correct_message_mod);
        if other.blocks.len() != expected_num_blocks {
            return Err(GenericIntegerBlockError::NumberOfBlocks(
                expected_num_blocks,
                other.blocks.len(),
            ));
        }

        // For each block, check that carry modulus and message modulus are valid
        for block in &other.blocks {
            let (input_carry_mod, input_message_mod) = (block.carry_modulus, block.message_modulus);

            if input_carry_mod != correct_carry_mod {
                return Err(GenericIntegerBlockError::CarryModulus(
                    correct_carry_mod,
                    input_carry_mod,
                ));
            } else if input_message_mod != correct_message_mod {
                return Err(GenericIntegerBlockError::MessageModulus(
                    correct_message_mod,
                    input_message_mod,
                ));
            }
        }

        let mut ciphertext = Self::new(other);
        ciphertext.move_to_device_of_server_key_if_set();
        Ok(ciphertext)
    }
}

impl<Id, T> TryFrom<Vec<T>> for FheUint<Id>
where
    Id: FheUintId,
    crate::integer::RadixCiphertext: From<Vec<T>>,
{
    type Error = GenericIntegerBlockError;
    fn try_from(blocks: Vec<T>) -> Result<Self, GenericIntegerBlockError> {
        let ciphertext = crate::integer::RadixCiphertext::from(blocks);
        Self::try_from(ciphertext)
    }
}

impl<FromId, IntoId> CastFrom<FheInt<FromId>> for FheUint<IntoId>
where
    FromId: FheIntId,
    IntoId: FheUintId,
{
    /// Cast a FheInt to an FheUint
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt32, FheUint16};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheInt32::encrypt(i32::MIN, &client_key);
    /// let b = FheUint16::cast_from(a);
    ///
    /// let decrypted: u16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MIN as u16);
    /// ```
    fn cast_from(input: FheInt<FromId>) -> Self {
        global_state::with_internal_keys(|keys| {
            #[allow(irrefutable_let_patterns)]
            let InternalServerKey::Cpu(integer_key) = keys
            else {
                panic!("Cuda devices do not support signed integers");
            };
            let casted = integer_key.pbs_key().cast_to_unsigned(
                input.ciphertext.into_cpu(),
                IntoId::num_blocks(integer_key.message_modulus()),
            );
            Self::new(casted)
        })
    }
}

impl<FromId, IntoId> CastFrom<FheUint<FromId>> for FheUint<IntoId>
where
    FromId: FheUintId,
    IntoId: FheUintId,
{
    /// Cast FheUint to another FheUint
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16, FheUint32};
    ///
    /// let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheUint32::encrypt(u32::MAX, &client_key);
    /// let b = FheUint16::cast_from(a);
    ///
    /// let decrypted: u16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MAX as u16);
    /// ```
    fn cast_from(input: FheUint<FromId>) -> Self {
        global_state::with_internal_keys(|keys| {
            #[allow(irrefutable_let_patterns)]
            let InternalServerKey::Cpu(integer_key) = keys
            else {
                panic!("Cuda devices do not support casting unsigned integers");
            };
            let casted = integer_key.pbs_key().cast_to_unsigned(
                input.ciphertext.on_cpu().into_owned(),
                IntoId::num_blocks(integer_key.message_modulus()),
            );
            Self::new(casted)
        })
    }
}

impl<Id> CastFrom<FheBool> for FheUint<Id>
where
    Id: FheUintId,
{
    /// Cast a boolean ciphertext to an unsigned ciphertext
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
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheUint16::cast_from(a);
    ///
    /// let decrypted: u16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, u16::from(true));
    /// ```
    fn cast_from(input: FheBool) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(cpu_key) => {
                let ciphertext: crate::integer::RadixCiphertext = input
                    .ciphertext
                    .on_cpu()
                    .into_owned()
                    .into_radix(Id::num_blocks(cpu_key.message_modulus()), cpu_key.pbs_key());
                Self::new(ciphertext)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support casting yet");
            }
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::prelude::UnsignedInteger;
    use crate::prelude::*;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use crate::shortint::{CiphertextModulus, PBSOrder};
    use crate::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
    use rand::{thread_rng, Rng};

    type IndexedParameterAccessor<Ct, T> = dyn Fn(usize, &mut Ct) -> &mut T;

    type IndexedParameterModifier<'a, Ct> = dyn Fn(usize, &mut Ct) + 'a;

    fn change_parameters<Ct, T: UnsignedInteger>(
        func: &IndexedParameterAccessor<Ct, T>,
    ) -> [Box<IndexedParameterModifier<'_, Ct>>; 3] {
        [
            Box::new(|i, ct| *func(i, ct) = T::ZERO),
            Box::new(|i, ct| *func(i, ct) = func(i, ct).wrapping_add(T::ONE)),
            Box::new(|i, ct| *func(i, ct) = func(i, ct).wrapping_sub(T::ONE)),
        ]
    }

    #[test]
    fn test_invalid_generic_integer() {
        type Ct = FheUint8;

        let config = ConfigBuilder::default().build();

        let (client_key, _server_key) = generate_keys(config);

        let ct = FheUint8::try_encrypt(0_u64, &client_key).unwrap();

        assert!(ct.is_conformant(&FheUintConformanceParams::from(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        )));

        let breaker_lists = [
            change_parameters(&|i, ct: &mut Ct| {
                &mut ct.ciphertext.as_cpu_mut().blocks[i].message_modulus.0
            }),
            change_parameters(&|i, ct: &mut Ct| {
                &mut ct.ciphertext.as_cpu_mut().blocks[i].carry_modulus.0
            }),
            change_parameters(&|i, ct: &mut Ct| {
                ct.ciphertext.as_cpu_mut().blocks[i].degree.as_mut()
            }),
        ];

        for breaker_list in breaker_lists {
            for breaker in breaker_list {
                for i in 0..ct.ciphertext.on_cpu().blocks.len() {
                    let mut ct_clone = ct.clone();

                    breaker(i, &mut ct_clone);

                    assert!(!ct_clone.is_conformant(&FheUintConformanceParams::from(
                        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    )));
                }
            }
        }
        let breakers2: Vec<&IndexedParameterModifier<'_, Ct>> = vec![
            &|i, ct: &mut Ct| {
                *ct.ciphertext.as_cpu_mut().blocks[i]
                    .ct
                    .get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new_power_of_2(1).unwrap();
            },
            &|i, ct: &mut Ct| {
                *ct.ciphertext.as_cpu_mut().blocks[i]
                    .ct
                    .get_mut_ciphertext_modulus() = CiphertextModulus::try_new(3).unwrap();
            },
            &|_i, ct: &mut Ct| {
                ct.ciphertext.as_cpu_mut().blocks.pop();
            },
            &|i, ct: &mut Ct| {
                let cloned_block = ct.ciphertext.on_cpu().blocks[i].clone();
                ct.ciphertext.as_cpu_mut().blocks.push(cloned_block);
            },
            &|i, ct: &mut Ct| {
                ct.ciphertext.as_cpu_mut().blocks[i].pbs_order = PBSOrder::BootstrapKeyswitch;
            },
        ];

        for breaker in breakers2 {
            for i in 0..ct.ciphertext.on_cpu().blocks.len() {
                let mut ct_clone = ct.clone();

                breaker(i, &mut ct_clone);

                assert!(!ct_clone.is_conformant(&FheUintConformanceParams::from(
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                )));
            }
        }
    }

    #[test]
    fn test_valid_generic_integer() {
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config);

        set_server_key(server_key);

        let ct = FheUint8::try_encrypt(0_u64, &client_key).unwrap();

        assert!(ct.is_conformant(&FheUintConformanceParams::from(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        )));

        let mut rng = thread_rng();

        let num_blocks = ct.ciphertext.on_cpu().blocks.len();

        for _ in 0..10 {
            let mut ct_clone = ct.clone();

            for i in 0..num_blocks {
                ct_clone.ciphertext.as_cpu_mut().blocks[i]
                    .ct
                    .as_mut()
                    .fill_with(|| rng.gen::<u64>());
            }

            assert!(ct.is_conformant(&FheUintConformanceParams::from(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            )));

            ct_clone += &ct_clone.clone();
        }
    }
}
