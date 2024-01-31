use crate::conformance::ParameterSetConformant;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::{FheUint, FheUintId, IntegerId};
use crate::integer::client_key::RecomposableSignedInteger;
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::integer::SignedRadixCiphertext;
use crate::named::Named;
use crate::prelude::CastFrom;
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::{CompactFheInt, CompressedFheInt, FheBool};

pub trait FheIntId: IntegerId {}

/// A Generic FHE signed integer
///
/// This struct is generic over some Id, as its the Id
/// that controls how many bit they represent.
///
/// You will need to use one of this type specialization (e.g., [FheInt8], [FheInt16]).
///
/// Its the type that overloads the operators (`+`, `-`, `*`),
/// since the `FheInt` type is not `Copy` the operators are also overloaded
/// to work with references.
///
/// [FheInt8]: crate::high_level_api::FheUint8
/// [FheInt16]: crate::high_level_api::FheInt16
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct FheInt<Id: FheIntId> {
    pub(in crate::high_level_api) ciphertext: SignedRadixCiphertext,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id> From<CompressedFheInt<Id>> for FheInt<Id>
where
    Id: FheIntId,
{
    fn from(value: CompressedFheInt<Id>) -> Self {
        value.decompress()
    }
}

impl<Id> From<CompactFheInt<Id>> for FheInt<Id>
where
    Id: FheIntId,
{
    fn from(value: CompactFheInt<Id>) -> Self {
        value.expand()
    }
}

impl<Id: FheIntId> ParameterSetConformant for FheInt<Id> {
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.ciphertext.is_conformant(params)
    }
}

impl<Id: FheIntId> Named for FheInt<Id> {
    const NAME: &'static str = "high_level_api::FheInt";
}

impl<Id> FheInt<Id>
where
    Id: FheIntId,
{
    pub(in crate::high_level_api) fn new(ciphertext: SignedRadixCiphertext) -> Self {
        Self {
            ciphertext,
            id: Id::default(),
        }
    }

    pub fn into_raw_parts(self) -> (SignedRadixCiphertext, Id) {
        let Self { ciphertext, id } = self;
        (ciphertext, id)
    }

    pub fn from_raw_parts(ciphertext: SignedRadixCiphertext, id: Id) -> Self {
        Self { ciphertext, id }
    }

    /// Returns the absolute value
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
    /// let result: i16 = a.abs().decrypt(&client_key);
    /// assert_eq!(result, (-3i16).wrapping_abs());
    ///
    /// let a = FheInt16::encrypt(3i16, &client_key);
    /// let result: i16 = a.abs().decrypt(&client_key);
    /// assert_eq!(result, (-3i16).wrapping_abs());
    ///
    /// // The abs of the minimum cannot be represented
    /// // and overflows to itself
    /// let a = FheInt16::encrypt(i16::MIN, &client_key);
    /// let result: i16 = a.abs().decrypt(&client_key);
    /// assert_eq!(result, i16::MIN.wrapping_abs());
    /// ```
    pub fn abs(&self) -> Self {
        let ciphertext = global_state::with_cpu_internal_keys(|keys| {
            keys.pbs_key().abs_parallelized(&self.ciphertext)
        });

        Self::new(ciphertext)
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
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// // This is not a trivial ciphertext as we use a client key to encrypt.
    /// let non_trivial = FheInt16::encrypt(-1i16, &client_key);
    /// // This is a trivial ciphertext
    /// let trivial = FheInt16::encrypt_trivial(-2i16);
    ///
    /// // We can trivial decrypt
    /// let result: Result<i16, _> = trivial.try_decrypt_trivial();
    /// assert_eq!(result, Ok(-2));
    ///
    /// // We cannot trivial decrypt
    /// let result: Result<i16, _> = non_trivial.try_decrypt_trivial();
    /// matches!(result, Err(_));
    /// ```
    pub fn try_decrypt_trivial<Clear>(&self) -> Result<Clear, NotTrivialCiphertextError>
    where
        Clear: RecomposableSignedInteger,
    {
        self.ciphertext.decrypt_trivial()
    }
}

impl<FromId, IntoId> CastFrom<FheInt<FromId>> for FheInt<IntoId>
where
    FromId: FheIntId,
    IntoId: FheIntId,
{
    /// Cast a FheInt to another FheInt
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheInt32};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheInt32::encrypt(i32::MAX, &client_key);
    /// let b = FheInt16::cast_from(a);
    ///
    /// let decrypted: i16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, i32::MAX as i16);
    /// ```
    fn cast_from(input: FheInt<FromId>) -> Self {
        global_state::with_cpu_internal_keys(|keys| {
            let target_num_blocks = IntoId::num_blocks(keys.message_modulus());
            let new_ciphertext = keys
                .pbs_key()
                .cast_to_signed(input.ciphertext, target_num_blocks);
            Self::new(new_ciphertext)
        })
    }
}

impl<FromId, IntoId> CastFrom<FheUint<FromId>> for FheInt<IntoId>
where
    FromId: FheUintId,
    IntoId: FheIntId,
{
    /// Cast a FheUint to a FheInt
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheInt16};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// # set_server_key(server_key);
    /// #
    /// let a = FheUint32::encrypt(u32::MAX, &client_key);
    /// let b = FheInt16::cast_from(a);
    ///
    /// let decrypted: i16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, u32::MAX as i16);
    /// ```
    fn cast_from(input: FheUint<FromId>) -> Self {
        global_state::with_cpu_internal_keys(|keys| {
            let new_ciphertext = keys.key.cast_to_signed(
                input.ciphertext.on_cpu().to_owned(),
                IntoId::num_blocks(keys.message_modulus()),
            );
            Self::new(new_ciphertext)
        })
    }
}

impl<Id> CastFrom<FheBool> for FheInt<Id>
where
    Id: FheIntId,
{
    /// Cast a FheBool to a FheInt
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
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheInt16::cast_from(a);
    ///
    /// let decrypted: i16 = b.decrypt(&client_key);
    /// assert_eq!(decrypted, i16::from(true));
    /// ```
    fn cast_from(input: FheBool) -> Self {
        let ciphertext = global_state::with_cpu_internal_keys(|keys| {
            input
                .ciphertext
                .on_cpu()
                .into_owned()
                .into_radix(Id::num_blocks(keys.message_modulus()), keys.pbs_key())
        });

        Self::new(ciphertext)
    }
}
