use std::borrow::Borrow;
use std::ops::{BitAnd, BitOr, BitXor};

use crate::errors::Type;
use crate::high_level_api::global_state::WithGlobalKey;
use crate::high_level_api::internal_traits::TypeIdentifier;
use crate::high_level_api::keys::{ClientKey, PublicKey};
use crate::high_level_api::traits::{
    FheDecrypt, FheEq, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt,
};
use crate::shortint::{Ciphertext, CompressedCiphertext};
use crate::CompressedPublicKey;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

#[derive(Copy, Clone, Serialize, Deserialize)]
struct FheBoolId;

impl TypeIdentifier for FheBoolId {
    fn type_variant(&self) -> Type {
        Type::FheBool
    }
}

impl WithGlobalKey for FheBoolId {
    type Key = crate::high_level_api::integers::IntegerServerKey;

    fn with_unwrapped_global<R, F>(self, func: F) -> R
    where
        F: FnOnce(&Self::Key) -> R,
    {
        crate::high_level_api::global_state::with_internal_keys(|keys| func(&keys.integer_key))
    }
}

/// The FHE boolean data type.
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
///
/// let config = ConfigBuilder::default().build();
///
/// let (client_key, server_key) = generate_keys(config);
///
/// let ttrue = FheBool::encrypt(true, &client_key);
/// let ffalse = FheBool::encrypt(false, &client_key);
///
/// // Do not forget to set the server key before doing any computation
/// set_server_key(server_key);
///
/// let fhe_result = ttrue & ffalse;
///
/// let clear_result = fhe_result.decrypt(&client_key);
/// assert_eq!(clear_result, false);
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct FheBool {
    pub(in crate::high_level_api::booleans) ciphertext: Ciphertext,
    id: FheBoolId,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedFheBool {
    pub(in crate::high_level_api::booleans) ciphertext: CompressedCiphertext,
}

impl FheBool {
    pub(in crate::high_level_api::booleans) fn new(ciphertext: Ciphertext) -> Self {
        Self {
            ciphertext,
            id: FheBoolId,
        }
    }
}

impl<B> FheEq<B> for FheBool
where
    B: Borrow<Self>,
{
    type Output = Self;

    fn eq(&self, other: B) -> Self {
        let ciphertext = self.id.with_unwrapped_global(|key| {
            key.pbs_key()
                .key
                .equal(&self.ciphertext, &other.borrow().ciphertext)
        });
        Self::new(ciphertext)
    }

    fn ne(&self, other: B) -> Self {
        let ciphertext = self.id.with_unwrapped_global(|key| {
            key.pbs_key()
                .key
                .not_equal(&self.ciphertext, &other.borrow().ciphertext)
        });
        Self::new(ciphertext)
    }
}

impl CompressedFheBool {
    fn new(ciphertext: CompressedCiphertext) -> Self {
        Self { ciphertext }
    }
}

impl From<CompressedFheBool> for FheBool {
    fn from(value: CompressedFheBool) -> Self {
        let block: Ciphertext = value.ciphertext.into();
        Self::new(block)
    }
}

impl FheTryEncrypt<bool, ClientKey> for CompressedFheBool {
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let integer_client_key = &key.key.key;
        let ciphertext = integer_client_key.key.encrypt_compressed(u64::from(value));
        Ok(Self::new(ciphertext))
    }
}

impl FheTryEncrypt<bool, ClientKey> for FheBool {
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let integer_client_key = &key.key.key;
        let ciphertext = integer_client_key.encrypt_one_block(u64::from(value));
        Ok(Self::new(ciphertext))
    }
}

impl FheTryTrivialEncrypt<bool> for FheBool {
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt_trivial(value: bool) -> Result<Self, Self::Error> {
        let ciphertext = FheBoolId
            .with_unwrapped_global(|key| key.pbs_key().key.create_trivial(u64::from(value)));
        Ok(Self::new(ciphertext))
    }
}

impl FheTrivialEncrypt<bool> for FheBool {
    #[track_caller]
    fn encrypt_trivial(value: bool) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}

impl FheTryEncrypt<bool, CompressedPublicKey> for crate::FheBool {
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: bool, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let key = &key.key;
        let ciphertext = key.key.encrypt(u64::from(value));
        Ok(Self::new(ciphertext))
    }
}

impl FheTryEncrypt<bool, PublicKey> for FheBool {
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: bool, key: &PublicKey) -> Result<Self, Self::Error> {
        let key = &key.key;
        let ciphertext = key.key.encrypt(u64::from(value));
        Ok(Self::new(ciphertext))
    }
}

impl FheDecrypt<bool> for FheBool {
    fn decrypt(&self, key: &ClientKey) -> bool {
        let integer_client_key = &key.key.key;
        integer_client_key.decrypt_one_block(&self.ciphertext) != 0
    }
}

macro_rules! fhe_bool_impl_operation(
    ($trait_name:ident($trait_method:ident) => $key_method:ident) => {
        impl<B> $trait_name<B> for FheBool
        where B: Borrow<FheBool>,
        {
            type Output = FheBool;

            fn $trait_method(self, rhs: B) -> Self::Output {
                <&Self as $trait_name<B>>::$trait_method(&self, rhs)
            }
        }

        impl<B> $trait_name<B> for &FheBool
        where B: Borrow<FheBool>,
        {
            type Output = FheBool;

            fn $trait_method(self, rhs: B) -> Self::Output {
                let ciphertext = self.id.with_unwrapped_global(|key| {
                    key.pbs_key().key.$key_method(&self.ciphertext, &rhs.borrow().ciphertext)
                });
                FheBool::new(ciphertext)
            }
        }
    };
);

fhe_bool_impl_operation!(BitAnd(bitand) => bitand);
fhe_bool_impl_operation!(BitOr(bitor) => bitor);
fhe_bool_impl_operation!(BitXor(bitxor) => bitxor);

impl ::std::ops::Not for FheBool {
    type Output = Self;

    fn not(self) -> Self::Output {
        let ciphertext = self
            .id
            .with_unwrapped_global(|key| key.pbs_key().key.scalar_bitxor(&self.ciphertext, 1));
        Self::new(ciphertext)
    }
}

impl ::std::ops::Not for &FheBool {
    type Output = FheBool;

    fn not(self) -> Self::Output {
        let ciphertext = self
            .id
            .with_unwrapped_global(|key| key.pbs_key().key.scalar_bitxor(&self.ciphertext, 1));
        FheBool::new(ciphertext)
    }
}
