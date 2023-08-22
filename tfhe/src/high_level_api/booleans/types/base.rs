use std::borrow::Borrow;
use std::ops::{BitAnd, BitOr, BitXor};

use crate::boolean::ciphertext::{Ciphertext, CompressedCiphertext};
use crate::errors::{Type, UnwrapResultExt};
use crate::CompressedPublicKey;
use serde::{Deserialize, Serialize};

use crate::high_level_api::global_state::WithGlobalKey;
use crate::high_level_api::keys::{
    ClientKey, PublicKey, RefKeyFromKeyChain, RefKeyFromPublicKeyChain,
};
use crate::high_level_api::traits::{
    FheDecrypt, FheEq, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt,
};

use super::static_::{FheBoolClientKey, FheBoolPublicKey, FheBoolServerKey};

#[derive(Copy, Clone, Serialize, Deserialize)]
struct FheBoolId;

impl_with_global_key!(
    for FheBoolId {
        key_type: FheBoolServerKey,
        keychain_member: boolean_key.bool_key,
        type_variant: Type::FheBool,
    }
);

impl_ref_key_from_keychain!(
    for FheBoolId {
        key_type: FheBoolClientKey,
        keychain_member: boolean_key.bool_key,
        type_variant: Type::FheBool,
    }
);

impl_ref_key_from_public_keychain!(
    for FheBoolId {
        key_type: FheBoolPublicKey,
        keychain_member: boolean_key.bool_key,
        type_variant: Type::FheBool,
    }
);

/// The FHE boolean data type.
///
/// To be able to use this type, the cargo feature `booleans` must be enabled,
/// and your config should also enable the type with either default parameters or custom ones.
///
/// # Example
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
///
/// // Enable booleans in the config
/// let config = ConfigBuilder::all_disabled().enable_default_bool().build();
///
/// // With the booleans enabled in the config, the needed keys and details
/// // can be taken care of.
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
#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
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

    pub fn nand(&self, rhs: &Self) -> Self {
        self.id.with_unwrapped_global(|key| key.nand(self, rhs))
    }
}

impl<B> FheEq<B> for FheBool
where
    B: Borrow<Self>,
{
    type Output = Self;

    fn eq(&self, other: B) -> Self {
        self.id
            .with_unwrapped_global(|key| key.xnor(self, other.borrow()))
    }

    fn ne(&self, other: B) -> Self {
        self.id
            .with_unwrapped_global(|key| key.xor(self, other.borrow()))
    }
}

#[allow(dead_code)]
#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
pub fn if_then_else<B1, B2>(ct_condition: B1, ct_then: B2, ct_else: B2) -> FheBool
where
    B1: Borrow<FheBool>,
    B2: Borrow<FheBool>,
{
    let ct_condition = ct_condition.borrow();
    ct_condition
        .id
        .with_unwrapped_global(|key| key.mux(ct_condition, ct_then.borrow(), ct_else.borrow()))
}

impl CompressedFheBool {
    fn new(ciphertext: CompressedCiphertext) -> Self {
        Self { ciphertext }
    }
}

impl From<CompressedFheBool> for FheBool {
    fn from(value: CompressedFheBool) -> Self {
        Self::new(value.ciphertext.into())
    }
}

impl FheTryEncrypt<bool, ClientKey> for CompressedFheBool {
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = FheBoolId;
        let key = <FheBoolId as RefKeyFromKeyChain>::ref_key(id, key)?;
        let ciphertext = key.key.encrypt_compressed(value);
        Ok(CompressedFheBool::new(ciphertext))
    }
}

impl FheTryEncrypt<bool, ClientKey> for FheBool {
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = FheBoolId;
        let key = <FheBoolId as RefKeyFromKeyChain>::ref_key(id, key)?;
        let ciphertext = key.key.encrypt(value);
        Ok(FheBool::new(ciphertext))
    }
}

impl FheTryTrivialEncrypt<bool> for FheBool {
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt_trivial(value: bool) -> Result<Self, Self::Error> {
        FheBoolId.with_global(|key| {
            let ciphertext = key.key.trivial_encrypt(value);
            Ok(FheBool::new(ciphertext))
        })?
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
        let ciphertext = key
            .boolean_key
            .bool_key
            .as_ref()
            .ok_or(
                crate::high_level_api::errors::UninitializedCompressedPublicKey(
                    crate::high_level_api::errors::Type::FheBool,
                ),
            )
            .unwrap_display()
            .key
            .encrypt(value);
        Ok(FheBool::new(ciphertext))
    }
}

impl FheTryEncrypt<bool, PublicKey> for FheBool {
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: bool, key: &PublicKey) -> Result<Self, Self::Error> {
        let id = FheBoolId;
        let key = <FheBoolId as RefKeyFromPublicKeyChain>::ref_key(id, key)?;
        let ciphertext = key.key.encrypt(value);
        Ok(FheBool::new(ciphertext))
    }
}

impl FheDecrypt<bool> for FheBool {
    #[track_caller]
    fn decrypt(&self, key: &ClientKey) -> bool {
        let id = FheBoolId;
        let key = <FheBoolId as RefKeyFromKeyChain>::unwrapped_ref_key(id, key);
        key.key.decrypt(&self.ciphertext)
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
                self.id.with_unwrapped_global(|key| {
                  key.$key_method(self, rhs.borrow())
                })
            }
        }
    };
);

fhe_bool_impl_operation!(BitAnd(bitand) => and);
fhe_bool_impl_operation!(BitOr(bitor) => or);
fhe_bool_impl_operation!(BitXor(bitxor) => xor);

impl ::std::ops::Not for FheBool {
    type Output = Self;

    fn not(self) -> Self::Output {
        self.id.with_unwrapped_global(|key| key.not(&self))
    }
}

impl ::std::ops::Not for &FheBool {
    type Output = FheBool;

    fn not(self) -> Self::Output {
        self.id.with_unwrapped_global(|key| key.not(self))
    }
}
