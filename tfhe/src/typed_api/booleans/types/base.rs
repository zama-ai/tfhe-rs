use std::borrow::Borrow;
use std::ops::{BitAnd, BitOr, BitXor};

use crate::boolean::ciphertext::{Ciphertext, CompressedCiphertext};
use serde::{Deserialize, Serialize};

use crate::typed_api::booleans::client_key::GenericBoolClientKey;
use crate::typed_api::booleans::parameters::BooleanParameterSet;
use crate::typed_api::booleans::public_key::GenericBoolPublicKey;
use crate::typed_api::booleans::server_key::GenericBoolServerKey;
use crate::typed_api::global_state::WithGlobalKey;
use crate::typed_api::keys::{ClientKey, PublicKey, RefKeyFromKeyChain, RefKeyFromPublicKeyChain};
use crate::typed_api::traits::{
    FheDecrypt, FheEncrypt, FheEq, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt,
};

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
pub struct GenericBool<P>
where
    P: BooleanParameterSet,
{
    pub(in crate::typed_api::booleans) ciphertext: Ciphertext,
    pub(in crate::typed_api::booleans) id: P::Id,
}

pub struct CompressedBool<P>
where
    P: BooleanParameterSet,
{
    pub(in crate::typed_api::booleans) ciphertext: CompressedCiphertext,
    pub(in crate::typed_api::booleans) id: P::Id,
}

impl<P> GenericBool<P>
where
    P: BooleanParameterSet,
{
    pub(in crate::typed_api::booleans) fn new(ciphertext: Ciphertext, id: P::Id) -> Self {
        Self { ciphertext, id }
    }
}

impl<P> GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: WithGlobalKey<Key = GenericBoolServerKey<P>>,
{
    pub fn nand(&self, rhs: &Self) -> Self {
        self.id.with_unwrapped_global(|key| key.nand(self, rhs))
    }

    pub fn neq(&self, other: &Self) -> Self {
        self.id.with_unwrapped_global(|key| {
            let eq = key.xnor(self, other);
            key.not(&eq)
        })
    }
}

impl<P, B> FheEq<B> for GenericBool<P>
where
    B: Borrow<Self>,
    P: BooleanParameterSet,
    P::Id: WithGlobalKey<Key = GenericBoolServerKey<P>>,
{
    type Output = Self;

    fn eq(&self, other: B) -> Self {
        self.id
            .with_unwrapped_global(|key| key.xnor(self, other.borrow()))
    }
}

#[allow(dead_code)]
#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
pub fn if_then_else<B1, B2, P>(ct_condition: B1, ct_then: B2, ct_else: B2) -> GenericBool<P>
where
    B1: Borrow<GenericBool<P>>,
    B2: Borrow<GenericBool<P>>,
    P: BooleanParameterSet,
    P::Id: WithGlobalKey<Key = GenericBoolServerKey<P>>,
{
    let ct_condition = ct_condition.borrow();
    ct_condition
        .id
        .with_unwrapped_global(|key| key.mux(ct_condition, ct_then.borrow(), ct_else.borrow()))
}

impl<P> CompressedBool<P>
where
    P: BooleanParameterSet,
{
    fn new(ciphertext: CompressedCiphertext, id: P::Id) -> Self {
        Self { ciphertext, id }
    }
}

impl<P> From<CompressedBool<P>> for GenericBool<P>
where
    P: BooleanParameterSet,
{
    fn from(value: CompressedBool<P>) -> Self {
        Self::new(value.ciphertext.into(), value.id)
    }
}

impl<P> FheTryEncrypt<bool, ClientKey> for CompressedBool<P>
where
    P: BooleanParameterSet,
    P::Id: RefKeyFromKeyChain<Key = GenericBoolClientKey<P>> + Default,
{
    type Error = crate::typed_api::errors::Error;

    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let key = id.ref_key(key)?;
        let ciphertext = key.key.encrypt_compressed(value);
        Ok(CompressedBool::<P>::new(ciphertext, id))
    }
}

impl<P> FheEncrypt<bool, ClientKey> for CompressedBool<P>
where
    P: BooleanParameterSet,
    P::Id: RefKeyFromKeyChain<Key = GenericBoolClientKey<P>> + Default,
{
    #[track_caller]
    fn encrypt(value: bool, key: &ClientKey) -> Self {
        Self::try_encrypt(value, key).unwrap()
    }
}

impl<P> FheEncrypt<bool, ClientKey> for GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: RefKeyFromKeyChain<Key = GenericBoolClientKey<P>> + Default,
{
    #[track_caller]
    fn encrypt(value: bool, key: &ClientKey) -> Self {
        <Self as FheTryEncrypt<bool, ClientKey>>::try_encrypt(value, key).unwrap()
    }
}

impl<P> FheEncrypt<bool, PublicKey> for GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: RefKeyFromPublicKeyChain<Key = GenericBoolPublicKey<P>> + Default,
{
    #[track_caller]
    fn encrypt(value: bool, key: &PublicKey) -> Self {
        <Self as FheTryEncrypt<bool, PublicKey>>::try_encrypt(value, key).unwrap()
    }
}

impl<P> FheTryEncrypt<bool, ClientKey> for GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: RefKeyFromKeyChain<Key = GenericBoolClientKey<P>> + Default,
{
    type Error = crate::typed_api::errors::Error;

    fn try_encrypt(value: bool, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let key = id.ref_key(key)?;
        let ciphertext = key.key.encrypt(value);
        Ok(GenericBool::<P>::new(ciphertext, id))
    }
}

impl<P> FheTryTrivialEncrypt<bool> for GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: Default + WithGlobalKey<Key = GenericBoolServerKey<P>>,
{
    type Error = crate::typed_api::errors::Error;

    fn try_encrypt_trivial(value: bool) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        id.with_global(|key| {
            let ciphertext = key.key.trivial_encrypt(value);
            Ok(GenericBool::new(ciphertext, id))
        })?
    }
}

impl<P> FheTrivialEncrypt<bool> for GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: Default + WithGlobalKey<Key = GenericBoolServerKey<P>>,
{
    #[track_caller]
    fn encrypt_trivial(value: bool) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}

impl<P> FheTryEncrypt<bool, PublicKey> for GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: RefKeyFromPublicKeyChain<Key = GenericBoolPublicKey<P>> + Default,
{
    type Error = crate::typed_api::errors::Error;

    fn try_encrypt(value: bool, key: &PublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let key = id.ref_key(key)?;
        let ciphertext = key.key.encrypt(value);
        Ok(GenericBool::<P>::new(ciphertext, id))
    }
}

impl<P> FheDecrypt<bool> for GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: RefKeyFromKeyChain<Key = GenericBoolClientKey<P>>,
{
    #[track_caller]
    fn decrypt(&self, key: &ClientKey) -> bool {
        let key = self.id.unwrapped_ref_key(key);
        key.key.decrypt(&self.ciphertext)
    }
}

macro_rules! fhe_bool_impl_operation(
    ($trait_name:ident($trait_method:ident) => $key_method:ident) => {
        impl<P, B> $trait_name<B> for GenericBool<P>
        where B: Borrow<GenericBool<P>>,
              P: BooleanParameterSet,
              P::Id: WithGlobalKey<Key=GenericBoolServerKey<P>>,
        {
            type Output = GenericBool<P>;

            fn $trait_method(self, rhs: B) -> Self::Output {
                <&Self as $trait_name<B>>::$trait_method(&self, rhs)
            }
        }

        impl<P, B> $trait_name<B> for &GenericBool<P>
        where B: Borrow<GenericBool<P>>,
              P: BooleanParameterSet,
              P::Id: WithGlobalKey<Key=GenericBoolServerKey<P>>,
        {
            type Output = GenericBool<P>;

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

impl<P> ::std::ops::Not for GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: WithGlobalKey<Key = GenericBoolServerKey<P>>,
{
    type Output = Self;

    fn not(self) -> Self::Output {
        self.id.with_unwrapped_global(|key| key.not(&self))
    }
}

impl<P> ::std::ops::Not for &GenericBool<P>
where
    P: BooleanParameterSet,
    P::Id: WithGlobalKey<Key = GenericBoolServerKey<P>>,
{
    type Output = GenericBool<P>;

    fn not(self) -> Self::Output {
        self.id.with_unwrapped_global(|key| key.not(self))
    }
}
