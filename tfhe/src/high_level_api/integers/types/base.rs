use std::borrow::Borrow;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul, MulAssign,
    Neg, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::errors::{
    UninitializedClientKey, UninitializedCompressedPublicKey, UninitializedPublicKey,
    UnwrapResultExt,
};
use crate::high_level_api::global_state::WithGlobalKey;
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::server_key::{
    RadixCiphertextDyn, ServerKeyDefaultAdd, ServerKeyDefaultAddAssign, ServerKeyDefaultBitAnd,
    ServerKeyDefaultBitAndAssign, ServerKeyDefaultBitOr, ServerKeyDefaultBitOrAssign,
    ServerKeyDefaultBitXor, ServerKeyDefaultBitXorAssign, ServerKeyDefaultEq, ServerKeyDefaultGe,
    ServerKeyDefaultGt, ServerKeyDefaultLe, ServerKeyDefaultLt, ServerKeyDefaultMax,
    ServerKeyDefaultMin, ServerKeyDefaultMul, ServerKeyDefaultMulAssign, ServerKeyDefaultNeg,
    ServerKeyDefaultShl, ServerKeyDefaultShlAssign, ServerKeyDefaultShr, ServerKeyDefaultShrAssign,
    ServerKeyDefaultSub, ServerKeyDefaultSubAssign,
};
use crate::high_level_api::integers::IntegerServerKey;
use crate::high_level_api::internal_traits::{DecryptionKey, TypeIdentifier};
use crate::high_level_api::keys::{CompressedPublicKey, RefKeyFromKeyChain};
use crate::high_level_api::traits::{
    FheBootstrap, FheDecrypt, FheEq, FheOrd, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt,
};
use crate::high_level_api::{ClientKey, PublicKey};

/// A Generic FHE unsigned integer
///
/// Contrary to *shortints*, these integers can in theory by parametrized to
/// represent integers of any number of bits (eg: 16, 24, 32, 64).
///
/// However, in practice going above 16 bits may not be ideal as the
/// computations would not scale and become very expensive.
///
/// Integers works by combining together multiple shortints
/// with one of the available representation.
///
/// This struct is generic over some parameters, as its the parameters
/// that controls how many bit they represent.
/// You will need to use one of this type specialization (e.g., [FheUint8], [FheUint12],
/// [FheUint16]).
///
/// Its the type that overloads the operators (`+`, `-`, `*`),
/// since the `GenericInteger` type is not `Copy` the operators are also overloaded
/// to work with references.
///
///
/// To be able to use this type, the cargo feature `integers` must be enabled,
/// and your config should also enable the type with either default parameters or custom ones.
///
///
/// [FheUint8]: crate::high_level_api::FheUint8
/// [FheUint12]: crate::high_level_api::FheUint12
/// [FheUint16]: crate::high_level_api::FheUint16
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericInteger<P: IntegerParameter> {
    pub(in crate::high_level_api::integers) ciphertext: RadixCiphertextDyn,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::high_level_api::integers) fn new(
        ciphertext: RadixCiphertextDyn,
        id: P::Id,
    ) -> Self {
        Self { ciphertext, id }
    }

    pub fn cast_from<P2>(other: GenericInteger<P2>) -> Self
    where
        P2: IntegerParameter,
        P::Id: Default,
    {
        other.cast_into()
    }

    pub fn cast_into<P2>(mut self) -> GenericInteger<P2>
    where
        P2: IntegerParameter,
        P2::Id: Default,
    {
        crate::high_level_api::global_state::with_internal_keys(|keys| {
            let integer_key = keys.integer_key.pbs_key();
            let current_num_blocks = P::num_blocks();
            let target_num_blocks = P2::num_blocks();

            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                match &mut self.ciphertext {
                    RadixCiphertextDyn::Big(ct) => integer_key
                        .extend_radix_with_trivial_zero_blocks_msb_assign(ct, num_blocks_to_add),
                    RadixCiphertextDyn::Small(ct) => integer_key
                        .extend_radix_with_trivial_zero_blocks_msb_assign(ct, num_blocks_to_add),
                }
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                match &mut self.ciphertext {
                    RadixCiphertextDyn::Big(ct) => {
                        integer_key.trim_radix_blocks_msb_assign(ct, num_blocks_to_remove)
                    }
                    RadixCiphertextDyn::Small(ct) => {
                        integer_key.trim_radix_blocks_msb_assign(ct, num_blocks_to_remove)
                    }
                }
            }
            GenericInteger::<P2>::new(self.ciphertext, P2::Id::default())
        })
    }
}

impl<P, Block> From<Vec<Block>> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default,
    RadixCiphertextDyn: From<Vec<Block>>,
{
    fn from(blocks: Vec<Block>) -> GenericInteger<P> {
        GenericInteger::<P>::new(RadixCiphertextDyn::from(blocks), Default::default())
    }
}

impl<P> From<RadixCiphertextDyn> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default,
{
    fn from(other: RadixCiphertextDyn) -> GenericInteger<P> {
        GenericInteger::<P>::new(other, Default::default())
    }
}

impl<P, ClearType> FheDecrypt<ClearType> for GenericInteger<P>
where
    ClearType: crate::integer::block_decomposition::RecomposableFrom<u64>,
    P: IntegerParameter,
    P::Id: RefKeyFromKeyChain<Key = crate::integer::ClientKey>,
    crate::integer::ClientKey: DecryptionKey<RadixCiphertextDyn, ClearType>,
{
    fn decrypt(&self, key: &ClientKey) -> ClearType {
        let key = self.id.unwrapped_ref_key(key);
        key.decrypt(&self.ciphertext)
    }
}

impl<P, T> FheTryEncrypt<T, ClientKey> for GenericInteger<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();

        let integer_client_key = key
            .integer_key
            .key
            .as_ref()
            .ok_or(UninitializedClientKey(id.type_variant()))
            .unwrap_display();
        let encryption_type = key.integer_key.encryption_type();
        let ciphertext = match encryption_type {
            crate::shortint::EncryptionKeyChoice::Big => {
                RadixCiphertextDyn::Big(integer_client_key.encrypt_radix(value, P::num_blocks()))
            }
            crate::shortint::EncryptionKeyChoice::Small => RadixCiphertextDyn::Small(
                integer_client_key.encrypt_radix_small(value, P::num_blocks()),
            ),
        };
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryEncrypt<T, PublicKey> for GenericInteger<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &PublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let integer_public_key = key
            .base_integer_key
            .as_ref()
            .ok_or(UninitializedPublicKey(id.type_variant()))
            .unwrap_display();
        let ciphertext = match integer_public_key {
            crate::high_level_api::integers::PublicKeyDyn::Big(pk) => {
                RadixCiphertextDyn::Big(pk.encrypt_radix(value, P::num_blocks()))
            }
            crate::high_level_api::integers::PublicKeyDyn::Small(pk) => {
                RadixCiphertextDyn::Small(pk.encrypt_radix(value, P::num_blocks()))
            }
        };
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryEncrypt<T, CompressedPublicKey> for GenericInteger<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let integer_public_key = key
            .base_integer_key
            .as_ref()
            .ok_or(UninitializedCompressedPublicKey(id.type_variant()))
            .unwrap_display();
        let ciphertext = match integer_public_key {
            crate::high_level_api::integers::CompressedPublicKeyDyn::Big(pk) => {
                RadixCiphertextDyn::Big(pk.encrypt_radix(value, P::num_blocks()))
            }
            crate::high_level_api::integers::CompressedPublicKeyDyn::Small(pk) => {
                RadixCiphertextDyn::Small(pk.encrypt_radix(value, P::num_blocks()))
            }
        };
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryTrivialEncrypt<T> for GenericInteger<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + WithGlobalKey<Key = IntegerServerKey>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt_trivial(value: T) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let ciphertext =
            id.with_unwrapped_global(|integer_key| match integer_key.encryption_type {
                crate::shortint::EncryptionKeyChoice::Big => RadixCiphertextDyn::Big(
                    integer_key
                        .pbs_key()
                        .create_trivial_radix(value, P::num_blocks()),
                ),
                crate::shortint::EncryptionKeyChoice::Small => RadixCiphertextDyn::Small(
                    integer_key
                        .pbs_key()
                        .create_trivial_radix(value, P::num_blocks()),
                ),
            });
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTrivialEncrypt<T> for GenericInteger<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + WithGlobalKey<Key = IntegerServerKey>,
{
    #[track_caller]
    fn encrypt_trivial(value: T) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
    crate::integer::ServerKey: for<'a> ServerKeyDefaultMax<
        &'a RadixCiphertextDyn,
        &'a RadixCiphertextDyn,
        Output = RadixCiphertextDyn,
    >,
{
    pub fn max(&self, rhs: &Self) -> Self {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            <crate::integer::ServerKey as ServerKeyDefaultMax<_, _>>::max(
                integer_key.pbs_key(),
                &self.ciphertext,
                &rhs.ciphertext,
            )
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
    GenericInteger<P>: Clone,
    crate::integer::ServerKey: for<'a> ServerKeyDefaultMin<
        &'a RadixCiphertextDyn,
        &'a RadixCiphertextDyn,
        Output = RadixCiphertextDyn,
    >,
{
    pub fn min(&self, rhs: &Self) -> Self {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            <crate::integer::ServerKey as ServerKeyDefaultMin<_, _>>::min(
                integer_key.pbs_key(),
                &self.ciphertext,
                &rhs.ciphertext,
            )
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P, B> FheEq<B> for GenericInteger<P>
where
    B: Borrow<GenericInteger<P>>,
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
    crate::integer::ServerKey: for<'a> ServerKeyDefaultEq<
        &'a RadixCiphertextDyn,
        &'a RadixCiphertextDyn,
        Output = RadixCiphertextDyn,
    >,
{
    type Output = Self;

    fn eq(&self, rhs: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let borrowed = rhs.borrow();
            <crate::integer::ServerKey as ServerKeyDefaultEq<_, _>>::eq(
                integer_key.pbs_key(),
                &self.ciphertext,
                &borrowed.ciphertext,
            )
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P, B> FheOrd<B> for GenericInteger<P>
where
    B: Borrow<GenericInteger<P>>,
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
    crate::integer::ServerKey: for<'a> ServerKeyDefaultGe<
            &'a RadixCiphertextDyn,
            &'a RadixCiphertextDyn,
            Output = RadixCiphertextDyn,
        > + for<'a> ServerKeyDefaultGt<
            &'a RadixCiphertextDyn,
            &'a RadixCiphertextDyn,
            Output = RadixCiphertextDyn,
        > + for<'a> ServerKeyDefaultLe<
            &'a RadixCiphertextDyn,
            &'a RadixCiphertextDyn,
            Output = RadixCiphertextDyn,
        > + for<'a> ServerKeyDefaultLt<
            &'a RadixCiphertextDyn,
            &'a RadixCiphertextDyn,
            Output = RadixCiphertextDyn,
        >,
{
    type Output = Self;

    fn lt(&self, rhs: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let borrowed = rhs.borrow();
            <crate::integer::ServerKey as ServerKeyDefaultLt<_, _>>::lt(
                integer_key.pbs_key(),
                &self.ciphertext,
                &borrowed.ciphertext,
            )
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn le(&self, rhs: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let borrowed = rhs.borrow();
            <crate::integer::ServerKey as ServerKeyDefaultLe<_, _>>::le(
                integer_key.pbs_key(),
                &self.ciphertext,
                &borrowed.ciphertext,
            )
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn gt(&self, rhs: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let borrowed = rhs.borrow();
            <crate::integer::ServerKey as ServerKeyDefaultGt<_, _>>::gt(
                integer_key.pbs_key(),
                &self.ciphertext,
                &borrowed.ciphertext,
            )
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn ge(&self, rhs: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let borrowed = rhs.borrow();
            <crate::integer::ServerKey as ServerKeyDefaultGe<_, _>>::ge(
                integer_key.pbs_key(),
                &self.ciphertext,
                &borrowed.ciphertext,
            )
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P> FheBootstrap for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
    crate::integer::wopbs::WopbsKey:
        crate::high_level_api::integers::server_key::WopbsEvaluationKey<
            crate::integer::ServerKey,
            RadixCiphertextDyn,
        >,
{
    fn map<F: Fn(u64) -> u64>(&self, func: F) -> Self {
        use crate::high_level_api::integers::server_key::WopbsEvaluationKey;
        self.id.with_unwrapped_global(|integer_key| {
            let res = integer_key
                .wopbs_key
                .as_ref()
                .expect("Function evalutation on integers was not enabled in the config")
                .apply_wopbs(integer_key.pbs_key(), &self.ciphertext, func);
            GenericInteger::<P>::new(res, self.id)
        })
    }

    fn apply<F: Fn(u64) -> u64>(&mut self, func: F) {
        let result = self.map(func);
        *self = result;
    }
}

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
    crate::integer::wopbs::WopbsKey:
        crate::high_level_api::integers::server_key::WopbsEvaluationKey<
            crate::integer::ServerKey,
            RadixCiphertextDyn,
        >,
{
    pub fn bivariate_function<F>(&self, other: &Self, func: F) -> Self
    where
        F: Fn(u64, u64) -> u64,
    {
        use crate::high_level_api::integers::server_key::WopbsEvaluationKey;
        self.id.with_unwrapped_global(|integer_key| {
            let lhs = &self.ciphertext;
            let rhs = &other.ciphertext;
            let res = integer_key
                .wopbs_key
                .as_ref()
                .expect("Function evalutation on integers was not enabled in the config")
                .apply_bivariate_wopbs(integer_key.pbs_key(), lhs, rhs, func);
            GenericInteger::<P>::new(res, self.id)
        })
    }
}

macro_rules! generic_integer_impl_operation (
    ($rust_trait_name:ident($rust_trait_method:ident,$op:tt) => $trait_name:ident($trait_method:ident)) => {
        #[doc = concat!(" Allows using the `", stringify!($op), "` operator between a")]
        #[doc = " `GenericInteger` and a `GenericInteger` or a `&GenericInteger`"]
        #[doc = " "]
        #[doc = " # Examples "]
        #[doc = " "]
        #[doc = " ```"]
        #[doc = " # fn main() -> Result<(), tfhe::Error> {"]
        #[doc = " use tfhe::prelude::*;"]
        #[doc = " use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};"]
        #[doc = " use std::num::Wrapping;"]
        #[doc = " "]
        #[doc = " let config = ConfigBuilder::all_disabled()"]
        #[doc = "     .enable_default_integers()"]
        #[doc = "     .build();"]
        #[doc = " let (keys, server_key) = generate_keys(config);"]
        #[doc = " "]
        #[doc = " let a = FheUint8::try_encrypt(142u32, &keys)?;"]
        #[doc = " let b = FheUint8::try_encrypt(83u32, &keys)?;"]
        #[doc = " "]
        #[doc = " set_server_key(server_key);"]
        #[doc = " "]
        #[doc = concat!(" let c = a ", stringify!($op), " b;")]
        #[doc = " let decrypted: u8 = c.decrypt(&keys);"]
        #[doc = concat!(" let expected = Wrapping(142u8) ", stringify!($op), " Wrapping(83u8);")]
        #[doc = " assert_eq!(decrypted, expected.0);"]
        #[doc = " # Ok(())"]
        #[doc = " # }"]
        #[doc = " ```"]
        #[doc = " "]
        #[doc = " "]
        #[doc = " ```"]
        #[doc = " # fn main() -> Result<(), tfhe::Error> {"]
        #[doc = " use tfhe::prelude::*;"]
        #[doc = " use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};"]
        #[doc = " use std::num::Wrapping;"]
        #[doc = " "]
        #[doc = " let config = ConfigBuilder::all_disabled()"]
        #[doc = "     .enable_default_integers()"]
        #[doc = "     .build();"]
        #[doc = " let (keys, server_key) = generate_keys(config);"]
        #[doc = " "]
        #[doc = " let a = FheUint8::try_encrypt(208u32, &keys)?;"]
        #[doc = " let b = FheUint8::try_encrypt(29u32, &keys)?;"]
        #[doc = " "]
        #[doc = " set_server_key(server_key);"]
        #[doc = " "]
        #[doc = concat!(" let c = a ", stringify!($op), " &b;")]
        #[doc = " let decrypted: u8 = c.decrypt(&keys);"]
        #[doc = concat!(" let expected = Wrapping(208u8) ", stringify!($op), " Wrapping(29u8);")]
        #[doc = " assert_eq!(decrypted, expected.0);"]
        #[doc = " # Ok(())"]
        #[doc = " # }"]
        #[doc = " ```"]
        impl<P, B> $rust_trait_name<B> for GenericInteger<P>
        where
            P: IntegerParameter,
            B: Borrow<Self>,
            GenericInteger<P>: Clone,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
            crate::integer::ServerKey: for<'a> $trait_name<
                                            &'a RadixCiphertextDyn,
                                            &'a RadixCiphertextDyn,
                                            Output=RadixCiphertextDyn>,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                <&Self as $rust_trait_name<B>>::$trait_method(&self, rhs)
            }
        }

        impl<P, B> $rust_trait_name<B> for &GenericInteger<P>
        where
            P: IntegerParameter,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
            B: Borrow<GenericInteger<P>>,
            GenericInteger<P>: Clone,
            crate::integer::ServerKey: for<'a> $trait_name<
                                            &'a RadixCiphertextDyn,
                                            &'a RadixCiphertextDyn,
                                            Output=RadixCiphertextDyn>,
        {
            type Output = GenericInteger<P>;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                let ciphertext = self.id.with_unwrapped_global(|integer_key| {
                    let borrowed = rhs.borrow();
                    <crate::integer::ServerKey as $trait_name<_, _>>::$trait_method(
                        integer_key.pbs_key(),
                        &self.ciphertext,
                        &borrowed.ciphertext,
                    )
                });
                GenericInteger::<P>::new(ciphertext, self.id)
            }
        }
    }
);

macro_rules! generic_integer_impl_operation_assign (
    ($rust_trait_name:ident($rust_trait_method:ident, $op:tt) => $assign_trait:ident($assign_trait_method:ident)) => {
        impl<P, I> $rust_trait_name<I> for GenericInteger<P>
        where
            P: IntegerParameter,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
            crate::integer::ServerKey: for<'a> $assign_trait<RadixCiphertextDyn, &'a RadixCiphertextDyn>,
            I: Borrow<Self>,
        {
            fn $rust_trait_method(&mut self, rhs: I) {
                self.id.with_unwrapped_global(|integer_key| {
                    <crate::integer::ServerKey as $assign_trait<_, _>>::$assign_trait_method(
                        integer_key.pbs_key(),
                        &mut self.ciphertext,
                        &rhs.borrow().ciphertext
                    )
                })
            }
        }
    }
);

macro_rules! generic_integer_impl_scalar_operation {
    ($rust_trait_name:ident($rust_trait_method:ident) => $trait:ident($trait_method:ident($($scalar_type:ty),*))) => {
        $(
            impl<P> $rust_trait_name<$scalar_type> for GenericInteger<P>
            where
                P: IntegerParameter,
                P::Id: WithGlobalKey<Key = IntegerServerKey>,
            {
                type Output = GenericInteger<P>;

                fn $rust_trait_method(self, rhs: $scalar_type) -> Self::Output {
                    <&Self as $rust_trait_name<$scalar_type>>::$trait_method(&self, rhs)
                }
            }

            impl<P> $rust_trait_name<$scalar_type> for &GenericInteger<P>
            where
                P: IntegerParameter,
                P::Id: WithGlobalKey<Key = IntegerServerKey>,
            {
                type Output = GenericInteger<P>;

                fn $rust_trait_method(self, rhs: $scalar_type) -> Self::Output {
                    let ciphertext: RadixCiphertextDyn =
                        self.id.with_unwrapped_global(|integer_key| {
                            <crate::integer::ServerKey as $trait<_, u64>>::$trait_method(
                                integer_key.pbs_key(),
                                &self.ciphertext,
                                u64::from(rhs)
                            )
                        });

                    GenericInteger::<P>::new(ciphertext, self.id)
                }
            }
        )*
    };
}

macro_rules! generic_integer_impl_scalar_operation_assign {
    ($rust_trait_name:ident($rust_trait_method:ident) => $assign_trait:ident($assign_trait_method:ident($($scalar_type:ty),*))) => {
        $(
            impl<P> $rust_trait_name<$scalar_type> for GenericInteger<P>
                where
                    P: IntegerParameter,
                    P::Id: WithGlobalKey<Key = IntegerServerKey>,
                    crate::integer::ServerKey: for<'a> $assign_trait<RadixCiphertextDyn, u64>,
            {
                fn $rust_trait_method(&mut self, rhs: $scalar_type) {
                    self.id.with_unwrapped_global(|integer_key| {
                        <crate::integer::ServerKey as $assign_trait<_, _>>::$assign_trait_method(
                            integer_key.pbs_key(),
                            &mut self.ciphertext,
                            u64::from(rhs)
                        )
                    })
                }
            }
        )*
    }
}

generic_integer_impl_operation!(Add(add,+) => ServerKeyDefaultAdd(add));
generic_integer_impl_operation!(Sub(sub,-) => ServerKeyDefaultSub(sub));
generic_integer_impl_operation!(Mul(mul,*) => ServerKeyDefaultMul(mul));
generic_integer_impl_operation!(BitAnd(bitand,&) => ServerKeyDefaultBitAnd(bitand));
generic_integer_impl_operation!(BitOr(bitor,|) => ServerKeyDefaultBitOr(bitor));
generic_integer_impl_operation!(BitXor(bitxor,^) => ServerKeyDefaultBitXor(bitxor));

generic_integer_impl_operation_assign!(AddAssign(add_assign,+=) => ServerKeyDefaultAddAssign(add_assign));
generic_integer_impl_operation_assign!(SubAssign(sub_assign,-=) => ServerKeyDefaultSubAssign(sub_assign));
generic_integer_impl_operation_assign!(MulAssign(mul_assign,*=) => ServerKeyDefaultMulAssign(mul_assign));
generic_integer_impl_operation_assign!(BitAndAssign(bitand_assign,&=) => ServerKeyDefaultBitAndAssign(bitand_assign));
generic_integer_impl_operation_assign!(BitOrAssign(bitor_assign,|=) => ServerKeyDefaultBitOrAssign(bitor_assign));
generic_integer_impl_operation_assign!(BitXorAssign(bitxor_assign,^=) => ServerKeyDefaultBitXorAssign(bitxor_assign));

generic_integer_impl_scalar_operation!(Add(add) => ServerKeyDefaultAdd(add(u8, u16, u32, u64)));
generic_integer_impl_scalar_operation!(Sub(sub) => ServerKeyDefaultSub(sub(u8, u16, u32, u64)));
generic_integer_impl_scalar_operation!(Mul(mul) => ServerKeyDefaultMul(mul(u8, u16, u32, u64)));
generic_integer_impl_scalar_operation!(Shl(shl) => ServerKeyDefaultShl(shl(u8, u16, u32, u64)));
generic_integer_impl_scalar_operation!(Shr(shr) => ServerKeyDefaultShr(shr(u8, u16, u32, u64)));

generic_integer_impl_scalar_operation_assign!(AddAssign(add_assign) => ServerKeyDefaultAddAssign(add_assign(u8, u16, u32, u64)));
generic_integer_impl_scalar_operation_assign!(SubAssign(sub_assign) => ServerKeyDefaultSubAssign(sub_assign(u8, u16, u32, u64)));
generic_integer_impl_scalar_operation_assign!(MulAssign(mul_assign) => ServerKeyDefaultMulAssign(mul_assign(u8, u16, u32, u64)));
generic_integer_impl_scalar_operation_assign!(ShlAssign(shl_assign) => ServerKeyDefaultShlAssign(shl_assign(u8, u16, u32, u64)));
generic_integer_impl_scalar_operation_assign!(ShrAssign(shr_assign) => ServerKeyDefaultShrAssign(shr_assign(u8, u16, u32, u64)));

impl<P> Neg for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
    crate::integer::ServerKey:
        for<'a> ServerKeyDefaultNeg<&'a RadixCiphertextDyn, Output = RadixCiphertextDyn>,
{
    type Output = GenericInteger<P>;

    fn neg(self) -> Self::Output {
        <&Self as Neg>::neg(&self)
    }
}

impl<P> Neg for &GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
    crate::integer::ServerKey:
        for<'a> ServerKeyDefaultNeg<&'a RadixCiphertextDyn, Output = RadixCiphertextDyn>,
{
    type Output = GenericInteger<P>;

    fn neg(self) -> Self::Output {
        let ciphertext: RadixCiphertextDyn = self.id.with_unwrapped_global(|integer_key| {
            <crate::integer::ServerKey as ServerKeyDefaultNeg<_>>::neg(
                integer_key.pbs_key(),
                &self.ciphertext,
            )
        });
        GenericInteger::<P>::new(ciphertext, self.id)
    }
}
