use std::borrow::Borrow;
use std::cell::RefCell;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul, MulAssign,
    Neg, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::high_level_api::global_state::WithGlobalKey;
use crate::high_level_api::integers::client_key::GenericIntegerClientKey;
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::public_key::compressed::GenericIntegerCompressedPublicKey;
use crate::high_level_api::integers::public_key::GenericIntegerPublicKey;
use crate::high_level_api::integers::server_key::{
    GenericIntegerServerKey, RadixCiphertextDyn, SmartAdd, SmartAddAssign, SmartBitAnd,
    SmartBitAndAssign, SmartBitOr, SmartBitOrAssign, SmartBitXor, SmartBitXorAssign, SmartEq,
    SmartGe, SmartGt, SmartLe, SmartLt, SmartMax, SmartMin, SmartMul, SmartMulAssign, SmartNeg,
    SmartShl, SmartShlAssign, SmartShr, SmartShrAssign, SmartSub, SmartSubAssign,
};
use crate::high_level_api::internal_traits::{DecryptionKey, EncryptionKey};
use crate::high_level_api::keys::{
    CompressedPublicKey, RefKeyFromCompressedPublicKeyChain, RefKeyFromKeyChain,
    RefKeyFromPublicKeyChain,
};
use crate::high_level_api::traits::{
    FheBootstrap, FheDecrypt, FheEq, FheOrd, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt,
};
use crate::high_level_api::{ClientKey, PublicKey};
use crate::integer::U256;

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
    pub(in crate::high_level_api::integers) ciphertext: RefCell<P::InnerCiphertext>,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::high_level_api::integers) fn new(
        ciphertext: P::InnerCiphertext,
        id: P::Id,
    ) -> Self {
        Self {
            ciphertext: RefCell::new(ciphertext),
            id,
        }
    }
}

impl<P> FheDecrypt<u16> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: RefKeyFromKeyChain<Key = GenericIntegerClientKey<P>>,
    P::InnerClientKey: DecryptionKey<P::InnerCiphertext, u16>,
{
    fn decrypt(&self, key: &ClientKey) -> u16 {
        let key = self.id.unwrapped_ref_key(key);
        key.inner.decrypt(&self.ciphertext.borrow())
    }
}

impl<P> FheDecrypt<u32> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: RefKeyFromKeyChain<Key = GenericIntegerClientKey<P>>,
    P::InnerClientKey: DecryptionKey<P::InnerCiphertext, u32>,
{
    fn decrypt(&self, key: &ClientKey) -> u32 {
        let key = self.id.unwrapped_ref_key(key);
        key.inner.decrypt(&self.ciphertext.borrow())
    }
}

impl<P, ClearType> FheDecrypt<ClearType> for GenericInteger<P>
where
    ClearType: crate::integer::encryption::AsLittleEndianWords,
    P: IntegerParameter,
    P::Id: RefKeyFromKeyChain<Key = GenericIntegerClientKey<P>>,
    P::InnerClientKey: DecryptionKey<P::InnerCiphertext, ClearType>,
{
    fn decrypt(&self, key: &ClientKey) -> ClearType {
        let key = self.id.unwrapped_ref_key(key);
        key.inner.decrypt(&self.ciphertext.borrow())
    }
}

impl<P, T> FheTryEncrypt<T, ClientKey> for GenericInteger<P>
where
    T: Into<U256>,
    P: IntegerParameter,
    P::Id: RefKeyFromKeyChain<Key = GenericIntegerClientKey<P>> + Default,
    P::InnerClientKey: EncryptionKey<U256, P::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let value = value.into();
        let id = P::Id::default();
        let key = id.ref_key(key)?;
        let ciphertext = key.inner.encrypt(value);
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryEncrypt<T, PublicKey> for GenericInteger<P>
where
    T: Into<U256>,
    P: IntegerParameter,
    P::Id: RefKeyFromPublicKeyChain<Key = GenericIntegerPublicKey<P>> + Default,
    P::InnerPublicKey: EncryptionKey<U256, P::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &PublicKey) -> Result<Self, Self::Error> {
        let value = value.into();
        let id = P::Id::default();
        let key = id.ref_key(key)?;
        let ciphertext = key.inner.encrypt(value);
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryEncrypt<T, CompressedPublicKey> for GenericInteger<P>
where
    T: Into<U256>,
    P: IntegerParameter<InnerCiphertext = RadixCiphertextDyn>,
    P::Id: RefKeyFromCompressedPublicKeyChain<Key = GenericIntegerCompressedPublicKey<P>> + Default,
    P::InnerPublicKey: EncryptionKey<U256, P::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let value = value.into();
        let id = P::Id::default();
        let key = id.ref_key(key)?;
        let ciphertext = key.inner.encrypt(value);
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryTrivialEncrypt<T> for GenericInteger<P>
where
    T: Into<U256>,
    P: IntegerParameter<
        InnerCiphertext = RadixCiphertextDyn,
        InnerServerKey = crate::integer::ServerKey,
    >,
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>> + Default,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt_trivial(value: T) -> Result<Self, Self::Error> {
        let value = value.into();
        let id = P::Id::default();
        let ciphertext = id.with_global(|key| match key.pbs_order {
            crate::shortint::PBSOrder::KeyswitchBootstrap => {
                RadixCiphertextDyn::Big(key.inner.create_trivial_radix(value, key.num_block))
            }
            crate::shortint::PBSOrder::BootstrapKeyswitch => {
                RadixCiphertextDyn::Small(key.inner.create_trivial_radix(value, key.num_block))
            }
        })?;
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTrivialEncrypt<T> for GenericInteger<P>
where
    T: Into<U256>,
    P: IntegerParameter<
        InnerCiphertext = RadixCiphertextDyn,
        InnerServerKey = crate::integer::ServerKey,
    >,
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>> + Default,
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
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>>,
    P::InnerServerKey: for<'a> SmartMax<
        &'a mut P::InnerCiphertext,
        &'a mut P::InnerCiphertext,
        Output = P::InnerCiphertext,
    >,
{
    pub fn max(&self, rhs: &Self) -> Self {
        let inner_result = self.id.with_unwrapped_global(|server_key| {
            if std::ptr::eq(self, rhs) {
                let cloned = (*rhs).clone();
                let r = server_key.inner.smart_max(
                    &mut self.ciphertext.borrow_mut(),
                    &mut cloned.ciphertext.borrow_mut(),
                );
                r
            } else {
                server_key.inner.smart_max(
                    &mut self.ciphertext.borrow_mut(),
                    &mut rhs.ciphertext.borrow_mut(),
                )
            }
        });

        GenericInteger::new(inner_result, self.id)
    }
}

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>>,
    P::InnerServerKey: for<'a> SmartMin<
        &'a mut P::InnerCiphertext,
        &'a mut P::InnerCiphertext,
        Output = P::InnerCiphertext,
    >,
{
    pub fn min(&self, rhs: &Self) -> Self {
        let inner_result = self.id.with_unwrapped_global(|server_key| {
            if std::ptr::eq(self, rhs) {
                let cloned = (*rhs).clone();
                let r = server_key.inner.smart_min(
                    &mut self.ciphertext.borrow_mut(),
                    &mut cloned.ciphertext.borrow_mut(),
                );
                r
            } else {
                server_key.inner.smart_min(
                    &mut self.ciphertext.borrow_mut(),
                    &mut rhs.ciphertext.borrow_mut(),
                )
            }
        });

        GenericInteger::new(inner_result, self.id)
    }
}

impl<P, B> FheEq<B> for GenericInteger<P>
where
    B: Borrow<GenericInteger<P>>,
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>>,
    P::InnerServerKey: for<'a> SmartEq<
        &'a mut P::InnerCiphertext,
        &'a mut P::InnerCiphertext,
        Output = P::InnerCiphertext,
    >,
{
    type Output = Self;

    fn eq(&self, rhs: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|server_key| {
            let borrowed = rhs.borrow();
            if std::ptr::eq(self, borrowed) {
                let cloned = (*borrowed).clone();
                let r = server_key.inner.smart_eq(
                    &mut self.ciphertext.borrow_mut(),
                    &mut cloned.ciphertext.borrow_mut(),
                );
                r
            } else {
                server_key.inner.smart_eq(
                    &mut self.ciphertext.borrow_mut(),
                    &mut borrowed.ciphertext.borrow_mut(),
                )
            }
        });

        GenericInteger::new(inner_result, self.id)
    }
}

impl<P, B> FheOrd<B> for GenericInteger<P>
where
    B: Borrow<GenericInteger<P>>,
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>>,
    P::InnerServerKey: for<'a> SmartGe<
            &'a mut P::InnerCiphertext,
            &'a mut P::InnerCiphertext,
            Output = P::InnerCiphertext,
        > + for<'a> SmartGt<
            &'a mut P::InnerCiphertext,
            &'a mut P::InnerCiphertext,
            Output = P::InnerCiphertext,
        > + for<'a> SmartLe<
            &'a mut P::InnerCiphertext,
            &'a mut P::InnerCiphertext,
            Output = P::InnerCiphertext,
        > + for<'a> SmartLt<
            &'a mut P::InnerCiphertext,
            &'a mut P::InnerCiphertext,
            Output = P::InnerCiphertext,
        >,
{
    type Output = Self;

    fn lt(&self, other: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|server_key| {
            let borrowed = other.borrow();
            if std::ptr::eq(self, borrowed) {
                let cloned = borrowed.clone();
                let r = server_key.inner.smart_lt(
                    &mut self.ciphertext.borrow_mut(),
                    &mut cloned.ciphertext.borrow_mut(),
                );
                r
            } else {
                server_key.inner.smart_lt(
                    &mut self.ciphertext.borrow_mut(),
                    &mut borrowed.ciphertext.borrow_mut(),
                )
            }
        });

        GenericInteger::new(inner_result, self.id)
    }

    fn le(&self, other: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|server_key| {
            let borrowed = other.borrow();
            if std::ptr::eq(self, borrowed) {
                let cloned = borrowed.clone();
                let r = server_key.inner.smart_le(
                    &mut self.ciphertext.borrow_mut(),
                    &mut cloned.ciphertext.borrow_mut(),
                );
                r
            } else {
                server_key.inner.smart_le(
                    &mut self.ciphertext.borrow_mut(),
                    &mut borrowed.ciphertext.borrow_mut(),
                )
            }
        });

        GenericInteger::new(inner_result, self.id)
    }

    fn gt(&self, other: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|server_key| {
            let borrowed = other.borrow();
            if std::ptr::eq(self, borrowed) {
                let cloned = borrowed.clone();
                let r = server_key.inner.smart_gt(
                    &mut self.ciphertext.borrow_mut(),
                    &mut cloned.ciphertext.borrow_mut(),
                );
                r
            } else {
                server_key.inner.smart_gt(
                    &mut self.ciphertext.borrow_mut(),
                    &mut borrowed.ciphertext.borrow_mut(),
                )
            }
        });

        GenericInteger::new(inner_result, self.id)
    }

    fn ge(&self, other: B) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|server_key| {
            let borrowed = other.borrow();
            if std::ptr::eq(self, borrowed) {
                let cloned = borrowed.clone();
                let r = server_key.inner.smart_ge(
                    &mut self.ciphertext.borrow_mut(),
                    &mut cloned.ciphertext.borrow_mut(),
                );
                r
            } else {
                server_key.inner.smart_ge(
                    &mut self.ciphertext.borrow_mut(),
                    &mut borrowed.ciphertext.borrow_mut(),
                )
            }
        });

        GenericInteger::new(inner_result, self.id)
    }
}

impl<P> FheBootstrap for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>>,
    crate::integer::wopbs::WopbsKey:
        crate::high_level_api::integers::server_key::WopbsEvaluationKey<
            P::InnerServerKey,
            P::InnerCiphertext,
        >,
{
    fn map<F: Fn(u64) -> u64>(&self, func: F) -> Self {
        use crate::high_level_api::integers::server_key::WopbsEvaluationKey;
        self.id.with_unwrapped_global(|key| {
            let ct = self.ciphertext.borrow();
            let res = key.wopbs_key.apply_wopbs(&key.inner, &ct, func);
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
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>>,
    crate::integer::wopbs::WopbsKey:
        crate::high_level_api::integers::server_key::WopbsEvaluationKey<
            P::InnerServerKey,
            P::InnerCiphertext,
        >,
{
    pub fn bivariate_function<F>(&self, other: &Self, func: F) -> Self
    where
        F: Fn(u64, u64) -> u64,
    {
        self.id.with_unwrapped_global(|key| {
            use crate::high_level_api::integers::server_key::WopbsEvaluationKey;
            let lhs = self.ciphertext.borrow();
            let rhs = other.ciphertext.borrow();
            let res = key
                .wopbs_key
                .apply_bivariate_wopbs(&key.inner, &lhs, &rhs, func);
            GenericInteger::<P>::new(res, self.id)
        })
    }
}

macro_rules! generic_integer_impl_operation (
    ($trait_name:ident($trait_method:ident,$op:tt, $smart_trait:ident) => $key_method:ident) => {
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
        #[doc = "     .enable_default_uint8()"]
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
        #[doc = "     .enable_default_uint8()"]
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
        impl<P, B> $trait_name<B> for GenericInteger<P>
        where
            P: IntegerParameter,
            B: Borrow<Self>,
            GenericInteger<P>: Clone,
            P::Id: WithGlobalKey<Key=GenericIntegerServerKey<P>>,
            P::InnerServerKey: for<'a> $smart_trait<
                                            &'a mut P::InnerCiphertext,
                                            &'a mut P::InnerCiphertext,
                                            Output=P::InnerCiphertext>,
        {
            type Output = Self;

            fn $trait_method(self, rhs: B) -> Self::Output {
                <&Self as $trait_name<B>>::$trait_method(&self, rhs)
            }
        }

        impl<P, B> $trait_name<B> for &GenericInteger<P>
        where
            P: IntegerParameter,
            B: Borrow<GenericInteger<P>>,
            GenericInteger<P>: Clone,
            P::Id: WithGlobalKey<Key=GenericIntegerServerKey<P>>,
            P::InnerServerKey: for<'a> $smart_trait<
                                            &'a mut P::InnerCiphertext,
                                            &'a mut P::InnerCiphertext,
                                            Output=P::InnerCiphertext>,
        {
            type Output = GenericInteger<P>;

            fn $trait_method(self, rhs: B) -> Self::Output {
                let ciphertext = self.id.with_unwrapped_global(|key| {
                    let borrowed = rhs.borrow();
                    if std::ptr::eq(self, borrowed) {
                        let cloned = (*borrowed).clone();
                        let r = key.inner.$key_method(
                            &mut self.ciphertext.borrow_mut(),
                            &mut cloned.ciphertext.borrow_mut(),
                        );
                        r
                    } else {
                        key.inner.$key_method(
                            &mut self.ciphertext.borrow_mut(),
                            &mut borrowed.ciphertext.borrow_mut(),
                        )
                    }
                });

                GenericInteger::<P>::new(ciphertext, self.id)
            }
        }
    }
);

macro_rules! generic_integer_impl_operation_assign (
    ($trait_name:ident($trait_method:ident, $op:tt, $smart_assign_trait:ident) => $key_method:ident) => {
        impl<P, I> $trait_name<I> for GenericInteger<P>
        where
            P: IntegerParameter,
            P::Id: WithGlobalKey<Key=GenericIntegerServerKey<P>>,
            P::InnerServerKey: for<'a> $smart_assign_trait<P::InnerCiphertext, &'a mut P::InnerCiphertext>,
            I: Borrow<Self>,
        {
            fn $trait_method(&mut self, rhs: I) {
                self.id.with_unwrapped_global(|key| {
                    key.inner.$key_method(
                        self.ciphertext.get_mut(),
                        &mut rhs.borrow().ciphertext.borrow_mut()
                    )
                })
            }
        }
    }
);

macro_rules! generic_integer_impl_scalar_operation {
    ($trait_name:ident($trait_method:ident, $smart_trait:ident) => $key_method:ident($($scalar_type:ty),*)) => {
        $(
            impl<P> $trait_name<$scalar_type> for GenericInteger<P>
            where
                P: IntegerParameter,
                P::Id: WithGlobalKey<Key=GenericIntegerServerKey<P>>,
                P::InnerServerKey: for<'a> $smart_trait<
                                            &'a mut P::InnerCiphertext,
                                            u64,
                                            Output=P::InnerCiphertext>,
            {
                type Output = GenericInteger<P>;

                fn $trait_method(self, rhs: $scalar_type) -> Self::Output {
                    <&Self as $trait_name<$scalar_type>>::$trait_method(&self, rhs)
                }
            }

            impl<P> $trait_name<$scalar_type> for &GenericInteger<P>
            where
                P: IntegerParameter,
                P::Id: WithGlobalKey<Key=GenericIntegerServerKey<P>>,
                P::InnerServerKey: for<'a> $smart_trait<
                                            &'a mut P::InnerCiphertext,
                                            u64,
                                            Output=P::InnerCiphertext>,
            {
                type Output = GenericInteger<P>;

                fn $trait_method(self, rhs: $scalar_type) -> Self::Output {
                    let ciphertext = self.id.with_unwrapped_global(|key| {
                        key.inner.$key_method(
                            &mut self.ciphertext.borrow_mut(),
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
    ($trait_name:ident($trait_method:ident,$smart_assign_trait:ident) => $key_method:ident($($scalar_type:ty),*)) => {
        $(
            impl<P> $trait_name<$scalar_type> for GenericInteger<P>
                where
                    P: IntegerParameter,
                    P::Id: WithGlobalKey<Key=GenericIntegerServerKey<P>>,
                    P::InnerServerKey: for<'a> $smart_assign_trait<P::InnerCiphertext, u64>,
            {
                fn $trait_method(&mut self, rhs: $scalar_type) {
                    self.id.with_unwrapped_global(|key| {
                        key.inner.$key_method(
                            &mut self.ciphertext.borrow_mut(),
                            u64::from(rhs)
                        )
                    });
                }
            }
        )*
    }
}

generic_integer_impl_operation!(Add(add,+, SmartAdd) => smart_add);
generic_integer_impl_operation!(Sub(sub,-, SmartSub) => smart_sub);
generic_integer_impl_operation!(Mul(mul,*, SmartMul) => smart_mul);
generic_integer_impl_operation!(BitAnd(bitand,&, SmartBitAnd) => smart_bitand);
generic_integer_impl_operation!(BitOr(bitor,|, SmartBitOr) => smart_bitor);
generic_integer_impl_operation!(BitXor(bitxor,^, SmartBitXor) => smart_bitxor);

generic_integer_impl_operation_assign!(AddAssign(add_assign,+=, SmartAddAssign) => smart_add_assign);
generic_integer_impl_operation_assign!(SubAssign(sub_assign,-=, SmartSubAssign) => smart_sub_assign);
generic_integer_impl_operation_assign!(MulAssign(mul_assign,*=, SmartMulAssign) => smart_mul_assign);
generic_integer_impl_operation_assign!(BitAndAssign(bitand_assign,&=, SmartBitAndAssign) => smart_bitand_assign);
generic_integer_impl_operation_assign!(BitOrAssign(bitor_assign,|=, SmartBitOrAssign) => smart_bitor_assign);
generic_integer_impl_operation_assign!(BitXorAssign(bitxor_assign,^=, SmartBitXorAssign) => smart_bitxor_assign);

generic_integer_impl_scalar_operation!(Add(add, SmartAdd) => smart_add(u8, u16, u32, u64));
generic_integer_impl_scalar_operation!(Sub(sub, SmartSub) => smart_sub(u8, u16, u32, u64));
generic_integer_impl_scalar_operation!(Mul(mul, SmartMul) => smart_mul(u8, u16, u32, u64));
generic_integer_impl_scalar_operation!(Shl(shl, SmartShl) => smart_shl(u8, u16, u32, u64));
generic_integer_impl_scalar_operation!(Shr(shr, SmartShr) => smart_shr(u8, u16, u32, u64));

generic_integer_impl_scalar_operation_assign!(AddAssign(add_assign, SmartAddAssign) => smart_add_assign(u8, u16, u32, u64));
generic_integer_impl_scalar_operation_assign!(SubAssign(sub_assign, SmartSubAssign) => smart_sub_assign(u8, u16, u32, u64));
generic_integer_impl_scalar_operation_assign!(MulAssign(mul_assign, SmartMulAssign) => smart_mul_assign(u8, u16, u32, u64));
generic_integer_impl_scalar_operation_assign!(ShlAssign(shl_assign, SmartShlAssign) => smart_shl_assign(u8, u16, u32, u64));
generic_integer_impl_scalar_operation_assign!(ShrAssign(shr_assign, SmartShrAssign) => smart_shr_assign(u8, u16, u32, u64));

impl<P> Neg for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>>,
    GenericIntegerServerKey<P>: for<'a> SmartNeg<&'a GenericInteger<P>, Output = GenericInteger<P>>,
    P::InnerServerKey: for<'a> SmartNeg<&'a mut P::InnerCiphertext, Output = P::InnerCiphertext>,
{
    type Output = GenericInteger<P>;

    fn neg(self) -> Self::Output {
        <&Self as Neg>::neg(&self)
    }
}

impl<P> Neg for &GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = GenericIntegerServerKey<P>>,
    P::InnerServerKey: for<'a> SmartNeg<&'a mut P::InnerCiphertext, Output = P::InnerCiphertext>,
{
    type Output = GenericInteger<P>;

    fn neg(self) -> Self::Output {
        let ciphertext = self
            .id
            .with_unwrapped_global(|key| key.inner.smart_neg(&mut self.ciphertext.borrow_mut()));

        GenericInteger::<P>::new(ciphertext, self.id)
    }
}
