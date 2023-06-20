use std::borrow::Borrow;
use std::cell::RefCell;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Rem, Shl, Shr, Sub, SubAssign,
};

use serde::{Deserialize, Serialize};

use crate::shortint::ciphertext::Ciphertext as ShortintCiphertext;

use crate::high_level_api::errors::OutOfRangeError;
use crate::high_level_api::global_state::WithGlobalKey;
use crate::high_level_api::keys::{
    ClientKey, CompressedPublicKey, RefKeyFromCompressedPublicKeyChain, RefKeyFromKeyChain,
    RefKeyFromPublicKeyChain,
};
use crate::high_level_api::shortints::public_key::compressed::GenericShortIntCompressedPublicKey;
use crate::high_level_api::traits::{
    FheBootstrap, FheDecrypt, FheEq, FheNumberConstant, FheOrd, FheTrivialEncrypt, FheTryEncrypt,
    FheTryTrivialEncrypt,
};
use crate::high_level_api::PublicKey;

use super::{GenericShortIntClientKey, GenericShortIntServerKey};

use crate::high_level_api::shortints::parameters::{
    ShortIntegerParameter, StaticShortIntegerParameter,
};
use crate::high_level_api::shortints::public_key::GenericShortIntPublicKey;

/// A Generic short FHE unsigned integer
///
/// Short means less than 7 bits.
///
/// It is generic over some parameters, as its the parameters
/// that controls how many bit they represent.
///
/// Its the type that overloads the operators (`+`, `-`, `*`).
/// Since the `GenericShortInt` type is not `Copy` the operators are also overloaded
/// to work with references.
///
/// You will need to use one of this type specialization (e.g., [FheUint2], [FheUint3], [FheUint4]).
///
/// To be able to use this type, the cargo feature `shortints` must be enabled,
/// and your config should also enable the type with either default parameters or custom ones.
///
/// # Example
///
/// To use FheUint2
///
/// ```
/// # #[cfg(feature = "shortint")]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint2};
///
/// // Enable the FheUint2 type in the config
/// let config = ConfigBuilder::all_disabled().enable_default_uint2().build();
///
/// // With the FheUint2 type enabled in the config, the needed keys and details
/// // can be taken care of.
/// let (client_key, server_key) = generate_keys(config);
///
/// let a = FheUint2::try_encrypt(0, &client_key)?;
/// let b = FheUint2::try_encrypt(1, &client_key)?;
///
/// // Do not forget to set the server key before doing any computation
/// set_server_key(server_key);
///
/// // Since FHE types are bigger than native rust type they are not `Copy`,
/// // meaning that to reuse the same value in a computation and avoid the cost
/// // of calling `clone`, you'll have to use references:
/// let c = a + &b;
/// // `a` was moved but not `b`, so `a` cannot be reused, but `b` can
/// let d = &c + b;
/// // `b` was moved but not `c`, so `b` cannot be reused, but `c` can
/// let fhe_result = d + c;
/// // both `d` and `c` were moved.
///
/// let expected: u8 = {
///     let a = 0;
///     let b = 1;
///
///     let c = a + b;
///     let d = c + b;
///     d + c
/// };
/// let clear_result = fhe_result.decrypt(&client_key);
/// assert_eq!(expected, 3);
/// assert_eq!(clear_result, expected);
///
/// # Ok(())
/// # }
/// ```
///
/// [FheUint2]: crate::FheUint2
/// [FheUint3]: crate::FheUint3
/// [FheUint4]: crate::FheUint4
#[cfg_attr(all(doc, not(doctest)), cfg(feature = "shortint"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct GenericShortInt<P: ShortIntegerParameter> {
    /// The actual ciphertext.
    /// Wrapped inside a RefCell because some methods
    /// of the corresponding `ServerKey` (in tfhe-shortint)
    /// require the ciphertext to be a `&mut`,
    /// while we also overloads rust operators for have a `&` references
    pub(in crate::high_level_api::shortints) ciphertext: RefCell<ShortintCiphertext>,
    pub(in crate::high_level_api::shortints) id: P::Id,
}

impl<P> GenericShortInt<P>
where
    P: ShortIntegerParameter,
{
    pub(crate) fn new(inner: ShortintCiphertext, id: P::Id) -> Self {
        Self {
            ciphertext: RefCell::new(inner),
            id,
        }
    }
}

impl<P> GenericShortInt<P>
where
    P: ShortIntegerParameter,
{
    pub fn message_max(&self) -> u64 {
        self.message_modulus() - 1
    }

    pub fn message_modulus(&self) -> u64 {
        self.ciphertext.borrow().message_modulus.0 as u64
    }
}

impl<P> GenericShortInt<P>
where
    P: StaticShortIntegerParameter,
{
    /// Minimum value this type can hold, always 0.
    pub const MIN: u8 = 0;

    /// Maximum value this type can hold.
    pub const MAX: u8 = (1 << P::MESSAGE_BITS) - 1;

    pub const MODULUS: u8 = (1 << P::MESSAGE_BITS);
}

impl<P> FheNumberConstant for GenericShortInt<P>
where
    P: StaticShortIntegerParameter,
{
    const MIN: u64 = 0;

    const MAX: u64 = Self::MAX as u64;

    const MODULUS: u64 = Self::MODULUS as u64;
}

impl<T, P> FheTryEncrypt<T, ClientKey> for GenericShortInt<P>
where
    T: TryInto<u8>,
    P: StaticShortIntegerParameter,
    P::Id: Default + RefKeyFromKeyChain<Key = GenericShortIntClientKey<P>>,
{
    type Error = OutOfRangeError;

    /// Try to create a new value.
    ///
    /// As Shortints exposed by this crate have between 2 and 7 bits,
    /// creating a value from a rust `u8` may not be possible.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "shortint")]
    /// # {
    /// # use tfhe::{ConfigBuilder, FheUint3, generate_keys, set_server_key};
    /// # let config = ConfigBuilder::all_disabled().enable_default_uint3().build();
    /// # let (client_key, server_key) = generate_keys(config);
    /// # set_server_key(server_key);
    /// use tfhe::prelude::*;
    /// use tfhe::Error;
    ///
    /// // The maximum value that can be represented with 3 bits is 7.
    /// let a = FheUint3::try_encrypt(8, &client_key);
    /// assert_eq!(a.is_err(), true);
    ///
    /// let a = FheUint3::try_encrypt(7, &client_key);
    /// assert_eq!(a.is_ok(), true);
    /// # }
    /// ```
    #[track_caller]
    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let value = value.try_into().map_err(|_err| OutOfRangeError)?;
        if value > Self::MAX {
            Err(OutOfRangeError)
        } else {
            let id = P::Id::default();
            let key = id.unwrapped_ref_key(key);
            let ciphertext = key.key.encrypt(u64::from(value));
            Ok(Self {
                ciphertext: RefCell::new(ciphertext),
                id,
            })
        }
    }
}

impl<T, P> FheTryEncrypt<T, PublicKey> for GenericShortInt<P>
where
    T: TryInto<u8>,
    P: StaticShortIntegerParameter,
    P::Id: Default + RefKeyFromPublicKeyChain<Key = GenericShortIntPublicKey<P>>,
{
    type Error = crate::high_level_api::errors::Error;

    /// Try to create a new value.
    ///
    /// As Shortints exposed by this crate have between 2 and 7 bits,
    /// creating a value from a rust `u8` may not be possible.
    ///
    /// # Example
    ///
    /// ```
    /// # use tfhe::PublicKey;
    /// #[cfg(feature = "shortint")]
    /// # {
    /// # use tfhe::{ConfigBuilder, PublicKey, FheUint2, generate_keys, set_server_key};
    /// # let config = ConfigBuilder::all_disabled().enable_default_uint2().build();
    /// # let (client_key, server_key) = generate_keys(config);
    /// # set_server_key(server_key);
    /// use tfhe::prelude::*;
    /// use tfhe::Error;
    ///
    /// let public_key = PublicKey::new(&client_key);
    ///
    /// // The maximum value that can be represented with 2 bits is 3.
    /// let a = FheUint2::try_encrypt(8, &public_key);
    /// assert_eq!(a.is_err(), true);
    ///
    /// let a = FheUint2::try_encrypt(3, &public_key);
    /// assert_eq!(a.is_ok(), true);
    /// # }
    /// ```
    #[track_caller]
    fn try_encrypt(value: T, key: &PublicKey) -> Result<Self, Self::Error> {
        let value = value.try_into().map_err(|_err| OutOfRangeError)?;
        if value > Self::MAX {
            Err(OutOfRangeError.into())
        } else {
            let id = P::Id::default();
            let key = id.unwrapped_ref_key(key);
            let ciphertext = key.key.encrypt(u64::from(value));
            Ok(Self {
                ciphertext: RefCell::new(ciphertext),
                id,
            })
        }
    }
}

impl<T, P> FheTryEncrypt<T, CompressedPublicKey> for GenericShortInt<P>
where
    T: TryInto<u8>,
    P: StaticShortIntegerParameter,
    P::Id:
        Default + RefKeyFromCompressedPublicKeyChain<Key = GenericShortIntCompressedPublicKey<P>>,
{
    type Error = crate::high_level_api::errors::Error;

    #[track_caller]
    fn try_encrypt(value: T, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let value = value.try_into().map_err(|_err| OutOfRangeError)?;
        if value > Self::MAX {
            Err(OutOfRangeError.into())
        } else {
            let id = P::Id::default();
            let key = id.unwrapped_ref_key(key);
            let ciphertext = key.key.encrypt(u64::from(value));
            Ok(Self {
                ciphertext: RefCell::new(ciphertext),
                id,
            })
        }
    }
}

impl<Clear, P> FheTryTrivialEncrypt<Clear> for GenericShortInt<P>
where
    Clear: TryInto<u8>,
    P: StaticShortIntegerParameter,
    P::Id: Default + WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt_trivial(value: Clear) -> Result<Self, Self::Error> {
        let value = value.try_into().map_err(|_err| OutOfRangeError)?;
        if value > Self::MAX {
            Err(OutOfRangeError.into())
        } else {
            let id = P::Id::default();
            id.with_global(|key| {
                let ciphertext = key.key.create_trivial(value.into());
                Ok(Self {
                    ciphertext: RefCell::new(ciphertext),
                    id,
                })
            })?
        }
    }
}

impl<Clear, P> FheTrivialEncrypt<Clear> for GenericShortInt<P>
where
    Clear: TryInto<u8>,
    P: StaticShortIntegerParameter,
    P::Id: Default + WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    #[track_caller]
    fn encrypt_trivial(value: Clear) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}

impl<P> GenericShortInt<P>
where
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    pub fn bivariate_function<F>(&self, other: &Self, func: F) -> Self
    where
        F: Fn(u8, u8) -> u8,
    {
        self.id
            .with_unwrapped_global(|server_key| server_key.bivariate_pbs(self, other, func))
    }
}

impl<P> FheOrd<u8> for GenericShortInt<P>
where
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    type Output = Self;

    fn lt(&self, rhs: u8) -> Self {
        self.id
            .with_unwrapped_global(|server_key| server_key.scalar_less(self, rhs))
    }

    fn le(&self, rhs: u8) -> Self {
        self.id
            .with_unwrapped_global(|server_key| server_key.scalar_less_or_equal(self, rhs))
    }

    fn gt(&self, rhs: u8) -> Self {
        self.id
            .with_unwrapped_global(|server_key| server_key.scalar_greater(self, rhs))
    }

    fn ge(&self, rhs: u8) -> Self {
        self.id
            .with_unwrapped_global(|server_key| server_key.scalar_greater_or_equal(self, rhs))
    }
}

impl<P> FheEq<u8> for GenericShortInt<P>
where
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    type Output = Self;

    fn eq(&self, rhs: u8) -> Self::Output {
        self.id
            .with_unwrapped_global(|server_key| server_key.scalar_equal(self, rhs))
    }

    fn ne(&self, rhs: u8) -> Self::Output {
        self.id
            .with_unwrapped_global(|server_key| server_key.scalar_not_equal(self, rhs))
    }
}

impl<P, B> FheOrd<B> for GenericShortInt<P>
where
    B: Borrow<Self>,
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    type Output = Self;

    fn lt(&self, other: B) -> Self::Output {
        self.id
            .with_unwrapped_global(|server_key| server_key.less(self, other.borrow()))
    }

    fn le(&self, other: B) -> Self::Output {
        self.id
            .with_unwrapped_global(|server_key| server_key.less_or_equal(self, other.borrow()))
    }

    fn gt(&self, other: B) -> Self::Output {
        self.id
            .with_unwrapped_global(|server_key| server_key.greater(self, other.borrow()))
    }

    fn ge(&self, other: B) -> Self::Output {
        self.id
            .with_unwrapped_global(|server_key| server_key.greater_or_equal(self, other.borrow()))
    }
}

impl<P, B> FheEq<B> for GenericShortInt<P>
where
    B: Borrow<Self>,
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    type Output = Self;

    fn eq(&self, other: B) -> Self {
        self.id
            .with_unwrapped_global(|server_key| server_key.equal(self, other.borrow()))
    }

    fn ne(&self, rhs: B) -> Self::Output {
        self.id
            .with_unwrapped_global(|server_key| server_key.not_equal(self, rhs.borrow()))
    }
}

impl<P> FheBootstrap for GenericShortInt<P>
where
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    fn map<F>(&self, func: F) -> Self
    where
        F: Fn(u64) -> u64,
    {
        self.id
            .with_unwrapped_global(|key| key.bootstrap_with(self, func))
    }

    fn apply<F>(&mut self, func: F)
    where
        F: Fn(u64) -> u64,
    {
        self.id.with_unwrapped_global(|key| {
            key.bootstrap_inplace_with(self, func);
        })
    }
}

impl<P, B> std::iter::Sum<B> for GenericShortInt<P>
where
    B: Borrow<Self>,
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
    Self: FheTryTrivialEncrypt<u8> + AddAssign<B>,
{
    fn sum<I: Iterator<Item = B>>(iter: I) -> Self {
        let mut sum = Self::try_encrypt_trivial(0u8).expect("Failed to trivially encrypt zero");
        for item in iter {
            sum += item;
        }
        sum
    }
}

impl<P, B> std::iter::Product<B> for GenericShortInt<P>
where
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
    Self: FheTryTrivialEncrypt<u8> + MulAssign<B>,
{
    fn product<I: Iterator<Item = B>>(iter: I) -> Self {
        let mut product = Self::try_encrypt_trivial(1u8).expect(
            "Failed to trivially encrypt
one",
        );
        for item in iter {
            product *= item;
        }
        product
    }
}

impl<P> FheDecrypt<u8> for GenericShortInt<P>
where
    P: ShortIntegerParameter,
    P::Id: RefKeyFromKeyChain<Key = GenericShortIntClientKey<P>>,
{
    /// Decrypt the encrypted value to a u8
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "shortint")]
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # use tfhe::{ConfigBuilder, FheUint3, FheUint2, generate_keys, set_server_key};
    /// # let config = ConfigBuilder::all_disabled().enable_default_uint3().enable_default_uint2().build();
    /// # let (client_key, server_key) = generate_keys(config);
    /// # set_server_key(server_key);
    /// use tfhe::Error;
    /// use tfhe::prelude::*;
    ///
    /// let a = FheUint2::try_encrypt(2, &client_key)?;
    /// let a_clear = a.decrypt(&client_key);
    /// assert_eq!(a_clear, 2);
    ///
    /// let a = FheUint3::try_encrypt(7, &client_key)?;
    /// let a_clear = a.decrypt(&client_key);
    /// assert_eq!(a_clear, 7);
    /// # Ok(())
    /// # }
    /// ```
    #[track_caller]
    fn decrypt(&self, key: &ClientKey) -> u8 {
        let key = self.id.unwrapped_ref_key(key);
        key.key.decrypt(&self.ciphertext.borrow()) as u8
    }
}

macro_rules! short_int_impl_operation (
    ($trait_name:ident($trait_method:ident, $op:tt) => $key_method:ident) => {
        #[doc = concat!(" Allows using the `", stringify!($op), "` operator between a")]
        #[doc = " `GenericFheUint` and a `GenericFheUint` or a `&GenericFheUint`"]
        #[doc = " "]
        #[doc = " # Examples "]
        #[doc = " "]
        #[doc = " ```"]
        #[doc = " # fn main() -> Result<(), tfhe::Error> {"]
        #[doc = " use tfhe::prelude::*;"]
        #[doc = " use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint2};"]
        #[doc = " "]
        #[doc = " let config = ConfigBuilder::all_disabled()"]
        #[doc = "     .enable_default_uint2()"]
        #[doc = "     .build();"]
        #[doc = " let (keys, server_key) = generate_keys(config);"]
        #[doc = " "]
        #[doc = " let a = FheUint2::try_encrypt(2, &keys)?;"]
        #[doc = " let b = FheUint2::try_encrypt(1, &keys)?;"]
        #[doc = " "]
        #[doc = " set_server_key(server_key);"]
        #[doc = " "]
        #[doc = concat!(" let c = a ", stringify!($op), " b;")]
        #[doc = " let decrypted = c.decrypt(&keys);"]
        #[doc = concat!(" let expected = 2 ", stringify!($op), " 1;")]
        #[doc = " assert_eq!(decrypted, expected);"]
        #[doc = " # Ok(())"]
        #[doc = " # }"]
        #[doc = " ```"]
        #[doc = " "]
        #[doc = " "]
        #[doc = " ```"]
        #[doc = " # fn main() -> Result<(), tfhe::Error> {"]
        #[doc = " use tfhe::prelude::*;"]
        #[doc = " use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint2};"]
        #[doc = " "]
        #[doc = " let config = ConfigBuilder::all_disabled()"]
        #[doc = "     .enable_default_uint2()"]
        #[doc = "     .build();"]
        #[doc = " let (keys, server_key) = generate_keys(config);"]
        #[doc = " "]
        #[doc = " let a = FheUint2::try_encrypt(2, &keys)?;"]
        #[doc = " let b = FheUint2::try_encrypt(1, &keys)?;"]
        #[doc = " "]
        #[doc = " set_server_key(server_key);"]
        #[doc = " "]
        #[doc = concat!(" let c = a ", stringify!($op), " &b;")]
        #[doc = " let decrypted = c.decrypt(&keys);"]
        #[doc = concat!(" let expected = 2 ", stringify!($op), " 1;")]
        #[doc = " assert_eq!(decrypted, expected);"]
        #[doc = " # Ok(())"]
        #[doc = " # }"]
        #[doc = " ```"]
        impl<P, I> $trait_name<I> for GenericShortInt<P>
        where
            P: ShortIntegerParameter,
            GenericShortInt<P>: Clone,
            P::Id: WithGlobalKey<Key=GenericShortIntServerKey<P>>,
            I: Borrow<Self>,
        {
            type Output = Self;

            fn $trait_method(self, rhs: I) -> Self::Output {
                <&Self as $trait_name<I>>::$trait_method(&self, rhs)
            }
        }

        #[doc = concat!(" Allows using the `", stringify!($op), "` operator between a")]
        #[doc = " `&GenericFheUint` and a `GenericFheUint` or a `&GenericFheUint`"]
        #[doc = " "]
        #[doc = " # Examples "]
        #[doc = " "]
        #[doc = " ```"]
        #[doc = " # fn main() -> Result<(), tfhe::Error> {"]
        #[doc = " use tfhe::prelude::*;"]
        #[doc = " use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint2};"]
        #[doc = " "]
        #[doc = " let config = ConfigBuilder::all_disabled()"]
        #[doc = "     .enable_default_uint2()"]
        #[doc = "     .build();"]
        #[doc = " let (keys, server_key) = generate_keys(config);"]
        #[doc = " "]
        #[doc = " let a = FheUint2::try_encrypt(2, &keys)?;"]
        #[doc = " let b = FheUint2::try_encrypt(1, &keys)?;"]
        #[doc = " "]
        #[doc = " set_server_key(server_key);"]
        #[doc = " "]
        #[doc = concat!(" let c = &a ", stringify!($op), " b;")]
        #[doc = " let decrypted = c.decrypt(&keys);"]
        #[doc = concat!(" let expected = 2 ", stringify!($op), " 1;")]
        #[doc = " assert_eq!(decrypted, expected);"]
        #[doc = " # Ok(())"]
        #[doc = " # }"]
        #[doc = " ```"]
        #[doc = " "]
        #[doc = " "]
        #[doc = " ```"]
        #[doc = " # fn main() -> Result<(), tfhe::Error> {"]
        #[doc = " use tfhe::prelude::*;"]
        #[doc = " use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint2};"]
        #[doc = " "]
        #[doc = " let config = ConfigBuilder::all_disabled()"]
        #[doc = "     .enable_default_uint2()"]
        #[doc = "     .build();"]
        #[doc = " let (keys, server_key) = generate_keys(config);"]
        #[doc = " "]
        #[doc = " let a = FheUint2::try_encrypt(2, &keys)?;"]
        #[doc = " let b = FheUint2::try_encrypt(1, &keys)?;"]
        #[doc = " "]
        #[doc = " set_server_key(server_key);"]
        #[doc = " "]
        #[doc = concat!(" let c = &a ", stringify!($op), " &b;")]
        #[doc = " let decrypted = c.decrypt(&keys);"]
        #[doc = concat!(" let expected = 2 ", stringify!($op), " 1;")]
        #[doc = " assert_eq!(decrypted, expected);"]
        #[doc = " # Ok(())"]
        #[doc = " # }"]
        #[doc = " ```"]
        impl<P, I> $trait_name<I> for &GenericShortInt<P>
        where
            P: ShortIntegerParameter,
            GenericShortInt<P>: Clone,
            P::Id: WithGlobalKey<Key=GenericShortIntServerKey<P>>,
            I: Borrow<GenericShortInt<P>>,
        {
            type Output = GenericShortInt<P>;

            fn $trait_method(self, rhs: I) -> Self::Output {
                self.id.with_unwrapped_global(|key| {
                    let borrowed = rhs.borrow();
                    if std::ptr::eq(self, borrowed) {
                        let cloned = (*borrowed).clone();
                        key.$key_method(self, &cloned)
                    } else {
                        key.$key_method(self, borrowed)
                    }
                })
            }
        }
    };
);

macro_rules! short_int_impl_operation_assign (
    ($trait_name:ident($trait_method:ident, $op:tt) => $key_method:ident) => {
        #[doc = concat!(" Allows using the `", stringify!($op), "` operator between a")]
        #[doc = " `GenericFheUint` and a `GenericFheUint` or a `&GenericFheUint`"]
        #[doc = " "]
        #[doc = " # Examples "]
        #[doc = " "]
        #[doc = " ```"]
        #[doc = " # fn main() -> Result<(), tfhe::Error> {"]
        #[doc = " use tfhe::prelude::*;"]
        #[doc = " use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint2};"]
        #[doc = " "]
        #[doc = " let config = ConfigBuilder::all_disabled()"]
        #[doc = "     .enable_default_uint2()"]
        #[doc = "     .build();"]
        #[doc = " let (keys, server_key) = generate_keys(config);"]
        #[doc = " "]
        #[doc = " let mut a = FheUint2::try_encrypt(2, &keys)?;"]
        #[doc = " let b = FheUint2::try_encrypt(1, &keys)?;"]
        #[doc = " "]
        #[doc = " set_server_key(server_key);"]
        #[doc = " "]
        #[doc = concat!(" a ", stringify!($op), " b;")]
        #[doc = " let decrypted = a.decrypt(&keys);"]
        #[doc = " let mut expected = 2;"]
        #[doc = concat!(" expected ", stringify!($op), " 1;")]
        #[doc = " assert_eq!(decrypted, expected);"]
        #[doc = " # Ok(())"]
        #[doc = " # }"]
        #[doc = " ```"]
        #[doc = " "]
        #[doc = " "]
        #[doc = " ```"]
        #[doc = " # fn main() -> Result<(), tfhe::Error> {"]
        #[doc = " use tfhe::prelude::*;"]
        #[doc = " use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint2};"]
        #[doc = " "]
        #[doc = " let config = ConfigBuilder::all_disabled()"]
        #[doc = "     .enable_default_uint2()"]
        #[doc = "     .build();"]
        #[doc = " let (keys, server_key) = generate_keys(config);"]
        #[doc = " "]
        #[doc = " let mut a = FheUint2::try_encrypt(2, &keys)?;"]
        #[doc = " let b = FheUint2::try_encrypt(1, &keys)?;"]
        #[doc = " "]
        #[doc = " set_server_key(server_key);"]
        #[doc = " "]
        #[doc = concat!(" a ", stringify!($op), " &b;")]
        #[doc = " let decrypted = a.decrypt(&keys);"]
        #[doc = " let mut expected = 2;"]
        #[doc = concat!(" expected ", stringify!($op), " 1;")]
        #[doc = " assert_eq!(decrypted, expected);"]
        #[doc = " # Ok(())"]
        #[doc = " # }"]
        #[doc = " ```"]
        impl<P, I> $trait_name<I> for GenericShortInt<P>
        where
            P: ShortIntegerParameter,
            P::Id: WithGlobalKey<Key=GenericShortIntServerKey<P>>,
            I: Borrow<Self>,
        {
            fn $trait_method(&mut self, rhs: I) {
                // no need to check if self == rhs as, since we have &mut to self
                // we know its exclusive
                self.id.with_unwrapped_global(|key| {
                    key.$key_method(&self, rhs.borrow())
                })
            }
        }
    }
);

// Scalar operations
macro_rules! short_int_impl_scalar_operation {
    ($trait_name:ident($trait_method:ident) => $key_method:ident) => {
        impl<P> $trait_name<u8> for &GenericShortInt<P>
        where
            P: ShortIntegerParameter,
            P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
        {
            type Output = GenericShortInt<P>;

            fn $trait_method(self, rhs: u8) -> Self::Output {
                self.id
                    .with_unwrapped_global(|key| key.$key_method(self, rhs))
            }
        }

        impl<P> $trait_name<u8> for GenericShortInt<P>
        where
            P: ShortIntegerParameter,
            P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
        {
            type Output = GenericShortInt<P>;

            fn $trait_method(self, rhs: u8) -> Self::Output {
                <&Self as $trait_name<u8>>::$trait_method(&self, rhs)
            }
        }

        impl<P> $trait_name<&GenericShortInt<P>> for u8
        where
            P: ShortIntegerParameter,
            P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
        {
            type Output = GenericShortInt<P>;

            fn $trait_method(self, rhs: &GenericShortInt<P>) -> Self::Output {
                <&GenericShortInt<P> as $trait_name<u8>>::$trait_method(rhs, self)
            }
        }

        impl<P> $trait_name<GenericShortInt<P>> for u8
        where
            P: ShortIntegerParameter,
            P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
        {
            type Output = GenericShortInt<P>;

            fn $trait_method(self, rhs: GenericShortInt<P>) -> Self::Output {
                <Self as $trait_name<&GenericShortInt<P>>>::$trait_method(self, &rhs)
            }
        }
    };
}

macro_rules! short_int_impl_scalar_operation_assign {
    ($trait_name:ident($trait_method:ident) => $key_method:ident) => {
        impl<P> $trait_name<u8> for GenericShortInt<P>
        where
            P: ShortIntegerParameter,
            P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
        {
            fn $trait_method(&mut self, rhs: u8) {
                self.id
                    .with_unwrapped_global(|key| key.$key_method(self, rhs))
            }
        }
    };
}

impl<P> Neg for GenericShortInt<P>
where
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.id.with_unwrapped_global(|key| key.neg(&self))
    }
}

impl<P> Neg for &GenericShortInt<P>
where
    P: ShortIntegerParameter,
    P::Id: WithGlobalKey<Key = GenericShortIntServerKey<P>>,
{
    type Output = GenericShortInt<P>;

    fn neg(self) -> Self::Output {
        self.id.with_unwrapped_global(|key| key.neg(self))
    }
}

short_int_impl_operation!(Add(add,+) => add);
short_int_impl_operation!(Sub(sub,-) => sub);
short_int_impl_operation!(Mul(mul,*) => mul);
short_int_impl_operation!(Div(div,/) => div);
short_int_impl_operation!(BitAnd(bitand,&) => bitand);
short_int_impl_operation!(BitOr(bitor,|) => bitor);
short_int_impl_operation!(BitXor(bitxor,^) => bitxor);

short_int_impl_operation_assign!(AddAssign(add_assign,+=) => add_assign);
short_int_impl_operation_assign!(SubAssign(sub_assign,-=) => sub_assign);
short_int_impl_operation_assign!(MulAssign(mul_assign,*=) => mul_assign);
short_int_impl_operation_assign!(DivAssign(div_assign,/=) => div_assign);
short_int_impl_operation_assign!(BitAndAssign(bitand_assign,&=) => bitand_assign);
short_int_impl_operation_assign!(BitOrAssign(bitor_assign,|=) => bitor_assign);
short_int_impl_operation_assign!(BitXorAssign(bitxor_assign,^=) => bitxor_assign);

short_int_impl_scalar_operation!(Add(add) => scalar_add);
short_int_impl_scalar_operation!(Sub(sub) => scalar_sub);
short_int_impl_scalar_operation!(Mul(mul) => scalar_mul);
short_int_impl_scalar_operation!(Div(div) => scalar_div);
short_int_impl_scalar_operation!(Rem(rem) => scalar_mod);
short_int_impl_scalar_operation!(Shl(shl) => scalar_left_shift);
short_int_impl_scalar_operation!(Shr(shr) => scalar_right_shift);

short_int_impl_scalar_operation_assign!(AddAssign(add_assign) => scalar_add_assign);
short_int_impl_scalar_operation_assign!(SubAssign(sub_assign) => scalar_sub_assign);
short_int_impl_scalar_operation_assign!(MulAssign(mul_assign) => scalar_mul_assign);
