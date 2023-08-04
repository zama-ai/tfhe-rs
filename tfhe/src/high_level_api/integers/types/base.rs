use std::borrow::Borrow;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::core_crypto::prelude::UnsignedNumeric;
use crate::errors::{
    UninitializedClientKey, UninitializedCompressedPublicKey, UninitializedPublicKey,
    UnwrapResultExt,
};
use crate::high_level_api::global_state::WithGlobalKey;
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::IntegerServerKey;
use crate::high_level_api::internal_traits::{DecryptionKey, TypeIdentifier};
use crate::high_level_api::keys::{CompressedPublicKey, RefKeyFromKeyChain};
use crate::high_level_api::traits::{
    DivRem, FheBootstrap, FheDecrypt, FheEq, FheMax, FheMin, FheOrd, FheTrivialEncrypt,
    FheTryEncrypt, FheTryTrivialEncrypt, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
use crate::high_level_api::{ClientKey, PublicKey};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::{Reciprocable, ScalarMultiplier};
use crate::integer::U256;
use crate::CompactPublicKey;

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
            GenericIntegerBlockError::NumberOfBlocks(correct, incorrect) => write!(
                f,
                "Wrong number of blocks for creating 
                    a GenericInteger: should have been {}, but 
                    was {} instead",
                correct, incorrect
            ),
            GenericIntegerBlockError::CarryModulus(correct, incorrect) => write!(
                f,
                "Wrong carry modulus for creating 
                    a GenericInteger: should have been {:?}, but 
                    was {:?} instead",
                correct, incorrect
            ),
            GenericIntegerBlockError::MessageModulus(correct, incorrect) => write!(
                f,
                "Wrong message modulus for creating 
                    a GenericInteger: should have been {:?}, but 
                    was {:?} instead",
                correct, incorrect
            ),
        }
    }
}

#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericInteger<P: IntegerParameter> {
    pub(in crate::high_level_api::integers) ciphertext: RadixCiphertext,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::high_level_api::integers) fn new(ciphertext: RadixCiphertext, id: P::Id) -> Self {
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
                integer_key.extend_radix_with_trivial_zero_blocks_msb_assign(
                    &mut self.ciphertext,
                    num_blocks_to_add,
                );
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                integer_key
                    .trim_radix_blocks_msb_assign(&mut self.ciphertext, num_blocks_to_remove);
            }
            GenericInteger::<P2>::new(self.ciphertext, P2::Id::default())
        })
    }
}

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    pub fn if_then_else(&self, ct_then: &Self, ct_else: &Self) -> GenericInteger<P> {
        let ct_condition = self;
        let new_ct = ct_condition.id.with_unwrapped_global(|integer_key| {
            integer_key.pbs_key().if_then_else_parallelized(
                &ct_condition.ciphertext,
                &ct_then.ciphertext,
                &ct_else.ciphertext,
            )
        });

        GenericInteger::new(new_ct, ct_condition.id)
    }
}

impl<P> TryFrom<RadixCiphertext> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default + WithGlobalKey<Key = IntegerServerKey>,
{
    type Error = GenericIntegerBlockError;
    fn try_from(other: RadixCiphertext) -> Result<GenericInteger<P>, GenericIntegerBlockError> {
        // Check number of blocks
        if other.blocks.len() != P::num_blocks() {
            return Err(GenericIntegerBlockError::NumberOfBlocks(
                P::num_blocks(),
                other.blocks.len(),
            ));
        }

        // Get correct carry modulus and message modulus from ServerKey
        let id = P::Id::default();
        let (correct_carry_mod, correct_message_mod) = id.with_unwrapped_global(|integer_key| {
            (
                integer_key.pbs_key().key.carry_modulus,
                integer_key.pbs_key().key.message_modulus,
            )
        });

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

        Ok(GenericInteger::new(other, P::Id::default()))
    }
}

impl<P, T> TryFrom<Vec<T>> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default + WithGlobalKey<Key = IntegerServerKey>,
    RadixCiphertext: From<Vec<T>>,
{
    type Error = GenericIntegerBlockError;
    fn try_from(blocks: Vec<T>) -> Result<GenericInteger<P>, GenericIntegerBlockError> {
        GenericInteger::try_from(RadixCiphertext::from(blocks))
    }
}

impl<P, ClearType> FheDecrypt<ClearType> for GenericInteger<P>
where
    ClearType: crate::integer::block_decomposition::RecomposableFrom<u64>,
    P: IntegerParameter,
    P::Id: RefKeyFromKeyChain<Key = crate::integer::ClientKey>,
    crate::integer::ClientKey: DecryptionKey<RadixCiphertext, ClearType>,
{
    fn decrypt(&self, key: &ClientKey) -> ClearType {
        let key = self.id.unwrapped_ref_key(key);
        key.decrypt(&self.ciphertext)
    }
}

impl<P, T> FheTryEncrypt<T, ClientKey> for GenericInteger<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64> + UnsignedNumeric,
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
        let ciphertext = integer_client_key.encrypt_radix(value, P::num_blocks());
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
        let ciphertext = integer_public_key.encrypt_radix(value, P::num_blocks());
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
        let ciphertext = integer_public_key.encrypt_radix(value, P::num_blocks());
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryEncrypt<T, CompactPublicKey> for GenericInteger<P>
where
    T: Into<U256>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let ciphertext = key
            .integer_key
            .try_encrypt(value, P::num_blocks())
            .ok_or(UninitializedPublicKey(id.type_variant()))
            .unwrap_display();
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
        let ciphertext = id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .create_trivial_radix(value, P::num_blocks())
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

impl<P> FheMax<&Self> for GenericInteger<P>
where
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn max(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .max_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P, Clear> FheMax<Clear> for GenericInteger<P>
where
    Clear: DecomposableInto<u64>,
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn max(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_max_parallelized(&self.ciphertext, rhs)
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P> FheMin<&Self> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
    GenericInteger<P>: Clone,
{
    type Output = Self;

    fn min(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .min_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P, Clear> FheMin<Clear> for GenericInteger<P>
where
    Clear: DecomposableInto<u64>,
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn min(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_min_parallelized(&self.ciphertext, rhs)
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P> FheEq<Self> for GenericInteger<P>
where
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn eq(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .eq_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn ne(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .ne_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P> FheEq<&Self> for GenericInteger<P>
where
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn eq(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .eq_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn ne(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .ne_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P, Clear> FheEq<Clear> for GenericInteger<P>
where
    Clear: DecomposableInto<u64>,
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn eq(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_eq_parallelized(&self.ciphertext, rhs)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn ne(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_ne_parallelized(&self.ciphertext, rhs)
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P> FheOrd<Self> for GenericInteger<P>
where
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn lt(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .lt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn le(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .le_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn gt(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .gt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn ge(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .ge_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P> FheOrd<&Self> for GenericInteger<P>
where
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn lt(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .lt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn le(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .le_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn gt(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .gt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn ge(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .ge_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        GenericInteger::new(inner_result, self.id)
    }
}

impl<P, Clear> FheOrd<Clear> for GenericInteger<P>
where
    Clear: DecomposableInto<u64>,
    P: IntegerParameter,
    GenericInteger<P>: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn lt(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_lt_parallelized(&self.ciphertext, rhs)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn le(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_le_parallelized(&self.ciphertext, rhs)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn gt(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_gt_parallelized(&self.ciphertext, rhs)
        });
        GenericInteger::new(inner_result, self.id)
    }

    fn ge(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_ge_parallelized(&self.ciphertext, rhs)
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
            RadixCiphertext,
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
            RadixCiphertext,
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

impl<P, Clear> DivRem<Clear> for GenericInteger<P>
where
    P: IntegerParameter,
    Clear: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: Clear) -> Self::Output {
        <&Self as DivRem<Clear>>::div_rem(&self, rhs)
    }
}

impl<P, Clear> DivRem<Clear> for &GenericInteger<P>
where
    P: IntegerParameter,
    Clear: Reciprocable + ScalarMultiplier + DecomposableInto<u8>,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (GenericInteger<P>, GenericInteger<P>);

    fn div_rem(self, rhs: Clear) -> Self::Output {
        let (q, r) = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_div_rem_parallelized(&self.ciphertext, rhs)
        });
        (
            GenericInteger::<P>::new(q, self.id),
            GenericInteger::<P>::new(r, self.id),
        )
    }
}

impl<P> DivRem<GenericInteger<P>> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (GenericInteger<P>, GenericInteger<P>);

    fn div_rem(self, rhs: GenericInteger<P>) -> Self::Output {
        <Self as DivRem<&GenericInteger<P>>>::div_rem(self, &rhs)
    }
}

impl<P> DivRem<&GenericInteger<P>> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (GenericInteger<P>, GenericInteger<P>);

    fn div_rem(self, rhs: &GenericInteger<P>) -> Self::Output {
        <&Self as DivRem<&GenericInteger<P>>>::div_rem(&self, rhs)
    }
}

impl<P> DivRem<GenericInteger<P>> for &GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (GenericInteger<P>, GenericInteger<P>);

    fn div_rem(self, rhs: GenericInteger<P>) -> Self::Output {
        <Self as DivRem<&GenericInteger<P>>>::div_rem(self, &rhs)
    }
}

impl<P> DivRem<&GenericInteger<P>> for &GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (GenericInteger<P>, GenericInteger<P>);

    fn div_rem(self, rhs: &GenericInteger<P>) -> Self::Output {
        let (q, r) = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .div_rem_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        (
            GenericInteger::<P>::new(q, self.id),
            GenericInteger::<P>::new(r, self.id),
        )
    }
}

macro_rules! generic_integer_impl_operation (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {

        impl<P, B> $rust_trait_name<B> for GenericInteger<P>
        where
            P: IntegerParameter,
            B: Borrow<Self>,
            GenericInteger<P>: Clone,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                <&Self as $rust_trait_name<B>>::$rust_trait_method(&self, rhs)
            }

        }

        impl<P, B> $rust_trait_name<B> for &GenericInteger<P>
        where
            P: IntegerParameter,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
            B: Borrow<GenericInteger<P>>,
            GenericInteger<P>: Clone,
        {
            type Output = GenericInteger<P>;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                let ciphertext = self.id.with_unwrapped_global(|integer_key| {
                    let borrowed = rhs.borrow();
                    integer_key
                        .pbs_key()
                        .$key_method(&self.ciphertext, &borrowed.ciphertext)
                });
                GenericInteger::<P>::new(ciphertext, self.id)
            }
        }
    }
);

macro_rules! generic_integer_impl_operation_assign (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {
        impl<P, I> $rust_trait_name<I> for GenericInteger<P>
        where
            P: IntegerParameter,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
            I: Borrow<Self>,
        {
            fn $rust_trait_method(&mut self, rhs: I) {
                self.id.with_unwrapped_global(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&mut self.ciphertext, &rhs.borrow().ciphertext)
                })
            }
        }
    }
);

macro_rules! generic_integer_impl_scalar_operation {
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident($($scalar_type:ty),*)) => {
        $(
            impl<P> $rust_trait_name<$scalar_type> for GenericInteger<P>
            where
                P: IntegerParameter,
                P::Id: WithGlobalKey<Key = IntegerServerKey>,
            {
                type Output = GenericInteger<P>;

                fn $rust_trait_method(self, rhs: $scalar_type) -> Self::Output {
                    <&Self as $rust_trait_name<$scalar_type>>::$rust_trait_method(&self, rhs)
                }
            }

            impl<P> $rust_trait_name<$scalar_type> for &GenericInteger<P>
            where
                P: IntegerParameter,
                P::Id: WithGlobalKey<Key = IntegerServerKey>,
            {
                type Output = GenericInteger<P>;

                fn $rust_trait_method(self, rhs: $scalar_type) -> Self::Output {
                    let ciphertext: RadixCiphertext =
                        self.id.with_unwrapped_global(|integer_key| {
                            integer_key.pbs_key().$key_method(&self.ciphertext, rhs)
                        });

                    GenericInteger::<P>::new(ciphertext, self.id)
                }
            }
        )*
    };
}

macro_rules! generic_integer_impl_scalar_operation_assign {
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident($($scalar_type:ty),*)) => {
        $(
            impl<P> $rust_trait_name<$scalar_type> for GenericInteger<P>
                where
                    P: IntegerParameter,
                    P::Id: WithGlobalKey<Key = IntegerServerKey>,
            {
                fn $rust_trait_method(&mut self, rhs: $scalar_type) {
                    self.id.with_unwrapped_global(|integer_key| {
                        integer_key.pbs_key().$key_method(&mut self.ciphertext, rhs);
                    })
                }
            }
        )*
    }
}

generic_integer_impl_operation!(Add(add) => add_parallelized);
generic_integer_impl_operation!(Sub(sub) => sub_parallelized);
generic_integer_impl_operation!(Mul(mul) => mul_parallelized);
generic_integer_impl_operation!(BitAnd(bitand) => bitand_parallelized);
generic_integer_impl_operation!(BitOr(bitor) => bitor_parallelized);
generic_integer_impl_operation!(BitXor(bitxor) => bitxor_parallelized);
generic_integer_impl_operation!(Shl(shl) => left_shift_parallelized);
generic_integer_impl_operation!(Shr(shr) => right_shift_parallelized);
generic_integer_impl_operation!(RotateLeft(rotate_left) => rotate_left_parallelized);
generic_integer_impl_operation!(RotateRight(rotate_right) => rotate_right_parallelized);
generic_integer_impl_operation!(Div(div) => div_parallelized);
generic_integer_impl_operation!(Rem(rem) => rem_parallelized);

generic_integer_impl_operation_assign!(AddAssign(add_assign) => add_assign_parallelized);
generic_integer_impl_operation_assign!(SubAssign(sub_assign) => sub_assign_parallelized);
generic_integer_impl_operation_assign!(MulAssign(mul_assign) => mul_assign_parallelized);
generic_integer_impl_operation_assign!(BitAndAssign(bitand_assign) => bitand_assign_parallelized);
generic_integer_impl_operation_assign!(BitOrAssign(bitor_assign) => bitor_assign_parallelized);
generic_integer_impl_operation_assign!(BitXorAssign(bitxor_assign) => bitxor_assign_parallelized);
generic_integer_impl_operation_assign!(ShlAssign(shl_assign) => left_shift_assign_parallelized);
generic_integer_impl_operation_assign!(ShrAssign(shr_assign) => right_shift_assign_parallelized);
generic_integer_impl_operation_assign!(RotateLeftAssign(rotate_left_assign) => rotate_left_assign_parallelized);
generic_integer_impl_operation_assign!(RotateRightAssign(rotate_right_assign) => rotate_right_assign_parallelized);
generic_integer_impl_operation_assign!(DivAssign(div_assign) => div_assign_parallelized);
generic_integer_impl_operation_assign!(RemAssign(rem_assign) => rem_assign_parallelized);

generic_integer_impl_scalar_operation!(Add(add) => scalar_add_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(Sub(sub) => scalar_sub_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(Mul(mul) => scalar_mul_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(BitAnd(bitand) => scalar_bitand_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(BitOr(bitor) => scalar_bitor_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(BitXor(bitxor) => scalar_bitxor_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(Shl(shl) => scalar_left_shift_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(Shr(shr) => scalar_right_shift_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(RotateLeft(rotate_left) => scalar_rotate_left_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(RotateRight(rotate_right) => scalar_rotate_right_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(Div(div) => scalar_div_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation!(Rem(rem) => scalar_rem_parallelized(u8, u16, u32, u64, u128, U256));

generic_integer_impl_scalar_operation_assign!(AddAssign(add_assign) => scalar_add_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(SubAssign(sub_assign) => scalar_sub_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(MulAssign(mul_assign) => scalar_mul_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(BitAndAssign(bitand_assign) => scalar_bitand_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(BitOrAssign(bitor_assign) => scalar_bitor_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(BitXorAssign(bitxor_assign) => scalar_bitxor_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(ShlAssign(shl_assign) => scalar_left_shift_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(ShrAssign(shr_assign) => scalar_right_shift_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(RotateLeftAssign(rotate_left_assign) => scalar_rotate_left_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(RotateRightAssign(rotate_right_assign) => scalar_rotate_right_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(DivAssign(div_assign) => scalar_div_assign_parallelized(u8, u16, u32, u64, u128, U256));
generic_integer_impl_scalar_operation_assign!(RemAssign(rem_assign) => scalar_rem_assign_parallelized(u8, u16, u32, u64, u128, U256));

impl<P> Neg for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
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
{
    type Output = GenericInteger<P>;

    fn neg(self) -> Self::Output {
        let ciphertext = self.id.with_unwrapped_global(|integer_key| {
            integer_key.pbs_key().neg_parallelized(&self.ciphertext)
        });
        GenericInteger::<P>::new(ciphertext, self.id)
    }
}

impl<P> Not for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = GenericInteger<P>;

    fn not(self) -> Self::Output {
        <&Self as Not>::not(&self)
    }
}

impl<P> Not for &GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = GenericInteger<P>;

    fn not(self) -> Self::Output {
        let ciphertext = self.id.with_unwrapped_global(|integer_key| {
            integer_key.pbs_key().bitnot_parallelized(&self.ciphertext)
        });
        GenericInteger::<P>::new(ciphertext, self.id)
    }
}
