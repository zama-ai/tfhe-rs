use std::borrow::Borrow;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::CastFrom;
use crate::high_level_api::global_state::WithGlobalKey;
use crate::high_level_api::integers::parameters::IntegerId;
use crate::high_level_api::integers::IntegerServerKey;
use crate::high_level_api::internal_traits::{DecryptionKey, EncryptionKey};
use crate::high_level_api::keys::CompressedPublicKey;
use crate::high_level_api::traits::{
    DivRem, FheBootstrap, FheDecrypt, FheEq, FheMax, FheMin, FheOrd, FheTrivialEncrypt,
    FheTryEncrypt, FheTryTrivialEncrypt, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
use crate::high_level_api::{ClientKey, PublicKey};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{IntegerRadixCiphertext, RadixCiphertext};
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::integer::{IntegerCiphertext, SignedRadixCiphertext, I256, U256};
use crate::named::Named;
use crate::{CompactPublicKey, FheBool};

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

/// A Generic FHE unsigned integer
///
/// This struct is generic over some Id, as its the Id
/// that controls how many bit they represent.
///
/// You will need to use one of this type specialization (e.g., [FheUint8], [FheUint12],
/// [FheUint16]).
///
/// Its the type that overloads the operators (`+`, `-`, `*`),
/// since the `GenericInteger` type is not `Copy` the operators are also overloaded
/// to work with references.
///
/// [FheUint8]: crate::high_level_api::FheUint8
/// [FheUint12]: crate::high_level_api::FheUint12
/// [FheUint16]: crate::high_level_api::FheUint16
#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericInteger<Id: IntegerId> {
    pub(in crate::high_level_api) ciphertext: Id::InnerCiphertext,
    pub(in crate::high_level_api::integers) id: Id,
}

impl<Id: IntegerId> ParameterSetConformant for GenericInteger<Id>
where
    Id::InnerCiphertext: ParameterSetConformant<ParameterSet = RadixCiphertextConformanceParams>,
{
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.ciphertext.is_conformant(params)
    }
}

impl<Id: IntegerId> Named for GenericInteger<Id> {
    const NAME: &'static str = "high_level_api::GenericInteger";
}

impl<Id> GenericInteger<Id>
where
    Id: IntegerId,
{
    pub(in crate::high_level_api) fn new(ciphertext: Id::InnerCiphertext, id: Id) -> Self {
        Self { ciphertext, id }
    }

    pub fn abs(&self) -> Self {
        let ciphertext = crate::high_level_api::global_state::with_internal_keys(|keys| {
            keys.integer_key
                .pbs_key()
                .abs_parallelized(&self.ciphertext)
        });

        Self::new(ciphertext, self.id)
    }
}

impl<FromId, IntoId> CastFrom<GenericInteger<FromId>> for GenericInteger<IntoId>
where
    FromId: IntegerId,
    IntoId: IntegerId,
{
    fn cast_from(input: GenericInteger<FromId>) -> Self {
        crate::high_level_api::global_state::with_internal_keys(|keys| {
            let integer_key = keys.integer_key.pbs_key();
            let current_num_blocks = FromId::num_blocks();
            let target_num_blocks = IntoId::num_blocks();

            let blocks = if FromId::InnerCiphertext::IS_SIGNED {
                if target_num_blocks > current_num_blocks {
                    let mut ct_as_signed_radix =
                        SignedRadixCiphertext::from_blocks(input.ciphertext.into_blocks());
                    let num_blocks_to_add = target_num_blocks - current_num_blocks;
                    integer_key.extend_radix_with_sign_msb_assign(
                        &mut ct_as_signed_radix,
                        num_blocks_to_add,
                    );
                    ct_as_signed_radix.blocks
                } else {
                    let mut ct_as_unsigned_radix =
                        RadixCiphertext::from_blocks(input.ciphertext.into_blocks());
                    let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                    integer_key.trim_radix_blocks_msb_assign(
                        &mut ct_as_unsigned_radix,
                        num_blocks_to_remove,
                    );
                    ct_as_unsigned_radix.blocks
                }
            } else {
                let mut ct_as_unsigned_radix =
                    RadixCiphertext::from_blocks(input.ciphertext.into_blocks());
                if target_num_blocks > current_num_blocks {
                    let num_blocks_to_add = target_num_blocks - current_num_blocks;
                    integer_key.extend_radix_with_trivial_zero_blocks_msb_assign(
                        &mut ct_as_unsigned_radix,
                        num_blocks_to_add,
                    );
                } else {
                    let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                    integer_key.trim_radix_blocks_msb_assign(
                        &mut ct_as_unsigned_radix,
                        num_blocks_to_remove,
                    );
                }
                ct_as_unsigned_radix.blocks
            };

            assert_eq!(
                blocks.len(),
                IntoId::num_blocks(),
                "internal error, wrong number of blocks after casting"
            );
            let new_ciphertext = IntoId::InnerCiphertext::from_blocks(blocks);
            Self::new(new_ciphertext, IntoId::default())
        })
    }
}

impl<Id> CastFrom<FheBool> for GenericInteger<Id>
where
    Id: IntegerId,
{
    fn cast_from(input: FheBool) -> Self {
        let ciphertext = crate::high_level_api::global_state::with_internal_keys(|keys| {
            input
                .ciphertext
                .into_radix(Id::num_blocks(), keys.integer_key.pbs_key())
        });

        Self::new(ciphertext, Id::default())
    }
}

impl<Id> TryFrom<RadixCiphertext> for GenericInteger<Id>
where
    Id: IntegerId<InnerCiphertext = RadixCiphertext> + WithGlobalKey<Key = IntegerServerKey>,
{
    type Error = GenericIntegerBlockError;
    fn try_from(other: RadixCiphertext) -> Result<Self, GenericIntegerBlockError> {
        // Check number of blocks
        if other.blocks.len() != Id::num_blocks() {
            return Err(GenericIntegerBlockError::NumberOfBlocks(
                Id::num_blocks(),
                other.blocks.len(),
            ));
        }

        // Get correct carry modulus and message modulus from ServerKey
        let id = Id::default();
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

        Ok(Self::new(other, Id::default()))
    }
}

impl<Id, T> TryFrom<Vec<T>> for GenericInteger<Id>
where
    Id: IntegerId<InnerCiphertext = RadixCiphertext> + WithGlobalKey<Key = IntegerServerKey>,
    Id::InnerCiphertext: From<Vec<T>>,
{
    type Error = GenericIntegerBlockError;
    fn try_from(blocks: Vec<T>) -> Result<Self, GenericIntegerBlockError> {
        let ciphertext = Id::InnerCiphertext::from(blocks);
        Self::try_from(ciphertext)
    }
}

impl<Id, ClearType> FheDecrypt<ClearType> for GenericInteger<Id>
where
    Id: IntegerId,
    crate::integer::ClientKey: DecryptionKey<Id::InnerCiphertext, ClearType>,
{
    fn decrypt(&self, key: &ClientKey) -> ClearType {
        let key = &key.key.key;
        key.decrypt(&self.ciphertext)
    }
}

impl<Id, T> FheTryEncrypt<T, ClientKey> for GenericInteger<Id>
where
    Id: IntegerId,
    crate::integer::ClientKey: EncryptionKey<(T, usize), Id::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = Id::default();

        let integer_client_key = &key.key.key;
        let ciphertext = <crate::integer::ClientKey as EncryptionKey<_, _>>::encrypt(
            integer_client_key,
            (value, Id::num_blocks()),
        );
        Ok(Self::new(ciphertext, id))
    }
}

impl<Id, T> FheTryEncrypt<T, PublicKey> for GenericInteger<Id>
where
    Id: IntegerId,
    crate::integer::PublicKey: EncryptionKey<(T, usize), Id::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &PublicKey) -> Result<Self, Self::Error> {
        let id = Id::default();
        let integer_public_key = &key.key;
        let ciphertext = <crate::integer::PublicKey as EncryptionKey<_, _>>::encrypt(
            integer_public_key,
            (value, Id::num_blocks()),
        );
        Ok(Self::new(ciphertext, id))
    }
}

impl<Id, T> FheTryEncrypt<T, CompressedPublicKey> for GenericInteger<Id>
where
    Id: IntegerId,
    crate::integer::CompressedPublicKey: EncryptionKey<(T, usize), Id::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let id = Id::default();
        let integer_public_key = &key.key;
        let ciphertext = <crate::integer::CompressedPublicKey as EncryptionKey<_, _>>::encrypt(
            integer_public_key,
            (value, Id::num_blocks()),
        );
        Ok(Self::new(ciphertext, id))
    }
}

impl<Id, T> FheTryEncrypt<T, CompactPublicKey> for GenericInteger<Id>
where
    Id: IntegerId,
    crate::integer::public_key::CompactPublicKey: EncryptionKey<(T, usize), Id::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = Id::default();
        let integer_public_key = &key.key.key;
        let ciphertext =
            <crate::integer::public_key::CompactPublicKey as EncryptionKey<_, _>>::encrypt(
                integer_public_key,
                (value, Id::num_blocks()),
            );
        Ok(Self::new(ciphertext, id))
    }
}

impl<Id, T> FheTryTrivialEncrypt<T> for GenericInteger<Id>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt_trivial(value: T) -> Result<Self, Self::Error> {
        let id = Id::default();
        let ciphertext: Id::InnerCiphertext = id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .create_trivial_radix(value, Id::num_blocks())
        });
        Ok(Self::new(ciphertext, id))
    }
}

impl<Id, T> FheTrivialEncrypt<T> for GenericInteger<Id>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
{
    #[track_caller]
    fn encrypt_trivial(value: T) -> Self {
        Self::try_encrypt_trivial(value).unwrap()
    }
}

impl<Id> FheMax<&Self> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Self: Clone,
{
    type Output = Self;

    fn max(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .max_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }
}

impl<Id, Clear> FheMax<Clear> for GenericInteger<Id>
where
    Clear: DecomposableInto<u64>,
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Self: Clone,
{
    type Output = Self;

    fn max(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_max_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result, self.id)
    }
}

impl<Id> FheMin<&Self> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Self: Clone,
{
    type Output = Self;

    fn min(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .min_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }
}

impl<Id, Clear> FheMin<Clear> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Clear: DecomposableInto<u64>,
    Self: Clone,
{
    type Output = Self;

    fn min(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_min_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result, self.id)
    }
}

impl<Id> FheEq<Self> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Self: Clone,
{
    fn eq(&self, rhs: Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.eq_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    fn ne(&self, rhs: Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.ne_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }
}

impl<Id> FheEq<&Self> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Self: Clone,
{
    fn eq(&self, rhs: &Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.eq_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    fn ne(&self, rhs: &Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.ne_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }
}

impl<Id, Clear> FheEq<Clear> for GenericInteger<Id>
where
    Clear: DecomposableInto<u64>,
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Self: Clone,
{
    fn eq(&self, rhs: Clear) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.scalar_eq_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    fn ne(&self, rhs: Clear) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.scalar_ne_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }
}

impl<Id> FheOrd<Self> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Self: Clone,
{
    fn lt(&self, rhs: Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.lt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    fn le(&self, rhs: Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.le_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    fn gt(&self, rhs: Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.gt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    fn ge(&self, rhs: Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.ge_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }
}

impl<Id> FheOrd<&Self> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Self: Clone,
{
    fn lt(&self, rhs: &Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.lt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    fn le(&self, rhs: &Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.le_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    fn gt(&self, rhs: &Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.gt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }

    fn ge(&self, rhs: &Self) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.ge_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        FheBool::new(inner_result)
    }
}

impl<Id, Clear> FheOrd<Clear> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
    Clear: DecomposableInto<u64>,
    Self: Clone,
{
    fn lt(&self, rhs: Clear) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.scalar_lt_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    fn le(&self, rhs: Clear) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.scalar_le_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    fn gt(&self, rhs: Clear) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.scalar_gt_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }

    fn ge(&self, rhs: Clear) -> FheBool {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            let pbs_key = integer_key.pbs_key();
            pbs_key.scalar_ge_parallelized(&self.ciphertext, rhs)
        });
        FheBool::new(inner_result)
    }
}

impl<Id> FheBootstrap for GenericInteger<Id>
where
    Id: IntegerId<InnerCiphertext = RadixCiphertext> + WithGlobalKey<Key = IntegerServerKey>,
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
                .expect("Function evaluation on integers was not enabled in the config")
                .apply_wopbs(integer_key.pbs_key(), &self.ciphertext, func);
            Self::new(res, self.id)
        })
    }

    fn apply<F: Fn(u64) -> u64>(&mut self, func: F) {
        let result = self.map(func);
        *self = result;
    }
}

impl<Id> GenericInteger<Id>
where
    Id: IntegerId<InnerCiphertext = RadixCiphertext> + WithGlobalKey<Key = IntegerServerKey>,
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
                .expect("Function evaluation on integers was not enabled in the config")
                .apply_bivariate_wopbs(integer_key.pbs_key(), lhs, rhs, func);
            Self::new(res, self.id)
        })
    }
}

impl<Id> DivRem<Self> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: Self) -> Self::Output {
        <Self as DivRem<&Self>>::div_rem(self, &rhs)
    }
}

impl<Id> DivRem<&Self> for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: &Self) -> Self::Output {
        <&Self as DivRem<&Self>>::div_rem(&self, rhs)
    }
}

impl<Id> DivRem<Self> for &GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (GenericInteger<Id>, GenericInteger<Id>);

    fn div_rem(self, rhs: Self) -> Self::Output {
        let (q, r) = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .div_rem_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        (
            GenericInteger::<Id>::new(q, self.id),
            GenericInteger::<Id>::new(r, self.id),
        )
    }
}

// Shifts and rotations are special cases where the right hand side
// is for now, required to be a unsigned integer type.
// And its constraints are a bit relaxed: rhs does not needs to have the same
// amount a bits.
macro_rules! generic_integer_impl_shift_rotate (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {

        // a op b
        impl<Id, Id2> $rust_trait_name<GenericInteger<Id2>> for GenericInteger<Id>
        where
            Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
            Id2: IntegerId<InnerCiphertext=RadixCiphertext>,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: GenericInteger<Id2>) -> Self::Output {
                <&Self as $rust_trait_name<&GenericInteger<Id2>>>::$rust_trait_method(&self, &rhs)
            }

        }

        // a op &b
        impl<Id, Id2> $rust_trait_name<&GenericInteger<Id2>> for GenericInteger<Id>
        where
            Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
            Id2: IntegerId<InnerCiphertext=RadixCiphertext>,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: &GenericInteger<Id2>) -> Self::Output {
                <&Self as $rust_trait_name<&GenericInteger<Id2>>>::$rust_trait_method(&self, rhs)
            }

        }

        // &a op b
        impl<Id, Id2> $rust_trait_name<GenericInteger<Id2>> for &GenericInteger<Id>
        where
            Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
            Id2: IntegerId<InnerCiphertext=RadixCiphertext>,
        {
            type Output = GenericInteger<Id>;

            fn $rust_trait_method(self, rhs: GenericInteger<Id2>) -> Self::Output {
                <Self as $rust_trait_name<&GenericInteger<Id2>>>::$rust_trait_method(self, &rhs)
            }
        }

        // &a op &b
        impl<Id, Id2> $rust_trait_name<&GenericInteger<Id2>> for &GenericInteger<Id>
        where
            Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
            Id2: IntegerId<InnerCiphertext=RadixCiphertext>,
        {
            type Output = GenericInteger<Id>;

            fn $rust_trait_method(self, rhs: &GenericInteger<Id2>) -> Self::Output {
                let ciphertext = self.id.with_unwrapped_global(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&self.ciphertext, &rhs.ciphertext)
                });
                GenericInteger::<Id>::new(ciphertext, self.id)
            }
        }
    }
);

macro_rules! generic_integer_impl_shift_rotate_assign(
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {
        // a op= b
        impl<Id, Id2> $rust_trait_name<GenericInteger<Id2>> for GenericInteger<Id>
        where
            Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
            Id2: IntegerId<InnerCiphertext=RadixCiphertext>,
        {
            fn $rust_trait_method(&mut self, rhs: GenericInteger<Id2>) {
                <Self as $rust_trait_name<&GenericInteger<Id2>>>::$rust_trait_method(self, &rhs)
            }
        }

        // a op= &b
        impl<Id, Id2> $rust_trait_name<&GenericInteger<Id2>> for GenericInteger<Id>
        where
            Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
            Id2: IntegerId<InnerCiphertext=RadixCiphertext>,
        {
            fn $rust_trait_method(&mut self, rhs: &GenericInteger<Id2>) {
                self.id.with_unwrapped_global(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&mut self.ciphertext, &rhs.ciphertext)
                })
            }
        }
    }
);

macro_rules! generic_integer_impl_operation (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {

        impl<Id, B> $rust_trait_name<B> for GenericInteger<Id>
        where
            Id: IntegerId +  WithGlobalKey<Key = IntegerServerKey>,
            B: Borrow<Self>,
            GenericInteger<Id>: Clone,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                <&Self as $rust_trait_name<B>>::$rust_trait_method(&self, rhs)
            }

        }

        impl<Id, B> $rust_trait_name<B> for &GenericInteger<Id>
        where
            Id: IntegerId +  WithGlobalKey<Key = IntegerServerKey>,
            B: Borrow<GenericInteger<Id>>,
            GenericInteger<Id>: Clone,
        {
            type Output = GenericInteger<Id>;

            fn $rust_trait_method(self, rhs: B) -> Self::Output {
                let ciphertext = self.id.with_unwrapped_global(|integer_key| {
                    let borrowed = rhs.borrow();
                    integer_key
                        .pbs_key()
                        .$key_method(&self.ciphertext, &borrowed.ciphertext)
                });
                GenericInteger::<Id>::new(ciphertext, self.id)
            }
        }
    }
);

macro_rules! generic_integer_impl_operation_assign (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {
        impl<Id, I> $rust_trait_name<I> for GenericInteger<Id>
        where
            Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
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

// DivRem is a bit special as it returns a tuple of quotient and remainder
macro_rules! generic_integer_impl_scalar_div_rem {
    (
        key_method: $key_method:ident,
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($scalar_type:ty),*)
        ),*
        $(,)?
    ) => {
        $( // First repeating pattern
            $( // Second repeating pattern
                impl DivRem<$scalar_type> for $concrete_type
                {
                    type Output = ($concrete_type, $concrete_type);

                    fn div_rem(self, rhs: $scalar_type) -> Self::Output {
                        <&Self as DivRem<$scalar_type>>::div_rem(&self, rhs)
                    }
                }

                impl DivRem<$scalar_type> for &$concrete_type
                {
                    type Output = ($concrete_type, $concrete_type);

                    fn div_rem(self, rhs: $scalar_type) -> Self::Output {
                        let (q, r) =
                            self.id.with_unwrapped_global(|integer_key| {
                                integer_key.pbs_key().$key_method(&self.ciphertext, rhs)
                            });

                        (
                            <$concrete_type>::new(q, self.id),
                            <$concrete_type>::new(r, self.id)
                        )
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}
generic_integer_impl_scalar_div_rem!(
    key_method: scalar_div_rem_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_div_rem!(
    key_method: signed_scalar_div_rem_parallelized,
    fhe_and_scalar_type:
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);

macro_rules! generic_integer_impl_scalar_operation {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        key_method: $key_method:ident,
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($scalar_type:ty),*)
        ),*
        $(,)?
    ) => {
        $( // First repeating pattern
            $( // Second repeating pattern
                impl $rust_trait_name<$scalar_type> for $concrete_type
                {
                    type Output = $concrete_type;

                    fn $rust_trait_method(self, rhs: $scalar_type) -> Self::Output {
                        <&Self as $rust_trait_name<$scalar_type>>::$rust_trait_method(&self, rhs)
                    }
                }

                impl $rust_trait_name<$scalar_type> for &$concrete_type
                {
                    type Output = $concrete_type;

                    fn $rust_trait_method(self, rhs: $scalar_type) -> Self::Output {
                        let ciphertext =
                            self.id.with_unwrapped_global(|integer_key| {
                                integer_key.pbs_key().$key_method(&self.ciphertext, rhs)
                            });

                        <$concrete_type>::new(ciphertext, self.id)
                    }
                }
            )* // Closing second repeating pattern
        )* // Closing first repeating pattern
    };
}

macro_rules! generic_integer_impl_scalar_operation_assign {
    (
        rust_trait: $rust_trait_name:ident($rust_trait_method:ident),
        key_method: $key_method:ident,
        // A 'list' of tuple, where the first element is the concrete Fhe type
        // e.g (FheUint8 and the rest is scalar types (u8, u16, etc)
        fhe_and_scalar_type: $(
            ($concrete_type:ty, $($scalar_type:ty),*)
        ),*
        $(,)?
    ) => {
        $(
            $(
                impl $rust_trait_name<$scalar_type> for $concrete_type
                {
                    fn $rust_trait_method(&mut self, rhs: $scalar_type) {
                        self.id.with_unwrapped_global(|integer_key| {
                            integer_key.pbs_key().$key_method(&mut self.ciphertext, rhs);
                        })
                    }
                }
            )*
        )*
    }
}

generic_integer_impl_operation!(Add(add) => add_parallelized);
generic_integer_impl_operation!(Sub(sub) => sub_parallelized);
generic_integer_impl_operation!(Mul(mul) => mul_parallelized);
generic_integer_impl_operation!(BitAnd(bitand) => bitand_parallelized);
generic_integer_impl_operation!(BitOr(bitor) => bitor_parallelized);
generic_integer_impl_operation!(BitXor(bitxor) => bitxor_parallelized);
generic_integer_impl_operation!(Div(div) => div_parallelized);
generic_integer_impl_operation!(Rem(rem) => rem_parallelized);
generic_integer_impl_shift_rotate!(Shl(shl) => left_shift_parallelized);
generic_integer_impl_shift_rotate!(Shr(shr) => right_shift_parallelized);
generic_integer_impl_shift_rotate!(RotateLeft(rotate_left) => rotate_left_parallelized);
generic_integer_impl_shift_rotate!(RotateRight(rotate_right) => rotate_right_parallelized);
// assign operations
generic_integer_impl_operation_assign!(AddAssign(add_assign) => add_assign_parallelized);
generic_integer_impl_operation_assign!(SubAssign(sub_assign) => sub_assign_parallelized);
generic_integer_impl_operation_assign!(MulAssign(mul_assign) => mul_assign_parallelized);
generic_integer_impl_operation_assign!(BitAndAssign(bitand_assign) => bitand_assign_parallelized);
generic_integer_impl_operation_assign!(BitOrAssign(bitor_assign) => bitor_assign_parallelized);
generic_integer_impl_operation_assign!(BitXorAssign(bitxor_assign) => bitxor_assign_parallelized);
generic_integer_impl_operation_assign!(DivAssign(div_assign) => div_assign_parallelized);
generic_integer_impl_operation_assign!(RemAssign(rem_assign) => rem_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(ShlAssign(shl_assign) => left_shift_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(ShrAssign(shr_assign) => right_shift_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(RotateLeftAssign(rotate_left_assign) => rotate_left_assign_parallelized);
generic_integer_impl_shift_rotate_assign!(RotateRightAssign(rotate_right_assign) => rotate_right_assign_parallelized);

generic_integer_impl_scalar_operation!(
    rust_trait: Add(add),
    key_method: scalar_add_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Sub(sub),
    key_method: scalar_sub_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Mul(mul),
    key_method: scalar_mul_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: BitAnd(bitand),
    key_method: scalar_bitand_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: BitOr(bitor),
    key_method: scalar_bitor_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: BitXor(bitxor),
    key_method: scalar_bitxor_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Shl(shl),
    key_method: scalar_left_shift_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Shr(shr),
    key_method: scalar_right_shift_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: RotateLeft(rotate_left),
    key_method: scalar_rotate_left_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: RotateRight(rotate_right),
    key_method: scalar_rotate_right_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Div(div),
    key_method: scalar_div_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Rem(rem),
    key_method: scalar_rem_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Div(div),
    key_method: signed_scalar_div_parallelized,
    fhe_and_scalar_type:
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation!(
    rust_trait: Rem(rem),
    key_method: signed_scalar_rem_parallelized,
    fhe_and_scalar_type:
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
// Scalar assign ops
generic_integer_impl_scalar_operation_assign!(
    rust_trait: AddAssign(add_assign),
    key_method: scalar_add_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: SubAssign(sub_assign),
    key_method: scalar_sub_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: MulAssign(mul_assign),
    key_method: scalar_mul_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: BitAndAssign(bitand_assign),
    key_method: scalar_bitand_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: BitOrAssign(bitor_assign),
    key_method: scalar_bitor_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: BitXorAssign(bitxor_assign),
    key_method: scalar_bitxor_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: ShlAssign(shl_assign),
    key_method: scalar_left_shift_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: ShrAssign(shr_assign),
    key_method: scalar_right_shift_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RotateLeftAssign(rotate_left_assign),
    key_method: scalar_rotate_left_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RotateRightAssign(rotate_right_assign),
    key_method: scalar_rotate_right_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8, u16, u32, u64, u128),
        (super::FheUint10, u8, u16, u32, u64, u128),
        (super::FheUint12, u8, u16, u32, u64, u128),
        (super::FheUint14, u8, u16, u32, u64, u128),
        (super::FheUint16, u8, u16, u32, u64, u128),
        (super::FheUint32, u8, u16, u32, u64, u128),
        (super::FheUint64, u8, u16, u32, u64, u128),
        (super::FheUint128, u8, u16, u32, u64, u128),
        (super::FheUint256, u8, u16, u32, u64, u128, U256),
        (super::FheInt8, u8, u16, u32, u64, u128),
        (super::FheInt16, u8, u16, u32, u64, u128),
        (super::FheInt32, u8, u16, u32, u64, u128),
        (super::FheInt64, u8, u16, u32, u64, u128),
        (super::FheInt128, u8, u16, u32, u64, u128),
        (super::FheInt256, u8, u16, u32, u64, u128, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: DivAssign(div_assign),
    key_method: scalar_div_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RemAssign(rem_assign),
    key_method: scalar_rem_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheUint8, u8),
        (super::FheUint10, u16),
        (super::FheUint12, u16),
        (super::FheUint14, u16),
        (super::FheUint16, u16),
        (super::FheUint32, u32),
        (super::FheUint64, u64),
        (super::FheUint128, u128),
        (super::FheUint256, U256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: DivAssign(div_assign),
    key_method: signed_scalar_div_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);
generic_integer_impl_scalar_operation_assign!(
    rust_trait: RemAssign(rem_assign),
    key_method: signed_scalar_rem_assign_parallelized,
    fhe_and_scalar_type:
        (super::FheInt8, i8),
        (super::FheInt16, i16),
        (super::FheInt32, i32),
        (super::FheInt64, i64),
        (super::FheInt128, i128),
        (super::FheInt256, I256),
);

impl<Id> Neg for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        <&Self as Neg>::neg(&self)
    }
}

impl<Id> Neg for &GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = GenericInteger<Id>;

    fn neg(self) -> Self::Output {
        let ciphertext = self.id.with_unwrapped_global(|integer_key| {
            integer_key.pbs_key().neg_parallelized(&self.ciphertext)
        });
        GenericInteger::new(ciphertext, self.id)
    }
}

impl<Id> Not for GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn not(self) -> Self::Output {
        <&Self as Not>::not(&self)
    }
}

impl<Id> Not for &GenericInteger<Id>
where
    Id: IntegerId + WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = GenericInteger<Id>;

    fn not(self) -> Self::Output {
        let ciphertext = self.id.with_unwrapped_global(|integer_key| {
            integer_key.pbs_key().bitnot_parallelized(&self.ciphertext)
        });
        GenericInteger::<Id>::new(ciphertext, self.id)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::conformance::ParameterSetConformant;
    use crate::core_crypto::prelude::UnsignedInteger;
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

        assert!(
            ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                4
            ))
        );

        let breaker_lists = [
            change_parameters(&|i, ct: &mut Ct| &mut ct.ciphertext.blocks[i].message_modulus.0),
            change_parameters(&|i, ct: &mut Ct| &mut ct.ciphertext.blocks[i].carry_modulus.0),
            change_parameters(&|i, ct: &mut Ct| ct.ciphertext.blocks[i].degree.as_mut()),
        ];

        for breaker_list in breaker_lists {
            for breaker in breaker_list {
                for i in 0..ct.ciphertext.blocks.len() {
                    let mut ct_clone = ct.clone();

                    breaker(i, &mut ct_clone);

                    assert!(!ct_clone.is_conformant(
                        &RadixCiphertextConformanceParams::from_pbs_parameters(
                            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                            4
                        )
                    ));
                }
            }
        }
        let breakers2: Vec<&IndexedParameterModifier<'_, Ct>> = vec![
            &|i, ct: &mut Ct| {
                *ct.ciphertext.blocks[i].ct.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new_power_of_2(1).unwrap();
            },
            &|i, ct: &mut Ct| {
                *ct.ciphertext.blocks[i].ct.get_mut_ciphertext_modulus() =
                    CiphertextModulus::try_new(3).unwrap();
            },
            &|_i, ct: &mut Ct| {
                ct.ciphertext.blocks.pop();
            },
            &|i, ct: &mut Ct| {
                ct.ciphertext.blocks.push(ct.ciphertext.blocks[i].clone());
            },
            &|i, ct: &mut Ct| {
                ct.ciphertext.blocks[i].pbs_order = PBSOrder::BootstrapKeyswitch;
            },
        ];

        for breaker in breakers2 {
            for i in 0..ct.ciphertext.blocks.len() {
                let mut ct_clone = ct.clone();

                breaker(i, &mut ct_clone);

                assert!(!ct_clone.is_conformant(
                    &RadixCiphertextConformanceParams::from_pbs_parameters(
                        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                        4
                    )
                ));
            }
        }
    }

    #[test]
    fn test_valid_generic_integer() {
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config);

        set_server_key(server_key);

        let ct = FheUint8::try_encrypt(0_u64, &client_key).unwrap();

        assert!(
            ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                4
            ))
        );

        let mut rng = thread_rng();

        let num_blocks = ct.ciphertext.blocks.len();

        for _ in 0..10 {
            let mut ct_clone = ct.clone();

            for i in 0..num_blocks {
                ct_clone.ciphertext.blocks[i]
                    .ct
                    .as_mut()
                    .fill_with(|| rng.gen::<u64>());
            }

            assert!(ct_clone.is_conformant(
                &RadixCiphertextConformanceParams::from_pbs_parameters(
                    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                    4
                )
            ));

            ct_clone += &ct_clone.clone();
        }
    }
}
