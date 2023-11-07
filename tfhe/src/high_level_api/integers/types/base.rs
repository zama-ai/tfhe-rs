use std::borrow::Borrow;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::conformance::ParameterSetConformant;
use crate::high_level_api::global_state::WithGlobalKey;
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::IntegerServerKey;
use crate::high_level_api::internal_traits::{DecryptionKey, EncryptionKey, TypeIdentifier};
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
use crate::CompactPublicKey;

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
                    a GenericInteger: should have been {}, but 
                    was {} instead",
                correct, incorrect
            ),
            Self::CarryModulus(correct, incorrect) => write!(
                f,
                "Wrong carry modulus for creating 
                    a GenericInteger: should have been {:?}, but 
                    was {:?} instead",
                correct, incorrect
            ),
            Self::MessageModulus(correct, incorrect) => write!(
                f,
                "Wrong message modulus for creating 
                    a GenericInteger: should have been {:?}, but 
                    was {:?} instead",
                correct, incorrect
            ),
        }
    }
}

/// A Generic FHE unsigned integer
///
/// This struct is generic over some parameters, as its the parameters
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
pub struct GenericInteger<P: IntegerParameter> {
    pub(in crate::high_level_api::integers) ciphertext: P::InnerCiphertext,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P: IntegerParameter> ParameterSetConformant for GenericInteger<P>
where
    P::InnerCiphertext: ParameterSetConformant<ParameterSet = RadixCiphertextConformanceParams>,
{
    type ParameterSet = RadixCiphertextConformanceParams;
    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.ciphertext.is_conformant(params)
    }
}

impl<P: IntegerParameter> Named for GenericInteger<P> {
    const NAME: &'static str = "high_level_api::GenericInteger";
}

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
{
    pub(in crate::high_level_api::integers) fn new(
        ciphertext: P::InnerCiphertext,
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

    pub fn cast_into<P2>(self) -> GenericInteger<P2>
    where
        P2: IntegerParameter,
        P2::Id: Default,
    {
        crate::high_level_api::global_state::with_internal_keys(|keys| {
            let integer_key = keys.integer_key.pbs_key();
            let current_num_blocks = P::num_blocks();
            let target_num_blocks = P2::num_blocks();

            let blocks = if P::InnerCiphertext::IS_SIGNED {
                if target_num_blocks > current_num_blocks {
                    let mut ct_as_signed_radix =
                        SignedRadixCiphertext::from_blocks(self.ciphertext.into_blocks());
                    let num_blocks_to_add = target_num_blocks - current_num_blocks;
                    integer_key.extend_radix_with_sign_msb_assign(
                        &mut ct_as_signed_radix,
                        num_blocks_to_add,
                    );
                    ct_as_signed_radix.blocks
                } else {
                    let mut ct_as_unsigned_radix =
                        RadixCiphertext::from_blocks(self.ciphertext.into_blocks());
                    let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                    integer_key.trim_radix_blocks_msb_assign(
                        &mut ct_as_unsigned_radix,
                        num_blocks_to_remove,
                    );
                    ct_as_unsigned_radix.blocks
                }
            } else {
                let mut ct_as_unsigned_radix =
                    RadixCiphertext::from_blocks(self.ciphertext.into_blocks());
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
                P2::num_blocks(),
                "internal error, wrong number of blocks after casting"
            );
            let new_ciphertext = P2::InnerCiphertext::from_blocks(blocks);
            GenericInteger::<P2>::new(new_ciphertext, P2::Id::default())
        })
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

impl<P> GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    /// Conditional selection.
    ///
    /// The output value returned depends on the value of `self`.
    ///
    /// `self` has to encrypt 0 or 1.
    ///
    /// - if `self` is true (1), the output will have the value of `ct_then`
    /// - if `self` is false (0), the output will have the value of `ct_else`
    pub fn if_then_else(&self, ct_then: &Self, ct_else: &Self) -> Self {
        let ct_condition = self;
        let new_ct = ct_condition.id.with_unwrapped_global(|integer_key| {
            integer_key.pbs_key().if_then_else_parallelized(
                &ct_condition.ciphertext,
                &ct_then.ciphertext,
                &ct_else.ciphertext,
            )
        });

        Self::new(new_ct, ct_condition.id)
    }

    /// Conditional selection.
    ///
    /// cmux is another name for (if_then_else)[Self::if_then_else]
    pub fn cmux(&self, ct_then: &Self, ct_else: &Self) -> Self {
        self.if_then_else(ct_then, ct_else)
    }
}

impl<P> TryFrom<RadixCiphertext> for GenericInteger<P>
where
    P: IntegerParameter<InnerCiphertext = RadixCiphertext>,
    P::Id: Default + WithGlobalKey<Key = IntegerServerKey>,
{
    type Error = GenericIntegerBlockError;
    fn try_from(other: RadixCiphertext) -> Result<Self, GenericIntegerBlockError> {
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

        Ok(Self::new(other, P::Id::default()))
    }
}

impl<P, T> TryFrom<Vec<T>> for GenericInteger<P>
where
    P: IntegerParameter<InnerCiphertext = RadixCiphertext>,
    P::Id: Default + WithGlobalKey<Key = IntegerServerKey>,
    P::InnerCiphertext: From<Vec<T>>,
{
    type Error = GenericIntegerBlockError;
    fn try_from(blocks: Vec<T>) -> Result<Self, GenericIntegerBlockError> {
        let ciphertext = P::InnerCiphertext::from(blocks);
        Self::try_from(ciphertext)
    }
}

impl<P, ClearType> FheDecrypt<ClearType> for GenericInteger<P>
where
    P: IntegerParameter,
    crate::integer::ClientKey: DecryptionKey<P::InnerCiphertext, ClearType>,
{
    fn decrypt(&self, key: &ClientKey) -> ClearType {
        let key = &key.key.key;
        key.decrypt(&self.ciphertext)
    }
}

impl<P, T> FheTryEncrypt<T, ClientKey> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
    crate::integer::ClientKey: EncryptionKey<(T, usize), P::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &ClientKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();

        let integer_client_key = &key.key.key;
        let ciphertext = <crate::integer::ClientKey as EncryptionKey<_, _>>::encrypt(
            integer_client_key,
            (value, P::num_blocks()),
        );
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryEncrypt<T, PublicKey> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
    crate::integer::PublicKey: EncryptionKey<(T, usize), P::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &PublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let integer_public_key = &key.key;
        let ciphertext = <crate::integer::PublicKey as EncryptionKey<_, _>>::encrypt(
            integer_public_key,
            (value, P::num_blocks()),
        );
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryEncrypt<T, CompressedPublicKey> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
    crate::integer::CompressedPublicKey: EncryptionKey<(T, usize), P::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let integer_public_key = &key.key;
        let ciphertext = <crate::integer::CompressedPublicKey as EncryptionKey<_, _>>::encrypt(
            integer_public_key,
            (value, P::num_blocks()),
        );
        Ok(Self::new(ciphertext, id))
    }
}

impl<P, T> FheTryEncrypt<T, CompactPublicKey> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
    crate::integer::public_key::CompactPublicKey: EncryptionKey<(T, usize), P::InnerCiphertext>,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let integer_public_key = &key.key.key;
        let ciphertext =
            <crate::integer::public_key::CompactPublicKey as EncryptionKey<_, _>>::encrypt(
                integer_public_key,
                (value, P::num_blocks()),
            );
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
        let ciphertext: P::InnerCiphertext = id.with_unwrapped_global(|integer_key| {
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
    Self: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
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

impl<P, Clear> FheMax<Clear> for GenericInteger<P>
where
    Clear: DecomposableInto<u64>,
    P: IntegerParameter,
    Self: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
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

impl<P> FheMin<&Self> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
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

impl<P, Clear> FheMin<Clear> for GenericInteger<P>
where
    Clear: DecomposableInto<u64>,
    P: IntegerParameter,
    Self: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
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

impl<P> FheEq<Self> for GenericInteger<P>
where
    P: IntegerParameter,
    Self: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn eq(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .eq_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }

    fn ne(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .ne_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }
}

impl<P> FheEq<&Self> for GenericInteger<P>
where
    P: IntegerParameter,
    Self: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn eq(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .eq_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }

    fn ne(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .ne_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }
}

impl<P, Clear> FheEq<Clear> for GenericInteger<P>
where
    Clear: DecomposableInto<u64>,
    P: IntegerParameter,
    Self: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn eq(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_eq_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result, self.id)
    }

    fn ne(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_ne_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result, self.id)
    }
}

impl<P> FheOrd<Self> for GenericInteger<P>
where
    P: IntegerParameter,
    Self: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn lt(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .lt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }

    fn le(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .le_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }

    fn gt(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .gt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }

    fn ge(&self, rhs: Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .ge_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }
}

impl<P> FheOrd<&Self> for GenericInteger<P>
where
    P: IntegerParameter,
    Self: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn lt(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .lt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }

    fn le(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .le_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }

    fn gt(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .gt_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }

    fn ge(&self, rhs: &Self) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .ge_parallelized(&self.ciphertext, &rhs.ciphertext)
        });
        Self::new(inner_result, self.id)
    }
}

impl<P, Clear> FheOrd<Clear> for GenericInteger<P>
where
    Clear: DecomposableInto<u64>,
    P: IntegerParameter,
    Self: Clone,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

    fn lt(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_lt_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result, self.id)
    }

    fn le(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_le_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result, self.id)
    }

    fn gt(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_gt_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result, self.id)
    }

    fn ge(&self, rhs: Clear) -> Self::Output {
        let inner_result = self.id.with_unwrapped_global(|integer_key| {
            integer_key
                .pbs_key()
                .scalar_ge_parallelized(&self.ciphertext, rhs)
        });
        Self::new(inner_result, self.id)
    }
}

impl<P> FheBootstrap for GenericInteger<P>
where
    P: IntegerParameter<InnerCiphertext = RadixCiphertext>,
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

impl<P> GenericInteger<P>
where
    P: IntegerParameter<InnerCiphertext = RadixCiphertext>,
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
                .expect("Function evaluation on integers was not enabled in the config")
                .apply_bivariate_wopbs(integer_key.pbs_key(), lhs, rhs, func);
            Self::new(res, self.id)
        })
    }
}

impl<P> DivRem<Self> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: Self) -> Self::Output {
        <Self as DivRem<&Self>>::div_rem(self, &rhs)
    }
}

impl<P> DivRem<&Self> for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (Self, Self);

    fn div_rem(self, rhs: &Self) -> Self::Output {
        <&Self as DivRem<&Self>>::div_rem(&self, rhs)
    }
}

impl<P> DivRem<Self> for &GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (GenericInteger<P>, GenericInteger<P>);

    fn div_rem(self, rhs: Self) -> Self::Output {
        <Self as DivRem<&Self>>::div_rem(self, &rhs)
    }
}

impl<P> DivRem<&Self> for &GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = (GenericInteger<P>, GenericInteger<P>);

    fn div_rem(self, rhs: &Self) -> Self::Output {
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

// Shifts and rotations are special cases where the right hand side
// is for now, required to be a unsigned integer type.
// And its constraints are a bit relaxed: rhs does not needs to have the same
// amount a bits.
macro_rules! generic_integer_impl_shift_rotate (
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {

        // a op b
        impl<P, P2> $rust_trait_name<GenericInteger<P2>> for GenericInteger<P>
        where
            P: IntegerParameter,
            P2: IntegerParameter<InnerCiphertext=RadixCiphertext>,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: GenericInteger<P2>) -> Self::Output {
                <&Self as $rust_trait_name<&GenericInteger<P2>>>::$rust_trait_method(&self, &rhs)
            }

        }

        // a op &b
        impl<P, P2> $rust_trait_name<&GenericInteger<P2>> for GenericInteger<P>
        where
            P: IntegerParameter,
            P2: IntegerParameter<InnerCiphertext=RadixCiphertext>,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
        {
            type Output = Self;

            fn $rust_trait_method(self, rhs: &GenericInteger<P2>) -> Self::Output {
                <&Self as $rust_trait_name<&GenericInteger<P2>>>::$rust_trait_method(&self, rhs)
            }

        }

        // &a op b
        impl<P, P2> $rust_trait_name<GenericInteger<P2>> for &GenericInteger<P>
        where
            P: IntegerParameter,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
            P2: IntegerParameter<InnerCiphertext=RadixCiphertext>,
        {
            type Output = GenericInteger<P>;

            fn $rust_trait_method(self, rhs: GenericInteger<P2>) -> Self::Output {
                <Self as $rust_trait_name<&GenericInteger<P2>>>::$rust_trait_method(self, &rhs)
            }
        }

        // &a op &b
        impl<P, P2> $rust_trait_name<&GenericInteger<P2>> for &GenericInteger<P>
        where
            P: IntegerParameter,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
            P2: IntegerParameter<InnerCiphertext=RadixCiphertext>,
        {
            type Output = GenericInteger<P>;

            fn $rust_trait_method(self, rhs: &GenericInteger<P2>) -> Self::Output {
                let ciphertext = self.id.with_unwrapped_global(|integer_key| {
                    integer_key
                        .pbs_key()
                        .$key_method(&self.ciphertext, &rhs.ciphertext)
                });
                GenericInteger::<P>::new(ciphertext, self.id)
            }
        }
    }
);

macro_rules! generic_integer_impl_shift_rotate_assign(
    ($rust_trait_name:ident($rust_trait_method:ident) => $key_method:ident) => {
        // a op= b
        impl<P, P2> $rust_trait_name<GenericInteger<P2>> for GenericInteger<P>
        where
            P: IntegerParameter,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
            P2: IntegerParameter<InnerCiphertext=RadixCiphertext>,
        {
            fn $rust_trait_method(&mut self, rhs: GenericInteger<P2>) {
                <Self as $rust_trait_name<&GenericInteger<P2>>>::$rust_trait_method(self, &rhs)
            }
        }

        // a op= &b
        impl<P, P2> $rust_trait_name<&GenericInteger<P2>> for GenericInteger<P>
        where
            P: IntegerParameter,
            P::Id: WithGlobalKey<Key = IntegerServerKey>,
            P2: IntegerParameter<InnerCiphertext=RadixCiphertext>,
        {
            fn $rust_trait_method(&mut self, rhs: &GenericInteger<P2>) {
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

impl<P> Neg for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

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
        GenericInteger::new(ciphertext, self.id)
    }
}

impl<P> Not for GenericInteger<P>
where
    P: IntegerParameter,
    P::Id: WithGlobalKey<Key = IntegerServerKey>,
{
    type Output = Self;

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
