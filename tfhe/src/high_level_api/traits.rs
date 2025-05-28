use std::ops::RangeBounds;

use crate::error::InvalidRangeError;
use crate::high_level_api::ClientKey;
use crate::{FheBool, Tag};

use super::compressed_ciphertext_list::HlExpandable;

/// Trait used to have a generic way of creating a value of a FHE type
/// from a native value.
///
/// This trait is for when FHE type the native value is encrypted
/// supports the same numbers of bits of precision.
///
/// The `Key` is required as it contains the key needed to do the
/// actual encryption.
pub trait FheEncrypt<T, Key> {
    fn encrypt(value: T, key: &Key) -> Self;
}

impl<Clear, Key, T> FheEncrypt<Clear, Key> for T
where
    T: FheTryEncrypt<Clear, Key>,
{
    fn encrypt(value: Clear, key: &Key) -> Self {
        T::try_encrypt(value, key).unwrap()
    }
}

// This trait has the same signature than
// `std::convert::From` however we create our own trait
// to be explicit about the `trivial`
pub trait FheTrivialEncrypt<T> {
    fn encrypt_trivial(value: T) -> Self;
}

/// Trait used to have a generic **fallible** way of creating a value of a FHE type.
///
/// For example this trait may be implemented by FHE types which may not be able
/// to represent all the values of even the smallest native type.
///
/// For example, `FheUint2` which has 2 bits of precision may not be constructed from
/// all values that a `u8` can hold.
pub trait FheTryEncrypt<T, Key>
where
    Self: Sized,
{
    type Error: std::error::Error;

    fn try_encrypt(value: T, key: &Key) -> Result<Self, Self::Error>;
}

/// Trait for fallible trivial encryption.
pub trait FheTryTrivialEncrypt<T>
where
    Self: Sized,
{
    type Error: std::error::Error;

    fn try_encrypt_trivial(value: T) -> Result<Self, Self::Error>;
}

/// Decrypt a FHE type to a native type.
pub trait FheDecrypt<T> {
    fn decrypt(&self, key: &ClientKey) -> T;
}

/// Key switch an ciphertext into a new ciphertext of same type but encrypted
/// under a different key.
pub trait FheKeyswitch<T> {
    fn keyswitch(&self, input: &T) -> T;
}

/// Trait for fully homomorphic equality test.
///
/// The standard trait [std::cmp::PartialEq] can not be used
/// has it requires to return a [bool].
///
/// This means that to compare ciphertext to another ciphertext or a scalar,
/// for equality, one cannot use the standard operator `==` but rather, use
/// the function directly.
pub trait FheEq<Rhs = Self> {
    fn eq(&self, other: Rhs) -> FheBool;

    fn ne(&self, other: Rhs) -> FheBool;
}

/// Trait for fully homomorphic comparisons.
///
/// The standard trait [std::cmp::PartialOrd] can not be used
/// has it requires to return a [bool].
///
/// This means that to compare ciphertext to another ciphertext or a scalar,
/// one cannot use the standard operators (`>`, `<`, etc) and must use
/// the functions directly.
pub trait FheOrd<Rhs = Self> {
    fn lt(&self, other: Rhs) -> FheBool;
    fn le(&self, other: Rhs) -> FheBool;
    fn gt(&self, other: Rhs) -> FheBool;
    fn ge(&self, other: Rhs) -> FheBool;
}

pub trait FheMin<Rhs = Self> {
    type Output;

    fn min(&self, other: Rhs) -> Self::Output;
}

pub trait FheMax<Rhs = Self> {
    type Output;

    fn max(&self, other: Rhs) -> Self::Output;
}

pub trait RotateLeft<Rhs = Self> {
    type Output;

    fn rotate_left(self, amount: Rhs) -> Self::Output;
}

pub trait RotateRight<Rhs = Self> {
    type Output;

    fn rotate_right(self, amount: Rhs) -> Self::Output;
}

pub trait RotateLeftAssign<Rhs = Self> {
    fn rotate_left_assign(&mut self, amount: Rhs);
}

pub trait RotateRightAssign<Rhs = Self> {
    fn rotate_right_assign(&mut self, amount: Rhs);
}

pub trait DivRem<Rhs = Self> {
    type Output;

    fn div_rem(self, amount: Rhs) -> Self::Output;
}

pub trait IfThenElse<Ciphertext> {
    fn if_then_else(&self, ct_then: &Ciphertext, ct_else: &Ciphertext) -> Ciphertext;
    fn select(&self, ct_when_true: &Ciphertext, ct_when_false: &Ciphertext) -> Ciphertext {
        self.if_then_else(ct_when_true, ct_when_false)
    }
    fn cmux(&self, ct_then: &Ciphertext, ct_else: &Ciphertext) -> Ciphertext {
        self.if_then_else(ct_then, ct_else)
    }
}

pub trait ScalarIfThenElse<Lhs, Rhs> {
    type Output;

    fn scalar_if_then_else(&self, value_true: Lhs, value_false: Rhs) -> Self::Output;

    fn scalar_select(&self, value_true: Lhs, value_false: Rhs) -> Self::Output {
        self.scalar_if_then_else(value_true, value_false)
    }

    fn scalar_cmux(&self, value_true: Lhs, value_false: Rhs) -> Self::Output {
        self.scalar_if_then_else(value_true, value_false)
    }
}

pub trait OverflowingAdd<Rhs> {
    type Output;

    fn overflowing_add(self, rhs: Rhs) -> (Self::Output, FheBool);
}

pub trait OverflowingSub<Rhs> {
    type Output;

    fn overflowing_sub(self, rhs: Rhs) -> (Self::Output, FheBool);
}

pub trait OverflowingMul<Rhs> {
    type Output;

    fn overflowing_mul(self, rhs: Rhs) -> (Self::Output, FheBool);
}

pub trait OverflowingNeg {
    type Output;

    fn overflowing_neg(self) -> (Self::Output, FheBool);
}

pub trait BitSlice<Bounds> {
    type Output;

    fn bitslice<R>(self, range: R) -> Result<Self::Output, InvalidRangeError>
    where
        R: RangeBounds<Bounds>;
}

pub trait Tagged {
    fn tag(&self) -> &Tag;

    fn tag_mut(&mut self) -> &mut Tag;
}

pub trait CiphertextList {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes>;
    fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: HlExpandable + Tagged;
}

pub trait FheId: Copy + Default {}

pub trait SquashNoise {
    type Output;

    fn squash_noise(&self) -> crate::Result<Self::Output>;
}

/// Trait used to have a generic way of waiting Hw accelerator result
pub trait FheWait {
    fn wait(&self);
}

/// Struct used to have a generic way of starting custom Hpu IOp
#[cfg(feature = "hpu")]
pub struct HpuHandle<T> {
    pub native: Vec<T>,
    pub boolean: Vec<FheBool>,
    pub imm: Vec<u128>,
}

#[cfg(feature = "hpu")]
pub trait FheHpu
where
    Self: Sized,
{
    fn iop_exec(
        iop: &tfhe_hpu_backend::prelude::hpu_asm::AsmIOpcode,
        src: HpuHandle<&Self>,
    ) -> HpuHandle<Self>;
}

#[cfg(feature = "gpu")]
pub trait SizeOnGpu<Rhs = Self> {
    fn get_size_on_gpu(&self) -> u64;
}
#[cfg(feature = "gpu")]
pub trait AddSizeOnGpu<Rhs = Self> {
    fn get_add_size_on_gpu(&self, amount: Rhs) -> u64;
}

#[cfg(feature = "gpu")]
pub trait SubSizeOnGpu<Rhs = Self> {
    fn get_sub_size_on_gpu(&self, amount: Rhs) -> u64;
}

#[cfg(feature = "gpu")]
pub trait BitAndSizeOnGpu<Rhs = Self> {
    fn get_bitand_size_on_gpu(&self, amount: Rhs) -> u64;
}
#[cfg(feature = "gpu")]
pub trait BitOrSizeOnGpu<Rhs = Self> {
    fn get_bitor_size_on_gpu(&self, amount: Rhs) -> u64;
}
#[cfg(feature = "gpu")]
pub trait BitXorSizeOnGpu<Rhs = Self> {
    fn get_bitxor_size_on_gpu(&self, amount: Rhs) -> u64;
}
#[cfg(feature = "gpu")]
pub trait BitNotSizeOnGpu {
    fn get_bitnot_size_on_gpu(&self) -> u64;
}

#[cfg(feature = "gpu")]
pub trait FheOrdSizeOnGpu<Rhs = Self> {
    fn get_gt_size_on_gpu(&self, amount: Rhs) -> u64;
    fn get_lt_size_on_gpu(&self, amount: Rhs) -> u64;
    fn get_ge_size_on_gpu(&self, amount: Rhs) -> u64;
    fn get_le_size_on_gpu(&self, amount: Rhs) -> u64;
}
#[cfg(feature = "gpu")]
pub trait FheMinSizeOnGpu<Rhs = Self> {
    fn get_min_size_on_gpu(&self, other: Rhs) -> u64;
}

#[cfg(feature = "gpu")]
pub trait FheMaxSizeOnGpu<Rhs = Self> {
    fn get_max_size_on_gpu(&self, other: Rhs) -> u64;
}

#[cfg(feature = "gpu")]
pub trait ShlSizeOnGpu<Rhs = Self> {
    fn get_left_shift_size_on_gpu(&self, other: Rhs) -> u64;
}

#[cfg(feature = "gpu")]
pub trait ShrSizeOnGpu<Rhs = Self> {
    fn get_right_shift_size_on_gpu(&self, other: Rhs) -> u64;
}

#[cfg(feature = "gpu")]
pub trait RotateLeftSizeOnGpu<Rhs = Self> {
    fn get_rotate_left_size_on_gpu(&self, other: Rhs) -> u64;
}

#[cfg(feature = "gpu")]
pub trait RotateRightSizeOnGpu<Rhs = Self> {
    fn get_rotate_right_size_on_gpu(&self, other: Rhs) -> u64;
}

#[cfg(feature = "gpu")]
pub trait IfThenElseSizeOnGpu<Ciphertext> {
    fn get_if_then_else_size_on_gpu(&self, ct_then: &Ciphertext, ct_else: &Ciphertext) -> u64;
    fn get_select_size_on_gpu(&self, ct_when_true: &Ciphertext, ct_when_false: &Ciphertext) -> u64 {
        self.get_if_then_else_size_on_gpu(ct_when_true, ct_when_false)
    }
    fn get_cmux_size_on_gpu(&self, ct_then: &Ciphertext, ct_else: &Ciphertext) -> u64 {
        self.get_if_then_else_size_on_gpu(ct_then, ct_else)
    }
}
