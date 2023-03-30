use std::marker::PhantomData;

use crate::typed_api::integers::parameters::EvaluationIntegerKey;

use super::client_key::GenericIntegerClientKey;
use super::parameters::IntegerParameter;

use crate::integer::wopbs::WopbsKey;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericIntegerServerKey<P: IntegerParameter> {
    pub(in crate::typed_api::integers) inner: P::InnerServerKey,
    pub(in crate::typed_api::integers) wopbs_key: WopbsKey,
    _marker: PhantomData<P>,
}

impl<P> GenericIntegerServerKey<P>
where
    P: IntegerParameter,
    P::InnerServerKey: EvaluationIntegerKey<P::InnerClientKey>,
{
    pub(super) fn new(client_key: &GenericIntegerClientKey<P>) -> Self {
        let inner = P::InnerServerKey::new(&client_key.inner);
        let wopbs_key = P::InnerServerKey::new_wopbs_key(
            &client_key.inner,
            &inner,
            client_key.params.wopbs_block_parameters(),
        );
        Self {
            inner,
            wopbs_key,
            _marker: Default::default(),
        }
    }
}

pub(super) trait SmartNeg<Ciphertext> {
    type Output;
    fn smart_neg(&self, lhs: Ciphertext) -> Self::Output;
}

macro_rules! define_smart_server_key_op {
    ($op_name:ident) => {
        paste::paste! {
            pub trait [< Smart $op_name >]<Lhs, Rhs> {
                type Output;

                fn [< smart_ $op_name:lower >](
                    &self,
                    lhs: Lhs,
                    rhs: Rhs,
                ) -> Self::Output;
            }

            pub trait [< Smart $op_name Assign >]<Lhs, Rhs> {
                fn [< smart_ $op_name:lower _assign >](
                    &self,
                    lhs: &mut Lhs,
                    rhs: Rhs,
                );
            }
        }
    };
    ($($op:ident),*) => {
        $(
            define_smart_server_key_op!($op);
        )*
    };
}

define_smart_server_key_op!(
    Add, Sub, Mul, BitAnd, BitOr, BitXor, Shl, Shr, Eq, Ge, Gt, Le, Lt, Max, Min
);

macro_rules! impl_smart_op_for_tfhe_integer_server_key {
    ($smart_trait:ident($smart_trait_fn:ident) => ($ciphertext:ty, $method:ident)) => {
        impl $smart_trait<&mut $ciphertext, &mut $ciphertext> for crate::integer::ServerKey {
            type Output = $ciphertext;

            fn $smart_trait_fn(
                &self,
                lhs: &mut $ciphertext,
                rhs: &mut $ciphertext,
            ) -> Self::Output {
                self.$method(lhs, rhs)
            }
        }
    };
}

macro_rules! impl_smart_assign_op_for_tfhe_integer_server_key {
    ($smart_trait:ident($smart_trait_fn:ident) => ($ciphertext:ty, $method:ident)) => {
        impl $smart_trait<$ciphertext, &mut $ciphertext> for crate::integer::ServerKey {
            fn $smart_trait_fn(&self, lhs: &mut $ciphertext, rhs: &mut $ciphertext) {
                self.$method(lhs, rhs);
            }
        }
    };
}

macro_rules! impl_smart_scalar_op_for_tfhe_integer_server_key {
    ($smart_trait:ident($smart_trait_fn:ident) => ($ciphertext:ty, $method:ident)) => {
        impl $smart_trait<&mut $ciphertext, u64> for crate::integer::ServerKey {
            type Output = $ciphertext;

            fn $smart_trait_fn(&self, lhs: &mut $ciphertext, rhs: u64) -> Self::Output {
                self.$method(lhs, rhs.try_into().unwrap())
            }
        }
    };
}

macro_rules! impl_smart_scalar_assign_op_for_tfhe_integer_server_key {
    ($smart_trait:ident($smart_trait_fn:ident) => ($ciphertext:ty, $method:ident)) => {
        impl $smart_trait<$ciphertext, u64> for crate::integer::ServerKey {
            fn $smart_trait_fn(&self, lhs: &mut $ciphertext, rhs: u64) {
                self.$method(lhs, rhs.try_into().unwrap());
            }
        }
    };
}

impl SmartNeg<&mut crate::integer::RadixCiphertextBig> for crate::integer::ServerKey {
    type Output = crate::integer::RadixCiphertextBig;
    fn smart_neg(&self, lhs: &mut crate::integer::RadixCiphertextBig) -> Self::Output {
        self.smart_neg_parallelized(lhs)
    }
}

impl_smart_op_for_tfhe_integer_server_key!(SmartAdd(smart_add) => (crate::integer::RadixCiphertextBig, smart_add_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartSub(smart_sub) => (crate::integer::RadixCiphertextBig, smart_sub_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartMul(smart_mul) => (crate::integer::RadixCiphertextBig, smart_mul_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartBitAnd(smart_bitand) => (crate::integer::RadixCiphertextBig, smart_bitand_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartBitOr(smart_bitor) => (crate::integer::RadixCiphertextBig, smart_bitor_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartBitXor(smart_bitxor) => (crate::integer::RadixCiphertextBig, smart_bitxor_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartEq(smart_eq) => (crate::integer::RadixCiphertextBig, smart_eq_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartGe(smart_ge) => (crate::integer::RadixCiphertextBig, smart_ge_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartGt(smart_gt) => (crate::integer::RadixCiphertextBig, smart_gt_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartLe(smart_le) => (crate::integer::RadixCiphertextBig, smart_le_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartLt(smart_lt) => (crate::integer::RadixCiphertextBig, smart_lt_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartMax(smart_max) => (crate::integer::RadixCiphertextBig, smart_max_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartMin(smart_min) => (crate::integer::RadixCiphertextBig, smart_min_parallelized));

impl_smart_assign_op_for_tfhe_integer_server_key!(SmartAddAssign(smart_add_assign) => (crate::integer::RadixCiphertextBig, smart_add_assign_parallelized));
impl_smart_assign_op_for_tfhe_integer_server_key!(SmartSubAssign(smart_sub_assign) => (crate::integer::RadixCiphertextBig, smart_sub_assign_parallelized));
impl_smart_assign_op_for_tfhe_integer_server_key!(SmartMulAssign(smart_mul_assign) => (crate::integer::RadixCiphertextBig, smart_mul_assign_parallelized));
impl_smart_assign_op_for_tfhe_integer_server_key!(SmartBitAndAssign(smart_bitand_assign) => (crate::integer::RadixCiphertextBig, smart_bitand_assign_parallelized));
impl_smart_assign_op_for_tfhe_integer_server_key!(SmartBitOrAssign(smart_bitor_assign) => (crate::integer::RadixCiphertextBig, smart_bitor_assign_parallelized));
impl_smart_assign_op_for_tfhe_integer_server_key!(SmartBitXorAssign(smart_bitxor_assign) => (crate::integer::RadixCiphertextBig, smart_bitxor_assign_parallelized));

impl_smart_scalar_op_for_tfhe_integer_server_key!(SmartAdd(smart_add) => (crate::integer::RadixCiphertextBig, smart_scalar_add_parallelized));
impl_smart_scalar_op_for_tfhe_integer_server_key!(SmartSub(smart_sub) => (crate::integer::RadixCiphertextBig, smart_scalar_sub_parallelized));
impl_smart_scalar_op_for_tfhe_integer_server_key!(SmartMul(smart_mul) => (crate::integer::RadixCiphertextBig, smart_scalar_mul_parallelized));
impl_smart_scalar_op_for_tfhe_integer_server_key!(SmartShl(smart_shl) => (crate::integer::RadixCiphertextBig, unchecked_scalar_left_shift_parallelized));
impl_smart_scalar_op_for_tfhe_integer_server_key!(SmartShr(smart_shr) => (crate::integer::RadixCiphertextBig, unchecked_scalar_right_shift_parallelized));

impl_smart_scalar_assign_op_for_tfhe_integer_server_key!(SmartAddAssign(smart_add_assign) => (crate::integer::RadixCiphertextBig, smart_scalar_add_assign_parallelized));
impl_smart_scalar_assign_op_for_tfhe_integer_server_key!(SmartSubAssign(smart_sub_assign) => (crate::integer::RadixCiphertextBig, smart_scalar_sub_assign_parallelized));
impl_smart_scalar_assign_op_for_tfhe_integer_server_key!(SmartMulAssign(smart_mul_assign) => (crate::integer::RadixCiphertextBig, smart_scalar_mul_assign_parallelized));
impl_smart_scalar_assign_op_for_tfhe_integer_server_key!(SmartShlAssign(smart_shl_assign) => (crate::integer::RadixCiphertextBig, unchecked_scalar_left_shift_assign_parallelized));
impl_smart_scalar_assign_op_for_tfhe_integer_server_key!(SmartShrAssign(smart_shr_assign) => (crate::integer::RadixCiphertextBig, unchecked_scalar_right_shift_assign_parallelized));

// Crt

impl_smart_op_for_tfhe_integer_server_key!(SmartAdd(smart_add) => (crate::integer::CrtCiphertext, smart_crt_add_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartSub(smart_sub) => (crate::integer::CrtCiphertext, smart_crt_sub_parallelized));
impl_smart_op_for_tfhe_integer_server_key!(SmartMul(smart_mul) => (crate::integer::CrtCiphertext, smart_crt_mul_parallelized));

impl_smart_assign_op_for_tfhe_integer_server_key!(SmartAddAssign(smart_add_assign) => (crate::integer::CrtCiphertext, smart_crt_add_assign_parallelized));
impl_smart_assign_op_for_tfhe_integer_server_key!(SmartSubAssign(smart_sub_assign) => (crate::integer::CrtCiphertext, smart_crt_sub_parallelized));
impl_smart_assign_op_for_tfhe_integer_server_key!(SmartMulAssign(smart_mul_assign) => (crate::integer::CrtCiphertext, smart_crt_mul_assign_parallelized));

impl_smart_scalar_op_for_tfhe_integer_server_key!(SmartAdd(smart_add) => (crate::integer::CrtCiphertext, smart_crt_scalar_add));
impl_smart_scalar_op_for_tfhe_integer_server_key!(SmartSub(smart_sub) => (crate::integer::CrtCiphertext, smart_crt_scalar_sub));
impl_smart_scalar_op_for_tfhe_integer_server_key!(SmartMul(smart_mul) => (crate::integer::CrtCiphertext, smart_crt_scalar_mul));

impl_smart_scalar_assign_op_for_tfhe_integer_server_key!(SmartAddAssign(smart_add_assign) => (crate::integer::CrtCiphertext, smart_crt_scalar_add_assign));
impl_smart_scalar_assign_op_for_tfhe_integer_server_key!(SmartSubAssign(smart_sub_assign) => (crate::integer::CrtCiphertext, smart_crt_scalar_sub_assign));
impl_smart_scalar_assign_op_for_tfhe_integer_server_key!(SmartMulAssign(smart_mul_assign) => (crate::integer::CrtCiphertext, smart_crt_scalar_mul_assign));

impl SmartNeg<&mut crate::integer::CrtCiphertext> for crate::integer::ServerKey {
    type Output = crate::integer::CrtCiphertext;
    fn smart_neg(&self, lhs: &mut crate::integer::CrtCiphertext) -> Self::Output {
        self.smart_crt_neg_parallelized(lhs)
    }
}
