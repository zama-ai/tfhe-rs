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

pub(crate) fn wopbs_radix<O>(
    wopbs_key: &WopbsKey,
    server_key: &crate::integer::ServerKey,
    ct_in: &crate::integer::ciphertext::RadixCiphertext<O>,
    func: impl Fn(u64) -> u64,
) -> crate::integer::ciphertext::RadixCiphertext<O>
where
    O: crate::shortint::PBSOrderMarker,
    crate::integer::ciphertext::RadixCiphertext<O>: crate::integer::IntegerCiphertext,
{
    let switched_ct = wopbs_key.keyswitch_to_wopbs_params(server_key, ct_in);
    let luts = wopbs_key.generate_lut_radix(&switched_ct, func);
    let res = wopbs_key.wopbs(&switched_ct, luts.as_slice());
    wopbs_key.keyswitch_to_pbs_params(&res)
}

pub(crate) fn bivariate_wopbs_radix<O>(
    wopbs_key: &WopbsKey,
    server_key: &crate::integer::ServerKey,
    lhs: &crate::integer::ciphertext::RadixCiphertext<O>,
    rhs: &crate::integer::ciphertext::RadixCiphertext<O>,
    func: impl Fn(u64, u64) -> u64,
) -> crate::integer::ciphertext::RadixCiphertext<O>
where
    O: crate::shortint::PBSOrderMarker,
    crate::integer::ciphertext::RadixCiphertext<O>: crate::integer::IntegerCiphertext,
{
    let switched_lhs = wopbs_key.keyswitch_to_wopbs_params(server_key, lhs);
    let switched_rhs = wopbs_key.keyswitch_to_wopbs_params(server_key, rhs);
    let lut = wopbs_key.generate_lut_bivariate_radix(&switched_lhs, &switched_rhs, func);
    let res = wopbs_key.bivariate_wopbs_with_degree(&switched_lhs, &switched_rhs, lut.as_slice());
    wopbs_key.keyswitch_to_pbs_params(&res)
}

pub(crate) fn wopbs_crt(
    wopbs_key: &WopbsKey,
    server_key: &crate::integer::ServerKey,
    ct_in: &crate::integer::CrtCiphertext,
    func: impl Fn(u64) -> u64,
) -> crate::integer::CrtCiphertext {
    let switched_ct = wopbs_key.keyswitch_to_wopbs_params(server_key, ct_in);
    let luts = wopbs_key.generate_lut_crt(&switched_ct, func);
    let res = wopbs_key.wopbs(&switched_ct, luts.as_slice());
    wopbs_key.keyswitch_to_pbs_params(&res)
}

pub(crate) fn bivariate_wopbs_crt(
    wopbs_key: &WopbsKey,
    server_key: &crate::integer::ServerKey,
    lhs: &crate::integer::CrtCiphertext,
    rhs: &crate::integer::CrtCiphertext,
    func: impl Fn(u64, u64) -> u64,
) -> crate::integer::CrtCiphertext {
    let switched_lhs = wopbs_key.keyswitch_to_wopbs_params(server_key, lhs);
    let switched_rhs = wopbs_key.keyswitch_to_wopbs_params(server_key, rhs);
    let lut = wopbs_key.generate_lut_bivariate_crt(&switched_lhs, &switched_rhs, func);
    let res = wopbs_key.bivariate_wopbs_native_crt(&switched_lhs, &switched_rhs, lut.as_slice());
    wopbs_key.keyswitch_to_pbs_params(&res)
}

pub trait WopbsEvaluationKey<ServerKey, Ciphertext> {
    fn apply_wopbs(&self, sks: &ServerKey, ct: &Ciphertext, f: impl Fn(u64) -> u64) -> Ciphertext;

    fn apply_bivariate_wopbs(
        &self,
        sks: &ServerKey,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
        f: impl Fn(u64, u64) -> u64,
    ) -> Ciphertext;
}

impl
    WopbsEvaluationKey<
        crate::integer::ServerKey,
        crate::typed_api::integers::server_key::RadixCiphertextDyn,
    > for WopbsKey
{
    fn apply_wopbs(
        &self,
        sks: &crate::integer::ServerKey,
        ct: &crate::typed_api::integers::server_key::RadixCiphertextDyn,
        f: impl Fn(u64) -> u64,
    ) -> crate::typed_api::integers::server_key::RadixCiphertextDyn {
        match ct {
            RadixCiphertextDyn::Big(ct) => {
                let res = wopbs_radix(self, sks, ct, f);
                RadixCiphertextDyn::Big(res)
            }
            RadixCiphertextDyn::Small(ct) => {
                let res = wopbs_radix(self, sks, ct, f);
                RadixCiphertextDyn::Small(res)
            }
        }
    }

    fn apply_bivariate_wopbs(
        &self,
        sks: &crate::integer::ServerKey,
        lhs: &crate::typed_api::integers::server_key::RadixCiphertextDyn,
        rhs: &crate::typed_api::integers::server_key::RadixCiphertextDyn,
        f: impl Fn(u64, u64) -> u64,
    ) -> crate::typed_api::integers::server_key::RadixCiphertextDyn {
        match (lhs, rhs) {
            (RadixCiphertextDyn::Big(lhs), RadixCiphertextDyn::Big(rhs)) => {
                let res = bivariate_wopbs_radix(self, sks, lhs, rhs, f);
                RadixCiphertextDyn::Big(res)
            }
            (RadixCiphertextDyn::Small(lhs), RadixCiphertextDyn::Small(rhs)) => {
                let res = bivariate_wopbs_radix(self, sks, lhs, rhs, f);
                RadixCiphertextDyn::Small(res)
            }
            (_, _) => {
                unreachable!("internal error: cannot mix big and small ciphertext")
            }
        }
    }
}

impl WopbsEvaluationKey<crate::integer::ServerKey, crate::integer::CrtCiphertext> for WopbsKey {
    fn apply_wopbs(
        &self,
        sks: &crate::integer::ServerKey,
        ct: &crate::integer::CrtCiphertext,
        f: impl Fn(u64) -> u64,
    ) -> crate::integer::CrtCiphertext {
        wopbs_crt(self, sks, ct, f)
    }

    fn apply_bivariate_wopbs(
        &self,
        sks: &crate::integer::ServerKey,
        lhs: &crate::integer::CrtCiphertext,
        rhs: &crate::integer::CrtCiphertext,
        f: impl Fn(u64, u64) -> u64,
    ) -> crate::integer::CrtCiphertext {
        bivariate_wopbs_crt(self, sks, lhs, rhs, f)
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

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub enum RadixCiphertextDyn {
    Big(crate::integer::RadixCiphertextBig),
    Small(crate::integer::RadixCiphertextSmall),
}

impl SmartNeg<&mut RadixCiphertextDyn> for crate::integer::ServerKey {
    type Output = RadixCiphertextDyn;
    fn smart_neg(&self, lhs: &mut RadixCiphertextDyn) -> Self::Output {
        match lhs {
            RadixCiphertextDyn::Big(lhs) => {
                RadixCiphertextDyn::Big(self.smart_neg_parallelized(lhs))
            }
            RadixCiphertextDyn::Small(lhs) => {
                RadixCiphertextDyn::Small(self.smart_neg_parallelized(lhs))
            }
        }
    }
}

macro_rules! impl_smart_op_for_tfhe_integer_server_key_dyn {
    ($smart_trait:ident($smart_trait_fn:ident) => $method:ident) => {
        impl $smart_trait<&mut RadixCiphertextDyn, &mut RadixCiphertextDyn>
            for crate::integer::ServerKey
        {
            type Output = RadixCiphertextDyn;

            fn $smart_trait_fn(
                &self,
                lhs_enum: &mut RadixCiphertextDyn,
                rhs_enum: &mut RadixCiphertextDyn,
            ) -> Self::Output {
                match (lhs_enum, rhs_enum) {
                    (RadixCiphertextDyn::Big(lhs), RadixCiphertextDyn::Big(rhs)) => {
                        RadixCiphertextDyn::Big(self.$method(lhs, rhs))
                    }
                    (RadixCiphertextDyn::Small(lhs), RadixCiphertextDyn::Small(rhs)) => {
                        RadixCiphertextDyn::Small(self.$method(lhs, rhs))
                    }
                    (_, _) => unreachable!("internal error: mismatched big and small integer"),
                }
            }
        }
    };
}

macro_rules! impl_smart_assign_op_for_tfhe_integer_server_key_dyn {
    ($smart_trait:ident($smart_trait_fn:ident) => $method_assign:ident) => {
        impl $smart_trait<RadixCiphertextDyn, &mut RadixCiphertextDyn>
            for crate::integer::ServerKey
        {
            fn $smart_trait_fn(
                &self,
                lhs_enum: &mut RadixCiphertextDyn,
                rhs_enum: &mut RadixCiphertextDyn,
            ) {
                match (lhs_enum, rhs_enum) {
                    (RadixCiphertextDyn::Big(lhs), RadixCiphertextDyn::Big(rhs)) => {
                        self.$method_assign(lhs, rhs)
                    }
                    (RadixCiphertextDyn::Small(lhs), RadixCiphertextDyn::Small(rhs)) => {
                        self.$method_assign(lhs, rhs)
                    }
                    (_, _) => unreachable!("internal error: mismatched big and small integer"),
                }
            }
        }
    };
}

macro_rules! impl_smart_scalar_op_for_tfhe_integer_server_key_dyn {
    ($smart_trait:ident($smart_trait_fn:ident) => $method:ident) => {
        impl $smart_trait<&mut RadixCiphertextDyn, u64> for crate::integer::ServerKey {
            type Output = RadixCiphertextDyn;

            fn $smart_trait_fn(&self, lhs: &mut RadixCiphertextDyn, rhs: u64) -> Self::Output {
                match lhs {
                    RadixCiphertextDyn::Big(lhs) => {
                        RadixCiphertextDyn::Big(self.$method(lhs, rhs.try_into().unwrap()))
                    }
                    RadixCiphertextDyn::Small(lhs) => {
                        RadixCiphertextDyn::Small(self.$method(lhs, rhs.try_into().unwrap()))
                    }
                }
            }
        }
    };
}

macro_rules! impl_smart_scalar_assign_op_for_tfhe_integer_server_key_dyn {
    ($smart_trait:ident($smart_trait_fn:ident) => $method_assign:ident) => {
        impl $smart_trait<RadixCiphertextDyn, u64> for crate::integer::ServerKey {
            fn $smart_trait_fn(&self, lhs: &mut RadixCiphertextDyn, rhs: u64) {
                match lhs {
                    RadixCiphertextDyn::Big(lhs) => {
                        self.$method_assign(lhs, rhs.try_into().unwrap())
                    }
                    RadixCiphertextDyn::Small(lhs) => {
                        self.$method_assign(lhs, rhs.try_into().unwrap())
                    }
                }
            }
        }
    };
}

impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartAdd(smart_add) => smart_add_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartSub(smart_sub) => smart_sub_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartMul(smart_mul) => smart_mul_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartBitAnd(smart_bitand) => smart_bitand_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartBitOr(smart_bitor) => smart_bitor_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartBitXor(smart_bitxor) => smart_bitxor_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartEq(smart_eq) => smart_eq_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartGe(smart_ge) => smart_ge_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartGt(smart_gt) => smart_gt_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartLe(smart_le) => smart_le_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartLt(smart_lt) => smart_lt_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartMax(smart_max) => smart_max_parallelized);
impl_smart_op_for_tfhe_integer_server_key_dyn!(SmartMin(smart_min) => smart_min_parallelized);

impl_smart_assign_op_for_tfhe_integer_server_key_dyn!(SmartAddAssign(smart_add_assign) => smart_add_assign_parallelized);
impl_smart_assign_op_for_tfhe_integer_server_key_dyn!(SmartSubAssign(smart_sub_assign) => smart_sub_assign_parallelized);
impl_smart_assign_op_for_tfhe_integer_server_key_dyn!(SmartMulAssign(smart_mul_assign) => smart_mul_assign_parallelized);
impl_smart_assign_op_for_tfhe_integer_server_key_dyn!(SmartBitAndAssign(smart_bitand_assign) => smart_bitand_assign_parallelized);
impl_smart_assign_op_for_tfhe_integer_server_key_dyn!(SmartBitOrAssign(smart_bitor_assign) => smart_bitor_assign_parallelized);
impl_smart_assign_op_for_tfhe_integer_server_key_dyn!(SmartBitXorAssign(smart_bitxor_assign) => smart_bitxor_assign_parallelized);

impl_smart_scalar_op_for_tfhe_integer_server_key_dyn!(SmartAdd(smart_add) => smart_scalar_add_parallelized);
impl_smart_scalar_op_for_tfhe_integer_server_key_dyn!(SmartSub(smart_sub) => smart_scalar_sub_parallelized);
impl_smart_scalar_op_for_tfhe_integer_server_key_dyn!(SmartMul(smart_mul) => smart_scalar_mul_parallelized);
impl_smart_scalar_op_for_tfhe_integer_server_key_dyn!(SmartShl(smart_shl) => unchecked_scalar_left_shift_parallelized);
impl_smart_scalar_op_for_tfhe_integer_server_key_dyn!(SmartShr(smart_shr) => unchecked_scalar_right_shift_parallelized);

impl_smart_scalar_assign_op_for_tfhe_integer_server_key_dyn!(SmartAddAssign(smart_add_assign) => smart_scalar_add_assign_parallelized);
impl_smart_scalar_assign_op_for_tfhe_integer_server_key_dyn!(SmartSubAssign(smart_sub_assign) => smart_scalar_sub_assign_parallelized);
impl_smart_scalar_assign_op_for_tfhe_integer_server_key_dyn!(SmartMulAssign(smart_mul_assign) => smart_scalar_mul_assign_parallelized);
impl_smart_scalar_assign_op_for_tfhe_integer_server_key_dyn!(SmartShlAssign(smart_shl_assign) => unchecked_scalar_left_shift_assign_parallelized);
impl_smart_scalar_assign_op_for_tfhe_integer_server_key_dyn!(SmartShrAssign(smart_shr_assign) => unchecked_scalar_right_shift_assign_parallelized);
