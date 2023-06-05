use crate::integer::wopbs::WopbsKey;

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
    let res = wopbs_key.wopbs(&switched_ct, &luts);
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
    let res = wopbs_key.bivariate_wopbs_with_degree(&switched_lhs, &switched_rhs, &lut);
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
    let res = wopbs_key.wopbs(&switched_ct, &luts);
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
    let res = wopbs_key.bivariate_wopbs_native_crt(&switched_lhs, &switched_rhs, &lut);
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
        crate::high_level_api::integers::server_key::RadixCiphertextDyn,
    > for WopbsKey
{
    fn apply_wopbs(
        &self,
        sks: &crate::integer::ServerKey,
        ct: &crate::high_level_api::integers::server_key::RadixCiphertextDyn,
        f: impl Fn(u64) -> u64,
    ) -> crate::high_level_api::integers::server_key::RadixCiphertextDyn {
        match ct {
            RadixCiphertextDyn::Big(ct) => {
                let mut tmp_ct: crate::integer::ciphertext::RadixCiphertextBig;

                let ct = if ct.block_carries_are_empty() {
                    ct
                } else {
                    tmp_ct = ct.clone();
                    sks.full_propagate_parallelized(&mut tmp_ct);
                    &tmp_ct
                };

                let res = wopbs_radix(self, sks, ct, f);
                RadixCiphertextDyn::Big(res)
            }
            RadixCiphertextDyn::Small(ct) => {
                let mut tmp_ct: crate::integer::ciphertext::RadixCiphertextSmall;

                let ct = if ct.block_carries_are_empty() {
                    ct
                } else {
                    tmp_ct = ct.clone();
                    sks.full_propagate_parallelized(&mut tmp_ct);
                    &tmp_ct
                };

                let res = wopbs_radix(self, sks, ct, f);
                RadixCiphertextDyn::Small(res)
            }
        }
    }

    fn apply_bivariate_wopbs(
        &self,
        sks: &crate::integer::ServerKey,
        lhs: &crate::high_level_api::integers::server_key::RadixCiphertextDyn,
        rhs: &crate::high_level_api::integers::server_key::RadixCiphertextDyn,
        f: impl Fn(u64, u64) -> u64,
    ) -> crate::high_level_api::integers::server_key::RadixCiphertextDyn {
        match (lhs, rhs) {
            (RadixCiphertextDyn::Big(lhs), RadixCiphertextDyn::Big(rhs)) => {
                let mut tmp_lhs: crate::integer::ciphertext::RadixCiphertextBig;
                let mut tmp_rhs: crate::integer::ciphertext::RadixCiphertextBig;

                // Clean carries to have a small wopbs to compute
                let (lhs, rhs) =
                    match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
                        (true, true) => (lhs, rhs),
                        (true, false) => {
                            tmp_rhs = rhs.clone();
                            sks.full_propagate_parallelized(&mut tmp_rhs);
                            (lhs, &tmp_rhs)
                        }
                        (false, true) => {
                            tmp_lhs = lhs.clone();
                            sks.full_propagate_parallelized(&mut tmp_lhs);
                            (&tmp_lhs, rhs)
                        }
                        (false, false) => {
                            tmp_lhs = lhs.clone();
                            tmp_rhs = rhs.clone();
                            rayon::join(
                                || sks.full_propagate_parallelized(&mut tmp_lhs),
                                || sks.full_propagate_parallelized(&mut tmp_rhs),
                            );
                            (&tmp_lhs, &tmp_rhs)
                        }
                    };

                let res = bivariate_wopbs_radix(self, sks, lhs, rhs, f);
                RadixCiphertextDyn::Big(res)
            }
            (RadixCiphertextDyn::Small(lhs), RadixCiphertextDyn::Small(rhs)) => {
                let mut tmp_lhs: crate::integer::ciphertext::RadixCiphertextSmall;
                let mut tmp_rhs: crate::integer::ciphertext::RadixCiphertextSmall;

                // Clean carries to have a small wopbs to compute
                let (lhs, rhs) =
                    match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
                        (true, true) => (lhs, rhs),
                        (true, false) => {
                            tmp_rhs = rhs.clone();
                            sks.full_propagate_parallelized(&mut tmp_rhs);
                            (lhs, &tmp_rhs)
                        }
                        (false, true) => {
                            tmp_lhs = lhs.clone();
                            sks.full_propagate_parallelized(&mut tmp_lhs);
                            (&tmp_lhs, rhs)
                        }
                        (false, false) => {
                            tmp_lhs = lhs.clone();
                            tmp_rhs = rhs.clone();
                            rayon::join(
                                || sks.full_propagate_parallelized(&mut tmp_lhs),
                                || sks.full_propagate_parallelized(&mut tmp_rhs),
                            );
                            (&tmp_lhs, &tmp_rhs)
                        }
                    };

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

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub enum RadixCiphertextDyn {
    Big(crate::integer::RadixCiphertextBig),
    Small(crate::integer::RadixCiphertextSmall),
}

pub(super) trait ServerKeyDefaultNeg<Ciphertext> {
    type Output;
    fn neg(&self, lhs: Ciphertext) -> Self::Output;
}

macro_rules! define_default_server_key_op {
    ($op_name:ident) => {
        paste::paste! {
            pub trait [< ServerKeyDefault $op_name >]<Lhs, Rhs> {
                type Output;

                fn [< $op_name:lower >](
                    &self,
                    lhs: Lhs,
                    rhs: Rhs,
                ) -> Self::Output;
            }

            pub trait [< ServerKeyDefault $op_name Assign >]<Lhs, Rhs> {
                fn [< $op_name:lower _assign >](
                    &self,
                    lhs: &mut Lhs,
                    rhs: Rhs,
                );
            }
        }
    };
    ($($op:ident),*) => {
        $(
            define_default_server_key_op!($op);
        )*
    };
}

define_default_server_key_op!(
    Add, Sub, Mul, BitAnd, BitOr, BitXor, Shl, Shr, Eq, Ge, Gt, Le, Lt, Max, Min
);

impl ServerKeyDefaultNeg<&RadixCiphertextDyn> for crate::integer::ServerKey {
    type Output = RadixCiphertextDyn;

    fn neg(&self, lhs: &RadixCiphertextDyn) -> Self::Output {
        match lhs {
            RadixCiphertextDyn::Big(lhs) => RadixCiphertextDyn::Big(self.neg_parallelized(lhs)),
            RadixCiphertextDyn::Small(lhs) => RadixCiphertextDyn::Small(self.neg_parallelized(lhs)),
        }
    }
}

macro_rules! impl_default_op_for_tfhe_integer_server_key_dyn {
    ($default_trait:ident($default_trait_fn:ident) => $method:ident) => {
        impl $default_trait<&RadixCiphertextDyn, &RadixCiphertextDyn>
            for crate::integer::ServerKey
        {
            type Output = RadixCiphertextDyn;

            fn $default_trait_fn(
                &self,
                lhs_enum: &RadixCiphertextDyn,
                rhs_enum: &RadixCiphertextDyn,
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

macro_rules! impl_default_assign_op_for_tfhe_integer_server_key_dyn {
    ($default_trait:ident($default_trait_fn:ident) => $method_assign:ident) => {
        impl $default_trait<RadixCiphertextDyn, &RadixCiphertextDyn> for crate::integer::ServerKey {
            fn $default_trait_fn(
                &self,
                lhs_enum: &mut RadixCiphertextDyn,
                rhs_enum: &RadixCiphertextDyn,
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

macro_rules! impl_default_scalar_op_for_tfhe_integer_server_key_dyn {
    ($default_trait:ident($default_trait_fn:ident) => $method:ident) => {
        impl $default_trait<&RadixCiphertextDyn, u64> for crate::integer::ServerKey {
            type Output = RadixCiphertextDyn;

            fn $default_trait_fn(&self, lhs: &RadixCiphertextDyn, rhs: u64) -> Self::Output {
                let value: u64 = rhs.try_into().unwrap();
                match lhs {
                    RadixCiphertextDyn::Big(lhs) => {
                        RadixCiphertextDyn::Big(self.$method(lhs, value))
                    }
                    RadixCiphertextDyn::Small(lhs) => {
                        RadixCiphertextDyn::Small(self.$method(lhs, value))
                    }
                }
            }
        }
    };
}

macro_rules! impl_default_scalar_assign_op_for_tfhe_integer_server_key_dyn {
    ($default_trait:ident($default_trait_fn:ident) => $method_assign:ident) => {
        impl $default_trait<RadixCiphertextDyn, u64> for crate::integer::ServerKey {
            fn $default_trait_fn(&self, lhs: &mut RadixCiphertextDyn, rhs: u64) {
                let value: u64 = rhs.try_into().unwrap();
                match lhs {
                    RadixCiphertextDyn::Big(lhs) => self.$method_assign(lhs, value),
                    RadixCiphertextDyn::Small(lhs) => self.$method_assign(lhs, value),
                }
            }
        }
    };
}

impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultAdd(add) => add_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultSub(sub) => sub_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultMul(mul) => mul_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultBitAnd(bitand) => bitand_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultBitOr(bitor) => bitor_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultBitXor(bitxor) => bitxor_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultEq(eq) => eq_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultGe(ge) => ge_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultGt(gt) => gt_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultLe(le) => le_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultLt(lt) => lt_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultMax(max) => max_parallelized);
impl_default_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultMin(min) => min_parallelized);

impl_default_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultAddAssign(add_assign) => add_assign_parallelized);
impl_default_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultSubAssign(sub_assign) => sub_assign_parallelized);
impl_default_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultMulAssign(mul_assign) => mul_assign_parallelized);
impl_default_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultBitAndAssign(bitand_assign) => bitand_assign_parallelized);
impl_default_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultBitOrAssign(bitor_assign) => bitor_assign_parallelized);
impl_default_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultBitXorAssign(bitxor_assign) => bitxor_assign_parallelized);

impl_default_scalar_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultAdd(add) => scalar_add_parallelized);
impl_default_scalar_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultSub(sub) => scalar_sub_parallelized);
impl_default_scalar_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultMul(mul) => scalar_mul_parallelized);
impl_default_scalar_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultShl(shl) => scalar_left_shift_parallelized);
impl_default_scalar_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultShr(shr) => scalar_right_shift_parallelized);

impl_default_scalar_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultAddAssign(add_assign) => scalar_add_assign_parallelized);
impl_default_scalar_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultSubAssign(sub_assign) => scalar_sub_assign_parallelized);
impl_default_scalar_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultMulAssign(mul_assign) => scalar_mul_assign_parallelized);
impl_default_scalar_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultShlAssign(shl_assign) => scalar_left_shift_assign_parallelized);
impl_default_scalar_assign_op_for_tfhe_integer_server_key_dyn!(ServerKeyDefaultShrAssign(shr_assign) => scalar_right_shift_assign_parallelized);
