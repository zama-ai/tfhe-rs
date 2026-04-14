use crate::core_crypto::prelude::CastFrom;
use crate::high_level_api::traits::{FusedMulScalarDiv, FusedScalarMulScalarDiv};
use crate::integer::bigint::{I1024, I2048, I256, I512};

/// Generates `FusedMulScalarDiv` impls for (encrypted * encrypted) / scalar. (signed)
///
/// Input tuple is of the form (NarrowFhe, WideFhe, NarrowScalar, WideScalar)`
/// Inputs are `NarrowFhe` and `NarrowScalar`, and get widened to `WideFhe` and `WideScalar`, mul
/// and div are computed on the widened values and result is truncated back down to `NarrowFhe`
macro_rules! impl_fused_mul_scalar_div {
    ($(
        ($fhe_narrow:ty, $fhe_wide:ty, $scalar_narrow:ty, $scalar_wide:ty)
    ),* $(,)?) => {
        $(
            // (&enc * &enc) / scalar (ref, ref, main impl)
            impl FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow> for &$fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_mul_scalar_div(
                    self,
                    mul: &$fhe_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    let wide_self = <$fhe_wide>::cast_from(self.clone());
                    let wide_mul = <$fhe_wide>::cast_from(mul.clone());
                    let wide_product = &wide_self * &wide_mul;
                    let wide_result = wide_product / <$scalar_wide>::cast_from(div_scalar);
                    <$fhe_narrow>::cast_from(wide_result)
                }
            }

            // (enc * enc) / scalar (owned, owned)
            impl FusedMulScalarDiv<$fhe_narrow, $scalar_narrow> for $fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_mul_scalar_div(
                    self,
                    mul: $fhe_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    <&Self as FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow>>::fused_mul_scalar_div(&self, &mul, div_scalar)
                }
            }

            // (&enc * enc) / scalar (ref, owned)
            impl FusedMulScalarDiv<$fhe_narrow, $scalar_narrow> for &$fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_mul_scalar_div(
                    self,
                    mul: $fhe_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    <Self as FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow>>::fused_mul_scalar_div(self, &mul, div_scalar)
                }
            }

            // (enc * &enc) / scalar (owned, ref)
            impl FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow> for $fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_mul_scalar_div(
                    self,
                    mul: &$fhe_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    <&Self as FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow>>::fused_mul_scalar_div(&self, mul, div_scalar)
                }
            }
        )*
    };
}

/// Generates `FusedScalarMulScalarDiv` impls for (encrypted * scalar) / scalar (signed).
///
/// Input tuple is of the form (NarrowFhe, WideFhe, NarrowScalar, WideScalar)`
/// Inputs are `NarrowFhe` and `NarrowScalar`, and get widened to `WideFhe` and `WideScalar`, mul
/// and div are computed on the widened values and result is truncated back down to `NarrowFhe`
macro_rules! impl_fused_scalar_mul_scalar_div {
    ($(
        ($fhe_narrow:ty, $fhe_wide:ty, $scalar_narrow:ty, $scalar_wide:ty)
    ),* $(,)?) => {
        $(
            // (&enc * scalar) / scalar (main impl)
            impl FusedScalarMulScalarDiv<$scalar_narrow> for &$fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_scalar_mul_scalar_div(
                    self,
                    mul_scalar: $scalar_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    let wide_self = <$fhe_wide>::cast_from(self.clone());
                    let wide_product = wide_self * <$scalar_wide>::cast_from(mul_scalar);
                    let wide_result = wide_product / <$scalar_wide>::cast_from(div_scalar);
                    <$fhe_narrow>::cast_from(wide_result)
                }
            }

            // (enc * scalar) / scalar (owned)
            impl FusedScalarMulScalarDiv<$scalar_narrow> for $fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_scalar_mul_scalar_div(
                    self,
                    mul_scalar: $scalar_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    <&Self as FusedScalarMulScalarDiv<$scalar_narrow>>::fused_scalar_mul_scalar_div(&self, mul_scalar, div_scalar)
                }
            }
        )*
    };
}

macro_rules! impl_fused_mul_divs {
    ($(
        ($fhe_narrow:ty, $fhe_wide:ty, $scalar_narrow:ty, $scalar_wide:ty)
    ),* $(,)?) => {
        impl_fused_mul_scalar_div!($(
            ($fhe_narrow, $fhe_wide, $scalar_narrow, $scalar_wide),
        )*);
        impl_fused_scalar_mul_scalar_div!($(
            ($fhe_narrow, $fhe_wide, $scalar_narrow, $scalar_wide),
        )*);
    }
}

// Standard types (always available)
//
// (NarrowFhe, WideFhe, NarrowScalar, WideScalar)
//
// Types without at least double-width FheInt (FheInt2048) are not supported.
impl_fused_mul_divs!(
    (super::FheInt2, super::FheInt4, i8, i8),
    (super::FheInt4, super::FheInt8, i8, i8),
    (super::FheInt6, super::FheInt12, i8, i16),
    (super::FheInt8, super::FheInt16, i8, i16),
    (super::FheInt10, super::FheInt32, i16, i32),
    (super::FheInt12, super::FheInt32, i16, i32),
    (super::FheInt14, super::FheInt32, i16, i32),
    (super::FheInt16, super::FheInt32, i16, i32),
    (super::FheInt32, super::FheInt64, i32, i64),
    (super::FheInt64, super::FheInt128, i64, i128),
    (super::FheInt128, super::FheInt256, i128, I256),
    (super::FheInt160, super::FheInt512, I256, I512),
    (super::FheInt256, super::FheInt512, I256, I512),
    (super::FheInt512, super::FheInt1024, I512, I1024),
    (super::FheInt1024, super::FheInt2048, I1024, I2048),
);

#[cfg(feature = "extended-types")]
impl_fused_mul_divs!(
    (super::FheInt24, super::FheInt48, i32, i64),
    (super::FheInt40, super::FheInt80, i64, i128),
    (super::FheInt48, super::FheInt96, i64, i128),
    (super::FheInt56, super::FheInt112, i64, i128),
    (super::FheInt72, super::FheInt144, i128, I256),
    (super::FheInt80, super::FheInt160, i128, I256),
    (super::FheInt88, super::FheInt176, i128, I256),
    (super::FheInt96, super::FheInt192, i128, I256),
    (super::FheInt104, super::FheInt208, i128, I256),
    (super::FheInt112, super::FheInt224, i128, I256),
    (super::FheInt120, super::FheInt240, i128, I256),
    (super::FheInt136, super::FheInt512, I256, I512),
    (super::FheInt144, super::FheInt512, I256, I512),
    (super::FheInt152, super::FheInt512, I256, I512),
    (super::FheInt168, super::FheInt512, I256, I512),
    (super::FheInt176, super::FheInt512, I256, I512),
    (super::FheInt184, super::FheInt512, I256, I512),
    (super::FheInt192, super::FheInt512, I256, I512),
    (super::FheInt200, super::FheInt512, I256, I512),
    (super::FheInt208, super::FheInt512, I256, I512),
    (super::FheInt216, super::FheInt512, I256, I512),
    (super::FheInt224, super::FheInt512, I256, I512),
    (super::FheInt232, super::FheInt512, I256, I512),
    (super::FheInt240, super::FheInt512, I256, I512),
    (super::FheInt248, super::FheInt512, I256, I512),
);
