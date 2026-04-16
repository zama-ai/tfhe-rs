use crate::integer::bigint::{U1024, U2048, U256, U512};

/// Generates `FusedMulScalarDiv` impls for (encrypted * encrypted) / scalar.
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
            impl crate::high_level_api::traits::FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow> for &$fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_mul_scalar_div(
                    self,
                    mul: &$fhe_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    use crate::core_crypto::prelude::CastFrom;
                    let wide_self = <$fhe_wide>::cast_from(self.clone());
                    let wide_mul = <$fhe_wide>::cast_from(mul.clone());
                    let wide_product = &wide_self * &wide_mul;
                    let wide_result = wide_product / <$scalar_wide>::cast_from(div_scalar);
                    <$fhe_narrow>::cast_from(wide_result)
                }
            }

            // (enc * enc) / scalar (owned, owned)
            impl crate::high_level_api::traits::FusedMulScalarDiv<$fhe_narrow, $scalar_narrow> for $fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_mul_scalar_div(
                    self,
                    mul: $fhe_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    use crate::high_level_api::traits::FusedMulScalarDiv;
                    <&Self as FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow>>::fused_mul_scalar_div(&self, &mul, div_scalar)
                }
            }

            // (&enc * enc) / scalar (ref, owned)
            impl crate::high_level_api::traits::FusedMulScalarDiv<$fhe_narrow, $scalar_narrow> for &$fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_mul_scalar_div(
                    self,
                    mul: $fhe_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    use crate::high_level_api::traits::FusedMulScalarDiv;
                    <Self as FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow>>::fused_mul_scalar_div(self, &mul, div_scalar)
                }
            }

            // (enc * &enc) / scalar (owned, ref)
            impl crate::high_level_api::traits::FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow> for $fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_mul_scalar_div(
                    self,
                    mul: &$fhe_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    use crate::high_level_api::traits::FusedMulScalarDiv;
                    <&Self as FusedMulScalarDiv<&$fhe_narrow, $scalar_narrow>>::fused_mul_scalar_div(&self, mul, div_scalar)
                }
            }
        )*
    };
}
pub(crate) use impl_fused_mul_scalar_div;

/// Generates `FusedScalarMulScalarDiv` impls for (encrypted * scalar) / scalar.
///
/// Input tuple is of the form (NarrowFhe, WideFhe, NarrowScalar, WideScalar)`
/// Inputs are `NarrowFhe` and `NarrowScalar`, and get widened to `WideFhe` and `WideScalar`, mul
/// and div are computed on the widened values and result is truncated back down to `NarrowFhe`
macro_rules! impl_fused_scalar_mul_scalar_div {
    ($(
        ($fhe_narrow:ty, $fhe_wide:ty, $scalar_narrow:ty, $scalar_wide:ty)
    ),* $(,)?) => {
        $(
            // (&enc * scalar) / scalar (ref, main impl)
            impl crate::high_level_api::traits::FusedScalarMulScalarDiv<$scalar_narrow> for &$fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_scalar_mul_scalar_div(
                    self,
                    mul_scalar: $scalar_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    use crate::core_crypto::prelude::CastFrom;
                    let wide_self = <$fhe_wide>::cast_from(self.clone());
                    let wide_product = wide_self * <$scalar_wide>::cast_from(mul_scalar);
                    let wide_result = wide_product / <$scalar_wide>::cast_from(div_scalar);
                    <$fhe_narrow>::cast_from(wide_result)
                }
            }

            // (enc * scalar) / scalar (owned)
            impl crate::high_level_api::traits::FusedScalarMulScalarDiv<$scalar_narrow> for $fhe_narrow {
                type Output = $fhe_narrow;

                fn fused_scalar_mul_scalar_div(
                    self,
                    mul_scalar: $scalar_narrow,
                    div_scalar: $scalar_narrow,
                ) -> Self::Output {
                    use crate::high_level_api::traits::FusedScalarMulScalarDiv;
                    <&Self as FusedScalarMulScalarDiv<$scalar_narrow>>::fused_scalar_mul_scalar_div(&self, mul_scalar, div_scalar)
                }
            }
        )*
    };
}
pub(crate) use impl_fused_scalar_mul_scalar_div;

macro_rules! impl_fused_mul_divs {
    ($(
        ($fhe_narrow:ty, $fhe_wide:ty, $scalar_narrow:ty, $scalar_wide:ty)
    ),* $(,)?) => {
        crate::high_level_api::integers::unsigned::fused_ops::impl_fused_mul_scalar_div!($(
            ($fhe_narrow, $fhe_wide, $scalar_narrow, $scalar_wide),
        )*);
        crate::high_level_api::integers::unsigned::fused_ops::impl_fused_scalar_mul_scalar_div!($(
            ($fhe_narrow, $fhe_wide, $scalar_narrow, $scalar_wide),
        )*);
    }
}
pub(crate) use impl_fused_mul_divs;

// Standard types (always available)
//
// (NarrowFhe, WideFhe, NarrowScalar, WideScalar)
//
// Types without at least double-width FheUint (FheUint2048) are not supported.
impl_fused_mul_divs!(
    (super::FheUint2, super::FheUint4, u8, u8),
    (super::FheUint4, super::FheUint8, u8, u8),
    (super::FheUint6, super::FheUint12, u8, u16),
    (super::FheUint8, super::FheUint16, u8, u16),
    (super::FheUint10, super::FheUint32, u16, u32),
    (super::FheUint12, super::FheUint32, u16, u32),
    (super::FheUint14, super::FheUint32, u16, u32),
    (super::FheUint16, super::FheUint32, u16, u32),
    (super::FheUint32, super::FheUint64, u32, u64),
    (super::FheUint64, super::FheUint128, u64, u128),
    (super::FheUint128, super::FheUint256, u128, U256),
    (super::FheUint160, super::FheUint512, U256, U512),
    (super::FheUint256, super::FheUint512, U256, U512),
    (super::FheUint512, super::FheUint1024, U512, U1024),
    (super::FheUint1024, super::FheUint2048, U1024, U2048),
);

#[cfg(feature = "extended-types")]
impl_fused_mul_divs!(
    (super::FheUint24, super::FheUint48, u32, u64),
    (super::FheUint40, super::FheUint80, u64, u128),
    (super::FheUint48, super::FheUint96, u64, u128),
    (super::FheUint56, super::FheUint112, u64, u128),
    (super::FheUint72, super::FheUint144, u128, U256),
    (super::FheUint80, super::FheUint160, u128, U256),
    (super::FheUint88, super::FheUint176, u128, U256),
    (super::FheUint96, super::FheUint192, u128, U256),
    (super::FheUint104, super::FheUint208, u128, U256),
    (super::FheUint112, super::FheUint224, u128, U256),
    (super::FheUint120, super::FheUint240, u128, U256),
    (super::FheUint136, super::FheUint512, U256, U512),
    (super::FheUint144, super::FheUint512, U256, U512),
    (super::FheUint152, super::FheUint512, U256, U512),
    (super::FheUint168, super::FheUint512, U256, U512),
    (super::FheUint176, super::FheUint512, U256, U512),
    (super::FheUint184, super::FheUint512, U256, U512),
    (super::FheUint192, super::FheUint512, U256, U512),
    (super::FheUint200, super::FheUint512, U256, U512),
    (super::FheUint208, super::FheUint512, U256, U512),
    (super::FheUint216, super::FheUint512, U256, U512),
    (super::FheUint224, super::FheUint512, U256, U512),
    (super::FheUint232, super::FheUint512, U256, U512),
    (super::FheUint240, super::FheUint512, U256, U512),
    (super::FheUint248, super::FheUint512, U256, U512),
);
