use crate::high_level_api::integers::unsigned::fused_ops::impl_fused_mul_divs;
use crate::integer::bigint::{I1024, I2048, I256, I512};

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
