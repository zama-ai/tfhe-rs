#[cfg(feature = "hpu-xfer")]
mod hpu_macro;
#[cfg(feature = "hpu-xfer")]
use hpu_macro::*;

// #[cfg(feature = "hpu-xfer")]
// NB: Currently Scalar operation arn't correctly supported due to offline code generation
// TODO Fixme
// crate::hpu_testbundle!("alus"::64 => [
//     "adds",
//     "subs",
//     "ssub",
//     "muls"
// ]);

#[cfg(feature = "hpu-xfer")]
crate::hpu_testbundle!("alu"::64 => [
    "add",
    "sub",
    "mul"
]);

#[cfg(feature = "hpu-xfer")]
crate::hpu_testbundle!("bitwise"::64 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

#[cfg(feature = "hpu-xfer")]
crate::hpu_testbundle!("cmp"::64 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);
