#[cfg(feature = "hpu-xfer")]
mod hpu_macro;
#[cfg(feature = "hpu-xfer")]
use hpu_macro::*;

#[cfg(feature = "hpu-xfer")]
crate::hpu_testbundle!("alus"::32 => [
    "adds",
    "subs",
    "ssub",
    "muls"
]);

#[cfg(feature = "hpu-xfer")]
crate::hpu_testbundle!("alu"::32 => [
    "add",
    "sub",
    "mul"
]);

#[cfg(feature = "hpu-xfer")]
crate::hpu_testbundle!("bitwise"::32 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

#[cfg(feature = "hpu-xfer")]
crate::hpu_testbundle!("cmp"::32 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);
