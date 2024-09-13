mod hpu_macro;
use hpu_macro::*;

// NB: Currently Scalar operation arn't correctly supported due to offline code generation
// TODO Fixme
// crate::hpu_testbundle!("alus"::32 => [
//     "adds",
//     "subs",
//     "ssub",
//     "muls"
// ]);

crate::hpu_testbundle!("alu"::32 => [
    "add",
    "sub",
    "mul"
]);

crate::hpu_testbundle!("bitwise"::32 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

crate::hpu_testbundle!("cmp"::32 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);
