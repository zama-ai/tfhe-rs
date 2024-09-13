mod hpu_macro;
use hpu_macro::*;

// NB: Currently Scalar operation arn't correctly supported due to offline code generation
// TODO Fixme
// crate::hpu_testbundle!("alus"::64 => [
//     "adds",
//     "subs",
//     "ssub",
//     "muls"
// ]);

crate::hpu_testbundle!("alu"::64 => [
    "add",
    "sub",
    "mul"
]);

crate::hpu_testbundle!("bitwise"::64 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

crate::hpu_testbundle!("cmp"::64 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);
