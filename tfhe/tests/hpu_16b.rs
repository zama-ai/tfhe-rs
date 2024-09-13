mod hpu_macro;
use hpu_macro::*;

// NB: Currently Scalar operation arn't correctly supported due to offline code generation
// TODO Fixme
// crate::hpu_testbundle!("alus"::16 => [
//     "adds",
//     "subs",
//     "ssub",
//     "muls"
// ]);

crate::hpu_testbundle!("alu"::16 => [
    "add",
    "sub",
    "mul"
]);

crate::hpu_testbundle!("bitwise"::16 => [
    "bw_and",
    "bw_or",
    "bw_xor"
]);

crate::hpu_testbundle!("cmp"::16 => [
    "cmp_gt",
    "cmp_gte",
    "cmp_lt",
    "cmp_lte",
    "cmp_eq",
    "cmp_neq"
]);
