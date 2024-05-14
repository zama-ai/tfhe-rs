use crate::high_level_api::global_state::with_cpu_internal_keys;
use crate::high_level_api::integers::FheUintId;
use crate::{FheBool, FheUint};

pub fn fhe_uint_array_eq<Id: FheUintId>(lhs: &[FheUint<Id>], rhs: &[FheUint<Id>]) -> FheBool {
    with_cpu_internal_keys(|cpu_keys| {
        let tmp_lhs = lhs
            .iter()
            .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
            .collect::<Vec<_>>();
        let tmp_rhs = rhs
            .iter()
            .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
            .collect::<Vec<_>>();

        let result = cpu_keys
            .pbs_key()
            .all_eq_slices_parallelized(&tmp_lhs, &tmp_rhs);
        FheBool::new(result)
    })
}

pub fn fhe_uint_array_contains_sub_slice<Id: FheUintId>(
    lhs: &[FheUint<Id>],
    pattern: &[FheUint<Id>],
) -> FheBool {
    with_cpu_internal_keys(|cpu_keys| {
        let tmp_lhs = lhs
            .iter()
            .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
            .collect::<Vec<_>>();
        let tmp_pattern = pattern
            .iter()
            .map(|fhe_uint| fhe_uint.ciphertext.on_cpu().to_owned())
            .collect::<Vec<_>>();

        let result = cpu_keys
            .pbs_key()
            .contains_sub_slice_parallelized(&tmp_lhs, &tmp_pattern);
        FheBool::new(result)
    })
}
