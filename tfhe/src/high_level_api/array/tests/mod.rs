mod booleans;
mod signed;
mod unsigned;

use crate::high_level_api::array::fhe_array_contains;
use crate::high_level_api::integers::FheIntegerType;
use crate::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheId};
use rand::distributions::{Distribution, Standard};
use rand::random;
use std::fmt::Debug;

use crate::array::traits::IOwnedArray;
use crate::array::ClearArray;
use crate::high_level_api::array::{FheBackendArray, FheBackendArraySlice};
use crate::prelude::{FheDecrypt, FheEncrypt, FheTryEncrypt};
use std::ops::{BitAnd, BitOr, BitXor};

fn draw_random_values<T>(num_values: usize) -> Vec<T>
where
    Standard: Distribution<T>,
{
    (0..num_values).map(|_| random()).collect()
}

fn setup_default_cpu() -> ClientKey {
    let config = ConfigBuilder::default().build();
    let (ck, sk) = generate_keys(config);
    set_server_key(sk);

    ck
}

fn bitand_test_case<Id, Backend, Clear>(ck: &ClientKey)
where
    Id: FheId,
    Backend: crate::high_level_api::array::ArrayBackend,
    Standard: Distribution<Clear>,
    Clear: BitAnd<Clear, Output = Clear> + Copy + Eq + Debug,
    FheBackendArray<Backend, Id>: Clone
        + for<'a> FheTryEncrypt<&'a [Clear], ClientKey>
        + FheDecrypt<Vec<Clear>>
        + BitAnd<FheBackendArray<Backend, Id>, Output = FheBackendArray<Backend, Id>>
        + for<'a> BitAnd<&'a FheBackendArray<Backend, Id>, Output = FheBackendArray<Backend, Id>>,
    // for all 4 possible slice ops
    for<'a> FheBackendArraySlice<'a, Backend, Id>:
        BitAnd<FheBackendArraySlice<'a, Backend, Id>, Output = FheBackendArray<Backend, Id>>,
    for<'a> &'a FheBackendArray<Backend, Id>: BitAnd<FheBackendArray<Backend, Id>, Output = FheBackendArray<Backend, Id>>
        + BitAnd<&'a FheBackendArray<Backend, Id>, Output = FheBackendArray<Backend, Id>>
        // for the 2 tested slice/array ops
        + BitAnd<FheBackendArraySlice<'a, Backend, Id>, Output = FheBackendArray<Backend, Id>>
        + BitAnd<&'a FheBackendArray<Backend, Id>, Output = FheBackendArray<Backend, Id>>,
    for<'a> FheBackendArraySlice<'a, Backend, Id>:
        BitAnd<&'a FheBackendArray<Backend, Id>, Output = FheBackendArray<Backend, Id>>,
{
    let num_values = 5;
    let clear_lhs = draw_random_values::<Clear>(num_values);
    let clear_rhs = draw_random_values::<Clear>(num_values);
    let expected_result = clear_lhs
        .iter()
        .zip(clear_rhs.iter())
        .map(|(&lhs, &rhs)| lhs & rhs)
        .collect::<Vec<_>>();

    let lhs = FheBackendArray::<Backend, Id>::try_encrypt(&clear_lhs, ck).unwrap();
    let rhs = FheBackendArray::<Backend, Id>::try_encrypt(&clear_rhs, ck).unwrap();

    // Working on slice type
    {
        let lhs_slice = lhs.as_slice();
        let rhs_slice = rhs.as_slice();

        let result = (lhs_slice & rhs_slice).decrypt(ck);
        assert_eq!(result, expected_result);
    }

    // Mixing array and slice
    {
        let lhs_slice = lhs.as_slice();
        let rhs_slice = rhs.as_slice();

        let result = (&lhs & rhs_slice).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs_slice & &rhs).decrypt(ck);
        assert_eq!(result, expected_result);
    }

    // Working on array type
    {
        let result = (&lhs & &rhs).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (&lhs & rhs.clone()).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs.clone() & &rhs).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs & rhs).decrypt(ck);
        assert_eq!(result, expected_result);
    }
}

fn bitor_test_case<Array, Clear>(ck: &ClientKey)
where
    Standard: Distribution<Clear>,
    Clear: BitOr<Clear, Output = Clear> + Copy + Eq + Debug,
    Array: IOwnedArray
        + for<'a> FheTryEncrypt<&'a [Clear], ClientKey>
        + FheDecrypt<Vec<Clear>>
        + BitOr<Array, Output = Array>
        + for<'a> BitOr<&'a Array, Output = Array>,
    for<'a> &'a Array: BitOr<Array, Output = Array>
        + BitOr<&'a Array, Output = Array>
        + BitOr<Array::Slice<'a>, Output = Array>,
    // Bounds for slicing tests
    for<'a, 'b> Array::Slice<'a>: BitOr<Array::Slice<'a>, Output = Array>,
    // for the 2 tested slice/array ops
    for<'a, 'b> Array::Slice<'a>: BitOr<&'b Array, Output = Array>,
{
    let num_values = 5;
    let clear_lhs = draw_random_values::<Clear>(num_values);
    let clear_rhs = draw_random_values::<Clear>(num_values);
    let expected_result = clear_lhs
        .iter()
        .zip(clear_rhs.iter())
        .map(|(&lhs, &rhs)| lhs | rhs)
        .collect::<Vec<_>>();

    let lhs = Array::try_encrypt(&clear_lhs, ck).unwrap();
    let rhs = Array::try_encrypt(&clear_rhs, ck).unwrap();

    // Working on slice type
    {
        let lhs_slice = lhs.as_slice();
        let rhs_slice = rhs.as_slice();

        let result = (lhs_slice | rhs_slice).decrypt(ck);
        assert_eq!(result, expected_result);
    }

    // Mixing array and slice
    {
        let lhs_slice = lhs.as_slice();
        let rhs_slice = rhs.as_slice();

        let result = (&lhs | rhs_slice).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs_slice | &rhs).decrypt(ck);
        assert_eq!(result, expected_result);
    }

    // Working on array type
    {
        let result = (&lhs | &rhs).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (&lhs | rhs.clone()).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs.clone() | &rhs).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs | rhs).decrypt(ck);
        assert_eq!(result, expected_result);
    }
}

fn bitxor_test_case<Array, Clear>(ck: &ClientKey)
where
    Standard: Distribution<Clear>,
    Clear: Copy + BitXor<Clear, Output = Clear> + Eq + Debug,
    Array: IOwnedArray
        + for<'a> FheTryEncrypt<&'a [Clear], ClientKey>
        + FheDecrypt<Vec<Clear>>
        + BitXor<Array, Output = Array>
        + for<'a> BitXor<&'a Array, Output = Array>,
    for<'a> &'a Array: BitXor<Array, Output = Array>
        + BitXor<&'a Array, Output = Array>
        + BitXor<Array::Slice<'a>, Output = Array>,
    // Bounds for slicing tests
    for<'a, 'b> Array::Slice<'a>: BitXor<Array::Slice<'a>, Output = Array>,
    // for the 2 tested slice/array ops
    for<'a, 'b> Array::Slice<'a>: BitXor<&'b Array, Output = Array>,
{
    let num_values = 5;
    let clear_lhs = draw_random_values::<Clear>(num_values);
    let clear_rhs = draw_random_values::<Clear>(num_values);
    let expected_result = clear_lhs
        .iter()
        .zip(clear_rhs.iter())
        .map(|(&lhs, &rhs)| lhs ^ rhs)
        .collect::<Vec<_>>();

    let lhs = Array::try_encrypt(&clear_lhs, ck).unwrap();
    let rhs = Array::try_encrypt(&clear_rhs, ck).unwrap();

    // Working on slice type
    {
        let lhs_slice = lhs.as_slice();
        let rhs_slice = rhs.as_slice();

        let result = (lhs_slice ^ rhs_slice).decrypt(ck);
        assert_eq!(result, expected_result);
    }

    // Mixing array and slice
    {
        let lhs_slice = lhs.as_slice();
        let rhs_slice = rhs.as_slice();

        let result = (&lhs ^ rhs_slice).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs_slice ^ &rhs).decrypt(ck);
        assert_eq!(result, expected_result);
    }

    // Working on array type
    {
        let result = (&lhs ^ &rhs).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (&lhs ^ rhs.clone()).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs.clone() ^ &rhs).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs ^ rhs).decrypt(ck);
        assert_eq!(result, expected_result);
    }
}

fn bitand_scalar_slice_test_case<Array, Clear>(ck: &ClientKey)
where
    Standard: Distribution<Clear>,
    Clear: Copy + BitAnd<Clear, Output = Clear> + Eq + Debug,
    Array: IOwnedArray
        + for<'a> FheTryEncrypt<&'a [Clear], ClientKey>
        + FheDecrypt<Vec<Clear>>
        + for<'a> BitAnd<&'a ClearArray<Clear>, Output = Array>,
    for<'a> &'a Array: BitAnd<&'a ClearArray<Clear>, Output = Array>,
    for<'a, 'b> Array::Slice<'a>: BitAnd<&'b ClearArray<Clear>, Output = Array>,
{
    let num_values = 5;
    let clear_lhs = draw_random_values::<Clear>(num_values);
    let clear_rhs = draw_random_values::<Clear>(num_values);
    let expected_result = clear_lhs
        .iter()
        .zip(clear_rhs.iter())
        .map(|(&lhs, &rhs)| lhs & rhs)
        .collect::<Vec<_>>();

    let lhs = Array::try_encrypt(&clear_lhs, ck).unwrap();
    let rhs = ClearArray::new(clear_rhs, vec![clear_lhs.len()]);

    // Working on slice type
    {
        let lhs_slice = lhs.as_slice();

        let result = (lhs_slice & &rhs).decrypt(ck);
        assert_eq!(result, expected_result);
    }

    // Working on array type
    {
        let result = (&lhs & &rhs).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs.clone() & &rhs).decrypt(ck);
        assert_eq!(result, expected_result);

        let result = (lhs & &rhs).decrypt(ck);
        assert_eq!(result, expected_result);
    }
}

fn test_case_contains<T, Clear>(ck: &ClientKey)
where
    T: FheIntegerType + FheEncrypt<Clear, ClientKey>,
    Standard: Distribution<Clear>,
    Clear: Copy + Eq,
{
    let values = draw_random_values::<Clear>(5);

    // Pick one element that is guaranteed to be in the slice
    let present_value = values[random::<usize>() % values.len()];

    // Generate an absent value that is not in the slice
    let absent_value = loop {
        let candidate: Clear = random();
        if !values.contains(&candidate) {
            break candidate;
        }
    };

    let data: Vec<T> = values.iter().map(|&v| T::encrypt(v, ck)).collect();

    let present = T::encrypt(present_value, ck);
    let result: bool = fhe_array_contains(&data, &present).decrypt(ck);
    assert!(result);

    let absent = T::encrypt(absent_value, ck);
    let result: bool = fhe_array_contains(&data, &absent).decrypt(ck);
    assert!(!result);

    // Test with a duplicated value in the slice
    let mut values_with_dup = values.clone();
    values_with_dup.push(values[0]);
    let data_with_dup: Vec<T> = values_with_dup.iter().map(|&v| T::encrypt(v, ck)).collect();

    let present_dup = T::encrypt(values[0], ck);
    let result: bool = fhe_array_contains(&data_with_dup, &present_dup).decrypt(ck);
    assert!(result);
}
