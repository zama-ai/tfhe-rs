mod booleans;
mod signed;
mod unsigned;

use crate::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheId};
#[cfg(feature = "gpu")]
use crate::{Config, CudaServerKey};
use rand::distributions::{Distribution, Standard};
use rand::random;
use std::fmt::Debug;

use crate::array::traits::IOwnedArray;
use crate::array::ClearArray;
use crate::high_level_api::array::{FheBackendArray, FheBackendArraySlice};
use crate::prelude::{FheDecrypt, FheTryEncrypt};
use std::ops::{BitAnd, BitOr, BitXor};

#[cfg(feature = "gpu")]
pub(crate) fn generate_cuda_keys<C: Into<Config>>(config: C) -> (ClientKey, CudaServerKey) {
    let client_kc = ClientKey::generate(config);
    let server_kc = client_kc.generate_compressed_server_key();
    let cuda_server_kc = server_kc.decompress_to_gpu();

    (client_kc, cuda_server_kc)
}
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

#[cfg(feature = "gpu")]
fn setup_default_gpu() -> ClientKey {
    let config = ConfigBuilder::default().build();
    let (ck, sk) = generate_cuda_keys(config);
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
