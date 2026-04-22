use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::bitonic_shuffle::bitonic_network;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

/// Clear reference: sorts data by keys using the same bitonic network
/// as `ServerKey::bitonic_shuffle_with_keys`.
fn clear_bitonic_shuffle_with_keys(data: &[u32], keys: &[u32]) -> Vec<u32> {
    assert_eq!(data.len(), keys.len());
    let n = data.len();
    if n <= 1 {
        return data.to_vec();
    }

    let padded_n = n.next_power_of_two();
    let mut keys = keys.iter().copied().map(u64::from).collect::<Vec<_>>();
    let mut data = data.to_vec();

    // Pad with MAX keys and zero data, so padding sorts to the end and is truncated
    for _ in 0..(padded_n - n) {
        keys.push(u64::MAX);
        data.push(0u32);
    }

    let network = bitonic_network(padded_n);
    for stage in &network {
        let swaps: Vec<_> = stage
            .iter()
            .map(|&(i, j, ascending)| {
                let should_swap = if ascending {
                    keys[i] > keys[j]
                } else {
                    keys[i] < keys[j]
                };
                (i, j, should_swap)
            })
            .collect();

        for (i, j, should_swap) in swaps {
            if should_swap {
                keys.swap(i, j);
                data.swap(i, j);
            }
        }
    }

    data.truncate(n);
    data
}

create_parameterized_test!(integer_bitonic_shuffle_with_keys);

fn integer_bitonic_shuffle_with_keys<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::bitonic_shuffle_with_keys::<RadixCiphertext>);
    bitonic_shuffle_with_keys_test(param, executor);
}

pub(crate) fn bitonic_shuffle_with_keys_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (Vec<RadixCiphertext>, Vec<RadixCiphertext>),
        Result<Vec<RadixCiphertext>, crate::Error>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_blocks = 32usize.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let cks = RadixClientKey::from((cks, num_blocks));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::thread_rng();

    for _ in 0..4 {
        let len = rng.gen_range(1..=16usize).next_power_of_two();
        let clear_keys: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        println!("clear_keys: {clear_keys:?}, clear_data: {clear_data:?}");

        let enc_keys = clear_keys.iter().map(|&v| cks.encrypt(v as u64)).collect();
        let enc_data = clear_data.iter().map(|&v| cks.encrypt(v as u64)).collect();

        let result = executor.execute((enc_data, enc_keys)).unwrap();

        let mut decrypted: Vec<u32> = result
            .iter()
            .map(|ct| cks.decrypt::<u64>(ct) as u32)
            .collect();

        // Check the encrypted implementation matches the clear one
        let expected = clear_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected);

        // Check that the permutation did not lose any of the data
        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "permutation lost data");
    }

    {
        let len = 17;
        let mut clear_keys: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        clear_keys[3] = u32::MAX;
        assert!(!clear_keys.len().is_power_of_two());
        println!("clear_keys: {clear_keys:?}, clear_data: {clear_data:?}");

        let enc_keys = clear_keys.iter().map(|&v| cks.encrypt(v as u64)).collect();
        let enc_data = clear_data.iter().map(|&v| cks.encrypt(v as u64)).collect();

        let result = executor.execute((enc_data, enc_keys)).unwrap();

        let mut decrypted: Vec<u32> = result
            .iter()
            .map(|ct| cks.decrypt::<u64>(ct) as u32)
            .collect();

        // Check the encrypted implementation matches the clear one
        let expected = clear_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected);

        // Check that the permutation did not lose any of the data
        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "permutation lost data");
    }
}
