use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::bitonic_shuffle::{
    bitonic_network, BitonicShuffleKeySize,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, SignedRadixCiphertext};
use crate::shortint::parameters::TestParameters;
use rand::Rng;
use std::sync::Arc;
use tfhe_csprng::seeders::Seed;

/// Clear reference: sorts signed data by unsigned keys using the same bitonic network
/// as `ServerKey::bitonic_shuffle_with_keys`.
fn clear_signed_bitonic_shuffle_with_keys(data: &[i32], keys: &[u32]) -> Vec<i32> {
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
        data.push(0i32);
    }

    let network = bitonic_network(padded_n);
    for stage in &network {
        let swaps: Vec<_> = stage
            .iter()
            .map(|&(i, j, ascending)| {
                // Mirror the GPU backend: ascending uses strict gt, descending swaps on
                // lt-or-equal so that equal keys end up on the same branch on both sides.
                let should_swap = if ascending {
                    keys[i] > keys[j]
                } else {
                    keys[i] <= keys[j]
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

/// Number of blocks used to encrypt the data values in the parameterized tests.
const NUM_DATA_BLOCKS: usize = 16;

pub(crate) fn signed_bitonic_shuffle_with_keys_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (Vec<SignedRadixCiphertext>, Vec<RadixCiphertext>),
        Result<Vec<SignedRadixCiphertext>, crate::Error>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NUM_DATA_BLOCKS));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::thread_rng();

    for &len in &[2usize, 3, 5, 8, 9] {
        let clear_keys: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let mut clear_data: Vec<i32> = (0..len).map(|_| rng.gen::<i32>()).collect();

        let enc_keys: Vec<RadixCiphertext> = clear_keys
            .iter()
            .map(|&v| cks.encrypt(u64::from(v)))
            .collect();
        let enc_data: Vec<SignedRadixCiphertext> = clear_data
            .iter()
            .map(|&v| cks.encrypt_signed(i64::from(v)))
            .collect();

        let result = executor.execute((enc_data, enc_keys)).unwrap();

        let mut decrypted: Vec<i32> = result
            .iter()
            .map(|ct| cks.decrypt_signed::<i64>(ct) as i32)
            .collect();

        let expected = clear_signed_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected, "len={len}");

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "len={len} permutation lost data");
    }
}

pub(crate) fn signed_unchecked_bitonic_shuffle_with_keys_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (Vec<SignedRadixCiphertext>, Vec<RadixCiphertext>),
        Vec<SignedRadixCiphertext>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NUM_DATA_BLOCKS));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::thread_rng();

    for &len in &[2usize, 3, 5, 8, 9] {
        let clear_keys: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let mut clear_data: Vec<i32> = (0..len).map(|_| rng.gen::<i32>()).collect();

        let enc_keys: Vec<RadixCiphertext> = clear_keys
            .iter()
            .map(|&v| cks.encrypt(u64::from(v)))
            .collect();
        let enc_data: Vec<SignedRadixCiphertext> = clear_data
            .iter()
            .map(|&v| cks.encrypt_signed(i64::from(v)))
            .collect();

        let result = executor.execute((enc_data, enc_keys));

        let mut decrypted: Vec<i32> = result
            .iter()
            .map(|ct| cks.decrypt_signed::<i64>(ct) as i32)
            .collect();

        let expected = clear_signed_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected, "len={len}");

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "len={len} permutation lost data");
    }
}

pub(crate) fn signed_bitonic_shuffle_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (Vec<SignedRadixCiphertext>, BitonicShuffleKeySize, Seed),
        Result<Vec<SignedRadixCiphertext>, crate::Error>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NUM_DATA_BLOCKS));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::thread_rng();

    for &len in &[2usize, 3, 5, 8, 9] {
        let mut clear_data: Vec<i32> = (0..len).map(|_| rng.gen::<i32>()).collect();
        let enc_data: Vec<SignedRadixCiphertext> = clear_data
            .iter()
            .map(|&v| cks.encrypt_signed(i64::from(v)))
            .collect();

        let result = executor
            .execute((
                enc_data,
                BitonicShuffleKeySize::num_bits(32),
                Seed(0xCAFE_BABE),
            ))
            .expect("bitonic_shuffle returned an error");
        let mut decrypted: Vec<i32> = result
            .iter()
            .map(|ct| cks.decrypt_signed::<i64>(ct) as i32)
            .collect();

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "len={len} permutation lost data");
    }
}
