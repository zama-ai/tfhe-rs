use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::bitonic_shuffle::{
    bitonic_network, BitonicShuffleKeySize,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::TestParameters;
use rand::Rng;
use std::sync::Arc;
use tfhe_csprng::seeders::Seed;

/// Clear reference: sorts data by keys using the same bitonic network
/// as `ServerKey::bitonic_shuffle_with_keys`.
pub(crate) fn clear_bitonic_shuffle_with_keys(data: &[u32], keys: &[u32]) -> Vec<u32> {
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

pub(crate) fn bitonic_shuffle_with_keys_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: FunctionExecutor<
        (Vec<RadixCiphertext>, Vec<RadixCiphertext>),
        Result<Vec<RadixCiphertext>, crate::Error>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NUM_DATA_BLOCKS));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::thread_rng();

    for &len in &[2usize, 3, 4, 5, 8, 9, 12, 16] {
        let clear_keys: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();

        let enc_keys = clear_keys
            .iter()
            .map(|&v| cks.encrypt(v as u64))
            .collect::<Vec<_>>();
        let enc_data = clear_data
            .iter()
            .map(|&v| cks.encrypt(v as u64))
            .collect::<Vec<_>>();

        let result = executor.execute((enc_data, enc_keys)).unwrap();

        let mut decrypted: Vec<u32> = result
            .iter()
            .map(|ct| cks.decrypt::<u64>(ct) as u32)
            .collect();

        let expected = clear_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected, "len={len}");

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "len={len} permutation lost data");
    }

    // Non-power-of-2 case with a forced MAX key to stress the padding
    {
        let len = 17;
        let mut clear_keys: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        clear_keys[3] = u32::MAX;
        assert!(!clear_keys.len().is_power_of_two());

        let enc_keys = clear_keys
            .iter()
            .map(|&v| cks.encrypt(v as u64))
            .collect::<Vec<_>>();
        let enc_data = clear_data
            .iter()
            .map(|&v| cks.encrypt(v as u64))
            .collect::<Vec<_>>();

        let result = executor.execute((enc_data, enc_keys)).unwrap();

        let mut decrypted: Vec<u32> = result
            .iter()
            .map(|ct| cks.decrypt::<u64>(ct) as u32)
            .collect();

        let expected = clear_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected);

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "permutation lost data");
    }
}

pub(crate) fn unchecked_bitonic_shuffle_with_keys_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: FunctionExecutor<(Vec<RadixCiphertext>, Vec<RadixCiphertext>), Vec<RadixCiphertext>>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NUM_DATA_BLOCKS));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::thread_rng();

    for &len in &[2usize, 3, 4, 5, 8, 9, 12, 16] {
        let clear_keys: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();

        let enc_keys = clear_keys
            .iter()
            .map(|&v| cks.encrypt(v as u64))
            .collect::<Vec<_>>();
        let enc_data = clear_data
            .iter()
            .map(|&v| cks.encrypt(v as u64))
            .collect::<Vec<_>>();

        let result = executor.execute((enc_data, enc_keys));

        let mut decrypted: Vec<u32> = result
            .iter()
            .map(|ct| cks.decrypt::<u64>(ct) as u32)
            .collect();

        let expected = clear_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected, "len={len}");

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "len={len} permutation lost data");
    }
}

pub(crate) fn bitonic_shuffle_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: FunctionExecutor<
        (Vec<RadixCiphertext>, BitonicShuffleKeySize, Seed),
        Result<Vec<RadixCiphertext>, crate::Error>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NUM_DATA_BLOCKS));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::thread_rng();

    for &len in &[2usize, 3, 5, 8, 9] {
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let enc_data = clear_data
            .iter()
            .map(|&v| cks.encrypt(v as u64))
            .collect::<Vec<_>>();

        let result = executor
            .execute((
                enc_data,
                BitonicShuffleKeySize::num_bits(32),
                Seed(0xDEAD_BEEF),
            ))
            .expect("bitonic_shuffle returned an error");
        let mut decrypted: Vec<u32> = result
            .iter()
            .map(|ct| cks.decrypt::<u64>(ct) as u32)
            .collect();

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "len={len} permutation lost data");
    }

    // key_num_bits = 0 should error
    let enc_data = [1u32, 2, 3, 4]
        .iter()
        .map(|&v| cks.encrypt(v as u64))
        .collect::<Vec<_>>();
    assert!(executor
        .execute((enc_data, BitonicShuffleKeySize::num_bits(0), Seed(0)))
        .is_err());
}

pub(crate) fn bitonic_shuffle_with_keys_errors_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: FunctionExecutor<
        (Vec<RadixCiphertext>, Vec<RadixCiphertext>),
        Result<Vec<RadixCiphertext>, crate::Error>,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NUM_DATA_BLOCKS));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let enc_data = [1u32, 2]
        .iter()
        .map(|&v| cks.encrypt(v as u64))
        .collect::<Vec<_>>();
    let enc_keys = [1u32, 2, 3, 4]
        .iter()
        .map(|&v| cks.encrypt(v as u64))
        .collect::<Vec<_>>();

    assert!(executor.execute((enc_data, enc_keys)).is_err());
}

pub(crate) fn bitonic_shuffle_with_keys_invalid_block_counts_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: FunctionExecutor<
        (Vec<RadixCiphertext>, Vec<RadixCiphertext>),
        Result<Vec<RadixCiphertext>, crate::Error>,
    >,
{
    let param = param.into();
    let (cpu_cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cpu_cks.clone(), NUM_DATA_BLOCKS));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::thread_rng();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2() as usize;

    // Keys with arbitrary block counts (independent of the data block count)
    for &key_num_blocks in &[1usize, 2, 3, 5, 6, 7] {
        let len = 4usize;
        let key_value_modulus: u64 = 1u64 << (key_num_blocks as u32 * bits_per_block as u32);
        let clear_keys: Vec<u32> = (0..len)
            .map(|_| (rng.gen::<u64>() % key_value_modulus) as u32)
            .collect();
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();

        let key_cks = RadixClientKey::from((cpu_cks.clone(), key_num_blocks));
        let enc_keys: Vec<RadixCiphertext> = clear_keys
            .iter()
            .map(|&v| key_cks.encrypt(u64::from(v)))
            .collect();
        let enc_data: Vec<RadixCiphertext> =
            clear_data.iter().map(|&v| cks.encrypt(v as u64)).collect();

        let result = executor
            .execute((enc_data, enc_keys))
            .expect("bitonic_shuffle_with_keys returned an error");
        let mut decrypted: Vec<u32> = result
            .iter()
            .map(|ct| cks.decrypt::<u64>(ct) as u32)
            .collect();

        let expected = clear_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected, "key_num_blocks={key_num_blocks}");

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(
            decrypted, clear_data,
            "key_num_blocks={key_num_blocks} permutation lost data"
        );
    }
}
