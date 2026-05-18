use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::{IntegerKeyKind, RadixClientKey};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::TestParameters;
use rand::Rng;
use tfhe_csprng::seeders::{Seed, Seeder};

const NUM_DATA_BLOCKS: usize = 16; // 32 bits with message_modulus = 2^2

// Mirrors the GPU kernel's padding logic: extends each real key into u64
// (so sentinel=u64::MAX strictly outranks every real key) and appends
// (MAX, 0) sentinels up to next_power_of_two, then runs the bitonic network
// and truncates back to n.
fn clear_bitonic_shuffle_with_keys(data: &[u32], keys: &[u32]) -> Vec<u32> {
    let n = data.len();
    assert!(n >= 2);
    let padded_n = n.next_power_of_two();

    let mut keys: Vec<u64> = keys.iter().map(|&k| u64::from(k)).collect();
    let mut data = data.to_vec();
    while keys.len() < padded_n {
        keys.push(u64::MAX);
        data.push(0);
    }

    let mut k = 2usize;
    while k <= padded_n {
        let mut j = k >> 1;
        while j > 0 {
            for i in 0..padded_n {
                let l = i ^ j;
                if l > i {
                    let ascending = (i & k) == 0;
                    let swap = if ascending {
                        keys[i] > keys[l]
                    } else {
                        keys[i] < keys[l]
                    };
                    if swap {
                        keys.swap(i, l);
                        data.swap(i, l);
                    }
                }
            }
            j >>= 1;
        }
        k <<= 1;
    }
    data.truncate(n);
    data
}

fn setup_unsigned(param: TestParameters) -> (RadixClientKey, CudaServerKey, CudaStreams) {
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NUM_DATA_BLOCKS));
    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(cks.as_ref(), &streams);
    streams.synchronize();
    (cks, sks, streams)
}

fn encrypt_data_unsigned(
    cks: &RadixClientKey,
    streams: &CudaStreams,
    clear: &[u32],
) -> Vec<CudaUnsignedRadixCiphertext> {
    clear
        .iter()
        .map(|&v| {
            let ct = cks.encrypt(v as u64);
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, streams)
        })
        .collect()
}

fn decrypt_unsigned(
    cks: &RadixClientKey,
    streams: &CudaStreams,
    cts: &[CudaUnsignedRadixCiphertext],
) -> Vec<u32> {
    cts.iter()
        .map(|d_ct| {
            let ct = d_ct.to_radix_ciphertext(streams);
            cks.decrypt::<u64>(&ct) as u32
        })
        .collect()
}

#[derive(Default)]
struct DummySeeder {
    state: u128,
}

impl Seeder for DummySeeder {
    fn seed(&mut self) -> Seed {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        Seed(self.state)
    }

    fn is_available() -> bool {
        true
    }
}

fn run_unchecked_bitonic_shuffle_with_keys(param: TestParameters) {
    let (cks, sks, streams) = setup_unsigned(param);
    let mut rng = rand::thread_rng();

    for &len in &[2usize, 3, 4, 5, 8, 9, 12, 16] {
        let clear_keys: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();

        let enc_keys = encrypt_data_unsigned(&cks, &streams, &clear_keys);
        let enc_data = encrypt_data_unsigned(&cks, &streams, &clear_data);

        let result = sks.unchecked_bitonic_shuffle_with_keys(enc_data, enc_keys, &streams);
        let mut decrypted = decrypt_unsigned(&cks, &streams, &result);

        let expected = clear_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected, "len={len}");

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "len={len} permutation lost data");
    }
}

fn run_bitonic_shuffle_with_keys(param: TestParameters) {
    let (cks, sks, streams) = setup_unsigned(param);
    let mut rng = rand::thread_rng();

    for &len in &[2usize, 3, 5, 8, 9] {
        let clear_keys: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();

        let enc_keys = encrypt_data_unsigned(&cks, &streams, &clear_keys);
        let enc_data = encrypt_data_unsigned(&cks, &streams, &clear_data);

        let result = sks
            .bitonic_shuffle_with_keys(enc_data, enc_keys, &streams)
            .expect("bitonic_shuffle_with_keys returned an error");
        let mut decrypted = decrypt_unsigned(&cks, &streams, &result);

        let expected = clear_bitonic_shuffle_with_keys(&clear_data, &clear_keys);
        assert_eq!(decrypted, expected, "len={len}");

        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "len={len} permutation lost data");
    }
}

fn run_bitonic_shuffle(param: TestParameters) {
    let (cks, sks, streams) = setup_unsigned(param);
    let mut rng = rand::thread_rng();

    for &len in &[2usize, 3, 5, 8, 9] {
        let mut clear_data: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        let enc_data = encrypt_data_unsigned(&cks, &streams, &clear_data);

        let mut seeder = DummySeeder { state: 0xDEAD_BEEF };
        let result = sks
            .bitonic_shuffle(enc_data, 8, &mut seeder, &streams)
            .expect("bitonic_shuffle returned an error");
        let mut decrypted = decrypt_unsigned(&cks, &streams, &result);

        // We cannot predict the random permutation; verify multiset equality.
        decrypted.sort_unstable();
        clear_data.sort_unstable();
        assert_eq!(decrypted, clear_data, "len={len} permutation lost data");
    }

    // Error path: key_num_blocks = 0
    let enc_data = encrypt_data_unsigned(&cks, &streams, &[1, 2, 3, 4]);
    let mut seeder = DummySeeder::default();
    assert!(sks
        .bitonic_shuffle(enc_data, 0, &mut seeder, &streams)
        .is_err());
}

fn run_bitonic_shuffle_with_keys_errors(param: TestParameters) {
    let (cks, sks, streams) = setup_unsigned(param);
    // Mismatched lengths: 2 data, 4 keys.
    let enc_data = encrypt_data_unsigned(&cks, &streams, &[1, 2]);
    let enc_keys = encrypt_data_unsigned(&cks, &streams, &[1, 2, 3, 4]);
    assert!(sks
        .bitonic_shuffle_with_keys(enc_data, enc_keys, &streams)
        .is_err());
}

#[test]
fn test_unchecked_bitonic_shuffle_with_keys_unsigned() {
    run_unchecked_bitonic_shuffle_with_keys(
        TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
    );
}

#[test]
fn test_bitonic_shuffle_with_keys_unsigned() {
    run_bitonic_shuffle_with_keys(
        TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
    );
}

#[test]
fn test_bitonic_shuffle_unsigned() {
    run_bitonic_shuffle(
        TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
    );
}

#[test]
fn test_bitonic_shuffle_with_keys_errors_unsigned() {
    run_bitonic_shuffle_with_keys_errors(
        TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
    );
}
