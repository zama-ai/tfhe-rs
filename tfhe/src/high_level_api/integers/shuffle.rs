use crate::high_level_api::global_state;
use crate::high_level_api::integers::FheIntegerType;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::{
    PrfReRandomizationContext, ReRandomizationMetadata, ReRandomizationMode,
};
pub use crate::integer::server_key::radix_parallel::bitonic_shuffle::BitonicShuffleKeySize;
use crate::OprfSeed;

/// Shuffles `data` into a uniformly random permutation using a bitonic
/// sorting network with OPRF-generated random keys.
///
/// `key_size` controls the bit-width of the random sort keys used internally,
/// either by specifying a target collision probability or by passing a raw
/// bit count. Larger keys reduce collision probability (improving shuffle
/// uniformity) at the cost of more computation per comparison.
///
/// The re-randomization metadata of the input elements is not preserved
/// through the shuffle.
///
/// # Errors
///
/// Returns an error if the resolved key block count is 0
pub fn bitonic_shuffle<T, S>(
    data: Vec<T>,
    key_size: BitonicShuffleKeySize,
    seed: S,
) -> Result<Vec<T>, crate::Error>
where
    T: FheIntegerType,
    S: OprfSeed,
{
    global_state::with_internal_keys(|key| match key {
        InternalServerKey::Cpu(cpu_key) => {
            let inner = data.into_iter().map(|v| v.into_cpu()).collect();
            let result =
                cpu_key
                    .pbs_key()
                    .bitonic_shuffle(&cpu_key.oprf_key(), inner, key_size, seed)?;
            Ok(result
                .into_iter()
                .map(|ct| T::from_cpu(ct, cpu_key.tag.clone(), ReRandomizationMetadata::default()))
                .collect())
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(cuda_key) => {
            let streams = &cuda_key.streams;
            let inner = data.into_iter().map(|v| v.into_gpu(streams)).collect();
            let result = cuda_key.pbs_key().bitonic_shuffle(
                &cuda_key.oprf_key(),
                inner,
                key_size,
                seed,
                streams,
            )?;
            Ok(result
                .into_iter()
                .map(|ct| T::from_gpu(ct, cuda_key.tag.clone(), ReRandomizationMetadata::default()))
                .collect())
        }
        #[cfg(feature = "hpu")]
        InternalServerKey::Hpu(_) => Err(crate::Error::new(
            "bitonic_shuffle is not supported on Hpu".to_string(),
        )),
    })
}

pub fn re_randomized_keys_bitonic_shuffle<T, S>(
    data: Vec<T>,
    key_size: BitonicShuffleKeySize,
    seed: S,
    re_randomization_mode: ReRandomizationMode,
    prf_re_randomization_context: &PrfReRandomizationContext,
) -> Result<Vec<T>, crate::Error>
where
    T: FheIntegerType,
    S: OprfSeed,
{
    global_state::with_internal_keys(|key| match key {
        InternalServerKey::Cpu(cpu_key) => {
            let re_randomization_key =
                cpu_key.integer_re_randomization_key_from_mode(re_randomization_mode)?;
            let inner = data.into_iter().map(|v| v.into_cpu()).collect();
            let result = cpu_key.pbs_key().re_randomized_keys_bitonic_shuffle(
                &cpu_key.oprf_key(),
                inner,
                key_size,
                seed,
                &re_randomization_key,
                prf_re_randomization_context.inner(),
            )?;
            Ok(result
                .into_iter()
                .map(|ct| T::from_cpu(ct, cpu_key.tag.clone(), ReRandomizationMetadata::default()))
                .collect())
        }
        #[cfg(feature = "gpu")]
        InternalServerKey::Cuda(cuda_key) => {
            let re_randomization_key =
                cuda_key.integer_re_randomization_key_from_mode(re_randomization_mode)?;
            let streams = &cuda_key.streams;
            let inner = data.into_iter().map(|v| v.into_gpu(streams)).collect();
            let result = cuda_key.pbs_key().bitonic_shuffle_and_re_randomize(
                &cuda_key.oprf_key(),
                inner,
                key_size,
                seed,
                &re_randomization_key,
                prf_re_randomization_context.inner(),
                streams,
            )?;
            Ok(result
                .into_iter()
                .map(|ct| T::from_gpu(ct, cuda_key.tag.clone(), ReRandomizationMetadata::default()))
                .collect())
        }
        #[cfg(feature = "hpu")]
        InternalServerKey::Hpu(_) => Err(crate::Error::new(
            "bitonic_shuffle is not supported on Hpu".to_string(),
        )),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::prelude::new_seeder;
    #[cfg(feature = "gpu")]
    use crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN;
    use crate::high_level_api::prelude::*;
    use crate::high_level_api::tests::setup_default_cpu;
    use crate::high_level_api::{set_server_key, ClientKey, ConfigBuilder, ServerKey};
    use crate::shortint::ciphertext::{ReRandomizationHashAlgo, ReRandomizationSeedHasher};
    use crate::shortint::parameters::ReRandomizationParameters;
    #[cfg(feature = "gpu")]
    use crate::CompressedServerKey;
    #[cfg(feature = "gpu")]
    use crate::{FheInt16, FheUint32};
    use crate::{FheInt8, FheUint8};
    #[cfg(feature = "gpu")]
    use rand::distributions::Standard;
    use rand::Rng;
    #[cfg(feature = "gpu")]
    use std::fmt::Debug;

    #[cfg(feature = "gpu")]
    use crate::high_level_api::tests::is_sanitizer_run;

    #[test]
    fn test_bitonic_shuffle_fheuint() {
        let cks = {
            let config = ConfigBuilder::default()
                .use_dedicated_oprf_key(true)
                .enable_ciphertext_re_randomization(
                    ReRandomizationParameters::DerivedCPKWithoutKeySwitch,
                )
                .build();

            let cks = ClientKey::generate(config);
            let sks = ServerKey::new(&cks);

            set_server_key(sks);

            cks
        };
        let mut rng = rand::thread_rng();
        let mut clear_values: Vec<u8> = (0..15).map(|_| rng.gen()).collect();

        let encrypted: Vec<FheUint8> = clear_values
            .iter()
            .map(|&v| FheUint8::try_encrypt(v, &cks).unwrap())
            .collect();

        let seed = new_seeder().seed();
        println!("seed: {seed:?}");
        let key_size = BitonicShuffleKeySize::num_bits(32);
        let shuffled = bitonic_shuffle(encrypted.clone(), key_size, seed).unwrap();
        let shuffled_rerand = {
            let mut shuffled_rerand = vec![];

            for rerand_hash_algo in [
                ReRandomizationHashAlgo::Blake3,
                ReRandomizationHashAlgo::Shake256,
            ] {
                let seed_hasher = ReRandomizationSeedHasher::new(
                    rerand_hash_algo,
                    crate::shortint::oprf::TFHE_PRF_RERAND_DOMAIN_SEPARATOR,
                );
                let prf_rerand_context = PrfReRandomizationContext::new_with_hasher(
                    crate::shortint::public_key::compact::TFHE_PKE_DOMAIN_SEPARATOR,
                    seed_hasher,
                );

                shuffled_rerand.push(
                    re_randomized_keys_bitonic_shuffle(
                        encrypted.clone(),
                        key_size,
                        seed,
                        ReRandomizationMode::UseAvailableMode,
                        &prf_rerand_context,
                    )
                    .unwrap(),
                );
            }

            shuffled_rerand
        };

        let decrypted_ref: Vec<u8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

        clear_values.sort_unstable();
        let decrypted_sorted = {
            let mut tmp = decrypted_ref.clone();
            tmp.sort_unstable();
            tmp
        };

        assert_eq!(decrypted_sorted, clear_values);

        for (idx, rerand_result) in shuffled_rerand.into_iter().enumerate() {
            let decrypted_rerand: Vec<u8> =
                rerand_result.iter().map(|ct| ct.decrypt(&cks)).collect();

            assert_eq!(
                decrypted_ref, decrypted_rerand,
                "failed at index {idx} of decrypted_rerand"
            );
        }
    }

    #[test]
    fn test_bitonic_shuffle_fheint() {
        let cks = {
            let config = ConfigBuilder::default()
                .use_dedicated_oprf_key(true)
                .enable_ciphertext_re_randomization(
                    ReRandomizationParameters::DerivedCPKWithoutKeySwitch,
                )
                .build();

            let cks = ClientKey::generate(config);
            let sks = ServerKey::new(&cks);

            set_server_key(sks);

            cks
        };

        let mut rng = rand::thread_rng();
        let mut clear_values: Vec<i8> = (0..15).map(|_| rng.gen()).collect();

        let encrypted: Vec<FheInt8> = clear_values
            .iter()
            .map(|&v| FheInt8::try_encrypt(v, &cks).unwrap())
            .collect();

        let seed = new_seeder().seed();
        println!("seed: {seed:?}");
        let key_size = BitonicShuffleKeySize::num_bits(32);
        let shuffled = bitonic_shuffle(encrypted.clone(), key_size, seed).unwrap();
        let shuffled_rerand = {
            let mut shuffled_rerand = vec![];

            for rerand_hash_algo in [
                ReRandomizationHashAlgo::Blake3,
                ReRandomizationHashAlgo::Shake256,
            ] {
                let seed_hasher = ReRandomizationSeedHasher::new(
                    rerand_hash_algo,
                    crate::shortint::oprf::TFHE_PRF_RERAND_DOMAIN_SEPARATOR,
                );
                let prf_rerand_context = PrfReRandomizationContext::new_with_hasher(
                    crate::shortint::public_key::compact::TFHE_PKE_DOMAIN_SEPARATOR,
                    seed_hasher,
                );

                shuffled_rerand.push(
                    re_randomized_keys_bitonic_shuffle(
                        encrypted.clone(),
                        key_size,
                        seed,
                        ReRandomizationMode::UseAvailableMode,
                        &prf_rerand_context,
                    )
                    .unwrap(),
                );
            }

            shuffled_rerand
        };

        let decrypted_ref: Vec<i8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

        clear_values.sort_unstable();
        let decrypted_sorted = {
            let mut tmp = decrypted_ref.clone();
            tmp.sort_unstable();
            tmp
        };

        assert_eq!(decrypted_sorted, clear_values);

        for (idx, rerand_result) in shuffled_rerand.into_iter().enumerate() {
            let decrypted_rerand: Vec<i8> =
                rerand_result.iter().map(|ct| ct.decrypt(&cks)).collect();

            assert_eq!(
                decrypted_ref, decrypted_rerand,
                "failed at index {idx} of decrypted_rerand"
            );
        }
    }

    #[test]
    fn test_bitonic_shuffle_collision_probability() {
        let cks = setup_default_cpu();
        let mut rng = rand::thread_rng();
        let mut clear_values: Vec<u8> = (0..15).map(|_| rng.gen()).collect();

        let encrypted: Vec<FheUint8> = clear_values
            .iter()
            .map(|&v| FheUint8::try_encrypt(v, &cks).unwrap())
            .collect();

        let seed = new_seeder().seed();
        println!("seed: {seed:?}");
        // For n = 15, ceil(log2(15^2 / (2 * 4e-8))) = 32 bits of key.
        let key_size = BitonicShuffleKeySize::collision_probability(4e-8);
        let shuffled = bitonic_shuffle(encrypted, key_size, seed).unwrap();

        let mut decrypted: Vec<u8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

        clear_values.sort_unstable();
        decrypted.sort_unstable();
        assert_eq!(decrypted, clear_values);
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn test_bitonic_shuffle_fheuint_gpu() {
        for setup_fn in GPU_SETUP_FN {
            let cks = setup_fn();
            let mut rng = rand::thread_rng();
            let mut clear_values: Vec<u8> = (0..15).map(|_| rng.gen()).collect();

            let encrypted: Vec<FheUint8> = clear_values
                .iter()
                .map(|&v| FheUint8::try_encrypt(v, &cks).unwrap())
                .collect();

            let seed = new_seeder().seed();
            let shuffled =
                bitonic_shuffle(encrypted, BitonicShuffleKeySize::num_bits(32), seed).unwrap();

            let mut decrypted: Vec<u8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

            clear_values.sort_unstable();
            decrypted.sort_unstable();
            assert_eq!(decrypted, clear_values);
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn test_bitonic_shuffle_fheint_gpu() {
        for setup_fn in GPU_SETUP_FN {
            let cks = setup_fn();
            let mut rng = rand::thread_rng();
            let mut clear_values: Vec<i8> = (0..15).map(|_| rng.gen()).collect();

            let encrypted: Vec<FheInt8> = clear_values
                .iter()
                .map(|&v| FheInt8::try_encrypt(v, &cks).unwrap())
                .collect();

            let seed = new_seeder().seed();
            let shuffled =
                bitonic_shuffle(encrypted, BitonicShuffleKeySize::num_bits(32), seed).unwrap();

            let mut decrypted: Vec<i8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

            clear_values.sort_unstable();
            decrypted.sort_unstable();
            assert_eq!(decrypted, clear_values);
        }
    }

    /// Generates some key sets and sorts on encrypted data
    /// with bitonic sort. Compares FHE results to clear-text results
    #[cfg(feature = "gpu")]
    fn common_test_bitonic_sort_order_cpu_vs_gpu<CT, ET>()
    where
        CT: Copy + Eq + Debug + Ord,
        ET: FheIntegerType + FheTryEncrypt<CT, ClientKey> + FheDecrypt<CT> + Clone,
        Standard: rand_distr::Distribution<CT>,
        u32: CastFrom<CT>,
    {
        use crate::high_level_api::global_state;
        use crate::high_level_api::keys::InternalServerKey;
        use crate::high_level_api::re_randomization::ReRandomizationMetadata;

        let mut rng = rand::thread_rng();

        let ns: &[usize] = if is_sanitizer_run() {
            &[2, 5, 11]
        } else {
            &[2, 5, 9, 11, 3, 6, 7, 10]
        };

        // Pre-generate clear data: three categories of key patterns.
        let cases: Vec<(Vec<u32>, Vec<CT>)> = ns
            .iter()
            .enumerate()
            .map(|(i, &n)| {
                let keys: Vec<u32> = if i < ns.len() / 3 {
                    // Descending keys: the sort should reverse the list of values
                    (0..n).rev().map(|i| i as u32).collect()
                } else if i < 2 * ns.len() / 3 {
                    // Duplicate keys: cycle through n/2+1 distinct values to
                    // force ties and exercise the bitonic network's equal-key
                    // tie-breaking (which differs from a stable sort)
                    (0..n).map(|j| j as u32 % (n as u32 / 2 + 1)).collect()
                } else {
                    // Random full-range u32 keys: simulates shuffle
                    (0..n).map(|_| rng.gen::<u32>()).collect()
                };
                let data: Vec<CT> = (0..n).map(|_| rng.gen()).collect();
                (keys, data)
            })
            .collect();

        // Clear-text reference: simulate the exact bitonic network (with its
        // non-stable equal-key tie-breaking) so the expected output matches the
        // GPU even when two keys collide (e.g. small CT types like i8/i16).
        let clear_refs: Vec<Vec<CT>> = cases
            .iter()
            .map(|(clear_keys, clear_data)| {
                use crate::integer::server_key::radix_parallel::tests_unsigned::test_bitonic_shuffle::clear_bitonic_shuffle_with_keys;
                let n = clear_data.len();
                let indices: Vec<u32> = (0..n as u32).collect();
                let sorted_indices = clear_bitonic_shuffle_with_keys(&indices, clear_keys);
                sorted_indices.iter().map(|&i| clear_data[i as usize]).collect()
            })
            .collect();

        // GPU: compare each result against the CPU reference, all crypto-parameter types
        for setup_fn in GPU_SETUP_FN {
            let cks = setup_fn();
            for (i, (clear_keys, clear_data)) in cases.iter().enumerate() {
                let n = ns[i];
                let enc_keys: Vec<FheUint32> = clear_keys
                    .iter()
                    .map(|&v| FheUint32::try_encrypt(v, &cks).unwrap())
                    .collect();
                let enc_data: Vec<ET> = clear_data
                    .iter()
                    .map(|&v| ET::try_encrypt(v, &cks).unwrap())
                    .collect();

                let sorted: Vec<ET> = global_state::with_internal_keys(|key| {
                    let InternalServerKey::Cuda(cuda_server_key) = key else {
                        panic!("expected CUDA server key");
                    };
                    let streams = &cuda_server_key.streams;
                    let gpu_keys = enc_keys
                        .into_iter()
                        .map(|k| k.into_gpu(streams))
                        .collect::<Vec<_>>();
                    let gpu_data = enc_data
                        .into_iter()
                        .map(|d| d.into_gpu(streams))
                        .collect::<Vec<_>>();
                    let r = cuda_server_key
                        .pbs_key()
                        .bitonic_shuffle_with_keys(gpu_data, gpu_keys, streams)
                        .unwrap();
                    r.into_iter()
                        .map(|ct| {
                            ET::from_gpu(
                                ct,
                                cuda_server_key.tag.clone(),
                                ReRandomizationMetadata::default(),
                            )
                        })
                        .collect::<Vec<_>>()
                });

                let gpu_dec: Vec<CT> = sorted.iter().map(|ct| ct.decrypt(&cks)).collect();
                assert_eq!(gpu_dec, clear_refs[i], "GPU/CPU mismatch for n={n}");
            }
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn test_bitonic_sort_order_cpu_vs_gpu() {
        common_test_bitonic_sort_order_cpu_vs_gpu::<i16, FheInt16>();
        if !is_sanitizer_run() {
            common_test_bitonic_sort_order_cpu_vs_gpu::<i8, FheInt8>();
            common_test_bitonic_sort_order_cpu_vs_gpu::<u32, FheUint32>();
        }
    }

    #[cfg(feature = "gpu")]
    fn common_test_bitonic_shuffle_seed_unique_gpu<CT, ET>()
    where
        CT: Copy + Eq + Debug + Ord,
        ET: FheIntegerType + FheTryEncrypt<CT, ClientKey> + FheDecrypt<CT> + Clone,
        Standard: rand_distr::Distribution<CT>,
    {
        for setup_fn in GPU_SETUP_FN {
            let cks = setup_fn();
            let mut rng = rand::thread_rng();
            let mut clear_values: Vec<CT> = (0..15).map(|_| rng.gen()).collect();

            let encrypted: Vec<ET> = clear_values
                .iter()
                .map(|&v| ET::try_encrypt(v, &cks).unwrap())
                .collect();

            let seed1 = new_seeder().seed();
            let shuffled1 = bitonic_shuffle(
                encrypted.clone(),
                BitonicShuffleKeySize::num_bits(32),
                seed1,
            )
            .unwrap();

            let seed2 = new_seeder().seed();
            let shuffled2 =
                bitonic_shuffle(encrypted, BitonicShuffleKeySize::num_bits(32), seed2).unwrap();

            let mut decrypted1: Vec<CT> = shuffled1.iter().map(|ct| ct.decrypt(&cks)).collect();
            let mut decrypted2: Vec<CT> = shuffled2.iter().map(|ct| ct.decrypt(&cks)).collect();

            assert_ne!(decrypted1, decrypted2, "For the same input, two shuffles with a different seed produced the same shuffled list");

            clear_values.sort_unstable();
            decrypted1.sort_unstable();
            assert_eq!(decrypted1, clear_values);

            decrypted2.sort_unstable();
            assert_eq!(decrypted2, clear_values);
        }
    }
    #[cfg(feature = "gpu")]
    #[test]
    fn test_bitonic_shuffle_unique_seed_gpu() {
        common_test_bitonic_shuffle_seed_unique_gpu::<u32, FheUint32>();
        if !is_sanitizer_run() {
            common_test_bitonic_shuffle_seed_unique_gpu::<i16, FheInt16>();
            common_test_bitonic_shuffle_seed_unique_gpu::<i8, FheInt8>();
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn test_bitonic_shuffle_collision_probability_gpu() {
        for setup_fn in GPU_SETUP_FN {
            let cks = setup_fn();
            let mut rng = rand::thread_rng();
            let mut clear_values: Vec<u8> = (0..15).map(|_| rng.gen()).collect();

            let encrypted: Vec<FheUint8> = clear_values
                .iter()
                .map(|&v| FheUint8::try_encrypt(v, &cks).unwrap())
                .collect();

            let seed = new_seeder().seed();
            let key_size = BitonicShuffleKeySize::collision_probability(4e-8);
            let shuffled = bitonic_shuffle(encrypted, key_size, seed).unwrap();

            let mut decrypted: Vec<u8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();

            clear_values.sort_unstable();
            decrypted.sort_unstable();
            assert_eq!(decrypted, clear_values);
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn test_bitonic_shuffle_rerand_fheuint_gpu() {
        let cks = {
            let config = ConfigBuilder::default()
                .use_dedicated_oprf_key(true)
                .enable_ciphertext_re_randomization(
                    ReRandomizationParameters::DerivedCPKWithoutKeySwitch,
                )
                .build();
            let cks = ClientKey::generate(config);
            let compressed_sks = CompressedServerKey::new(&cks);
            let sks = compressed_sks.decompress_to_gpu();
            set_server_key(sks);
            cks
        };
        let mut rng = rand::thread_rng();
        let mut clear_values: Vec<u8> = (0..15).map(|_| rng.gen()).collect();

        let encrypted: Vec<FheUint8> = clear_values
            .iter()
            .map(|&v| FheUint8::try_encrypt(v, &cks).unwrap())
            .collect();

        let seed = new_seeder().seed();
        println!("seed: {seed:?}");
        let key_size = BitonicShuffleKeySize::num_bits(32);
        let shuffled = bitonic_shuffle(encrypted.clone(), key_size, seed).unwrap();
        let shuffled_rerand = {
            let mut shuffled_rerand = vec![];
            for rerand_hash_algo in [
                ReRandomizationHashAlgo::Blake3,
                ReRandomizationHashAlgo::Shake256,
            ] {
                let seed_hasher = ReRandomizationSeedHasher::new(
                    rerand_hash_algo,
                    crate::shortint::oprf::TFHE_PRF_RERAND_DOMAIN_SEPARATOR,
                );
                let prf_rerand_context = PrfReRandomizationContext::new_with_hasher(
                    crate::shortint::public_key::compact::TFHE_PKE_DOMAIN_SEPARATOR,
                    seed_hasher,
                );
                shuffled_rerand.push(
                    re_randomized_keys_bitonic_shuffle(
                        encrypted.clone(),
                        key_size,
                        seed,
                        ReRandomizationMode::UseAvailableMode,
                        &prf_rerand_context,
                    )
                    .unwrap(),
                );
            }
            shuffled_rerand
        };

        let decrypted_ref: Vec<u8> = shuffled.iter().map(|ct| ct.decrypt(&cks)).collect();
        clear_values.sort_unstable();
        let decrypted_sorted = {
            let mut tmp = decrypted_ref.clone();
            tmp.sort_unstable();
            tmp
        };
        assert_eq!(decrypted_sorted, clear_values);

        for (idx, rerand_result) in shuffled_rerand.into_iter().enumerate() {
            let decrypted_rerand: Vec<u8> =
                rerand_result.iter().map(|ct| ct.decrypt(&cks)).collect();
            assert_eq!(
                decrypted_ref, decrypted_rerand,
                "failed at index {idx} of decrypted_rerand"
            );
        }
    }
}
