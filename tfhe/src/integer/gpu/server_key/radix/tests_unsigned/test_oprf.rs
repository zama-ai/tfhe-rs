use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
use crate::core_crypto::prelude::decrypt_lwe_ciphertext;
use crate::integer::gpu::server_key::radix::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{gen_keys_gpu, CudaServerKey};
use crate::integer::{ClientKey, RadixCiphertext};
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::oprf::{create_random_from_seed_modulus_switched, raw_seeded_msed_to_lwe};
use crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use rand::prelude::SliceRandom;
use rand::Rng;
use rayon::prelude::*;
use statrs::distribution::ContinuousCDF;
use std::collections::HashMap;
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::{Seed, Seeder};

fn square(a: f64) -> f64 {
    a * a
}

fn get_random_gpu_streams() -> CudaStreams {
    let num_gpus = get_number_of_gpus();
    assert_ne!(
        num_gpus, 0,
        "Cannot run GPU test, since no GPUs are available."
    );

    let mut gpu_indexes: Vec<GpuIndex> = (0..num_gpus).map(GpuIndex::new).collect();

    let mut rng = rand::thread_rng();
    gpu_indexes.shuffle(&mut rng);

    let num_gpus_to_use = rng.gen_range(1..=num_gpus as usize);

    let random_slice = &gpu_indexes[..num_gpus_to_use];

    CudaStreams::new_multi_gpu_with_indexes(random_slice)
}

#[test]
fn test_gpu_oprf_compare_plain_ci_run_filter() {
    let streams = get_random_gpu_streams();
    let (ck, gpu_sk) = gen_keys_gpu(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        &streams,
    );

    for seed in 0..1000 {
        oprf_compare_plain_from_seed(Seed(seed), &ck, &gpu_sk, &streams);
    }
}

fn oprf_compare_plain_from_seed(
    seed: Seed,
    ck: &ClientKey,
    sk: &CudaServerKey,
    streams: &CudaStreams,
) {
    let params = ck.parameters();
    let num_blocks = 8;
    let message_bits_per_block = params.message_modulus().0.ilog2() as u64;
    let random_bits_count = num_blocks * message_bits_per_block;

    let input_p = 2 * params.polynomial_size().0 as u64;
    let log_input_p = input_p.ilog2();
    let p_prime = 1 << message_bits_per_block;
    let output_p = 2 * params.carry_modulus().0 * params.message_modulus().0;
    let poly_delta = 2 * params.polynomial_size().0 as u64 / p_prime;

    let d_img: CudaUnsignedRadixCiphertext = sk
        .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
            seed,
            random_bits_count,
            num_blocks,
            streams,
        );
    let img: RadixCiphertext = d_img.to_radix_ciphertext(streams);

    let (lwe_size, polynomial_size) = match &sk.bootstrapping_key {
        CudaBootstrappingKey::Classic(d_bsk) => (
            d_bsk.input_lwe_dimension().to_lwe_size(),
            d_bsk.polynomial_size(),
        ),
        CudaBootstrappingKey::MultiBit(d_multibit_bsk) => (
            d_multibit_bsk.input_lwe_dimension().to_lwe_size(),
            d_multibit_bsk.polynomial_size(),
        ),
    };

    let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

    for i in 0..num_blocks as usize {
        let block_seed = seeder.seed();

        let ct = raw_seeded_msed_to_lwe(
            &create_random_from_seed_modulus_switched::<u64>(
                block_seed,
                lwe_size,
                polynomial_size.to_blind_rotation_input_modulus_log(),
            ),
            sk.ciphertext_modulus,
        );

        let AtomicPatternClientKey::Standard(std_ck) = &ck.key.atomic_pattern else {
            panic!("Only std AP is supported on GPU")
        };

        let secret_key = std_ck.small_lwe_secret_key();
        let plain_prf_input = decrypt_lwe_ciphertext(&secret_key, &ct)
            .0
            .wrapping_add(1 << (64 - log_input_p - 1))
            >> (64 - log_input_p);

        let half_negacyclic_part = |x| 2 * (x / poly_delta) + 1;
        let negacyclic_part = |x| {
            assert!(x < input_p);
            if x < input_p / 2 {
                half_negacyclic_part(x)
            } else {
                2 * output_p - half_negacyclic_part(x - (input_p / 2))
            }
        };
        let prf = |x| {
            let a = (negacyclic_part(x) + p_prime - 1) % (2 * output_p);
            assert!(a % 2 == 0);
            a / 2
        };

        let expected_output = prf(plain_prf_input);

        let output = ck.key.decrypt_message_and_carry(&img.blocks[i]);

        assert!(output < p_prime);
        assert_eq!(output, expected_output);
    }
}

#[test]
fn test_gpu_oprf_test_uniformity_ci_run_filter() {
    let sample_count: usize = 100_000;

    let p_value_limit: f64 = 0.000_01;
    let streams = get_random_gpu_streams();
    let (ck, gpu_sk) = gen_keys_gpu(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        &streams,
    );

    let test_uniformity = |distinct_values: u64, f: &(dyn Fn(usize) -> u64 + Sync)| {
        test_uniformity(sample_count, p_value_limit, distinct_values, f)
    };

    let random_bits_count = 2;

    test_uniformity(1 << random_bits_count, &|seed| {
        let d_img: CudaUnsignedRadixCiphertext = gpu_sk.generate_oblivious_pseudo_random(
            Seed(seed as u128),
            random_bits_count,
            &streams,
        );
        let img: RadixCiphertext = d_img.to_radix_ciphertext(&streams);
        ck.decrypt_radix(&img)
    });
}

pub fn test_uniformity<F>(sample_count: usize, p_value_limit: f64, distinct_values: u64, f: F)
where
    F: Sync + Fn(usize) -> u64,
{
    let p_value = uniformity_p_value(f, sample_count, distinct_values);

    assert!(
        p_value_limit < p_value,
        "p_value (={p_value}) expected to be bigger than {p_value_limit}"
    );
}

fn uniformity_p_value<F>(f: F, sample_count: usize, distinct_values: u64) -> f64
where
    F: Sync + Fn(usize) -> u64,
{
    let values: Vec<_> = (0..sample_count).into_par_iter().map(&f).collect();

    let mut values_count = HashMap::new();

    for i in &values {
        assert!(*i < distinct_values, "i {} dv{}", *i, distinct_values);

        *values_count.entry(i).or_insert(0) += 1;
    }

    let single_expected_count = sample_count as f64 / distinct_values as f64;

    // https://en.wikipedia.org/wiki/Pearson's_chi-squared_test
    let distance: f64 = (0..distinct_values)
        .map(|value| *values_count.get(&value).unwrap_or(&0))
        .map(|count| square(count as f64 - single_expected_count) / single_expected_count)
        .sum();

    statrs::distribution::ChiSquared::new((distinct_values - 1) as f64)
        .unwrap()
        .sf(distance)
}
